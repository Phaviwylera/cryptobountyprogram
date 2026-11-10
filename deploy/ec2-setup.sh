#!/usr/bin/env bash
# One-shot bootstrap for a fresh Ubuntu 22.04/24.04 EC2 instance (Docker path).
# Run as: bash ec2-setup.sh   (it installs Docker, builds the image, starts the dashboard 24/7)
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/Phaviwylera/cryptobountyprogram.git}"
APP_DIR="${APP_DIR:-$HOME/cryptobountyprogram}"

echo "==> Installing Docker + compose plugin"
if ! command -v docker >/dev/null; then
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl git
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo usermod -aG docker "$USER" || true
fi

echo "==> Fetching the app"
[ -d "$APP_DIR/.git" ] || git clone "$REPO_URL" "$APP_DIR"
cd "$APP_DIR/deploy"

if [ ! -f .env ]; then
  echo "==> Creating deploy/.env - EDIT IT with your keys, then re-run this script"
  cp bountyscan.env.example .env
  echo
  echo "    nano $APP_DIR/deploy/.env       # set ETHERSCAN_API_KEY and RPC_URL"
  echo
  exit 1
fi

if [ ! -f .htpasswd ]; then
  echo "==> Creating a dashboard login"
  read -rp "Dashboard username: " U
  # htpasswd via the httpd image so we don't install apache-utils
  sudo docker run --rm httpd:2.4-alpine htpasswd -nbB "$U" "$(openssl rand -base64 12 | tee /tmp/bs_pw)" > .htpasswd
  echo "    Password (save it): $(cat /tmp/bs_pw)"; rm -f /tmp/bs_pw
fi
mkdir -p certs

echo "==> Building and starting (24/7, restarts on reboot)"
sudo docker compose up -d --build
echo
echo "==> Done. Dashboard: http://<THIS-EC2-PUBLIC-IP>/  (basic-auth protected)"
echo "    Open security group port 80 (and 443 if you add TLS) to YOUR IP only."
echo "    Logs:   cd $APP_DIR/deploy && sudo docker compose logs -f"
echo "    Stop:   sudo docker compose down"
