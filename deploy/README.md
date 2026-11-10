# Deploying the bountyscan dashboard on EC2 (24/7)

The dashboard has two buttons — **Live Scan** (follows the chain forever, scanning every new
verified contract and moving to the next automatically) and **Immunefi Scan** (a bounty program's
in-scope contracts) — plus a **Results** page. Every fund-theft finding is independently
re-confirmed before it is saved, with a full what/where/how-exploited/how-to-fix report.

> **Security first.** The dashboard itself has no login, so it must never be exposed directly.
> nginx with HTTP basic auth sits in front of it, and only nginx's port is open. Lock the
> security group to your own IP. Treat every scan result as an unverified lead — see
> `../docs/DISCLOSURE.md` before contacting anyone.

## 1. Launch the instance

- **AMI:** Ubuntu Server 24.04 LTS. **Type:** `t3.small` is enough (`t3.medium` if you scan large
  programs). **Disk:** 20 GB gp3.
- **Security group inbound:**
  - SSH (22) from **your IP only**
  - HTTP (80) from **your IP only** (add 443 if you set up TLS)
  - **Do not** open 8080.
- Attach a key pair you own.

## 2. One-command setup (Docker)

SSH in, then:

```bash
curl -fsSL https://raw.githubusercontent.com/Phaviwylera/cryptobountyprogram/main/deploy/ec2-setup.sh -o ec2-setup.sh
bash ec2-setup.sh          # installs Docker, clones the repo, stops to let you add keys
nano ~/cryptobountyprogram/deploy/.env    # set ETHERSCAN_API_KEY and RPC_URL
bash ec2-setup.sh          # run again: it creates a login and starts everything
```

The second run prints a dashboard username/password (save it) and starts the stack with
`restart: unless-stopped`, so it survives reboots and keeps scanning 24/7.

Open `http://<EC2-PUBLIC-IP>/`, log in, click **Start live scan**.

### Everyday commands

```bash
cd ~/cryptobountyprogram/deploy
sudo docker compose logs -f         # watch progress
sudo docker compose restart         # restart
sudo docker compose down            # stop
sudo docker compose up -d --build   # update after `git pull`
```

Results, the SQLite state and fetched sources live in the `bountyscan-data` Docker volume, so
they persist across restarts and redeploys.

## 3. Alternative: systemd (no Docker)

```bash
sudo useradd -r -m -d /opt/bountyscan bountyscan
sudo git clone https://github.com/Phaviwylera/cryptobountyprogram.git /opt/bountyscan
cd /opt/bountyscan
sudo python3 -m venv .venv && sudo .venv/bin/pip install -e .
sudo cp deploy/bountyscan.env.example deploy/bountyscan.env
sudo nano deploy/bountyscan.env          # add keys
sudo chown -R bountyscan:bountyscan /opt/bountyscan
sudo chmod 600 deploy/bountyscan.env
sudo cp deploy/bountyscan.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now bountyscan
```

Then put nginx in front (basic auth) so port 8080 stays private:

```bash
sudo apt-get install -y nginx apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd youruser
# point /etc/nginx/sites-enabled/default at http://127.0.0.1:8080 using deploy/nginx.conf as a guide
sudo systemctl restart nginx
```

`sudo journalctl -u bountyscan -f` shows the live scan log.

## 4. Add HTTPS (recommended)

With a domain pointed at the instance:

```bash
sudo apt-get install -y certbot
sudo certbot certonly --standalone -d your.domain.com
# copy fullchain.pem/privkey.pem into deploy/certs/, uncomment the 443 block in nginx.conf,
# then: sudo docker compose restart nginx
```

## 5. Running costs

A `t3.small` is a few dollars a month. The scanner uses the free Etherscan key and a free public
RPC; both have rate limits the scanner respects. For heavy live scanning, use your own
Alchemy/Infura RPC URL in `.env`.

## Notes and limits

- **SAFE = no fund-theft pattern detected**, not a proof of safety. Logic bugs need a human.
- Live discovery sees contracts deployed directly by transactions; contracts created internally
  by factories are not enumerated here. Feed those via **Immunefi Scan** or an address list.
- The dashboard is single-tenant; one worker drains the queue. That is intentional — it keeps API
  usage within free-tier limits and the results ordered.
