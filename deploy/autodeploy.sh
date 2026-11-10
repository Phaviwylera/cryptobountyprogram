#!/usr/bin/env bash
# Pull-based continuous deployment for the bountyscan server.
#
# Run every minute by bountyscan-autodeploy.timer. If origin/main has a new commit:
#   1. check it out and install it
#   2. run the test suite        -> on failure, roll back
#   3. restart the service
#   4. health-check the dashboard -> on failure, roll back
# Nothing needs to be opened to GitHub and no server key is stored there: the server pulls.
set -uo pipefail

APP=/opt/cryptobountyprogram
BRANCH=main
HEALTH=http://127.0.0.1:8080/api/status
LOCK=/run/bountyscan-autodeploy.lock

exec 9>"$LOCK"
flock -n 9 || exit 0          # a deploy is already running

cd "$APP" || exit 1
git fetch -q origin "$BRANCH" || { echo "fetch failed (network?) - will retry next run"; exit 0; }

OLD=$(git rev-parse HEAD)
NEW=$(git rev-parse "origin/$BRANCH")
[ "$OLD" = "$NEW" ] && exit 0

echo "update ${OLD:0:7} -> ${NEW:0:7}: $(git log -1 --format=%s "$NEW")"

install_rev() {
  git reset -q --hard "$1" &&
  .venv/bin/pip install -q -e . >/dev/null
}

rollback() {
  echo "ROLLBACK to ${OLD:0:7}: $1"
  install_rev "$OLD"
  systemctl restart bountyscan
  exit 1
}

install_rev "$NEW" || rollback "install failed"

if ! .venv/bin/python -m unittest discover -s tests >/tmp/bountyscan-tests.log 2>&1; then
  tail -20 /tmp/bountyscan-tests.log
  rollback "tests failed on ${NEW:0:7}"
fi

systemctl restart bountyscan
for _ in $(seq 1 15); do
  sleep 2
  if curl -fs --max-time 3 "$HEALTH" >/dev/null; then
    echo "deployed ${NEW:0:7} - healthy"
    # keep the deployer itself current (new inode, safe while this copy runs)
    install -m 0755 "$APP/deploy/autodeploy.sh" /usr/local/bin/bountyscan-autodeploy
    exit 0
  fi
done
rollback "service unhealthy after restart on ${NEW:0:7}"
