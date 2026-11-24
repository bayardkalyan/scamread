#!/usr/bin/env bash
# Update app.scamread.com from GitHub. Run as root on the server:
#   bash /opt/scamread-src/deploy/deploy.sh
# Keeps data/ (the database) and venv/; rolls back if the new version fails its health check.
set -euo pipefail

REPO=https://github.com/bayardkalyan/scamread.git
SRC=/opt/scamread-src
APP=/opt/scamread
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP=/opt/scamread-backup-$STAMP

if [ -d "$SRC/.git" ]; then
  git -C "$SRC" fetch --depth 1 origin main
  git -C "$SRC" reset --hard origin/main
else
  git clone --depth 1 "$REPO" "$SRC"
fi

id scamread >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin scamread

echo "Backing up current app to $BACKUP"
rsync -a --exclude venv "$APP/" "$BACKUP/"

rsync -a --delete \
  --exclude '.git' --exclude 'venv' --exclude 'data' --exclude '__pycache__' \
  "$SRC/" "$APP/"

mkdir -p "$APP/data/private-patterns"
chown -R scamread:scamread "$APP/data"
chmod 750 "$APP/data"

[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --quiet --upgrade pip
"$APP/venv/bin/pip" install --quiet -r "$APP/requirements.txt"
"$APP/venv/bin/python" -m compileall -q "$APP/app"

install -m 644 "$APP/deploy/scamread.service" /etc/systemd/system/scamread.service
systemctl daemon-reload
systemctl restart scamread

for i in $(seq 1 20); do
  if curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
    echo "OK: $(curl -fsS http://127.0.0.1:8000/api/health)"
    exit 0
  fi
  sleep 1
done

echo "New version failed its health check. Rolling back." >&2
rsync -a --delete --exclude venv --exclude data "$BACKUP/" "$APP/"
systemctl restart scamread
exit 1
