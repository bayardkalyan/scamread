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

# Code is owned by root and read-only for the service user and nginx.
chmod 755 "$APP"
for d in app templates static deploy; do
  if [ -d "$APP/$d" ]; then chmod -R u=rwX,go=rX "$APP/$d"; fi
done

# Settings file with a fresh admin token, created once and readable by root only.
if [ ! -f /etc/scamread.env ]; then
  (
    umask 077
    {
      echo "SCAMREAD_ENV=production"
      echo "SCAMREAD_DATABASE_PATH=$APP/data/scamread.db"
      echo "SCAMREAD_PRIVATE_PATTERNS_DIR=$APP/data/private-patterns"
      echo "SCAMREAD_ADMIN_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    } > /etc/scamread.env
  )
  echo "Created /etc/scamread.env (the admin token is stored there)."
fi

[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --quiet --upgrade pip
"$APP/venv/bin/pip" install --quiet -r "$APP/requirements.txt"
"$APP/venv/bin/python" -m compileall -q "$APP/app"
chmod -R go+rX "$APP/venv" "$APP/app"

if [ -f /etc/systemd/system/scamread.service ]; then
  cp /etc/systemd/system/scamread.service "$BACKUP.service"
fi
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
journalctl -u scamread -n 30 --no-pager >&2 || true
rsync -a --delete --exclude venv --exclude data "$BACKUP/" "$APP/"
if [ -f "$BACKUP.service" ]; then
  install -m 644 "$BACKUP.service" /etc/systemd/system/scamread.service
  systemctl daemon-reload
fi
systemctl restart scamread
exit 1
