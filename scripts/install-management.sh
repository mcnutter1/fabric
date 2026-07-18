#!/usr/bin/env bash
#
# Fabric management-plane installer (Ubuntu).
#
#   curl -fsSL https://raw.githubusercontent.com/mcnutter1/fabric/main/scripts/install-management.sh | sudo bash
#
# Installs the FastAPI management service under systemd behind a local uvicorn.
# Front it with nginx/caddy + TLS for fabric.mcnutt.cloud in production.
#
set -euo pipefail

REPO="${FABRIC_REPO:-https://github.com/mcnutter1/fabric.git}"
BRANCH="${FABRIC_BRANCH:-main}"
PREFIX="/opt/fabric"
ENV_FILE="/etc/fabric/management.env"
RUN_USER="fabric"

log() { echo -e "\033[1;36m[fabric]\033[0m $*"; }
die() { echo -e "\033[1;31m[fabric:error]\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root (use sudo)"

log "installing system dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git ca-certificates

id "$RUN_USER" >/dev/null 2>&1 || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin "$RUN_USER"

if [[ -d "$PREFIX/.git" ]]; then
  log "updating checkout"
  git -C "$PREFIX" fetch --depth 1 origin "$BRANCH"
  git -C "$PREFIX" reset --hard "origin/$BRANCH"
else
  log "cloning $REPO"
  rm -rf "$PREFIX"
  git clone --depth 1 --branch "$BRANCH" "$REPO" "$PREFIX"
fi

log "creating virtualenv"
python3 -m venv "$PREFIX/management/.venv"
"$PREFIX/management/.venv/bin/pip" install --upgrade pip -q
"$PREFIX/management/.venv/bin/pip" install -q -r "$PREFIX/management/requirements.txt"

mkdir -p /etc/fabric /var/lib/fabric
if [[ ! -f "$ENV_FILE" ]]; then
  log "writing initial $ENV_FILE (EDIT SECRETS BEFORE PRODUCTION)"
  cat > "$ENV_FILE" <<EOF
FABRIC_ENV=production
FABRIC_DOMAIN=fabric.mcnutt.cloud
FABRIC_DATABASE_URL=sqlite:////var/lib/fabric/fabric.db
FABRIC_SESSION_SECRET=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
FABRIC_PKI_PASSPHRASE=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
FABRIC_MCNUTT_APP_ID=
FABRIC_MCNUTT_APP_SECRET=
FABRIC_MCNUTT_BASE_URL=https://login.mcnutt.cloud
EOF
  chmod 600 "$ENV_FILE"
fi
chown -R "$RUN_USER:$RUN_USER" /var/lib/fabric "$PREFIX"

log "installing systemd unit"
install -m 644 "$PREFIX/deploy/systemd/fabric-management.service" /etc/systemd/system/fabric-management.service
systemctl daemon-reload
systemctl enable --now fabric-management.service

log "done. seed starter nodes with:  sudo -u $RUN_USER $PREFIX/management/.venv/bin/python -m app.seed  (from $PREFIX/management)"
log "management API on 127.0.0.1:8080 — put nginx/caddy + TLS in front for fabric.mcnutt.cloud"
