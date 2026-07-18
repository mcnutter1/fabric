#!/usr/bin/env bash
#
# Fabric management-plane installer (Ubuntu/Debian/RHEL).
#
#   curl -fsSL https://raw.githubusercontent.com/mcnutter1/fabric/main/scripts/install-management.sh | sudo bash
#
# Installs the FastAPI management service under systemd (local uvicorn on
# 127.0.0.1:8080). Front it with nginx/caddy + TLS for fabric.mcnutt.cloud in
# production. Python dependencies are installed into the system interpreter —
# no virtualenv.
#
set -euo pipefail

REPO="${FABRIC_REPO:-https://github.com/mcnutter1/fabric.git}"
BRANCH="${FABRIC_BRANCH:-main}"
PREFIX="${FABRIC_PREFIX:-/opt/fabric}"
ENV_FILE="/etc/fabric/management.env"
RUN_USER="fabric"

log()  { echo -e "\033[1;36m[fabric]\033[0m $*"; }
warn() { echo -e "\033[1;33m[fabric:warn]\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m[fabric:error]\033[0m $*" >&2; exit 1; }

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

[[ $EUID -eq 0 ]] || die "must run as root (use sudo)"

# --- OS packages -------------------------------------------------------
log "installing system dependencies"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-pip git ca-certificates
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q python3 python3-pip git ca-certificates
else
  die "unsupported package manager (need apt-get or dnf)"
fi

command -v python3 >/dev/null 2>&1 || die "python3 not found after install"
log "using $(python3 --version 2>&1) at $(command -v python3)"

id "$RUN_USER" >/dev/null 2>&1 || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin "$RUN_USER"

# --- fetch / update code ----------------------------------------------
if [[ -d "$PREFIX/.git" ]]; then
  log "updating checkout in $PREFIX"
  git -C "$PREFIX" fetch --depth 1 origin "$BRANCH"
  git -C "$PREFIX" reset --hard "origin/$BRANCH"
else
  log "cloning $REPO ($BRANCH) -> $PREFIX"
  rm -rf "$PREFIX"
  git clone --depth 1 --branch "$BRANCH" "$REPO" "$PREFIX"
fi

# --- python dependencies (system interpreter, no venv) -----------------
# Respect PEP 668 "externally-managed" environments without a venv. We do NOT
# pass --upgrade: requirements use >= floors, so pip installs what's missing and
# leaves already-satisfying (e.g. distro-provided) packages untouched — avoids
# trying to uninstall Debian-managed packages that ship no RECORD file.
PIP_FLAGS=()
if python3 -m pip install --help 2>/dev/null | grep -q break-system-packages; then
  PIP_FLAGS+=(--break-system-packages)
fi
log "installing python dependencies (system-wide, no venv)"
python3 -m pip install "${PIP_FLAGS[@]}" -q -r "$PREFIX/management/requirements.txt"

# --- config ------------------------------------------------------------
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
else
  log "keeping existing $ENV_FILE"
fi
chown -R "$RUN_USER:$RUN_USER" /var/lib/fabric "$PREFIX"

# --- systemd -----------------------------------------------------------
log "installing systemd unit"
install -m 644 "$PREFIX/deploy/systemd/fabric-management.service" /etc/systemd/system/fabric-management.service
systemctl daemon-reload
systemctl enable --now fabric-management.service

if systemctl is-active --quiet fabric-management.service; then
  log "fabric-management.service is running"
else
  warn "service did not become active — check: journalctl -u fabric-management -e"
fi

log "done."
log "  seed starter nodes:  sudo -u $RUN_USER python3 -m app.seed   (run from $PREFIX/management)"
log "  API listens on 127.0.0.1:8080 — put nginx/caddy + TLS in front for fabric.mcnutt.cloud"
log "  logs:  journalctl -u fabric-management -f"
