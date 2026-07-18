#!/usr/bin/env bash
#
# Fabric management-plane installer (Ubuntu/Debian/RHEL).
#
# Installs the FastAPI management service under systemd (uvicorn on
# 127.0.0.1:8080), an nginx reverse proxy, and a trusted Let's Encrypt
# certificate. Python dependencies install into the system interpreter
# (no virtualenv).
#
# Usage:
#   sudo ./install-management.sh --domain fabric.example.com --email you@example.com
#   curl -fsSL https://raw.githubusercontent.com/mcnutter1/fabric/main/scripts/install-management.sh \
#       | sudo bash -s -- --domain fabric.example.com --email you@example.com
#
# Options:
#   --domain <fqdn>    Public hostname for the console (DNS must point here).
#   --email  <addr>    Contact e-mail for Let's Encrypt (enables TLS).
#   --node-domain <d>  Base domain for auto node hostnames (e.g. nodes.example.com).
#   --route53-zone <id> AWS Route53 hosted-zone ID enabling node auto-DNS + certs.
#   --aws-region <r>   AWS region for Route53 (default: us-east-1).
#   --no-tls           Skip Let's Encrypt; serve plain HTTP on port 80.
#   --branch <name>    Git branch to install (default: main).
#   -h, --help         Show this help.
#
set -euo pipefail

REPO="${FABRIC_REPO:-https://github.com/mcnutter1/fabric.git}"
BRANCH="${FABRIC_BRANCH:-main}"
PREFIX="${FABRIC_PREFIX:-/opt/fabric}"
ENV_FILE="/etc/fabric/management.env"
RUN_USER="fabric"

DOMAIN="${FABRIC_DOMAIN:-}"
ACME_EMAIL="${FABRIC_ACME_EMAIL:-}"
NODE_BASE_DOMAIN="${FABRIC_NODE_BASE_DOMAIN:-}"
ROUTE53_ZONE_ID="${FABRIC_ROUTE53_ZONE_ID:-}"
AWS_REGION="${FABRIC_AWS_REGION:-us-east-1}"
ENABLE_TLS=1

C_CYAN='\033[1;36m'; C_YEL='\033[1;33m'; C_RED='\033[1;31m'; C_GRN='\033[1;32m'; C_DIM='\033[2m'; C_RST='\033[0m'
log()  { echo -e "${C_CYAN}[fabric]${C_RST} $*"; }
warn() { echo -e "${C_YEL}[fabric:warn]${C_RST} $*" >&2; }
die()  { echo -e "${C_RED}[fabric:error]${C_RST} $*" >&2; exit 1; }
step() { echo -e "${C_DIM}  ->${C_RST} $*"; }

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# --- args --------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --email)  ACME_EMAIL="$2"; shift 2 ;;
    --node-domain) NODE_BASE_DOMAIN="$2"; shift 2 ;;
    --route53-zone) ROUTE53_ZONE_ID="$2"; shift 2 ;;
    --aws-region) AWS_REGION="$2"; shift 2 ;;
    --no-tls) ENABLE_TLS=0; shift ;;
    --branch) BRANCH="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "must run as root (use sudo)"

# Prompt for a domain when attached to a terminal and none was supplied.
if [[ -z "$DOMAIN" && -t 0 ]]; then
  read -rp "Public hostname for the console (blank = IP only, no TLS): " DOMAIN || true
fi
if [[ -n "$DOMAIN" && -z "$ACME_EMAIL" && "$ENABLE_TLS" == "1" && -t 0 ]]; then
  read -rp "Contact e-mail for Let's Encrypt (blank = skip TLS): " ACME_EMAIL || true
fi
[[ -z "$DOMAIN" ]] && ENABLE_TLS=0
[[ -z "$ACME_EMAIL" ]] && ENABLE_TLS=0

# Auto node onboarding: DNS (Route53) + per-node Let's Encrypt certs.
# When a Route53 hosted-zone ID is supplied, each node that enrolls gets an A
# record auto-created and is told to obtain its own trusted cert.
if [[ -z "$NODE_BASE_DOMAIN" && -n "$DOMAIN" && -t 0 ]]; then
  _default_base="${DOMAIN#*.}"
  read -rp "Base domain for node hostnames (blank = disable auto-DNS) [${_default_base}]: " NODE_BASE_DOMAIN || true
  NODE_BASE_DOMAIN="${NODE_BASE_DOMAIN:-$_default_base}"
fi
if [[ -n "$NODE_BASE_DOMAIN" && -z "$ROUTE53_ZONE_ID" && -t 0 ]]; then
  read -rp "AWS Route53 hosted-zone ID for ${NODE_BASE_DOMAIN} (blank = disable auto-DNS): " ROUTE53_ZONE_ID || true
fi
NODE_ACME_ENABLED=0
if [[ -n "$ROUTE53_ZONE_ID" && -n "$NODE_BASE_DOMAIN" ]]; then
  NODE_ACME_ENABLED=1
else
  ROUTE53_ZONE_ID=""
fi

# --- OS packages -------------------------------------------------------
log "installing system dependencies"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-pip git curl ca-certificates nginx
  [[ "$ENABLE_TLS" == "1" ]] && apt-get install -y -qq certbot python3-certbot-nginx
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q python3 python3-pip git curl ca-certificates nginx
  [[ "$ENABLE_TLS" == "1" ]] && dnf install -y -q certbot python3-certbot-nginx
else
  die "unsupported package manager (need apt-get or dnf)"
fi

command -v python3 >/dev/null 2>&1 || die "python3 not found after install"
log "using $(python3 --version 2>&1) at $(command -v python3)"

id "$RUN_USER" >/dev/null 2>&1 || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin "$RUN_USER"

# --- fetch / update code ----------------------------------------------
# The checkout is owned by $RUN_USER but git runs here as root; tell git this
# directory is trusted to avoid the "dubious ownership" fatal.
git config --global --add safe.directory "$PREFIX" 2>/dev/null || true
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
# boto3 is required for Route53 auto-DNS when node onboarding is enabled.
if [[ "$NODE_ACME_ENABLED" == "1" ]]; then
  python3 -m pip install "${PIP_FLAGS[@]}" -q "boto3>=1.34"
fi

# --- config ------------------------------------------------------------
PUBLIC_IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')"
if [[ "$ENABLE_TLS" == "1" ]]; then
  PUBLIC_URL="https://$DOMAIN"
elif [[ -n "$DOMAIN" ]]; then
  PUBLIC_URL="http://$DOMAIN"
else
  PUBLIC_URL="http://${PUBLIC_IP:-127.0.0.1}"
fi

mkdir -p /etc/fabric /var/lib/fabric
if [[ ! -f "$ENV_FILE" ]]; then
  log "writing initial $ENV_FILE (EDIT SSO SECRETS BEFORE PRODUCTION)"
  cat > "$ENV_FILE" <<EOF
FABRIC_ENV=production
FABRIC_DOMAIN=${DOMAIN:-$PUBLIC_IP}
FABRIC_PUBLIC_URL=$PUBLIC_URL
FABRIC_DATABASE_URL=sqlite:////var/lib/fabric/fabric.db
FABRIC_SESSION_SECRET=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
FABRIC_PKI_PASSPHRASE=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
FABRIC_AUTH_LOGIN_BASE=https://login.mcnutt.cloud
FABRIC_AUTH_APP_ID=fabric-console
FABRIC_AUTH_APP_SECRET=
FABRIC_AWS_REGION=$AWS_REGION
FABRIC_ROUTE53_ZONE_ID=$ROUTE53_ZONE_ID
FABRIC_NODE_BASE_DOMAIN=$NODE_BASE_DOMAIN
FABRIC_ACME_EMAIL=$ACME_EMAIL
FABRIC_NODE_ACME_ENABLED=$NODE_ACME_ENABLED
EOF
  chmod 600 "$ENV_FILE"
else
  log "keeping existing $ENV_FILE"
  # Keep the public URL in sync with this run's domain/TLS choice.
  if grep -q '^FABRIC_PUBLIC_URL=' "$ENV_FILE"; then
    sed -i "s#^FABRIC_PUBLIC_URL=.*#FABRIC_PUBLIC_URL=$PUBLIC_URL#" "$ENV_FILE"
  else
    echo "FABRIC_PUBLIC_URL=$PUBLIC_URL" >> "$ENV_FILE"
  fi
  # Sync node auto-onboarding (DNS + ACME) settings.
  _set_env() {
    local k="$1" v="$2"
    if grep -q "^${k}=" "$ENV_FILE"; then
      sed -i "s#^${k}=.*#${k}=${v}#" "$ENV_FILE"
    else
      echo "${k}=${v}" >> "$ENV_FILE"
    fi
  }
  _set_env FABRIC_AWS_REGION "$AWS_REGION"
  _set_env FABRIC_ROUTE53_ZONE_ID "$ROUTE53_ZONE_ID"
  _set_env FABRIC_NODE_BASE_DOMAIN "$NODE_BASE_DOMAIN"
  [[ -n "$ACME_EMAIL" ]] && _set_env FABRIC_ACME_EMAIL "$ACME_EMAIL"
  _set_env FABRIC_NODE_ACME_ENABLED "$NODE_ACME_ENABLED"
fi
chown -R "$RUN_USER:$RUN_USER" /var/lib/fabric "$PREFIX"

# --- systemd -----------------------------------------------------------
log "installing systemd unit"
install -m 644 "$PREFIX/deploy/systemd/fabric-management.service" /etc/systemd/system/fabric-management.service
systemctl daemon-reload
systemctl enable --now fabric-management.service

if systemctl is-active --quiet fabric-management.service; then
  step "fabric-management.service is running (127.0.0.1:8080)"
else
  warn "service did not become active — check: journalctl -u fabric-management -e"
fi

# --- nginx reverse proxy ----------------------------------------------
log "configuring nginx reverse proxy"
SERVER_NAME="${DOMAIN:-_}"
if [[ -d /etc/nginx/sites-available ]]; then
  NGINX_CONF="/etc/nginx/sites-available/fabric.conf"
  NGINX_LINK="/etc/nginx/sites-enabled/fabric.conf"
  rm -f /etc/nginx/sites-enabled/default
else
  NGINX_CONF="/etc/nginx/conf.d/fabric.conf"
  NGINX_LINK=""
fi
cat > "$NGINX_CONF" <<EOF
map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }

server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_NAME;

    client_max_body_size 10m;

    location /ws/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
[[ -n "$NGINX_LINK" ]] && ln -sf "$NGINX_CONF" "$NGINX_LINK"
if nginx -t >/dev/null 2>&1; then
  systemctl enable --now nginx >/dev/null 2>&1 || true
  systemctl reload nginx
  step "nginx proxying :80 -> 127.0.0.1:8080"
else
  warn "nginx config test failed — run 'nginx -t' to inspect"
fi

# --- Let's Encrypt -----------------------------------------------------
TLS_OK=0
if [[ "$ENABLE_TLS" == "1" ]]; then
  log "requesting Let's Encrypt certificate for $DOMAIN"
  if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos \
             -m "$ACME_EMAIL" --redirect >/tmp/fabric-certbot.log 2>&1; then
    systemctl reload nginx || true
    TLS_OK=1
    step "certificate installed; HTTP redirects to HTTPS"
  else
    warn "certbot failed — serving plain HTTP for now (see /tmp/fabric-certbot.log)"
    warn "ensure $DOMAIN resolves to this host and ports 80/443 are open, then re-run."
    PUBLIC_URL="http://$DOMAIN"
  fi
fi

# --- summary -----------------------------------------------------------
echo
echo -e "${C_GRN}============================================================${C_RST}"
echo -e "${C_GRN}  Fabric management plane is installed${C_RST}"
echo -e "${C_GRN}============================================================${C_RST}"
echo -e "  Console:   ${C_CYAN}${PUBLIC_URL}/${C_RST}"
if [[ "$TLS_OK" == "1" ]]; then
  echo -e "  TLS:       ${C_GRN}Let's Encrypt (auto-renew via certbot timer)${C_RST}"
elif [[ "$ENABLE_TLS" == "1" ]]; then
  echo -e "  TLS:       ${C_YEL}requested but not issued — see warning above${C_RST}"
else
  echo -e "  TLS:       ${C_YEL}disabled (HTTP only)${C_RST} — re-run with --domain/--email to enable"
fi
echo -e "  Service:   systemctl status fabric-management"
echo -e "  Logs:      journalctl -u fabric-management -f"
echo
echo -e "  ${C_YEL}Next steps:${C_RST}"
  echo -e "    1. Set SSO secrets in ${C_CYAN}$ENV_FILE${C_RST} (FABRIC_AUTH_APP_ID / FABRIC_AUTH_APP_SECRET),"
echo -e "       then: ${C_DIM}systemctl restart fabric-management${C_RST}"
echo -e "    2. Seed the starter fabric:"
echo -e "       ${C_DIM}cd $PREFIX/management && sudo -u $RUN_USER python3 -m app.seed${C_RST}"
[[ -n "$DOMAIN" ]] || echo -e "    3. Point a DNS record at ${C_CYAN}${PUBLIC_IP:-this host}${C_RST} and re-run with --domain/--email for TLS."
echo
