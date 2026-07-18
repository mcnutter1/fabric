#!/usr/bin/env bash
#
# Fabric node installer.
#
#   curl -fsSL https://fabric.mcnutt.cloud/install/node.sh | sudo bash -s -- \
#        --manager https://fabric.mcnutt.cloud --pair XXXX-XXXX-XXXX
#
# Installs WireGuard + the Fabric node agent, registers a systemd service, and
# enrols the node with the management plane using a one-time pairing code.
#
set -euo pipefail

REPO="${FABRIC_REPO:-https://github.com/mcnutter1/fabric.git}"
BRANCH="${FABRIC_BRANCH:-main}"
PREFIX="/opt/fabric"
STATE_DIR="/var/lib/fabric"
ENV_FILE="/etc/fabric/agent.env"
IFACE="fab0"
MANAGER="${FABRIC_AGENT_MANAGER:-}"
PAIR="${FABRIC_AGENT_PAIR:-}"
ADVERTISED="${FABRIC_AGENT_ENDPOINT:-}"
UPSTREAM_DNS="${FABRIC_AGENT_UPSTREAM_DNS:-1.1.1.1}"

log()  { echo -e "\033[1;36m[fabric]\033[0m $*"; }
err()  { echo -e "\033[1;31m[fabric:error]\033[0m $*" >&2; }
die()  { err "$*"; exit 1; }

# --- args --------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager)   MANAGER="$2"; shift 2 ;;
    --pair)      PAIR="$2"; shift 2 ;;
    --interface) IFACE="$2"; shift 2 ;;
    --endpoint)  ADVERTISED="$2"; shift 2 ;;
    --upstream-dns) UPSTREAM_DNS="$2"; shift 2 ;;
    --repo)      REPO="$2"; shift 2 ;;
    --branch)    BRANCH="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "must run as root (use sudo)"
[[ -n "$MANAGER" ]] || die "--manager URL is required"
[[ -n "$PAIR" ]] || die "--pair CODE is required"

# --- OS packages -------------------------------------------------------
log "installing system dependencies"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq wireguard wireguard-tools iproute2 iptables \
                         conntrack \
                         python3 python3-pip git curl ca-certificates certbot
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q wireguard-tools iproute iptables conntrack-tools python3 python3-pip git curl ca-certificates certbot
else
  die "unsupported package manager (need apt-get or dnf)"
fi

command -v python3 >/dev/null 2>&1 || die "python3 not found after install"
log "using $(python3 --version 2>&1) at $(command -v python3)"

# --- fetch / update code ----------------------------------------------
# Preferred path: download a self-contained bundle straight from the
# management plane (no GitHub access required on the node). Falls back to
# a git clone when no bundle URL is provided.
BUNDLE_URL="${FABRIC_BUNDLE_URL:-}"
if [[ -z "$BUNDLE_URL" && -n "$MANAGER" ]]; then
  BUNDLE_URL="${MANAGER%/}/install/node-agent.tar.gz"
fi

fetch_bundle() {
  local url="$1" tarball="/tmp/fabric-node-agent.tar.gz"
  log "downloading node bundle from $url"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tarball" || return 1
  else
    wget -qO "$tarball" "$url" || return 1
  fi
  # sanity check: must be a gzip tarball with content
  [[ -s "$tarball" ]] || return 1
  rm -rf "$PREFIX"
  mkdir -p "$PREFIX"
  tar -xzf "$tarball" -C "$PREFIX" || return 1
  rm -f "$tarball"
  [[ -f "$PREFIX/node-agent/requirements.txt" ]] || return 1
  return 0
}

if [[ -n "$BUNDLE_URL" ]] && fetch_bundle "$BUNDLE_URL"; then
  log "installed node bundle from management plane"
elif [[ -d "$PREFIX/.git" ]]; then
  log "updating existing checkout in $PREFIX"
  git config --global --add safe.directory "$PREFIX" 2>/dev/null || true
  git -C "$PREFIX" fetch --depth 1 origin "$BRANCH"
  git -C "$PREFIX" reset --hard "origin/$BRANCH"
else
  log "falling back to git clone $REPO ($BRANCH) -> $PREFIX"
  command -v git >/dev/null 2>&1 || die "git required for fallback clone"
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
python3 -m pip install "${PIP_FLAGS[@]}" -q -r "$PREFIX/node-agent/requirements.txt"

# --- state + config ----------------------------------------------------
mkdir -p "$STATE_DIR" /etc/fabric
chmod 700 "$STATE_DIR"

log "writing $ENV_FILE"
cat > "$ENV_FILE" <<EOF
FABRIC_AGENT_MANAGER=$MANAGER
FABRIC_AGENT_PAIR=$PAIR
FABRIC_AGENT_IFACE=$IFACE
FABRIC_AGENT_STATE_DIR=$STATE_DIR
FABRIC_AGENT_UPSTREAM_DNS=$UPSTREAM_DNS
FABRIC_AGENT_ENDPOINT=$ADVERTISED
EOF
chmod 600 "$ENV_FILE"

# --- agent CLI ---------------------------------------------------------
# Expose the `fabric-agent` wrapper so operators can run it from anywhere
# (e.g. `sudo fabric-agent update`) without worrying about the cwd.
if [[ -f "$PREFIX/scripts/fabric-agent" ]]; then
  chmod +x "$PREFIX/scripts/fabric-agent"
  ln -sf "$PREFIX/scripts/fabric-agent" /usr/local/bin/fabric-agent
fi

# --- systemd -----------------------------------------------------------
log "installing systemd unit"
install -m 644 "$PREFIX/deploy/systemd/fabric-agent.service" /etc/systemd/system/fabric-agent.service
systemctl daemon-reload
systemctl enable --now fabric-agent.service

if systemctl is-active --quiet fabric-agent.service; then
  log "fabric-agent.service is running — node is enrolling"
else
  err "service did not become active — check: journalctl -u fabric-agent -e"
fi

log "done. follow enrollment with:  journalctl -u fabric-agent -f"
