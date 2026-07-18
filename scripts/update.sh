#!/usr/bin/env bash
#
# Fabric updater — git pull + reinstall deps + restart services.
# Mirrors the server-manager update pattern. Auto-detects whether this host runs
# the management plane, a node agent, or both.
#
#   sudo /opt/fabric/scripts/update.sh
#
set -euo pipefail

PREFIX="${FABRIC_PREFIX:-/opt/fabric}"
BRANCH="${FABRIC_BRANCH:-main}"

log() { echo -e "\033[1;36m[fabric:update]\033[0m $*"; }
die() { echo -e "\033[1;31m[fabric:error]\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root (use sudo)"
[[ -d "$PREFIX/.git" ]] || die "no git checkout at $PREFIX"

log "fetching latest ($BRANCH)"
git -C "$PREFIX" fetch --depth 1 origin "$BRANCH"
BEFORE=$(git -C "$PREFIX" rev-parse HEAD)
git -C "$PREFIX" reset --hard "origin/$BRANCH"
AFTER=$(git -C "$PREFIX" rev-parse HEAD)

if [[ "$BEFORE" == "$AFTER" ]]; then
  log "already up to date ($AFTER)"
else
  log "updated $BEFORE -> $AFTER"
fi

restart_if_active() {
  local unit="$1" reqs="$2"
  if systemctl list-unit-files | grep -q "^$unit"; then
    log "refreshing deps for $unit"
    # No --upgrade: >= floors mean pip installs/upgrades only packages that don't
    # already satisfy the requirement, leaving distro-managed packages alone.
    local pip_flags=()
    if python3 -m pip install --help 2>/dev/null | grep -q break-system-packages; then
      pip_flags+=(--break-system-packages)
    fi
    python3 -m pip install -q "${pip_flags[@]}" -r "$reqs"
    log "restarting $unit"
    systemctl restart "$unit"
  fi
}

restart_if_active "fabric-management.service" "$PREFIX/management/requirements.txt"
restart_if_active "fabric-agent.service"      "$PREFIX/node-agent/requirements.txt"

log "update complete"
