#!/usr/bin/env bash
#
# Fabric updater — refresh code + deps + restart services.
#
#   sudo /opt/fabric/scripts/update.sh
#
# Auto-detects how this host was provisioned and updates accordingly:
#   * management plane / dev checkout (has /opt/fabric/.git) -> git pull
#   * node (installed from the management-plane bundle, no git) -> re-download
#     the node bundle from the management plane over HTTPS, exactly like the
#     initial install. Nodes never need GitHub access.
#
set -euo pipefail

PREFIX="${FABRIC_PREFIX:-/opt/fabric}"
BRANCH="${FABRIC_BRANCH:-main}"
AGENT_ENV="${FABRIC_AGENT_ENV:-/etc/fabric/agent.env}"

log() { echo -e "\033[1;36m[fabric:update]\033[0m $*"; }
die() { echo -e "\033[1;31m[fabric:error]\033[0m $*" >&2; exit 1; }

# Re-exec from a stable temp copy so a bundle update can safely overwrite this
# very script (and the rest of /opt/fabric) while it runs.
if [[ "${FABRIC_UPDATE_REEXEC:-}" != "1" ]]; then
  _self="$(mktemp /tmp/fabric-update.XXXXXX.sh)"
  cp -f "$0" "$_self"
  chmod +x "$_self"
  FABRIC_UPDATE_REEXEC=1 exec "$_self" "$@"
fi
# Running from the temp copy now; unlink it (the open fd keeps it valid on Linux).
rm -f "$0" 2>/dev/null || true

[[ $EUID -eq 0 ]] || die "must run as root (use sudo)"

# Pull the manager URL (and optional bundle URL) from the agent env for nodes.
if [[ -f "$AGENT_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$AGENT_ENV"
  set +a
fi

update_from_git() {
  log "git checkout detected — updating via git ($BRANCH)"
  git config --global --add safe.directory "$PREFIX" 2>/dev/null || true
  git -C "$PREFIX" fetch --depth 1 origin "$BRANCH"
  local before after
  before=$(git -C "$PREFIX" rev-parse HEAD)
  git -C "$PREFIX" reset --hard "origin/$BRANCH"
  after=$(git -C "$PREFIX" rev-parse HEAD)
  if [[ "$before" == "$after" ]]; then
    log "already up to date ($after)"
  else
    log "updated $before -> $after"
  fi
}

update_from_bundle() {
  local url="${FABRIC_BUNDLE_URL:-}"
  local manager="${FABRIC_AGENT_MANAGER:-}"
  if [[ -z "$url" && -n "$manager" ]]; then
    url="${manager%/}/install/node-agent.tar.gz"
  fi
  [[ -n "$url" ]] || die "no bundle URL: set FABRIC_BUNDLE_URL or FABRIC_AGENT_MANAGER in $AGENT_ENV"

  local tarball stage
  tarball="$(mktemp /tmp/fabric-bundle.XXXXXX.tar.gz)"
  stage="$(mktemp -d /tmp/fabric-bundle.XXXXXX)"
  trap 'rm -rf "$tarball" "$stage"' RETURN

  log "downloading node bundle from $url"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tarball" || die "bundle download failed"
  else
    wget -qO "$tarball" "$url" || die "bundle download failed"
  fi
  [[ -s "$tarball" ]] || die "downloaded bundle is empty"
  tar -xzf "$tarball" -C "$stage" || die "bundle is not a valid tar.gz"
  [[ -f "$stage/node-agent/requirements.txt" ]] || die "bundle missing node-agent (bad download?)"

  log "applying bundle to $PREFIX"
  mkdir -p "$PREFIX"
  cp -a "$stage"/. "$PREFIX"/

  # Reinstall the systemd unit from the bundle so the node always runs the
  # current unit (correct user/root + capabilities), not a stale one.
  if [[ -f "$PREFIX/deploy/systemd/fabric-agent.service" ]]; then
    install -m 644 "$PREFIX/deploy/systemd/fabric-agent.service" \
      /etc/systemd/system/fabric-agent.service
    systemctl daemon-reload
  fi
}

install_cli_wrappers() {
  # Install whichever operator CLIs are present so they're on PATH:
  #   fabric        (management host)  -> sudo fabric update-nodes
  #   fabric-agent  (node)             -> sudo fabric-agent update
  if [[ -f "$PREFIX/scripts/fabric" ]]; then
    chmod +x "$PREFIX/scripts/fabric"
    ln -sf "$PREFIX/scripts/fabric" /usr/local/bin/fabric
  fi
  if [[ -f "$PREFIX/scripts/fabric-agent" ]]; then
    chmod +x "$PREFIX/scripts/fabric-agent"
    ln -sf "$PREFIX/scripts/fabric-agent" /usr/local/bin/fabric-agent
  fi
}

restart_if_active() {
  local unit="$1" reqs="$2"
  if systemctl list-unit-files | grep -q "^$unit"; then
    if [[ -f "$reqs" ]]; then
      log "refreshing deps for $unit"
      # No --upgrade: >= floors mean pip installs/upgrades only packages that
      # don't already satisfy the requirement, leaving distro-managed ones alone.
      local pip_flags=()
      if python3 -m pip install --help 2>/dev/null | grep -q break-system-packages; then
        pip_flags+=(--break-system-packages)
      fi
      python3 -m pip install -q "${pip_flags[@]}" -r "$reqs"
    fi
    log "restarting $unit"
    systemctl restart "$unit"
  fi
}

if [[ -d "$PREFIX/.git" ]]; then
  update_from_git
else
  log "no git checkout — updating node from management plane bundle"
  update_from_bundle
fi

install_cli_wrappers

restart_if_active "fabric-management.service" "$PREFIX/management/requirements.txt"
restart_if_active "fabric-agent.service"      "$PREFIX/node-agent/requirements.txt"

log "update complete"
