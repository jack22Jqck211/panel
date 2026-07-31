#!/usr/bin/env bash
#
# Pulls the current configuration from the panel and applies it locally.
#
# Safety model: nothing is reloaded until both `nginx -t` and `xray -test`
# accept the new files. On any validation failure the previous configuration is
# restored and the services are left untouched, so a bad panel state cannot take
# the server down. This is also why validation happens here rather than only in
# the panel's test suite -- it runs against the real binaries, on this host,
# every single time.
#
# Reads PANEL_URL and SYNC_KEY from the environment or from
# /opt/xray-panel-agent/agent.env.
#
# Usage:
#   agent.sh            apply only when the panel revision changed
#   agent.sh --force    apply unconditionally
#
set -euo pipefail

AGENT_DIR="/opt/xray-panel-agent"
ENV_FILE="$AGENT_DIR/agent.env"
REV_FILE="$AGENT_DIR/revision"
XRAY_CONF="/usr/local/etc/xray/config.json"
NGINX_SITE="/etc/nginx/sites-available/xray-panel.conf"
NGINX_LINK="/etc/nginx/sites-enabled/xray-panel.conf"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

log() { printf '[agent] %s\n' "$1"; }
die() { printf '[agent] ERROR: %s\n' "$1" >&2; exit 1; }

# shellcheck source=/dev/null
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
: "${PANEL_URL:?PANEL_URL is not set}"
: "${SYNC_KEY:?SYNC_KEY is not set}"
PANEL_URL="${PANEL_URL%/}"

mkdir -p "$AGENT_DIR"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# ---------------------------------------------------------------------- fetch

if ! curl -fsS --max-time 30 "$PANEL_URL/api/sync?key=$SYNC_KEY" -o "$WORK/sync.json"; then
  die "could not fetch $PANEL_URL/api/sync (network down, or the sync key changed)"
fi

REMOTE_REV="$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1])).get("revision", ""))
' "$WORK/sync.json")"
[ -n "$REMOTE_REV" ] || die "the panel returned no revision"

LOCAL_REV=""
[ -f "$REV_FILE" ] && LOCAL_REV="$(cat "$REV_FILE")"

if [ "$FORCE" = "0" ] && [ "$REMOTE_REV" = "$LOCAL_REV" ]; then
  exit 0
fi
log "revision $LOCAL_REV -> $REMOTE_REV, applying"

# --------------------------------------------------------------------- unpack

python3 - "$WORK/sync.json" "$WORK/config.json" "$WORK/nginx.conf" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1]))

xray = payload.get("xray")
if not xray:
    sys.exit("the payload contains no xray config")
with open(sys.argv[2], "w") as f:
    json.dump(xray, f, indent=2)
    f.write("\n")

nginx = payload.get("nginx")
if nginx:
    with open(sys.argv[3], "w") as f:
        f.write(nginx)
else:
    # Absent when the panel has no server address configured yet. Not fatal:
    # the Xray side can still be updated.
    print("  note:", payload.get("nginxError", "no nginx config in payload"))
PY

# ------------------------------------------------------------------- validate

command -v xray >/dev/null 2>&1 || die "xray is not installed"
if ! xray -test -c "$WORK/config.json" >"$WORK/xray-test.log" 2>&1; then
  sed 's/^/    /' "$WORK/xray-test.log" >&2
  die "xray rejected the new config; nothing was changed"
fi
log "xray validated the new config"

if [ -f "$WORK/nginx.conf" ]; then
  # Validate the candidate in place, keeping a backup to roll back to.
  BACKUP=""
  if [ -f "$NGINX_SITE" ]; then
    BACKUP="$WORK/nginx.conf.backup"
    cp "$NGINX_SITE" "$BACKUP"
  fi
  cp "$WORK/nginx.conf" "$NGINX_SITE"
  ln -sf "$NGINX_SITE" "$NGINX_LINK"
  rm -f /etc/nginx/sites-enabled/default

  if ! nginx -t >"$WORK/nginx-test.log" 2>&1; then
    sed 's/^/    /' "$WORK/nginx-test.log" >&2
    if [ -n "$BACKUP" ]; then
      cp "$BACKUP" "$NGINX_SITE"
      log "restored the previous nginx config"
    else
      rm -f "$NGINX_SITE" "$NGINX_LINK"
      log "removed the invalid nginx config"
    fi
    die "nginx rejected the new config; nothing was reloaded"
  fi
  log "nginx validated the new config"
fi

# ---------------------------------------------------------------------- apply

mkdir -p "$(dirname "$XRAY_CONF")"
cp "$WORK/config.json" "$XRAY_CONF"

if systemctl is-enabled xray >/dev/null 2>&1 || systemctl is-active xray >/dev/null 2>&1; then
  systemctl restart xray || die "xray failed to restart -- check: journalctl -u xray -n 50"
else
  systemctl enable --now xray || die "xray failed to start -- check: journalctl -u xray -n 50"
fi
log "xray restarted"

if [ -f "$WORK/nginx.conf" ]; then
  systemctl reload nginx 2>/dev/null || systemctl restart nginx || die "nginx failed to reload"
  log "nginx reloaded"
fi

# Only record the revision once everything actually applied, so a failure is
# retried on the next tick instead of being silently skipped.
printf '%s' "$REMOTE_REV" >"$REV_FILE"

USERS="$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1])).get("users", "?"))
' "$WORK/sync.json")"
log "done: revision $REMOTE_REV, $USERS active user(s)"
