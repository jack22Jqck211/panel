#!/usr/bin/env bash
#
# Server-side installer for panel.
#
# Sets up, on one Ubuntu/Debian machine:
#   Tor-ML  50 isolated Tor instances, SOCKS on 127.0.0.1:48180-48229
#   Xray    50 loopback WebSocket inbounds, each routed to one Tor SOCKS port
#   nginx   TLS front door mapping /<prefix>/<country> to the matching inbound
#   agent   pulls config from the panel on a timer and reloads when it changes
#
# Everything must live on this one host: Tor-ML binds its SOCKS ports to
# loopback only, so Xray cannot reach them from anywhere else.
#
# Usage:
#   sudo bash install.sh \
#     --panel  https://your-panel.up.railway.app \
#     --key    YOUR_SYNC_KEY \
#     --domain srv.example.com \
#     [--email you@example.com] \
#     [--no-tls] \
#     [--start-tor all|1,3,10|none]
#
set -euo pipefail

PANEL_URL=""
SYNC_KEY=""
DOMAIN=""
EMAIL=""
USE_TLS=1
START_TOR="none"

AGENT_DIR="/opt/xray-panel-agent"
NGINX_SITE="/etc/nginx/sites-available/xray-panel.conf"
NGINX_LINK="/etc/nginx/sites-enabled/xray-panel.conf"
XRAY_CONF="/usr/local/etc/xray/config.json"
TOR_ML_BASE="/opt/tor-ml"

C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_WARN=$'\033[33m'; C_B=$'\033[1m'; C_N=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$C_B" "$1" "$C_N"; }
ok()   { printf '  %s✓%s %s\n' "$C_OK" "$C_N" "$1"; }
warn() { printf '  %s!%s %s\n' "$C_WARN" "$C_N" "$1"; }
die()  { printf '\n  %s✗ %s%s\n\n' "$C_ERR" "$1" "$C_N" >&2; exit 1; }

# ------------------------------------------------------------------- arguments

while [ $# -gt 0 ]; do
  case "$1" in
    --panel)     PANEL_URL="${2:-}"; shift 2 ;;
    --key)       SYNC_KEY="${2:-}"; shift 2 ;;
    --domain)    DOMAIN="${2:-}"; shift 2 ;;
    --email)     EMAIL="${2:-}"; shift 2 ;;
    --no-tls)    USE_TLS=0; shift ;;
    --start-tor) START_TOR="${2:-none}"; shift 2 ;;
    -h|--help)   sed -n '2,30p' "$0"; exit 0 ;;
    *)           die "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" = "0" ] || die "run this as root (sudo bash install.sh ...)"
[ -n "$PANEL_URL" ] || die "--panel is required"
[ -n "$SYNC_KEY" ]  || die "--key is required"
[ -n "$DOMAIN" ]    || die "--domain is required"
command -v apt-get >/dev/null 2>&1 || die "this installer targets Debian/Ubuntu (apt-get not found)"

PANEL_URL="${PANEL_URL%/}"

# ------------------------------------------------------------- sanity: memory
# 50 Tor daemons need roughly 1-1.5 GB. Better to say so before installing than
# to let the OOM killer explain it later.
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
step "Preflight"
ok "detected ${MEM_MB} MB RAM"
if [ "$MEM_MB" -lt 1800 ] && [ "$START_TOR" = "all" ]; then
  warn "starting all 50 Tor instances needs ~1-1.5 GB; this host may run out of memory"
  warn "consider --start-tor 1,2,3,4,5 to bring up a subset instead"
fi

# --------------------------------------------------------------- verify panel
step "Checking the panel is reachable"
SYNC_JSON="$(mktemp)"
trap 'rm -f "$SYNC_JSON"' EXIT
if ! curl -fsS --max-time 25 "$PANEL_URL/api/sync?key=$SYNC_KEY" -o "$SYNC_JSON"; then
  die "could not reach $PANEL_URL/api/sync -- check the URL and that SYNC_KEY matches the panel"
fi
python3 - "$SYNC_JSON" <<'PY' || die "the panel responded but the payload was not usable"
import json, sys
d = json.load(open(sys.argv[1]))
if "xray" not in d:
    sys.exit("no xray config in the sync payload")
print(f"  panel revision {d.get('revision','?')}, {d.get('users',0)} active user(s)")
PY
ok "panel reachable and authenticated"

# ------------------------------------------------------------------- packages
step "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
PKGS="nginx curl unzip ca-certificates python3 tor tor-geoipdb bc"
[ "$USE_TLS" = "1" ] && PKGS="$PKGS certbot"
apt-get install -y -qq $PKGS >/dev/null
ok "installed: $PKGS"

# --------------------------------------------------------------------- Tor-ML
step "Installing Tor-ML (50 Tor exit locations)"
if [ -d "$TOR_ML_BASE" ]; then
  ok "Tor-ML already present at $TOR_ML_BASE"
else
  TML="$(mktemp)"
  curl -fsSL --max-time 60 \
    https://raw.githubusercontent.com/icubaby/Tor-ML/main/tor-ml.sh -o "$TML" \
    || die "could not download tor-ml.sh"
  bash "$TML" --install || die "tor-ml.sh --install failed"
  rm -f "$TML"
  ok "Tor-ML installed"
fi

# ----------------------------------------------------------------------- Xray
step "Installing Xray"
if command -v xray >/dev/null 2>&1; then
  ok "Xray already installed ($(xray version 2>/dev/null | head -1))"
else
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install \
    || die "the Xray installer failed"
  ok "Xray installed ($(xray version 2>/dev/null | head -1))"
fi

# ------------------------------------------------------------------ the agent
step "Installing the sync agent"
mkdir -p "$AGENT_DIR"
install -m 0755 "$(dirname "$0")/agent.sh" "$AGENT_DIR/agent.sh" 2>/dev/null || {
  # Allow running this installer standalone, without the repo checked out.
  curl -fsSL --max-time 60 \
    "https://raw.githubusercontent.com/jack22Jqck211/panel/main/deploy/agent.sh" \
    -o "$AGENT_DIR/agent.sh" || die "could not obtain agent.sh"
  chmod 0755 "$AGENT_DIR/agent.sh"
}

cat >"$AGENT_DIR/agent.env" <<EOF
PANEL_URL=$PANEL_URL
SYNC_KEY=$SYNC_KEY
EOF
chmod 0600 "$AGENT_DIR/agent.env"
ok "agent installed at $AGENT_DIR (credentials are chmod 600)"

# --------------------------------------------------------- TLS bootstrap order
# The generated nginx config points at certificate files. Writing it before the
# certificate exists makes `nginx -t` fail, so obtain the certificate first
# behind a minimal HTTP-only vhost, then install the real config.
if [ "$USE_TLS" = "1" ]; then
  step "Obtaining a TLS certificate for $DOMAIN"
  if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    ok "certificate already present"
  else
    mkdir -p /var/www/html
    cat >"$NGINX_SITE" <<EOF
# Temporary bootstrap vhost, replaced once the certificate is issued.
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 200 'ok'; add_header Content-Type text/plain; }
}
EOF
    ln -sf "$NGINX_SITE" "$NGINX_LINK"
    rm -f /etc/nginx/sites-enabled/default
    nginx -t >/dev/null 2>&1 || die "the bootstrap nginx config failed validation"
    systemctl enable --now nginx >/dev/null 2>&1 || true
    systemctl reload nginx || systemctl restart nginx

    CERTBOT_ARGS="certonly --webroot -w /var/www/html -d $DOMAIN --agree-tos --non-interactive"
    if [ -n "$EMAIL" ]; then
      CERTBOT_ARGS="$CERTBOT_ARGS -m $EMAIL"
    else
      CERTBOT_ARGS="$CERTBOT_ARGS --register-unsafely-without-email"
    fi
    # shellcheck disable=SC2086
    certbot $CERTBOT_ARGS || die "certbot failed -- confirm $DOMAIN resolves to this server's IP and port 80 is open"
    ok "certificate issued"
  fi
fi

# ------------------------------------------------------- apply real configs
step "Applying the generated configuration"
"$AGENT_DIR/agent.sh" --force || die "the agent could not apply the configuration"

# -------------------------------------------------------------- systemd timer
step "Scheduling automatic sync"
cat >/etc/systemd/system/xray-panel-agent.service <<EOF
[Unit]
Description=Sync Xray config from the panel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=$AGENT_DIR/agent.env
ExecStart=$AGENT_DIR/agent.sh
EOF

cat >/etc/systemd/system/xray-panel-agent.timer <<EOF
[Unit]
Description=Sync Xray config from the panel every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now xray-panel-agent.timer >/dev/null 2>&1
ok "agent will sync every 60 seconds"

if [ "$USE_TLS" = "1" ]; then
  # certbot's package timer handles renewal; make sure nginx picks up new certs.
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat >/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'EOF'
#!/bin/sh
systemctl reload nginx || true
EOF
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
  ok "nginx will reload after certificate renewals"
fi

# ------------------------------------------------------------------ Tor nodes
step "Tor exit locations"
case "$START_TOR" in
  none)
    warn "no Tor instances started yet"
    echo "     Start them with:  sudo $AGENT_DIR/tor-start.sh all"
    echo "     Or a subset:      sudo $AGENT_DIR/tor-start.sh 1,2,3,4,5"
    ;;
  *)
    if [ -x "$(dirname "$0")/tor-start.sh" ]; then
      install -m 0755 "$(dirname "$0")/tor-start.sh" "$AGENT_DIR/tor-start.sh"
    fi
    if [ -x "$AGENT_DIR/tor-start.sh" ]; then
      "$AGENT_DIR/tor-start.sh" "$START_TOR" || warn "some Tor instances may not have started"
    else
      warn "tor-start.sh not available; start locations with the interactive 'tor' command"
    fi
    ;;
esac

# Always try to place the helper for later use.
if [ -f "$(dirname "$0")/tor-start.sh" ] && [ ! -f "$AGENT_DIR/tor-start.sh" ]; then
  install -m 0755 "$(dirname "$0")/tor-start.sh" "$AGENT_DIR/tor-start.sh"
fi

# ---------------------------------------------------------------------- done
SCHEME="https"; [ "$USE_TLS" = "1" ] || SCHEME="http"
cat <<EOF

$C_B==================== done ====================$C_N

  Panel      : $PANEL_URL
  Endpoint   : $SCHEME://$DOMAIN
  Xray config: $XRAY_CONF
  nginx site : $NGINX_SITE
  Agent      : $AGENT_DIR/agent.sh (every 60s)

  Useful commands:
    systemctl status xray
    systemctl status nginx
    journalctl -u xray-panel-agent -n 40
    sudo $AGENT_DIR/tor-start.sh all
    tor                      # Tor-ML interactive dashboard

  Check a Tor exit works:
    curl --socks5-hostname 127.0.0.1:48180 https://api.ipify.org

  Reminder: Tor instances must be running for a location to work. Configs for
  stopped locations stay in the subscription but will not connect.

EOF
