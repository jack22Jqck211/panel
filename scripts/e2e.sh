#!/usr/bin/env bash
#
# End-to-end check: boots the panel, drives it over HTTP exactly as a browser
# and a proxy client would, and validates the generated Xray config with the
# real xray binary.
#
# The last step is the important one. Structural assertions in Go tests prove the
# config has the shape we intended; only `xray -test` proves xray itself accepts
# it. Without that, "the config looks right" is an assumption.
#
# Usage:
#   scripts/e2e.sh [path-to-xray-binary]
#
# Requires: go, python3, curl. xray is optional but strongly recommended.

set -euo pipefail

XRAY_BIN="${1:-${XRAY_BIN:-xray}}"
PORT="${PORT:-18080}"
PASSWORD="e2e-password"
SYNC_KEY="e2e-sync-key"
DOMAIN="srv.example.com"
CLEAN_IP="104.17.0.1"

WORK="$(mktemp -d)"
COOKIE="$WORK/cookie.txt"
BASE="http://127.0.0.1:$PORT"
PANEL_PID=""

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }
info() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
  [ -n "$PANEL_PID" ] && kill "$PANEL_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------- build & boot

info "Building"
go build -ldflags="-s -w" -o "$WORK/panel" .
pass "binary built ($(du -h "$WORK/panel" | cut -f1))"

info "Booting panel on :$PORT"
ADMIN_PASSWORD="$PASSWORD" \
SYNC_KEY="$SYNC_KEY" \
SESSION_SECRET="e2e-session-secret" \
DATA_DIR="$WORK/data" \
PORT="$PORT" \
  "$WORK/panel" >"$WORK/panel.log" 2>&1 &
PANEL_PID=$!

for _ in $(seq 1 50); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
curl -fsS "$BASE/healthz" >/dev/null 2>&1 || { cat "$WORK/panel.log"; fail "panel did not come up"; }

LOC_COUNT=$(curl -fsS "$BASE/healthz" | python3 -c 'import json,sys;print(json.load(sys.stdin)["locations"])')
[ "$LOC_COUNT" = "50" ] && pass "healthz reports 50 locations" || fail "healthz reports $LOC_COUNT locations"

# ------------------------------------------------------------------------ auth

info "Authentication"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/state")
[ "$code" = "401" ] && pass "anonymous API access is rejected" || fail "expected 401, got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/login" \
  -H 'content-type: application/json' -d '{"password":"wrong"}')
[ "$code" = "401" ] && pass "wrong password is rejected" || fail "expected 401, got $code"

curl -fsS -c "$COOKIE" -X POST "$BASE/api/login" \
  -H 'content-type: application/json' -d "{\"password\":\"$PASSWORD\"}" >/dev/null
pass "logged in"

code=$(curl -s -b "$COOKIE" -o /dev/null -w '%{http_code}' "$BASE/api/state")
[ "$code" = "200" ] && pass "session cookie works" || fail "expected 200, got $code"

# -------------------------------------------------------------------- settings

info "Settings"
curl -fsS -b "$COOKIE" -X POST "$BASE/api/settings" -H 'content-type: application/json' \
  -d "{\"serverAddress\":\"$DOMAIN\",\"serverPort\":443,\"tls\":true,\"pathPrefix\":\"/ws\",\"defaultCleanIp\":\"\",\"subIntervalHours\":12,\"protocol\":\"vless\",\"panelBaseUrl\":\"\"}" \
  >/dev/null
pass "server address saved"

# ----------------------------------------------------------------------- users

info "Users"
curl -fsS -b "$COOKIE" -X POST "$BASE/api/users" -H 'content-type: application/json' \
  -d "{\"name\":\"ali\",\"cleanIp\":\"$CLEAN_IP\",\"note\":\"e2e\",\"expiresInDays\":0,\"quotaBytes\":0}" \
  >"$WORK/user.json"
TOKEN=$(python3 -c 'import json;print(json.load(open("'"$WORK"'/user.json"))["subToken"])')
UUID=$(python3 -c 'import json;print(json.load(open("'"$WORK"'/user.json"))["uuid"])')
pass "created user with a clean IP"

curl -fsS -b "$COOKIE" -X POST "$BASE/api/users" -H 'content-type: application/json' \
  -d '{"name":"sara","cleanIp":"","note":"","expiresInDays":30,"quotaBytes":5368709120}' >/dev/null
pass "created a second user with quota and expiry"

code=$(curl -s -b "$COOKIE" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/users" \
  -H 'content-type: application/json' -d '{"name":"ali"}')
[ "$code" = "409" ] && pass "duplicate name rejected" || fail "expected 409, got $code"

# ---------------------------------------------------------------- subscription

info "Subscription: 1 user -> 50 configs"

curl -fsS "$BASE/sub/$TOKEN?b64=1" >"$WORK/sub.b64"
N=$(python3 -c "
import base64
raw = base64.b64decode(open('$WORK/sub.b64').read()).decode()
print(len([l for l in raw.splitlines() if l.strip()]))
")
[ "$N" = "50" ] && pass "base64 subscription carries exactly 50 configs" || fail "got $N configs"

curl -fsS "$BASE/sub/$TOKEN?raw=1" >"$WORK/sub.txt"
N=$(grep -c '^vless://' "$WORK/sub.txt" || true)
[ "$N" = "50" ] && pass "raw subscription carries 50 vless URIs" || fail "got $N URIs"

# Every config must dial the clean IP but keep the real hostname for SNI.
BAD=$(grep -vc "@$CLEAN_IP:443" "$WORK/sub.txt" || true)
[ "$BAD" = "0" ] && pass "all 50 configs dial the clean IP" || fail "$BAD configs ignore the clean IP"
BAD=$(grep -vc "sni=$DOMAIN" "$WORK/sub.txt" || true)
[ "$BAD" = "0" ] && pass "all 50 configs keep the real SNI" || fail "$BAD configs lost the SNI"

# All 50 country paths must be present exactly once.
N=$(grep -o 'path=%2Fws%2F[a-z][a-z]' "$WORK/sub.txt" | sort -u | wc -l | tr -d ' ')
[ "$N" = "50" ] && pass "50 distinct country paths" || fail "found $N distinct paths"

# One identity across all of them.
N=$(grep -c "$UUID" "$WORK/sub.txt" || true)
[ "$N" = "50" ] && pass "all 50 share one UUID" || fail "UUID appears $N times"

info "Subscription formats"
CT=$(curl -fsS -o "$WORK/view.html" -w '%{content_type}' "$BASE/sub/$TOKEN/view")
case "$CT" in *text/html*) pass "/view returns HTML" ;; *) fail "/view returned $CT" ;; esac
N=$(grep -o 'class="cfg"' "$WORK/view.html" | wc -l | tr -d ' ')
[ "$N" = "50" ] && pass "browser page lists 50 configs" || fail "page lists $N configs"

CT=$(curl -fsS -o "$WORK/sub.yaml" -w '%{content_type}' "$BASE/sub/$TOKEN?format=clash")
case "$CT" in *yaml*) pass "clash format returns YAML" ;; *) fail "clash returned $CT" ;; esac
N=$(grep -c 'type: vless' "$WORK/sub.yaml" || true)
[ "$N" = "50" ] && pass "clash config lists 50 nodes" || fail "clash lists $N nodes"

# A browser hitting the bare link gets the page; a client gets base64.
CT=$(curl -fsS -H 'Accept: text/html,application/xhtml+xml' -o /dev/null -w '%{content_type}' "$BASE/sub/$TOKEN")
case "$CT" in *text/html*) pass "browser Accept header is detected" ;; *) fail "browser got $CT" ;; esac
CT=$(curl -fsS -H 'Accept: */*' -o /dev/null -w '%{content_type}' "$BASE/sub/$TOKEN")
case "$CT" in *text/plain*) pass "client Accept header falls back to base64" ;; *) fail "client got $CT" ;; esac

info "Subscription headers"
curl -fsS -D "$WORK/head.txt" -o /dev/null "$BASE/sub/$TOKEN?b64=1"
grep -qi '^subscription-userinfo:' "$WORK/head.txt" && pass "Subscription-Userinfo present" || fail "missing Subscription-Userinfo"
grep -qi '^profile-update-interval:' "$WORK/head.txt" && pass "Profile-Update-Interval present" || fail "missing Profile-Update-Interval"
grep -qi '^profile-title: base64:' "$WORK/head.txt" && pass "Profile-Title is base64 tagged" || fail "missing Profile-Title"

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/sub/not-a-real-token")
[ "$code" = "404" ] && pass "unknown token returns 404" || fail "expected 404, got $code"

# ------------------------------------------------------- generated server side

info "Generated nginx config"
curl -fsS -b "$COOKIE" "$BASE/api/generate/nginx" >"$WORK/nginx.conf"
N=$(grep -c '^    location /ws/' "$WORK/nginx.conf" || true)
[ "$N" = "50" ] && pass "50 location blocks" || fail "found $N location blocks"
N=$(grep -c 'proxy_set_header Upgrade \$http_upgrade;' "$WORK/nginx.conf" || true)
[ "$N" = "50" ] && pass "every block sets the Upgrade header" || fail "only $N blocks set Upgrade"
grep -q 'map \$http_upgrade \$connection_upgrade' "$WORK/nginx.conf" && pass "connection_upgrade map present" || fail "missing the upgrade map"
python3 - "$WORK/nginx.conf" <<'PY'
import sys
text = open(sys.argv[1]).read()
depth = 0
for ch in text:
    if ch == '{': depth += 1
    elif ch == '}': depth -= 1
    if depth < 0: sys.exit("unbalanced braces")
sys.exit(0 if depth == 0 else "unbalanced braces")
PY
pass "braces balanced"

info "Generated Xray config"
curl -fsS -b "$COOKIE" "$BASE/api/generate/xray" >"$WORK/xray.json"
python3 - "$WORK/xray.json" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
inb, outb, rules = cfg["inbounds"], cfg["outbounds"], cfg["routing"]["rules"]
assert len(inb) == 50, f"{len(inb)} inbounds"
assert len(outb) == 52, f"{len(outb)} outbounds"
assert len(rules) == 50, f"{len(rules)} rules"

# Verify the full chain per country: path -> inbound port -> tor socks port.
socks = {o["tag"]: o["settings"]["servers"][0]["port"] for o in outb if o["protocol"] == "socks"}
route = {r["inboundTag"][0]: r["outboundTag"] for r in rules}
for i, x in enumerate(inb):
    cc = x["tag"].removeprefix("in-")
    assert x["listen"] == "127.0.0.1", f"{cc} not loopback"
    assert x["port"] == 10001 + i, f"{cc} port {x['port']}"
    assert x["streamSettings"]["wsSettings"]["path"] == f"/ws/{cc}", f"{cc} path"
    assert socks[route[x["tag"]]] == 48180 + i, f"{cc} tor port mismatch"
print("chain verified for all 50 countries")
PY
pass "path -> inbound -> Tor SOCKS chain correct for all 50"

if command -v "$XRAY_BIN" >/dev/null 2>&1 || [ -x "$XRAY_BIN" ]; then
  if "$XRAY_BIN" -test -c "$WORK/xray.json" >"$WORK/xray-test.log" 2>&1; then
    pass "xray accepts the generated config ($("$XRAY_BIN" version 2>/dev/null | head -1))"
  else
    cat "$WORK/xray-test.log"
    fail "xray rejected the generated config"
  fi

  # The VMess path must be valid too, since the panel can switch protocols.
  curl -fsS -b "$COOKIE" -X POST "$BASE/api/settings" -H 'content-type: application/json' \
    -d "{\"serverAddress\":\"$DOMAIN\",\"serverPort\":443,\"tls\":true,\"pathPrefix\":\"/ws\",\"defaultCleanIp\":\"\",\"subIntervalHours\":12,\"protocol\":\"vmess\",\"panelBaseUrl\":\"\"}" >/dev/null
  curl -fsS -b "$COOKIE" "$BASE/api/generate/xray" >"$WORK/xray-vmess.json"
  if "$XRAY_BIN" -test -c "$WORK/xray-vmess.json" >"$WORK/xray-vmess.log" 2>&1; then
    pass "xray accepts the VMess variant too"
  else
    cat "$WORK/xray-vmess.log"
    fail "xray rejected the VMess config"
  fi
  N=$(curl -fsS "$BASE/sub/$TOKEN?raw=1" | grep -c '^vmess://' || true)
  [ "$N" = "50" ] && pass "subscription switched to 50 vmess URIs" || fail "got $N vmess URIs"

  # Restore VLESS.
  curl -fsS -b "$COOKIE" -X POST "$BASE/api/settings" -H 'content-type: application/json' \
    -d "{\"serverAddress\":\"$DOMAIN\",\"serverPort\":443,\"tls\":true,\"pathPrefix\":\"/ws\",\"defaultCleanIp\":\"\",\"subIntervalHours\":12,\"protocol\":\"vless\",\"panelBaseUrl\":\"\"}" >/dev/null
else
  printf '  \033[33mSKIP\033[0m xray binary not found at %s -- config not validated by xray itself\n' "$XRAY_BIN"
fi

# ------------------------------------------------------------------------ sync

info "Sync endpoint"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/sync?key=wrong")
[ "$code" = "401" ] && pass "bad sync key rejected" || fail "expected 401, got $code"

curl -fsS "$BASE/api/sync?key=$SYNC_KEY" >"$WORK/sync1.json"
REV1=$(python3 -c 'import json;print(json.load(open("'"$WORK"'/sync1.json"))["revision"])')
[ -n "$REV1" ] && pass "sync returns a revision" || fail "no revision"

curl -fsS -b "$COOKIE" -X POST "$BASE/api/users" -H 'content-type: application/json' \
  -d '{"name":"reza","cleanIp":"","note":"","expiresInDays":0,"quotaBytes":0}' >/dev/null
REV2=$(curl -fsS "$BASE/api/sync?key=$SYNC_KEY" | python3 -c 'import json,sys;print(json.load(sys.stdin)["revision"])')
[ "$REV1" != "$REV2" ] && pass "revision changes when users change" || fail "revision did not move"

# ------------------------------------------------------------------ revocation

info "Revocation"
UID2=$(curl -fsS -b "$COOKIE" "$BASE/api/state" | python3 -c '
import json,sys
for u in json.load(sys.stdin)["users"]:
    if u["name"] == "ali": print(u["id"])
')
curl -fsS -b "$COOKIE" -X POST "$BASE/api/users/$UID2/toggle" >/dev/null
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/sub/$TOKEN")
[ "$code" = "403" ] && pass "disabled user's subscription is refused" || fail "expected 403, got $code"

curl -fsS -b "$COOKIE" -X POST "$BASE/api/users/$UID2/toggle" >/dev/null
curl -fsS -b "$COOKIE" "$BASE/api/generate/xray" >"$WORK/xray2.json"
grep -q "$UUID" "$WORK/xray2.json" && pass "re-enabled user is back in the server config" || fail "user missing after re-enable"

# ------------------------------------------------------------- persistence

info "Persistence"
kill "$PANEL_PID" 2>/dev/null || true
wait "$PANEL_PID" 2>/dev/null || true
ADMIN_PASSWORD="$PASSWORD" SYNC_KEY="$SYNC_KEY" SESSION_SECRET="e2e-session-secret" \
DATA_DIR="$WORK/data" PORT="$PORT" "$WORK/panel" >>"$WORK/panel.log" 2>&1 &
PANEL_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
N=$(curl -fsS "$BASE/sub/$TOKEN?raw=1" | grep -c '^vless://' || true)
[ "$N" = "50" ] && pass "users survive a restart" || fail "after restart got $N configs"

info "All checks passed"
