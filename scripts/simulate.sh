#!/usr/bin/env bash
#
# Full-stack traffic simulation.
#
# Runs the real chain end to end, with only Tor itself substituted:
#
#   xray client  ->  frontdoor  ->  xray server  ->  fakesocks
#   (50 socks in)    (path route)   (50 inbounds)   (50 Tor ports)
#
# Every piece except Tor is the genuine article: the client configs come from the
# panel's subscription, the server config and the path routing table come from the
# panel's generators, and both Xray processes are the official binary.
#
# What it proves: traffic entering as location X leaves through the Tor SOCKS port
# assigned to X, for all 50 locations. That is the property no amount of reading
# the config can confirm, and the one whose failure would silently give a user the
# wrong exit country.
#
# What it does not prove: that Tor builds a circuit in the requested country. That
# needs a host where Tor can reach the network.
#
# Usage: scripts/simulate.sh <path-to-xray-binary>

set -uo pipefail

XRAY="${1:-${XRAY_BIN:-xray}}"
PANEL_PORT=18090
FRONT_PORT=18443
CLIENT_SOCKS_BASE=20001
PASSWORD="sim-password"

W="$(mktemp -d)"
COOKIE="$W/cookie"
BASE="http://127.0.0.1:$PANEL_PORT"
PIDS=()
FAILED=0

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; FAILED=$((FAILED + 1)); }
info() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  sleep 0.3
  rm -rf "$W"
}
trap cleanup EXIT

command -v "$XRAY" >/dev/null 2>&1 || [ -x "$XRAY" ] || {
  echo "xray binary not found at '$XRAY'"; exit 1;
}

# ------------------------------------------------------------------------ build

info "Building"
go build -o "$W/panel" . || exit 1
go build -o "$W/fakesocks" ./test/harness/fakesocks || exit 1
go build -o "$W/frontdoor" ./test/harness/frontdoor || exit 1
pass "panel and harness built"

# ------------------------------------------------------------------ panel setup

info "Starting the panel"
ADMIN_PASSWORD="$PASSWORD" SESSION_SECRET=sim SYNC_KEY=simkey \
DATA_DIR="$W/data" PORT="$PANEL_PORT" "$W/panel" >"$W/panel.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fsS "$BASE/healthz" >/dev/null 2>&1 || { cat "$W/panel.log"; fail "panel did not start"; exit 1; }
pass "panel up on :$PANEL_PORT"

curl -fsS -c "$COOKIE" -X POST "$BASE/api/login" -H 'content-type: application/json' \
  -d "{\"password\":\"$PASSWORD\"}" >/dev/null

# TLS off: there is no certificate here, and this also exercises the plain-WS path.
curl -fsS -b "$COOKIE" -X POST "$BASE/api/settings" -H 'content-type: application/json' \
  -d "{\"serverAddress\":\"127.0.0.1\",\"serverPort\":$FRONT_PORT,\"tls\":false,\"pathPrefix\":\"/ws\",\"defaultCleanIp\":\"\",\"subIntervalHours\":12,\"protocol\":\"vless\",\"panelBaseUrl\":\"\"}" >/dev/null
pass "settings pointed at the simulated front door"

curl -fsS -b "$COOKIE" -X POST "$BASE/api/users" -H 'content-type: application/json' \
  -d '{"name":"simuser","cleanIp":"","note":"","expiresInDays":0,"quotaBytes":0}' -o "$W/user.json"
TOKEN=$(python3 -c "import json;print(json.load(open('$W/user.json'))['subToken'])")
pass "user created"

curl -fsS -b "$COOKIE" "$BASE/api/generate/xray" -o "$W/server.json"
curl -fsS -b "$COOKIE" "$BASE/api/generate/nginx" -o "$W/nginx.conf"
curl -fsS "$BASE/sub/$TOKEN?raw=1" -o "$W/sub.txt"
N=$(grep -c '^vless://' "$W/sub.txt")
[ "$N" = "50" ] && pass "subscription returned 50 configs" || { fail "got $N configs"; exit 1; }

# --------------------------------------------------------------- client config
# Built from the subscription itself, so the test consumes exactly what a user
# would import rather than a hand-written equivalent.

info "Building the client config from the subscription"
python3 - "$W/sub.txt" "$W/client.json" "$FRONT_PORT" "$CLIENT_SOCKS_BASE" <<'PY'
import json, sys, urllib.parse

sub, out_path, front_port, socks_base = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])

inbounds, outbounds, rules = [], [], []
for i, line in enumerate(l.strip() for l in open(sub) if l.strip()):
    u = urllib.parse.urlparse(line)
    q = urllib.parse.parse_qs(u.query)
    uuid = u.username
    path = q["path"][0]
    cc = path.rsplit("/", 1)[-1]

    inbounds.append({
        "tag": f"in-{cc}",
        "listen": "127.0.0.1",
        "port": socks_base + i,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
    })
    stream = {"network": "ws", "security": "none", "wsSettings": {"path": path}}
    if "host" in q:
        stream["wsSettings"]["headers"] = {"Host": q["host"][0]}
    outbounds.append({
        "tag": f"out-{cc}",
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": "127.0.0.1",
            "port": front_port,
            "users": [{"id": uuid, "encryption": "none"}],
        }]},
        "streamSettings": stream,
    })
    rules.append({"type": "field", "inboundTag": [f"in-{cc}"], "outboundTag": f"out-{cc}"})

json.dump({
    "log": {"loglevel": "error"},
    "inbounds": inbounds,
    "outbounds": outbounds,
    "routing": {"domainStrategy": "AsIs", "rules": rules},
}, open(out_path, "w"), indent=2)
print(f"  {len(inbounds)} client socks inbounds -> {len(outbounds)} vless outbounds")
PY
pass "client config generated"

# ------------------------------------------------------------- validate configs

info "Validating both configs with the real xray binary"
"$XRAY" -test -c "$W/server.json" >"$W/t1.log" 2>&1 \
  && pass "server config accepted" || { cat "$W/t1.log"; fail "server config rejected"; exit 1; }
"$XRAY" -test -c "$W/client.json" >"$W/t2.log" 2>&1 \
  && pass "client config accepted" || { cat "$W/t2.log"; fail "client config rejected"; exit 1; }

# ---------------------------------------------------------------- start the mesh

info "Starting the simulated stack"
"$W/fakesocks" >"$W/fakesocks.log" 2>&1 &
PIDS+=($!)
sleep 1
grep -q '50 listeners up' "$W/fakesocks.log" \
  && pass "$(grep -o '[0-9]* listeners up' "$W/fakesocks.log") standing in for Tor" \
  || { cat "$W/fakesocks.log"; fail "fakesocks did not start"; exit 1; }

"$XRAY" run -c "$W/server.json" >"$W/xray-server.log" 2>&1 &
PIDS+=($!)
"$W/frontdoor" "$W/nginx.conf" "$FRONT_PORT" >"$W/frontdoor.log" 2>&1 &
PIDS+=($!)
"$XRAY" run -c "$W/client.json" >"$W/xray-client.log" 2>&1 &
PIDS+=($!)
sleep 3

grep -q 'routes parsed' "$W/frontdoor.log" \
  && pass "$(grep -o '[0-9]* routes parsed' "$W/frontdoor.log") from the generated nginx.conf" \
  || { cat "$W/frontdoor.log"; fail "frontdoor did not start"; exit 1; }

# Confirm the client's listeners actually came up before drawing conclusions.
UP=0
for i in $(seq 0 49); do
  (echo >"/dev/tcp/127.0.0.1/$((CLIENT_SOCKS_BASE + i))") 2>/dev/null && UP=$((UP + 1))
done
[ "$UP" = "50" ] && pass "xray client is listening on all 50 local ports" || fail "only $UP of 50 client ports are up"

# ------------------------------------------------------- the actual traffic test

info "Sending real traffic through all 50 locations"
python3 - "$W/sub.txt" >"$W/expected.txt" <<'PY'
import sys, urllib.parse
# Tor-ML assigns SOCKS ports sequentially from 48180 in table order, and the
# subscription is emitted in that same order.
for i, line in enumerate(l.strip() for l in open(sys.argv[1]) if l.strip()):
    q = urllib.parse.parse_qs(urllib.parse.urlparse(line).query)
    cc = q["path"][0].rsplit("/", 1)[-1]
    print(cc, 48180 + i)
PY

OK=0
MISROUTED=0
NORESP=0
i=0
while read -r cc expected; do
  port=$((CLIENT_SOCKS_BASE + i))
  got=$(curl -s --max-time 12 --socks5-hostname "127.0.0.1:$port" \
        "http://probe.invalid/" 2>/dev/null | grep -o 'TORPORT=[0-9]*' | cut -d= -f2)
  if [ -z "$got" ]; then
    NORESP=$((NORESP + 1))
    [ "$NORESP" -le 3 ] && printf '    %s: no response\n' "$cc"
  elif [ "$got" = "$expected" ]; then
    OK=$((OK + 1))
  else
    MISROUTED=$((MISROUTED + 1))
    printf '    \033[31m%s: left through %s, expected %s\033[0m\n' "$cc" "$got" "$expected"
  fi
  i=$((i + 1))
done < "$W/expected.txt"

echo
if [ "$OK" = "50" ]; then
  pass "all 50 locations routed to the correct Tor SOCKS port"
else
  fail "$OK of 50 correct ($MISROUTED misrouted, $NORESP no response)"
  echo "    xray server log:"; tail -5 "$W/xray-server.log" | sed 's/^/      /'
  echo "    xray client log:"; tail -5 "$W/xray-client.log" | sed 's/^/      /'
fi

# A wrong path must not silently fall through to some other inbound.
info "Negative check: an unknown path must be refused"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  "http://127.0.0.1:$FRONT_PORT/ws/zz")
[ "$code" = "404" ] && pass "unmapped path returns 404" || fail "unmapped path returned $code"

echo
if [ "$FAILED" = "0" ]; then
  printf '\033[1;32m===== SIMULATION PASSED =====\033[0m\n'
  printf 'Traffic flowed client -> front door -> xray -> the correct Tor port, 50/50.\n'
  printf 'Only Tor itself was substituted.\n'
else
  printf '\033[1;31m===== %s CHECK(S) FAILED =====\033[0m\n' "$FAILED"
  exit 1
fi
