#!/usr/bin/env bash
#
# Starts Tor-ML exit locations without the interactive dashboard.
#
# tor-ml.sh only exposes --install on the command line; everything else lives
# behind its menu. Rather than reimplementing its start logic (which would drift
# from upstream), this drives the menu over stdin: option 4 starts every
# location, option 2 accepts a comma-separated selection. The trailing blank line
# answers its "Press Enter" prompt and 0 exits cleanly -- without that final 0
# the menu loop would spin on EOF.
#
# Usage:
#   sudo tor-start.sh all          # all 50 locations (needs ~1-1.5 GB RAM)
#   sudo tor-start.sh 1,2,3,10     # only these location IDs
#   sudo tor-start.sh status       # show what is currently running
#
set -euo pipefail

TOR_ML_BIN="/usr/local/bin/tor"
TOR_ML_BASE="/opt/tor-ml"
SELECTION="${1:-}"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run this as root"
[ -d "$TOR_ML_BASE" ] || die "Tor-ML is not installed (expected $TOR_ML_BASE)"
[ -x "$TOR_ML_BIN" ] || die "the Tor-ML launcher is missing (expected $TOR_ML_BIN)"
[ -n "$SELECTION" ] || die "usage: tor-start.sh all|<ids>|status"

case "$SELECTION" in
  status)
    # Option 1 is Full Status; blank answers its pause, 0 exits.
    printf '1\n\n0\n' | "$TOR_ML_BIN" || true
    exit 0
    ;;
  all)
    MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    if [ "$MEM_MB" -lt 1800 ]; then
      printf 'WARNING: %s MB RAM detected. 50 Tor instances typically need 1-1.5 GB.\n' "$MEM_MB"
      printf 'Continuing in 5s -- Ctrl-C to abort and start a subset instead.\n'
      sleep 5
    fi
    printf 'Starting all 50 locations. Tor bootstrap takes a while per instance.\n'
    printf '4\n\n0\n' | "$TOR_ML_BIN" || true
    ;;
  *)
    # Option 2 prompts for a selection; Tor-ML accepts "1,2,3", "1 2 3" or "1.2.3".
    printf 'Starting locations: %s\n' "$SELECTION"
    printf '2\n%s\n\n0\n' "$SELECTION" | "$TOR_ML_BIN" || true
    ;;
esac

# Report what actually came up rather than assuming success: Tor cannot always
# build a circuit for low-relay countries such as SC, TN, CR or MD.
printf '\nListening SOCKS ports in the Tor-ML range:\n'
FOUND=0
for port in $(seq 48180 48229); do
  if (echo >"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    printf '  127.0.0.1:%s up\n' "$port"
    FOUND=$((FOUND + 1))
  fi
done
printf '\n%s of 50 locations are listening.\n' "$FOUND"

if [ "$FOUND" -eq 0 ]; then
  cat <<'EOF'

Nothing came up. Things worth checking:
  tor                          open the Tor-ML dashboard and read its status
  journalctl -n 50             look for OOM kills
  free -m                      confirm there is memory headroom

EOF
  exit 1
fi

cat <<'EOF'

A listening port means Tor accepted the connection, not that the country's exit
is reachable. Verify one end to end:

  curl --socks5-hostname 127.0.0.1:48180 https://api.ipify.org

Low-relay countries (SC, TN, CR, MD and similar) may never find an exit node --
that is a Tor network limitation, not a configuration error.
EOF
