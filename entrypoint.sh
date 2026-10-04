#!/bin/bash
# Container entrypoint: a SOCKS5 exit plus the tunnel.
#
# The password is passed through the environment rather than argv so it
# never shows up in the container's process list.
set -euo pipefail

: "${HILLSTONE_SERVER:?HILLSTONE_SERVER not set}"
: "${HILLSTONE_USER:?HILLSTONE_USER not set}"
: "${HILLSTONE_PASSWORD:?HILLSTONE_PASSWORD not set}"

echo "[*] SOCKS5 on 0.0.0.0:${SOCKS_PORT:-1080} (container netns only)" >&2
microsocks -i 0.0.0.0 -p "${SOCKS_PORT:-1080}" -q &
sleep 0.3
kill -0 $! 2>/dev/null || { echo "[!] microsocks failed to start" >&2; exit 1; }

cd /opt/hilldust
# exec so hilldust becomes PID 1 and receives SIGTERM directly from Docker,
# which lets it restore the network on the way out.
exec python3 hilldust.py "$HILLSTONE_SERVER" "$HILLSTONE_USER"
