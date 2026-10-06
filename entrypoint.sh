#!/bin/bash
# Container entrypoint: a SOCKS5 exit plus the tunnel.
#
# The password is passed through the environment rather than argv so it
# never shows up in the container's process list.
set -euo pipefail

: "${HILLSTONE_SERVER:?HILLSTONE_SERVER not set}"
: "${HILLSTONE_USER:?HILLSTONE_USER not set}"
: "${HILLSTONE_PASSWORD:?HILLSTONE_PASSWORD not set}"

PORT="${SOCKS_PORT:-1080}"

# Restarted in a loop rather than started once. If this listener dies the
# port stops answering while the tunnel happily keeps running, and nothing
# else would notice -- which is exactly how it failed once already.
(
    while :; do
        microsocks -i 0.0.0.0 -p "$PORT" -q || true
        echo "[!] microsocks exited, restarting in 1s" >&2
        sleep 1
    done
) &

sleep 0.5
if ! ss -tln 2>/dev/null | grep -q ":${PORT}"; then
    echo "[!] microsocks is not listening on ${PORT}" >&2
    exit 1
fi
echo "[*] SOCKS5 on 0.0.0.0:${PORT} (container netns only)" >&2

cd /opt/hilldust
# exec so hilldust becomes PID 1 and receives SIGTERM directly from Docker,
# which lets it restore the network on the way out.
exec python3 hilldust.py "$HILLSTONE_SERVER" "$HILLSTONE_USER"
