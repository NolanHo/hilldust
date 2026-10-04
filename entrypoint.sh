#!/bin/bash
# Runs inside the container's own network namespace.
# hilldust replaces the default route and /etc/resolv.conf -- both stay
# confined to this netns, the host is untouched.
set -uo pipefail

: "${HILLSTONE_SERVER:?HILLSTONE_SERVER not set}"
: "${HILLSTONE_USER:?HILLSTONE_USER not set}"
: "${HILLSTONE_PASSWORD:?HILLSTONE_PASSWORD not set}"

cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT

echo "[*] SOCKS5 listening on 0.0.0.0:${SOCKS_PORT} (container netns only)" >&2
microsocks -i 0.0.0.0 -p "${SOCKS_PORT}" -q &
SOCKS_PID=$!
sleep 0.3
if ! kill -0 "$SOCKS_PID" 2>/dev/null; then
  echo "[!] microsocks failed to start" >&2
  exit 1
fi

echo "[*] connecting to ${HILLSTONE_SERVER} as ${HILLSTONE_USER}" >&2

cd /opt/hilldust
# hilldust.py ends with input('Enter to exit.') -> requires stdin_open: true
python3 hilldust.py "${HILLSTONE_SERVER}" "${HILLSTONE_USER}" "${HILLSTONE_PASSWORD}"
rc=$?

# Backoff before the container exits, so `restart: unless-stopped` cannot
# hammer the gateway (and trip its account lockout) in a tight loop.
echo "[!] hilldust exited rc=${rc}; sleeping ${RESTART_BACKOFF:-30}s before restart" >&2
sleep "${RESTART_BACKOFF:-30}"
exit "$rc"
