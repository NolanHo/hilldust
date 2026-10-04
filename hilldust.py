#!/usr/bin/env python3
"""Hillstone Secure Connect client.

    hilldust.py ADDRESS:PORT USERNAME [PASSWORD]

PASSWORD may be omitted, in which case $HILLSTONE_PASSWORD is used, which
keeps it out of the process's argv.

Runs until interrupted. If the control channel drops, the session is torn
down and retried with exponential backoff. SIGINT/SIGTERM tear the network
down and exit, so the host is never left pointing at a dead tunnel.
"""

import argparse
import os
import signal
import socket
import sys
import threading
import time

import hillstone
import platform_linux
import tunnel

DEFAULT_BACKOFF = 5
MAX_BACKOFF = 60
# A rejected credential is almost never transient, so back off hard: a
# tight retry loop is how you trip a gateway-side lockout counter.
AUTH_BACKOFF = 120
# A session that stayed up this long counts as healthy, resetting backoff.
HEALTHY_UPTIME = 60

_stop = threading.Event()


def log(message):
    print('[%s] %s' % (time.strftime('%H:%M:%S'), message),
          file=sys.stderr, flush=True)


def _install_signal_handlers():
    def handler(signum, _frame):
        log('received %s, shutting down' % signal.Signals(signum).name)
        _stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handler)
        except ValueError:
            pass  # not called from the main thread


def _pump_inbound(client):
    while not _stop.is_set():
        try:
            datagram = client.recv()
        except socket.timeout:
            continue
        platform_linux.write(datagram)


def _pump_outbound(client):
    while not _stop.is_set():
        client.send(platform_linux.read())


def _drain_control(client):
    """Drain the control channel after setup.

    The gateway closes this channel a few seconds after the session comes
    up -- the data plane runs over UDP -- so its closure is NOT a liveness
    signal. We only report it, and only if it ends with an error.
    """
    try:
        while not _stop.is_set():
            hillstone.recv_message(client.socket)
    except (ConnectionError, OSError) as exc:
        log('control channel closed (%s); data continues over UDP' % exc)


def _probe_once(client, target, timeout=3.0):
    """Send one DNS query to `target` through the tunnel.

    A normal socket bound to the tun device: the query is routed into the
    tunnel by the /1 routes, and the reply arrives back through the tun,
    through the userspace ESP pump, and into this socket. If that round
    trip stops working, the tunnel is gone.
    """
    query = (b'\xab\xcd'          # transaction id
             b'\x01\x00'          # standard query, recursion desired
             b'\x00\x01'          # qdcount
             b'\x00\x00\x00\x00\x00\x00'   # ancount/nscount/arcount
             b'\x07example\x03com\x00'
             b'\x00\x01\x00\x01')         # A, IN
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((str(client.ip_ipv4.ip), 0))
        sock.settimeout(timeout)
        sock.sendto(query, (target, 53))
        return len(sock.recv(512)) > 0
    except (OSError, socket.timeout):
        return False
    finally:
        sock.close()


def _watch_liveness(client):
    """Reconnect when the data plane stops passing traffic.

    Only enabled when the gateway pushed a DNS server to probe and
    HILLDUST_LIVENESS is not "off" -- a probe target that is unreachable
    by policy would otherwise cause a permanent reconnect loop.
    """
    targets = [str(server) for server in client.dns_ipv4]
    if not targets or os.environ.get('HILLDUST_LIVENESS', '').lower() in ('0', 'off', 'no'):
        return

    interval = float(os.environ.get('HILLDUST_LIVENESS_INTERVAL', '15'))
    failures = int(os.environ.get('HILLDUST_LIVENESS_FAILURES', '3'))
    misses = 0

    while not _stop.wait(interval):
        if _probe_once(client, targets[0]):
            misses = 0
            continue
        misses += 1
        log('liveness probe %d/%d to %s failed' % (misses, failures, targets[0]))
        if misses >= failures:
            raise ConnectionError('data plane unresponsive after %d probes' % misses)


def run_session(host, port, username, password):
    """Run one session to completion. Returns (reason, seconds_up)."""
    client = tunnel.Client()
    started = time.monotonic()
    failure = threading.Event()
    reasons = []

    def guard(label, fn):
        """Run a pump thread. Returning normally is fine (the control
        drain does); only an exception tears the session down."""
        def run(*args):
            try:
                fn(*args)
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                reasons.append('%s: %s: %s' % (label, type(exc).__name__, exc))
                failure.set()
        return run

    try:
        client.connect(host, port)
        log('connected to %s:%d' % (host, port))

        client.auth(username, password, '', '')
        log('authenticated')

        client.client_info()
        client.wait_network()
        log('network: ip=%s gateway=%s dns=%s'
            % (client.ip_ipv4, client.gateway_ipv4,
               ', '.join(str(server) for server in client.dns_ipv4) or 'none'))

        client.new_key()
        log('key exchange: %s + %s'
            % (client.ipsec_algo.crypt_algo, client.ipsec_algo.auth_algo))

        platform_linux.set_network(client)
        log('tunnel up on %s (mtu %s)'
            % (platform_linux.tun_name, platform_linux.tun_mtu))

        for label, fn in (('rx', _pump_inbound),
                          ('tx', _pump_outbound),
                          ('control', _drain_control),
                          ('liveness', _watch_liveness)):
            threading.Thread(target=guard(label, fn),
                             args=(client,), daemon=True).start()

        while not _stop.is_set() and not failure.is_set():
            time.sleep(0.5)
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        reasons.append('%s: %s' % (type(exc).__name__, exc))
    finally:
        uptime = time.monotonic() - started
        platform_linux.restore_network()
        client.close()

    return (reasons[0] if reasons else 'session ended'), uptime


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='hilldust.py',
        description='Hillstone Secure Connect client.')
    parser.add_argument('address', metavar='ADDRESS:PORT',
                        help='gateway address, e.g. vpn.example.com:10443')
    parser.add_argument('username')
    parser.add_argument('password', nargs='?',
                        help='omit to read $HILLSTONE_PASSWORD instead')
    parser.add_argument('--backoff', type=int, default=DEFAULT_BACKOFF,
                        metavar='SECONDS',
                        help='initial reconnect delay (default %(default)s)')
    args = parser.parse_args(argv)

    if os.getuid() != 0:
        parser.error('must run as root: creating a tun device and changing '
                     'the routing table both require it')

    password = args.password or os.environ.get('HILLSTONE_PASSWORD')
    if not password:
        parser.error('no password given and HILLSTONE_PASSWORD is unset')

    host, sep, port = args.address.rpartition(':')
    if not sep or not host or not port.isdigit():
        parser.error('address must look like host:port, got %r' % args.address)

    _install_signal_handlers()

    backoff = max(1, args.backoff)
    while not _stop.is_set():
        reason, uptime = run_session(host, int(port), args.username, password)
        if _stop.is_set():
            break

        if uptime >= HEALTHY_UPTIME:
            backoff = max(1, args.backoff)
        elif reason.startswith('AuthError'):
            backoff = max(backoff, AUTH_BACKOFF)

        log('session ended after %ds (%s); reconnecting in %ds'
            % (int(uptime), reason, backoff))
        if _stop.wait(backoff):
            break
        backoff = min(backoff * 2, MAX_BACKOFF)

    log('stopped')
    return 0


if __name__ == '__main__':
    sys.exit(main())
