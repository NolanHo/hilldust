"""Linux network plumbing for hilldust.

Deliberately non-destructive. Upstream replaced the host's default route
outright and restored a routing-table blob after flushing the table, which
loses every route added while the tunnel was up (Docker, WireGuard, DHCP).

Here the default route is left untouched. Two /1 routes are added alongside
it -- together they cover all of IPv4, so longest-prefix match sends traffic
into the tunnel without ever deleting anything -- and teardown removes
exactly the routes that were added. If this process is killed uncleanly,
the recovery is `ip route del 0.0.0.0/1; ip route del 128.0.0.0/1`.
"""

import fcntl
import os
import struct
import subprocess

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# The inner packet must fit the path MTU once ESP, UDP and IP overhead are
# added: a 1500-byte inner packet leaves the host as ~1564 bytes and gets
# fragmented or dropped. The vendor client ships VnicMTU=1380.
DEFAULT_MTU = 1380

# The two halves of 0.0.0.0/0, used instead of replacing the default route.
SPLIT_DEFAULT = ('0.0.0.0/1', '128.0.0.0/1')

RESOLV_CONF = '/etc/resolv.conf'

tun = None
tun_name = None
tun_mtu = None
_added_routes = []
_resolv_backup = None


def _ip(*args, check=True):
    result = subprocess.run(['ip', *args], check=False,
                            capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError('ip %s failed: %s'
                           % (' '.join(args), result.stderr.strip() or 'unknown error'))
    return result


def _add_route(*args):
    _ip('route', 'add', *args)
    _added_routes.append(args)


def _current_path_to(host):
    """How the host reaches `host` right now -- the bypass path.

    The tunnel's own transport must not be routed into the tunnel.
    """
    out = _ip('route', 'get', 'fibmatch', host).stdout.split()
    via = out[out.index('via') + 1] if 'via' in out else None
    dev = out[out.index('dev') + 1] if 'dev' in out else None
    return via, dev


def _write_resolv(c):
    global _resolv_backup
    try:
        with open(RESOLV_CONF, 'rb') as handle:
            _resolv_backup = handle.read()
    except FileNotFoundError:
        _resolv_backup = b''
    body = ''.join('nameserver %s\n' % server for server in c.dns_ipv4)
    with open(RESOLV_CONF, 'wb') as handle:
        handle.write(body.encode('ascii'))


def set_network(c):
    """Bring up the tunnel interface and point the machine at it."""
    global tun, tun_name, tun_mtu

    try:
        handle = open('/dev/net/tun', 'r+b', buffering=0)
    except FileNotFoundError:
        raise RuntimeError('/dev/net/tun is missing -- a container needs '
                           '--device=/dev/net/tun and CAP_NET_ADMIN')

    ifr = fcntl.ioctl(handle, TUNSETIFF, struct.pack('16sH', b'', IFF_TUN | IFF_NO_PI))
    tun = handle
    tun_name = ifr[:ifr.index(b'\0')].decode('ascii')
    tun_mtu = int(os.environ.get('HILLDUST_MTU', DEFAULT_MTU))

    try:
        _ip('address', 'add', str(c.ip_ipv4.ip), 'dev', tun_name)
        _ip('link', 'set', 'dev', tun_name, 'mtu', str(tun_mtu))
        _ip('link', 'set', 'dev', tun_name, 'up')

        bypass = [c.server_host + '/32']
        via, dev = _current_path_to(c.server_host)
        if via:
            bypass += ['via', via]
        if dev:
            bypass += ['dev', dev]
        _add_route(*bypass)

        _add_route(str(c.gateway_ipv4), 'dev', tun_name)
        _add_route(str(c.ip_ipv4.network), 'via', str(c.gateway_ipv4))
        for prefix in SPLIT_DEFAULT:
            _add_route(prefix, 'via', str(c.gateway_ipv4), 'dev', tun_name)

        _write_resolv(c)
    except Exception:
        restore_network()
        raise


def restore_network():
    """Undo set_network(). Safe to call more than once."""
    global tun, _resolv_backup

    for args in reversed(_added_routes):
        _ip('route', 'del', *args, check=False)
    _added_routes.clear()

    if _resolv_backup is not None:
        try:
            with open(RESOLV_CONF, 'wb') as handle:
                handle.write(_resolv_backup)
        except OSError:
            pass
        _resolv_backup = None

    if tun is not None:
        try:
            tun.close()
        except OSError:
            pass
        tun = None


def write(datagram):
    os.write(tun.fileno(), datagram)


def read():
    return os.read(tun.fileno(), 8192)
