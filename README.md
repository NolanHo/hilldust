# Hilldust

[中文说明 / Chinese README](README.zh-CN.md)

(Unofficial) Yet another implementation of the *Hillstone™ Secure Connect VPN
Client* for Linux.

> This is a fork of [LionNatsu/hilldust](https://github.com/LionNatsu/hilldust).
> Upstream is a proof of concept, last touched 2020-04-22. See
> [What this fork adds](#what-this-fork-adds) for the delta.

---

## Read this first: hilldust rewrites your host's network

`platform_linux.py` — **unmodified upstream code** — does the following the
moment a tunnel comes up:

```python
subprocess.check_call('ip route replace default metric 0 via ' + str(c.gateway_ipv4), shell=True)

with open('/etc/resolv.conf', 'rb') as f:
    nameserver_bak = f.read()
with open('/etc/resolv.conf', 'wb') as f:
    for dns in c.dns_ipv4:
        f.write(('nameserver ' + str(dns) + '\n').encode('ascii'))
```

Four consequences:

1. **The default route is replaced, not added.** Every packet the machine
   sends — from every process, every container, every SSH session you have
   open — is re-routed into the tunnel. There is no split-tunnel switch.
2. **`/etc/resolv.conf` is overwritten in place**, and its only backup lives
   in the process's memory.
3. **The restore path is not guaranteed to run.** `restore_network()` is
   called only after a normal exit:

   ```python
   try:
       input('Enter to exit.')
   except KeyboardInterrupt:
       pass
   platform_linux.restore_network(c)
   ```

   `SIGTERM`, `SIGKILL`, a crash, an OOM kill, or simply closing the SSH
   session you launched it from all skip it. You are left with a rewritten
   default route and a rewritten resolver, on a machine whose own
   connectivity now depends on a tunnel that is no longer running.
4. **The restore path is itself destructive.** It runs
   `ip route flush table main` before `ip route restore`, against a blob
   captured at connect time. If that blob is stale — routes added by Docker,
   WireGuard or a DHCP renewal after the tunnel came up — they are flushed
   and not restored.

On a throwaway laptop this is an annoyance. On a server that also runs a
WireGuard mesh, Docker bridges and other people's services, it is an outage
waiting for a `Ctrl-C` that never comes.

### Our motivation

We wanted to keep using the Hillstone gateway without any of that, and
without the vendor's own macOS client either — an unsigned binary that
installs a root `LaunchDaemon` executing from a user-writable bundle, plus a
root shell that re-runs every 5 seconds.

This fork runs hilldust **inside a container with its own network
namespace**. Both destructive writes above then land in the container's
netns, and `docker compose down` reverts them by removing the namespace
entirely. The host keeps its routes, its resolver, and no tun device.

The container also solves a second problem: upstream hilldust only
implements 3DES-CBC + HMAC-SHA1-96, and current Hillstone gateways
negotiate AES-128-CBC + HMAC-MD5-96. See [The patch](#the-patch).

---

## What this fork adds

| File | Purpose |
| --- | --- |
| `patches/0001-*.patch` | adds AES-128-CBC + HMAC-MD5-96 support |
| `shim/sitecustomize.py` | restores `ssl.wrap_socket()`, removed in Python 3.12 |
| `Dockerfile`, `compose.yaml`, `entrypoint.sh` | run it confined, with a SOCKS5 exit |
| `probe.py`, `probe2.py`, `probe3.py` | diagnosis without guessing |
| `secret.env.example` | credential template |

Upstream `.py` files are kept byte-identical; everything is applied at image
build time so the delta stays reviewable.

## Quick start (Docker, recommended)

```bash
cp secret.env.example secret.env
$EDITOR secret.env          # gateway, username, password
chmod 600 secret.env

docker compose build
docker compose up -d
docker compose logs -f      # expect: "Network configured."
```

A SOCKS5 proxy is then published on `127.0.0.1:1080` of the host. It is
bound to loopback on purpose — reach it from elsewhere over SSH rather than
exposing an open proxy to your LAN:

```bash
ssh -N -L 1080:127.0.0.1:1080 <host>
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

Note the SOCKS proxy gives you a **full tunnel**: the container's default
route goes through the VPN, so anything you hand it exits via the remote
gateway, not your local line. Route only the domains that need it.

### Requirements

* `/dev/net/tun` present on the host
* the container needs `NET_ADMIN` and the tun device, nothing else
* no `--privileged`, no `--network host`

## Alternative: run it natively

If you accept the caveats above — a disposable VM, a lab box, a namespace of
your own — upstream usage still works:

```bash
sudo ./hilldust.py vpn.example.com:10443 username password
```

`sudo` is required for the tun device and the routing table.

## The patch

Upstream aborts with `NotSupported` unless the gateway answers the NEW_KEY
exchange with `ENC_ALG=3` (3DES-CBC) and `AUTH_ALG=2` (HMAC-SHA1-96):

```python
if res[Payload.ENC_ALG] != b'\0\x03' or res[Payload.AUTH_ALG] != b'\0\x02' or ...:
    raise NotSupported
```

Current gateways answer `ENC_ALG=12` (aes128_cbc) / `AUTH_ALG=1`
(hmac-md5-96). The patch replaces the hardcoded check with a lookup table
mapping `(ENC_ALG, AUTH_ALG)` to a cipher plus its key and IV sizes, and
hands the negotiated cipher to scapy. Adding another suite is a one-line
change to `IPSEC_ALGOS`.

The control channel is unaffected — it is TLS, negotiated independently of
the ESP data channel.

## Diagnostics

| Script | What it does | Login? |
| --- | --- | --- |
| `probe3.py` | prints scapy's supported ciphers and key sizes | no |
| `probe.py` | TLS handshake + shim check | **no** |
| `probe2.py` | dumps the NEW_KEY reply, i.e. the negotiated algorithms | yes |

```bash
docker compose run --rm --no-deps --entrypoint python3 \
  -v "$PWD/probe2.py:/probe2.py:ro" vpn /probe2.py
```

`probe.py` deliberately stops before sending AUTH, so probing a gateway
never increments its failed-login counter.

## Caveats

* Proof of concept. Upstream last commit 2020-04-22; treat accordingly.
* No device binding: `HOST_ID` / `HOST_NAME` are sent empty. A gateway
  configured for host checks will reject the login.
* The gateway certificate is not verified. Neither upstream, nor this fork,
  nor the vendor's own macOS client (which ships `VerifyServerCert=false`)
  verifies it.
* If the UDP data channel dies, hilldust does not notice. The container
  restarts it, after `RESTART_BACKOFF` (default 30s) so a bad credential
  cannot hammer the gateway into an account lockout.

## Credits and license

Upstream: [LionNatsu/hilldust](https://github.com/LionNatsu/hilldust), GPLv3.
The Hillstone and Hillstone Secure Connect names belong to Hillstone
Networks. This project is unofficial and unaffiliated.
