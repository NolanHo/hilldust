# Hilldust

[中文说明 / Chinese README](README.zh-CN.md)

(Unofficial) Yet another implementation of the *Hillstone™ Secure Connect VPN
Client* for Linux.

> A fork of [LionNatsu/hilldust](https://github.com/LionNatsu/hilldust).
> Upstream is a proof of concept, last touched 2020-04-22. See
> [Differences from upstream](#differences-from-upstream).

---

## Read this first: upstream rewrites your host's network

Upstream `platform_linux.py` does the following the moment a tunnel comes up:

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
2. **`/etc/resolv.conf` is overwritten in place**, its only backup in
   process memory.
3. **The restore path is not guaranteed to run.** It fires only after a
   normal exit (`input('Enter to exit.')` / `Ctrl-C`). `SIGTERM`,
   `SIGKILL`, a crash, an OOM kill, or simply losing the SSH session you
   launched it from all skip it.
4. **The restore path is itself destructive.** It runs
   `ip route flush table main` before `ip route restore`, against a blob
   captured at connect time. Routes added since — by Docker, WireGuard, a
   DHCP renewal — are flushed and not restored.

### Our motivation

We wanted to keep using a Hillstone gateway without any of that, and without
the vendor's macOS client either: an unsigned binary that installs a root
`LaunchDaemon` executing out of a user-writable bundle, alongside a root
shell that re-runs every 5 seconds.

This fork runs hilldust **inside a container with its own network
namespace**, so even the writes above would land in a throwaway namespace
that `docker compose down` deletes. It also stops doing most of them in the
first place — see below.

---

## Differences from upstream

| Area | Upstream | This fork |
| --- | --- | --- |
| Default route | replaced outright | left alone; two `/1` routes are added alongside it and removed on exit |
| Routing restore | flush table, restore stale blob | deletes exactly the routes it added; a crash leaves the original default intact |
| **ESP data path** | scapy builds a Packet object per datagram | `cryptography` directly — **0.8 MB/s → 9.5 MB/s measured** on the same link |
| Tun MTU | default (1500) | 1380, matching the vendor client's `VnicMTU`, so packets are not fragmented |
| Socket buffers | system default | 4 MiB via `SO_*BUFFFORCE` (the container has `CAP_NET_ADMIN`) |
| Ciphers | 3DES-CBC + HMAC-SHA1-96 only, else `NotSupported` | lookup table; adds AES-128-CBC + HMAC-MD5-96, which current gateways negotiate |
| TLS setup | `ssl.wrap_socket()` (removed in Python 3.12) | `SSLContext`, runs on 3.12+ |
| Message framing | one `recv()` assumed to be one packet | reads exactly the declared length |
| Dead tunnel | undetected, process idles forever | data-plane probe (DNS over the tunnel) → teardown and reconnect with exponential backoff |
| Shutdown | `input()` blocks; SIGTERM skips cleanup | SIGINT/SIGTERM tear the network down |
| Errors | `AuthError`, no reason | the gateway's own status code and message |
| Tests | none | `selftest.py` pins the ESP wire format; the image build fails if it breaks |

## Performance

Measured on the same gateway and link, 10 MB download through the tunnel:

| | throughput | CPU ceiling measured |
| --- | --- | --- |
| upstream (scapy ESP) | 0.80 MB/s (6.4 Mbps) | 7.8 Mbps |
| this fork (`cryptography` ESP) | **9.5 MB/s (76 Mbps)** | 445 Mbps |

The `cryptography` ESP implementation was verified byte-for-byte against
scapy's output over every padding residue, in both directions, before being
swapped in — and `selftest.py` freezes that format so a future change cannot
silently break interoperability with the gateway.

## Quick start (Docker, recommended)

```bash
cp secret.env.example secret.env
$EDITOR secret.env          # gateway, username, password
chmod 600 secret.env

docker compose build        # runs selftest.py; fails if the wire format breaks
docker compose up -d
docker compose logs -f      # expect: "tunnel up on tun0 (mtu 1380)"
docker compose ps           # expect: healthy
```

A SOCKS5 proxy is then published on `127.0.0.1:1080` of the host. It is
bound to loopback on purpose — reach it from elsewhere over SSH rather than
exposing an open proxy to your LAN:

```bash
ssh -N -L 1080:127.0.0.1:1080 <host>
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

The proxy is a **full tunnel**: everything you hand it exits via the remote
gateway, not your local line. Route only the domains that need it.

### Tuning

| Variable | Default | Purpose |
| --- | --- | --- |
| `HILLDUST_MTU` | 1380 | tun MTU; lower it if large packets still disappear |
| `HILLDUST_LIVENESS` | on | set to `off` to disable the data-plane probe |
| `HILLDUST_LIVENESS_INTERVAL` | 15 | seconds between probes |
| `HILLDUST_LIVENESS_FAILURES` | 3 | consecutive misses before reconnecting |

### Requirements

* `/dev/net/tun` on the host
* `NET_ADMIN` and that device — no `--privileged`, no `network_mode: host`

## Alternative: run it natively

```bash
sudo HILLSTONE_PASSWORD=... ./hilldust.py vpn.example.com:10443 username
```

`sudo` is required for the tun device and the routing table. Passing the
password in the environment keeps it out of `ps`.

The non-destructive routing means a crash no longer strands the machine: the
original default route is still there, shadowed by two `/1` routes you can
remove with

```bash
sudo ip route del 0.0.0.0/1; sudo ip route del 128.0.0.0/1
```

## Layout

    hillstone.py       protocol, TLS control channel, cipher negotiation
    esp.py             ESP data path on cryptography
    tunnel.py          the UDP tunnel client
    platform_linux.py  tun device, routes, resolver
    hilldust.py        CLI, session loop, reconnect, signals
    selftest.py        known-answer and invariant tests for the ESP format
    probe.py           TLS + ESP check, no login attempted
    probe2.py          dumps the negotiated algorithms (logs in)

## Diagnostics

| Script | What it does | Login? |
| --- | --- | --- |
| `selftest.py` | ESP format regression test | no |
| `probe.py` | TLS handshake + one ESP round trip per `IPSEC_ALGOS` entry | **no** |
| `probe2.py` | dumps the NEW_KEY reply, i.e. the negotiated algorithms | yes |

```bash
docker compose run --rm --no-deps --entrypoint python3 \
  -v "$PWD/probe2.py:/probe2.py:ro" vpn /probe2.py
```

`probe.py` stops before sending AUTH, so probing a gateway never records a
failed login. When a gateway negotiates something unsupported, `probe2.py`
tells you exactly which pair — and adding it is one row in `IPSEC_ALGOS`
plus the matching primitives in `esp.py`.

## Caveats

* Proof of concept lineage. Treat accordingly.
* No device binding: `HOST_ID` / `HOST_NAME` are sent empty. A gateway that
  enforces host checks will reject the login.
* The gateway certificate is not authenticated — same as the vendor client,
  which ships `VerifyServerCert=false`. This buys confidentiality, not
  authentication.
* The ESP initialisation vector is fixed for the life of the session, as the
  vendor protocol dictates. That is a CBC-mode weakness inherited from the
  protocol, not something this fork can fix unilaterally.
* Liveness is inferred from the data plane. If the gateway stops answering
  the probe target while still passing traffic, the session will reconnect
  unnecessarily; set `HILLDUST_LIVENESS=off` if that happens.

## Credits and license

Upstream: [LionNatsu/hilldust](https://github.com/LionNatsu/hilldust), GPLv3.
Hillstone and Hillstone Secure Connect are trademarks of Hillstone Networks.
Unofficial, unaffiliated.
