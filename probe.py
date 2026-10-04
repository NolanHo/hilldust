"""Check the ESP implementation and the gateway's TLS, WITHOUT sending an
AUTH message -- so probing never increments a failed-login counter.

    HILLSTONE_SERVER=vpn.example.com:10443 python3 probe.py
"""

import os
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import esp  # noqa: E402

import hillstone  # noqa: E402

print(f"python       : {sys.version.split()[0]}")
print(f"ssl module   : {ssl.OPENSSL_VERSION}")

for pair, algo in sorted(hillstone.IPSEC_ALGOS.items()):
    sa = esp.SecurityAssociation(
        spi=0x1234,
        crypt_algo=algo.crypt_algo,
        crypt_key=b"\x01" * algo.crypt_size,
        auth_algo=algo.auth_algo,
        auth_key=b"\x02" * algo.auth_size,
        iv=b"\x00" * algo.iv_size,
        icv_size=algo.icv_size,
    )
    sample = bytes(range(200))[:algo.crypt_size * 4 + 3]
    assert sa.decrypt(sa.encrypt(sample)) == sample, "ESP round trip failed"
    print(f"ESP suite    : ENC_ALG={pair[0]:<3} AUTH_ALG={pair[1]:<3} "
          f"-> {algo.crypt_algo} + {algo.auth_algo}  round trip OK")

target = os.environ.get("HILLSTONE_SERVER", "vpn.example.com:10443")
host, _, port = target.rpartition(":")

client = hillstone.ClientCore()
try:
    client.connect(host, int(port))
except Exception as exc:  # noqa: BLE001
    print(f"[!] TLS/connect FAILED: {type(exc).__name__}: {exc}")
    raise SystemExit(1)

sock = client.socket
print(f"peer         : {sock.getpeername()}")
print(f"TLS version  : {sock.version()}")
print(f"TLS cipher   : {sock.cipher()[0]}")
print("[+] handshake OK -- gateway reachable, no login attempted")
