"""Zero-risk probe: verify the compat shim and the gateway's TLS, WITHOUT
sending an AUTH message -- so no failed-login counter is incremented and
no account lockout can be triggered.

    HILLSTONE_SERVER=vpn.example.com:10443 python3 probe.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ssl  # noqa: E402

print(f"python       : {sys.version.split()[0]}")
print(f"ssl module   : {ssl.OPENSSL_VERSION}")
print(f"shim active  : {hasattr(ssl, 'wrap_socket')}")
if not hasattr(ssl, "wrap_socket"):
    raise SystemExit("[!] sitecustomize shim NOT loaded (check PYTHONPATH)")

# 1. crypto backend needed for the tunnel
import scapy.all  # noqa: E402

scapy.all.SecurityAssociation(
    proto=scapy.all.ESP,
    spi=0x1234,
    crypt_algo="3DES",
    crypt_key=b"\x01" * 24,
    auth_algo="HMAC-SHA1-96",
    auth_key=b"\x02" * 20,
)
print("scapy ESP    : 3DES-CBC + HMAC-SHA1-96 OK")

# 2. TLS handshake only -- no auth message sent
target = os.environ.get("HILLSTONE_SERVER", "vpn.example.com:10443")
host, _, port = target.rpartition(":")

import hillstone  # noqa: E402

c = hillstone.ClientCore()
try:
    c.connect(host, int(port))
except Exception as exc:
    print(f"[!] TLS/connect FAILED: {type(exc).__name__}: {exc}")
    raise SystemExit(1)

s = c.socket
print(f"peer         : {s.getpeername()}")
print(f"TLS version  : {s.version()}")
print(f"TLS cipher   : {s.cipher()[0]}")
print("[+] handshake OK -- shim works, gateway protocol reachable")
