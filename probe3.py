"""Check which ESP cipher suites scapy can actually provide (no network).

The question that matters for hilldust: is the (ENC_ALG, AUTH_ALG) pair
your gateway negotiates implementable on this Python stack? If you add a
row to IPSEC_ALGOS in patches/0001-*, add the matching row here.

Run:  python3 probe3.py
"""

import scapy.all as S
from scapy.layers.ipsec import AUTH_ALGOS, CRYPT_ALGOS

print("scapy crypt algos:")
for name, cls in CRYPT_ALGOS.items():
    print(f"  {name:18s} key_size={getattr(cls, 'key_size', None)} "
          f"iv_size={getattr(cls, 'iv_size', None)}")

print("scapy auth algos:")
for name, cls in AUTH_ALGOS.items():
    print(f"  {name:18s} icv_size={getattr(cls, 'icv_size', None)}")
print()

# (crypt_algo, crypt_key_size, iv_size, auth_algo, auth_key_size, origin)
SUITES = [
    ("3DES",    0x18, 8,  "HMAC-SHA1-96", 0x14, "upstream"),
    ("AES-CBC", 0x10, 16, "HMAC-MD5-96",  0x10, "patch 0001"),
]

failed = False
for crypt, csize, ivsize, auth, asize, origin in SUITES:
    try:
        sa = S.SecurityAssociation(
            proto=S.ESP,
            spi=0x1234,
            crypt_algo=crypt,
            crypt_key=b"\x01" * csize,
            auth_algo=auth,
            auth_key=b"\x02" * asize,
        )
        sealed = sa.encrypt(S.IP(b"\x45\x00\x00\x28" + b"\x00" * 36), iv=b"\x03" * ivsize)
        print(f"[+] {crypt} + {auth} usable ({origin}), "
              f"{len(bytes(sealed.payload))} bytes on the wire")
    except Exception as exc:  # noqa: BLE001
        failed = True
        print(f"[!] {crypt} + {auth} FAILED ({origin}): "
              f"{type(exc).__name__}: {exc}")

raise SystemExit(1 if failed else 0)
