"""One-shot diagnostic: perform a real login and dump the NEW_KEY reply.

hilldust aborts with NotSupported because the gateway picked an ENC_ALG /
AUTH_ALG pair it doesn't implement. This prints the raw values so we can
tell whether the choice is patchable.
"""
import os
import runpy
import sys

sys.path.insert(0, "/opt/hilldust")

import hillstone  # noqa: E402
from hillstone import (  # noqa: E402
    KeyExchangeMode,
    Message,
    MessageType,
    Payload,
    Unpack,
)

ENC_ALG = {
    0: "des3_cbc", 1: "des3_cbc", 2: "des", 3: "des3_cbc",
    4: "des3_cbc", 5: "des3_cbc", 6: "des3_cbc", 7: "des3_cbc",
    8: "des3_cbc", 9: "des3_cbc", 10: "des3_cbc", 11: "null",
    12: "aes128_cbc", 13: "des3_cbc", 14: "aes192_cbc", 15: "aes256_cbc",
}
AUTH_ALG = {
    0: "hmac-sha1-96", 1: "hmac-md5-96", 2: "hmac-sha1-96",
    3: "hmac-sha1-96", 4: "hmac-sha1-96", 5: "hmac-sha256-128",
    6: "hmac-sha384-192", 7: "hmac-sha512-256", 8: "hmac-null",
}
IPCOMP_ALG = {0: "none", 1: "deflate"}


def diag_new_key(self):
    from os import urandom

    key_material = urandom(0x30)
    inbound_spi = int.from_bytes(urandom(4), byteorder="big")
    inbound_cpi = int.from_bytes(urandom(2), byteorder="big")

    m = Message(MessageType.NEW_KEY)
    m.push_int(Payload.KEY_EXCH_MODE, 2, KeyExchangeMode.KEY_EXCH_PLAIN.value)
    m.push_bytes(Payload.KEYMAT, key_material)
    m.push_int(Payload.SPI, 4, inbound_spi)
    m.push_int(Payload.IPCOMP_CPI, 2, inbound_cpi)
    self.socket.send(m.finish())

    msg_id, res, _ = Unpack(self.socket.recv(4096))

    print("=== NEW_KEY reply ===", flush=True)
    for key, val in res.items():
        print(f"  {key.name:22s} = {val.hex()}", flush=True)

    enc = int.from_bytes(res[Payload.ENC_ALG], "big")
    auth = int.from_bytes(res[Payload.AUTH_ALG], "big")
    ipcomp = int.from_bytes(res[Payload.IPCOMP_ALG], "big")
    print("", flush=True)
    print(f"  ENC_ALG    = {enc:>3}  -> {ENC_ALG.get(enc, 'UNKNOWN')}", flush=True)
    print(f"  AUTH_ALG   = {auth:>3}  -> {AUTH_ALG.get(auth, 'UNKNOWN')}", flush=True)
    print(f"  IPCOMP_ALG = {ipcomp:>3}  -> {IPCOMP_ALG.get(ipcomp, 'UNKNOWN')}", flush=True)
    print("", flush=True)
    print(f"  hilldust needs: ENC_ALG=3 (des3_cbc), "
          f"AUTH_ALG=2 (hmac-sha1-96), IPCOMP_ALG=0 (none)", flush=True)
    raise SystemExit(0)


hillstone.ClientCore.new_key = diag_new_key

sys.argv = [
    "hilldust.py",
    os.environ["HILLSTONE_SERVER"],
    os.environ["HILLSTONE_USER"],
    os.environ["HILLSTONE_PASSWORD"],
]
runpy.run_path("/opt/hilldust/hilldust.py", run_name="__main__")
