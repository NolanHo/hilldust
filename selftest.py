#!/usr/bin/env python3
"""Known-answer and invariant tests for the ESP wire format.

The golden vectors below were captured from an implementation verified
byte-for-byte against scapy's ESP, over every padding residue and in both
directions. They are frozen here so a change to esp.py cannot silently break
interoperability with the gateway.

The invariant tests cover the parts a golden vector cannot: every payload
length, the RFC 4303 padding convention, and rejection of tampered input.

Run:  python3 selftest.py
"""

import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import esp

SPI = 0x11223344
CRYPT_KEY = bytes(range(16))
AUTH_KEY = bytes(range(16, 32))
IV = bytes(range(32, 48))

# (label, plaintext, expected ESP datagram)
VECTORS = [
    ("32-byte payload, 14 bytes of padding",
     bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                   "101112131415161718191a1b1c1d1e1f"),
     bytes.fromhex("1122334400000001"
                   "202122232425262728292a2b2c2d2e2f"
                   "9e3c311788a3dae7a3a6018da2c98cc6"
                   "99ebb9321498be212e79bb8d76d76cb4"
                   "646452cec1f24a0db37a6285832b5cc7"
                   "6c5bf3ac98251f9fee051f21")),

    ("28-byte payload, 2 bytes of padding",
     bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                   "101112131415161718191a1b"),
     bytes.fromhex("1122334400000001"
                   "202122232425262728292a2b2c2d2e2f"
                   "9e3c311788a3dae7a3a6018da2c98cc6"
                   "05fecc86d9fe60bb954b56df84603dac"
                   "a7a0c6a0d0b860d683995109")),

    ("60-byte IPv4/UDP tun packet",
     bytes.fromhex("4500003c0001000040115c9d0a0101010a090909"
                   "04d200350028cc73010101010101010101010101"
                   "0101010101010101010101010101010101010101"),
     bytes.fromhex("1122334400000001"
                   "202122232425262728292a2b2c2d2e2f"
                   "d2633873268769d3eb79f23cd917d953"
                   "16dad0fef65be9f637964ae009d61bb8"
                   "f057207e42e4a4bf6769165f904df4ee"
                   "99466721fcd8b88ec56e276691b486e1"
                   "543e22fb2f9adc5517e9b466")),
]


def sa():
    return esp.SecurityAssociation(
        spi=SPI, crypt_algo="AES-CBC", crypt_key=CRYPT_KEY,
        auth_algo="HMAC-MD5-96", auth_key=AUTH_KEY, iv=IV)


def plaintext_of(instance, wire):
    """Peel the ESP datagram open with raw AES, to inspect the framing."""
    iv = wire[8:8 + len(instance.iv)]
    engine = Cipher(algorithms.AES(instance.crypt_key), modes.CBC(iv)).decryptor()
    body = wire[8 + len(instance.iv):-instance.icv_size]
    return engine.update(body) + engine.finalize()


def main():
    failures = []
    check = failures.append

    print("golden vectors")
    for label, payload, expected in VECTORS:
        wire = sa().encrypt(payload)
        if wire != expected:
            check(f"{label}: encrypt mismatch\n"
                  f"      expected {expected.hex()}\n"
                  f"      got      {wire.hex()}")
        elif sa().decrypt(wire) != payload:
            check(f"{label}: decrypt did not round trip")
        else:
            print(f"  [+] {label}")

    print("framing invariants")
    for size in range(1, 129):
        payload = bytes((i * 7) & 0xFF for i in range(size))
        instance = sa()
        wire = instance.encrypt(payload)

        if instance.decrypt(wire) != payload:
            check(f"length {size}: round trip failed")
            break

        body_len = len(wire) - 8 - len(IV) - instance.icv_size
        if body_len % 16:
            check(f"length {size}: ciphertext is not block aligned")
            break

        plain = plaintext_of(instance, wire)
        pad_len = plain[-2]
        expected_pad = bytes(range(1, pad_len + 1))
        if plain[len(payload):-2] != expected_pad:
            check(f"length {size}: padding is not 1,2,3.. as RFC 4303 requires")
            break
        if plain[-1] != 4:
            check(f"length {size}: next-header is {plain[-1]}, expected 4 (IPIP)")
            break
        if (len(payload) + pad_len + 2) % 16:
            check(f"length {size}: payload+pad+trailer is not block aligned")
            break
    else:
        print("  [+] 128 payload lengths: round trip, padding and alignment")

    print("rejection")
    payload, good = VECTORS[0][1], VECTORS[0][2]

    tampered = bytearray(good)
    tampered[len(tampered) // 2] ^= 0x01
    try:
        sa().decrypt(bytes(tampered))
        check("tampered ciphertext was accepted")
    except esp.ESPError:
        print("  [+] tampered ciphertext rejected")

    try:
        sa().decrypt(bytes.fromhex("deadbeef") + good[4:])
        check("wrong SPI was accepted")
    except esp.ESPError:
        print("  [+] wrong SPI rejected")

    try:
        sa().decrypt(good[:16])
        check("truncated datagram was accepted")
    except esp.ESPError:
        print("  [+] truncated datagram rejected")

    print("sequence numbers")
    seq_sa = sa()
    first = seq_sa.encrypt(payload)
    second = seq_sa.encrypt(payload)
    if first[4:8] == second[4:8]:
        check("sequence number did not advance")
    elif second[4:8] != (int.from_bytes(first[4:8], "big") + 1).to_bytes(4, "big"):
        check("sequence number did not advance by one")
    else:
        print("  [+] advances by one and appears on the wire")

    if failures:
        print("\nFAILED:")
        for failure in failures:
            print(f"  [!] {failure}")
        return 1

    print("\nok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
