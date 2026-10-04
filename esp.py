"""ESP (RFC 4303) data path built on `cryptography` directly.

scapy builds a full Packet object per datagram: measured at 1.53 ms for one
encap+decap pair, which caps this client at ~8 Mbps. The same bytes with two
C calls is dramatically faster.

Layout on the wire, confirmed against scapy byte for byte:

    SPI(4) | Seq(4) | IV(block) | AES-CBC/CBC-ciphertext | ICV(12)
    plaintext = payload | padding 1,2,3.. | padlen(1) | next-header(1)
    ICV       = HMAC(key, SPI|Seq|IV|ciphertext)[:icv_size]
"""

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:  # cryptography >= 43 moved TripleDES out of the main namespace
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # pragma: no cover
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

BLOCK_SIZES = {'AES-CBC': 16, '3DES': 8}
CIPHERS = {'AES-CBC': algorithms.AES, '3DES': TripleDES}
HASHES = {'HMAC-MD5-96': hashlib.md5, 'HMAC-SHA1-96': hashlib.sha1}


class ESPError(Exception):
    """A datagram that failed to authenticate or parse."""


class SecurityAssociation(object):
    """One direction of the ESP tunnel."""

    def __init__(self, spi, crypt_algo, crypt_key, auth_algo, auth_key,
                 iv, icv_size=12):
        self.spi = spi
        self.crypt_algo = crypt_algo
        self.crypt_key = crypt_key
        self.auth_algo = auth_algo
        self.auth_key = auth_key
        self.iv = iv
        self.icv_size = icv_size
        self.block_size = BLOCK_SIZES[crypt_algo]
        self.cipher_cls = CIPHERS[crypt_algo]
        self.hash_cls = HASHES[auth_algo]
        self.seq = 1
        # A complete IPv4 packet is carried, so the ESP next-header is IPIP.
        # Measured, not guessed: scapy produces 4 here for a real tun packet.
        self.next_header = 4

    def _icv(self, body):
        return hmac.new(self.auth_key, body, self.hash_cls).digest()[:self.icv_size]

    def _cipher(self, iv, encrypt):
        ctx = Cipher(self.cipher_cls(self.crypt_key), modes.CBC(iv))
        return ctx.encryptor() if encrypt else ctx.decryptor()

    def encrypt(self, payload):
        pad_len = (self.block_size - (len(payload) + 2) % self.block_size) % self.block_size
        plain = payload + bytes(range(1, pad_len + 1)) + bytes([pad_len, self.next_header])

        engine = self._cipher(self.iv, True)
        body = struct.pack('!II', self.spi, self.seq) + self.iv
        body += engine.update(plain) + engine.finalize()
        self.seq = (self.seq + 1) & 0xFFFFFFFF
        return body + self._icv(body)

    def decrypt(self, packet):
        if len(packet) < 8 + len(self.iv) + self.icv_size:
            raise ESPError('short ESP packet (%d bytes)' % len(packet))
        spi = struct.unpack('!I', packet[:4])[0]
        if spi != self.spi:
            raise ESPError('SPI mismatch: got %#x, want %#x' % (spi, self.spi))

        body, icv = packet[:-self.icv_size], packet[-self.icv_size:]
        if not hmac.compare_digest(icv, self._icv(body)):
            raise ESPError('ICV mismatch')

        iv = packet[8:8 + len(self.iv)]
        engine = self._cipher(iv, False)
        plain = engine.update(packet[8 + len(self.iv):-self.icv_size])
        plain += engine.finalize()

        pad_len = plain[-2]
        if pad_len + 2 > len(plain):
            raise ESPError('bogus padding length %d' % pad_len)
        return plain[:-(pad_len + 2)]
