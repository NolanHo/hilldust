"""The tunnel data channel: hilldust's protocol over UDP-encapsulated ESP.

Replaces upstream's impl_scapy.py. scapy built a full Packet object for
every datagram -- measured at 1.5 ms for one encap+decap pair, which capped
this client near 8 Mbps regardless of the link. esp.py does the same bytes
in two C calls, and selftest.py pins the wire format it produces.
"""

import socket

import esp
import hillstone


class Client(hillstone.ClientCore):
    def __init__(self):
        super().__init__()
        self.outbound_sa = None
        self.inbound_sa = None
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # A timeout keeps recv() interruptible, so a shutdown request is
        # honoured instead of blocking forever on a dead tunnel.
        self.udp_socket.settimeout(1.0)
        self._enlarge_buffers()

    def _enlarge_buffers(self, size=4 << 20):
        """Deep socket buffers absorb bursts that would otherwise be dropped.

        SO_*BUFFFORCE bypasses net.core.{r,w}mem_max and needs CAP_NET_ADMIN,
        which the container already has for the tun device anyway.
        """
        for forced_name, plain_opt in (('SO_RCVBUFFORCE', socket.SO_RCVBUF),
                                       ('SO_SNDBUFFORCE', socket.SO_SNDBUF)):
            forced_opt = getattr(socket, forced_name, None)
            if forced_opt is not None:
                try:
                    self.udp_socket.setsockopt(socket.SOL_SOCKET, forced_opt, size)
                    continue
                except OSError:
                    pass
            try:
                self.udp_socket.setsockopt(socket.SOL_SOCKET, plain_opt, size)
            except OSError:
                pass

    def new_key(self):
        super().new_key()
        algo = self.ipsec_algo
        params = self.ipsec_param
        common = dict(crypt_algo=algo.crypt_algo, auth_algo=algo.auth_algo,
                      icv_size=algo.icv_size)
        self.outbound_sa = esp.SecurityAssociation(
            spi=params.out_spi, crypt_key=params.out_crypt_key,
            auth_key=params.out_auth_key, iv=params.out_iv, **common)
        self.inbound_sa = esp.SecurityAssociation(
            spi=params.in_spi, crypt_key=params.in_crypt_key,
            auth_key=params.in_auth_key, iv=params.in_iv, **common)

    def recv(self):
        """One decrypted datagram. Raises socket.timeout when idle."""
        datagram, _ = self.udp_socket.recvfrom(65535)
        return self.inbound_sa.decrypt(datagram)

    def send(self, datagram):
        return self.udp_socket.sendto(
            self.outbound_sa.encrypt(datagram),
            (self.server_host, self.server_udp_port))

    def close(self):
        for sock in (self.udp_socket, self.socket):
            try:
                sock.close()
            except OSError:
                pass
