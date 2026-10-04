import enum
import ipaddress
import socket
import ssl
import struct

class ProtocolError(Exception):
    """Malformed or truncated data on the control channel."""


class AuthError(Exception):
    pass


class ClientInfoError(Exception):
    pass


class NetworkInfoError(Exception):
    pass


class NewKeyError(Exception):
    pass


class NotSupported(Exception):
    pass


class MessageType(enum.Enum):
    NONE = 0x00
    AUTH = 0x01
    CLNT_INFO = 0x02
    SET_IP = 0x03
    SET_ROUTE = 0x04
    NEW_KEY = 0x05
    KEY_DONE = 0x06
    CLNT_LOGOUT = 0x07
    SERV_DISCONN = 0x08
    KEEP_ALIVE = 0x09
    REKEY = 0x0a
    HOST_CHECK = 0x0b
    HOST_CHECK_UPD = 0x0c
    CHPWD = 0x0d
    CHPWD_RESP = 0x0e
    SMS_AUTH_REQ = 0x0f
    SMS_AUTH_REQ_RSP = 0x10
    SMS_REQ = 0x11
    SMS_REQ_RSP = 0x12
    RSA_NEWPIN = 0x13
    RSA_NEWPIN_RSP = 0x14

class KeyExchangeMode(enum.Enum):
    KEY_EXCH_RSA = 1
    KEY_EXCH_DH = 2
    KEY_EXCH_PLAIN = 3

class Payload(enum.Enum):
    USERNAME = 1
    PASSWORD = 2
    CHAL_PASSWORD = 3
    STATUS = 4
    CLT_PUB_IPV4 = 5
    SVR_PUB_IPV4 = 6
    CLT_PRIV_IPV4 = 7
    SVR_PRIV_IPV4 = 8
    SVR_UDP_PORT = 9
    IP_SUBNET = 10
    NETMASK_IPV4 = 11
    GATEWAY_IPV4 = 12
    ROUTE_METRICS = 13
    IPSEC_SETTING = 14
    MODP_GROUP = 15
    KEYMAT = 16
    DNS_IPV4 = 17
    WINS_IPV4 = 18
    ROUTE_IPV4 = 19
    PERFE_SRV_IPV4 = 20
    COMM_SRV_IPV4 = 21
    KEY_EXCH_MODE = 32 # KeyExchangeMode
    SPI = 48
    ENC_ALG = 49
    '''
        des3_cbc
        des3_cbc
        des
        des3_cbc*
        des3_cbc
        des3_cbc
        des3_cbc
        des3_cbc
        des3_cbc
        des3_cbc
        des3_cbc
        null
        aes128_cbc
        des3_cbc
        aes192_cbc
        aes256_cbc
    '''
    
    AUTH_ALG = 50
    '''
        hmac-sha1-96
        hmac-md5-96
        hmac-sha1-96*
        hmac-sha1-96
        hmac-sha1-96
        hmac-sha256-128
        hmac-sha384-192
        hmac-sha512-256
        hmac-null
    '''
    
    SESSION_ID = 51
    EN_ERRO_MSG = 53
    CH_ERRO_MSG = 54
    ALIVE_STAUS = 64
    AUTH_TYPE = 81
    COOKIE = 82
    DISCONNECT = 83
    CLIENT_VER = 84
    HOST_ID = 96
    HOST_NAME = 97
    HOST_CHECK_MD5 = 112
    HOST_CHECK_RESULT = 115
    HOST_CHECK_RESULT_SIZE = 116
    IPCOMP_CPI = 128
    IPCOMP_ALG = 129
    ALLOW_PWD = 132
    NEED_SMS_AUTH = 133
    SMS_AUTH_CODE = 134
    CLIENT_AUTO_CONNECT = 136


def Unpack(packet:bytes) -> (MessageType, dict, bool):
    magic, reply, msg_t, size = struct.unpack('!BBHL', packet[:8])
    if magic == 0x0 and reply == 0 and msg_t == 0 and size == 0:
        return MessageType.NONE, {}, True
    if magic != 0x22: raise Exception('Not a packet')
    if size > len(packet):
        raise ProtocolError('truncated packet: header says %d, got %d' % (size, len(packet)))
    data = packet[8:size]
    unpacked = {}
    cur = 0
    while cur < len(data):
        key, size = struct.unpack('!HH', data[cur:cur+4])
        unpacked[Payload(key)] = data[cur+4:cur+4+size]
        cur += 4+size+((4-(size%4))%4)
    return MessageType(msg_t), unpacked, reply == 0x02


def recv_exactly(sock, count:int) -> bytes:
    """Read exactly `count` bytes, or raise if the peer goes away.

    A single recv() can return a partial message: over a real network that
    is the norm, not the exception. Upstream assumed one recv == one packet.
    """
    buf = b''
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError('control channel closed by peer')
        buf += chunk
    return buf


def recv_message(sock) -> (MessageType, dict, bool):
    """Read one complete protocol message off the control channel."""
    header = recv_exactly(sock, 8)
    magic, reply, msg_t, size = struct.unpack('!BBHL', header)
    if magic == 0x0 and reply == 0 and msg_t == 0 and size == 0:
        return MessageType.NONE, {}, True
    if magic != 0x22:
        raise ProtocolError('bad magic 0x%02x on control channel' % magic)
    if size < 8 or size > 0x100000:
        raise ProtocolError('implausible packet size %d' % size)
    return Unpack(header + recv_exactly(sock, size - 8))


def _server_message(res:dict) -> str:
    """The human-readable error text the gateway may attach."""
    for key in (Payload.EN_ERRO_MSG, Payload.CH_ERRO_MSG):
        if res.get(key):
            return res[key].decode('utf-8', 'replace').strip('\0').strip()
    return ''


def configure_tcp_keepalive(sock, idle:int=60, interval:int=15, count:int=4) -> None:
    """Let the OS notice a silently dead control channel.

    Without keepalive a half-open TCP connection looks healthy forever and
    the tunnel reports itself up while carrying nothing.
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        return
    for name, value in (('TCP_KEEPIDLE', idle), ('TCP_KEEPALIVE', idle),
                        ('TCP_KEEPINTVL', interval), ('TCP_KEEPCNT', count)):
        opt = getattr(socket, name, None)
        if opt is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, opt, value)
        except OSError:
            pass


def tls_socket() -> ssl.SSLSocket:
    """TLS transport for the control channel.

    The gateway certificate is deliberately not authenticated -- the vendor
    client ships VerifyServerCert=false and the gateway is typically
    self-signed. This buys confidentiality, not authentication.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))


class Message(object):
    def __init__(self, msg_t:MessageType, reply: bool=False):
        self.reply = reply
        self.msg_t = msg_t
        self.data = []
    def push_int(self, key:Payload, size:int, v:int):
        b = v.to_bytes(size, byteorder='big')
        self.data.append({'key': key, 'bytes': b})
    def push_ipv4(self, key:Payload, v:any):
        b = ipaddress.v4_int_to_packed(int(ipaddress.IPv4Address(v)))
        self.data.append({'key': key, 'bytes': b})
    def push_string(self, key:Payload, v:str):
        self.push_bytes(key, v.encode('utf-8'))
    def push_bytes(self, key:Payload, v:bytes):
        self.data.append({'key': key, 'bytes': v})
    def finish(self):
        b_prefix = bytes([0x22, 0x02 if self.reply else 0x00])
        b_prefix += self.msg_t.value.to_bytes(2, byteorder='big')
        b = b''
        for v in self.data:
            b += v['key'].value.to_bytes(2, byteorder='big')
            b += len(v['bytes']).to_bytes(2, byteorder='big')
            b += v['bytes']
            padding = (4-(len(b)%4)) % 4 # padding for alignment
            b = b.ljust(len(b)+padding, b'\0')
        size = (len(b)+8).to_bytes(4, byteorder='big')
        return b_prefix + size + b


class IPSecAlgo(object):
    """One ESP cipher suite plus the key material sizes it consumes."""
    def __init__(self, crypt_algo, crypt_size, iv_size, auth_algo, auth_size,
                 icv_size=12):
        self.crypt_algo = crypt_algo
        self.crypt_size = crypt_size
        self.iv_size = iv_size
        self.auth_algo = auth_algo
        self.auth_size = auth_size
        self.icv_size = icv_size


# (ENC_ALG, AUTH_ALG) as returned by the gateway in the NEW_KEY reply.
# auth_size is the HMAC key length (md5 -> 16, sha1 -> 20), crypt_size the
# cipher key length. Add a row here to support another negotiated suite.
IPSEC_ALGOS = {
    (3, 2): IPSecAlgo('3DES', 0x18, 8, 'HMAC-SHA1-96', 0x14),
    (12, 1): IPSecAlgo('AES-CBC', 0x10, 16, 'HMAC-MD5-96', 0x10),
}


class IPSecParameters(object):
    def __init__(self, in_spi, out_spi, keymat, iv_size, auth_size, crypt_size):
        from hashlib import sha1
        self.keymat = keymat
        self.in_spi = in_spi
        self.out_spi = out_spi
        self.out_iv = self.keymat[:iv_size]
        self.in_iv = self.keymat[:iv_size]
        self.enlarged_keymat = sha1(self.keymat).digest()
        for _ in range(9):
            self.enlarged_keymat += sha1(self.enlarged_keymat).digest()
        
        def read_bytes(buf:bytes, size:int) -> (bytes, bytes):
            return buf[:size], buf[size:]
        buf = self.enlarged_keymat
        self.out_auth_key, buf = read_bytes(buf, auth_size)
        self.out_crypt_key, buf = read_bytes(buf, crypt_size)
        self.in_auth_key, buf = read_bytes(buf, auth_size)
        self.in_crypt_key, buf = read_bytes(buf, crypt_size)


class ClientCore(object):
    def __init__(self):
        self.socket = tls_socket()
        self.client_ver = '1.0.0'
        self.server_host = ''
        self.server_port = -1

        self.ipsec_param = None
        self.ipsec_algo = None
        self.session_id = -1
        self.server_udp_port = -1
        self.ip_ipv4 = None
        self.gateway_ipv4 = None
        self.dns_ipv4 = []
        self.wins_ipv4 = None
        self.route_ipv4 = None

    def connect(self, host:str, port:int):
        self.server_host = socket.gethostbyname(host)
        self.server_port = port
        self.socket.connect((self.server_host, self.server_port))
        configure_tcp_keepalive(self.socket)

    def auth(self, username:str, password:str, host_id:str, host_name:str):
        m = Message(MessageType.AUTH)
        m.push_int(Payload.AUTH_TYPE, 2, 1) # Username + Password
        m.push_string(Payload.USERNAME, username)
        m.push_string(Payload.PASSWORD, password)
        m.push_string(Payload.CLIENT_VER, self.client_ver)
        m.push_string(Payload.HOST_ID, host_id)
        m.push_string(Payload.HOST_NAME, host_name)
        self.socket.send(m.finish())
        msg_id, res, _ = recv_message(self.socket)
        if res[Payload.STATUS] != b'\0\0\0\0':
            code = int.from_bytes(res[Payload.STATUS], byteorder='big')
            detail = _server_message(res)
            raise AuthError('%s (status=%d)%s'
                            % (auth_err_msg(code), code,
                               ': ' + detail if detail else ''))

    def client_info(self):
        client_ipv4, server_ipv4 = '127.0.0.1', self.server_host
        m = Message(MessageType.CLNT_INFO)
        m.push_ipv4(Payload.CLT_PUB_IPV4, client_ipv4)
        m.push_ipv4(Payload.SVR_PUB_IPV4, server_ipv4)
        self.socket.send(m.finish())
        msg_id, res, _ = recv_message(self.socket)
        if res[Payload.STATUS] != b'\0\0\0\0':
            raise ClientInfoError(_server_message(res) or 'client info rejected')

    def wait_network(self):
        while True:
            msg_id, res, _ = recv_message(self.socket)
            if msg_id == MessageType.NONE:
                continue
            if Payload.STATUS in res and res[Payload.STATUS] != b'\0\0\0\0':
                raise NetworkInfoError(_server_message(res) or 'network configuration rejected')
            elif msg_id == MessageType.SET_IP:
                network = ipaddress.IPv4Network((0, str(ipaddress.IPv4Address(res[Payload.NETMASK_IPV4]))))
                self.server_udp_port = int.from_bytes(res[Payload.SVR_UDP_PORT], byteorder='big')
                self.ip_ipv4 = ipaddress.IPv4Interface((res[Payload.CLT_PRIV_IPV4], network.prefixlen))
                self.gateway_ipv4 = ipaddress.IPv4Address(res[Payload.SVR_PRIV_IPV4])
                self.dns_ipv4 = []
                for i in range(0, len(res[Payload.DNS_IPV4]), 4):
                    self.dns_ipv4.append(ipaddress.IPv4Address(res[Payload.DNS_IPV4][i:i+4]))
                self.wins_ipv4 = res[Payload.WINS_IPV4]
            elif msg_id == MessageType.SET_ROUTE:
                self.route_ipv4 = res[Payload.ROUTE_IPV4]
            elif msg_id == MessageType.KEY_DONE:
                break

    def new_key(self):
        from os import urandom
        key_material_size = 0x30
        key_material = urandom(key_material_size)
        inbound_spi = int.from_bytes(urandom(4), byteorder='big')
        inbound_cpi = int.from_bytes(urandom(2), byteorder='big')
        m = Message(MessageType.NEW_KEY)
        m.push_int(Payload.KEY_EXCH_MODE, 2, KeyExchangeMode.KEY_EXCH_PLAIN.value)
        m.push_bytes(Payload.KEYMAT, key_material)
        m.push_int(Payload.SPI, 4, inbound_spi)
        m.push_int(Payload.IPCOMP_CPI, 2, inbound_cpi)
        self.socket.send(m.finish())
        msg_id, res, _ = recv_message(self.socket)
        if res[Payload.STATUS] != b'\0\0\0\0':
            raise NewKeyError(_server_message(res) or 'key exchange rejected')
        if res[Payload.IPCOMP_ALG] != b'\0\0':
            raise NotSupported('gateway requested IP compression, not implemented')
        enc_alg = int.from_bytes(res[Payload.ENC_ALG], byteorder='big')
        auth_alg = int.from_bytes(res[Payload.AUTH_ALG], byteorder='big')
        self.ipsec_algo = IPSEC_ALGOS.get((enc_alg, auth_alg))
        if self.ipsec_algo is None:
            raise NotSupported('gateway negotiated ENC_ALG=%d AUTH_ALG=%d, '
                               'which is not in IPSEC_ALGOS' % (enc_alg, auth_alg))
        outbound_spi = int.from_bytes(res[Payload.SPI], byteorder='big')
        # outbound_cpi = int.from_bytes(res[Payload.IPCOMP_CPI], byteorder='big')
        self.ipsec_param = IPSecParameters(inbound_spi, outbound_spi, key_material,
                                           auth_size=self.ipsec_algo.auth_size,
                                           crypt_size=self.ipsec_algo.crypt_size,
                                           iv_size=self.ipsec_algo.iv_size)
        self.session_id = res[Payload.SESSION_ID]

    def logout(self):
        m = Message(MessageType.CLNT_LOGOUT)
        m.push_int(Payload.DISCONNECT, 2, 0)
        self.socket.send(m.finish())

def auth_err_msg(errcode:int)->str:
    cases = {
        1: 'wrong_username_password',
        3: 'wrong_username_password',
        5: 'require_certificate',
        6: 'wrong_hardware_id',
        16: 'require_sms',
        21: 'wrong_phone_number'
    }
    if errcode not in cases:
        return 'auth error ' + str(errcode)
    return cases[errcode]
