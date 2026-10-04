"""Compat shim for running hilldust on Python 3.12+ / OpenSSL 3.

Two problems it solves:

1. hillstone.py calls ``ssl.wrap_socket()``, which was removed in Python 3.12
   (Debian 13 ships Python 3.13). We re-add it backed by a modern SSLContext.

2. The Hillstone gateway speaks legacy TLS1.0/1.1 with 3DES/SHA1 ciphers.
   OpenSSL 3 disables those at the default security level, so we drop to
   SECLEVEL=0 for this context only.

Auto-imported by CPython at startup because PYTHONPATH=/opt/shim.
Upstream hilldust source is deliberately left unmodified.
"""

import os
import ssl

_ORIG_WRAP = getattr(ssl, "wrap_socket", None)


def _wrap_socket(
    sock,
    keyfile=None,
    certfile=None,
    server_side=False,
    cert_reqs=ssl.CERT_NONE,
    ssl_version=None,
    ca_certs=None,
    do_handshake_on_connect=True,
    suppress_ragged_eofs=True,
    ciphers=None,
    server_hostname=None,
):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # order matters: must clear check_hostname before relaxing verify_mode
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError:
            pass
    else:
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass

    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    try:
        ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    except (ValueError, AttributeError):
        pass

    # Some Hillstone gateways require SNI; hilldust never passes one.
    if server_hostname is None:
        server_hostname = os.environ.get("HILLSTONE_SNI") or None

    return ctx.wrap_socket(
        sock,
        server_side=server_side,
        server_hostname=server_hostname,
        do_handshake_on_connect=do_handshake_on_connect,
        suppress_ragged_eofs=suppress_ragged_eofs,
    )


if _ORIG_WRAP is None:
    ssl.wrap_socket = _wrap_socket
