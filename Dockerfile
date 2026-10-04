FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 \
      python3-scapy \
      python3-cryptography \
      iproute2 \
      microsocks \
      ca-certificates \
      patch \
 && rm -rf /var/lib/apt/lists/*

# Upstream sources, kept byte-identical to the tree on disk.
COPY hillstone.py impl_scapy.py platform_linux.py hilldust.py /opt/hilldust/

# Local delta, applied at build time so /opt/hilldust stays auditable.
COPY patches/ /tmp/patches/
RUN cd /opt/hilldust \
 && patch -p1 --batch --forward < /tmp/patches/0001-support-aes128-cbc-hmac-md5-96.patch \
 && rm -rf /tmp/patches

# Compat shim: re-adds ssl.wrap_socket(), removed in Python 3.12.
# Injected via PYTHONPATH; upstream sources are never touched.
COPY shim/sitecustomize.py /opt/shim/sitecustomize.py

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh /opt/hilldust/hilldust.py

ENV PYTHONPATH=/opt/shim \
    PYTHONUNBUFFERED=1 \
    SOCKS_PORT=1080

EXPOSE 1080/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
