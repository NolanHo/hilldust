FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 \
      python3-cryptography \
      iproute2 \
      microsocks \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY hillstone.py esp.py platform_linux.py tunnel.py hilldust.py selftest.py /opt/hilldust/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /opt/hilldust/hilldust.py /usr/local/bin/entrypoint.sh

ENV PYTHONUNBUFFERED=1 \
    SOCKS_PORT=1080

EXPOSE 1080/tcp

# The ESP wire format is frozen by selftest.py; fail the build rather than
# ship something that cannot talk to the gateway.
RUN cd /opt/hilldust && python3 selftest.py

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
