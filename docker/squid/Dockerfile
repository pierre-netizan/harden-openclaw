FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        squid \
        apache2-utils \
        && rm -rf /var/lib/apt/lists/*

COPY http/squid.conf /etc/squid/squid.conf

RUN mkdir -p /var/log/squid /var/cache/squid && \
    chown -R proxy:proxy /var/log/squid /var/cache/squid

EXPOSE 3128

CMD ["squid", "-N", "-d", "1"]
