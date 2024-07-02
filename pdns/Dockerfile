# Move to a pinned latest pdns 4.5 is available
FROM ubuntu:22.04

RUN apt update && \
    apt install -y --no-install-recommends pdns-server pdns-backend-pgsql \
      python3 python3-pip python3-full pipx \
      postgresql-client \
      dnsutils curl vim wget iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Use envtpl to build the pdns.conf from template (at container start)
RUN pipx install envtpl

COPY docker-entrypoint.sh /
COPY pdns.conf.tpl /etc/powerdns/pdns.conf.tpl

EXPOSE 53 53/udp 8081 8081/tcp

ENTRYPOINT [ "/docker-entrypoint.sh" ]
CMD /usr/sbin/pdns_server
