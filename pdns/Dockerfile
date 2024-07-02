# /!\ Warning!
# Confirm pdns version. Does it require migrations?
# See: https://github.com/PowerDNS/pdns/blob/master/modules/gpgsqlbackend/4.3.0_to_4.7.0_schema.pgsql.sql
# See: https://doc.powerdns.com/authoritative/upgrading.html
FROM ubuntu:24.04
# /!\ Warning!


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
