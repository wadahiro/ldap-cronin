FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
# The package's own configuration (created by its postinst for dc=nodomain) is removed: entrypoint.sh creates the
# directory from LDAP_SUFFIX on the first start, as Samba's provisioning does.
RUN apt-get update \
 && apt-get install -y --no-install-recommends slapd ldap-utils openssl ca-certificates tini \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*

COPY entrypoint.sh ldap-init.sh seed.ldif /
COPY schema.d /schema.d
RUN chmod +x /entrypoint.sh /ldap-init.sh

EXPOSE 389 636
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
