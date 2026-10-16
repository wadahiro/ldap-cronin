FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      samba samba-ad-provision samba-ad-dc samba-dsdb-modules samba-vfs-modules winbind krb5-user \
      ldb-tools ldap-utils dnsutils pwgen tini \
 && apt-get clean

COPY entrypoint.sh ad-init.sh seed.sh /
COPY schema /schema
RUN chmod +x /entrypoint.sh /ad-init.sh /seed.sh

EXPOSE 53 88 389 445 464 636 3268
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
