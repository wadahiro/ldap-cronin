FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      samba samba-ad-provision samba-ad-dc samba-dsdb-modules samba-vfs-modules winbind krb5-user \
      ldb-tools ldap-utils dnsutils pwgen tini \
 && apt-get clean

COPY entrypoint.sh ad-init.sh seed.sh exchange-schema.py /
RUN chmod +x /entrypoint.sh /ad-init.sh /seed.sh
# Exchange's schema files when the image is built with them (make image EXCHANGE_ISO=...); otherwise only the
# .gitignore. An image with them must not be published: they are Microsoft's, from its setup image.
COPY exchange/ /exchange/

EXPOSE 53 88 389 445 464 636 3268
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
