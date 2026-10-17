#!/bin/bash
set -euo pipefail

# Only the domain name is specified, via AD_REALM (e.g. ad.example.com).
# The Kerberos realm, NetBIOS domain name and BASE_DN are all derived from it.
: "${AD_REALM:?AD_REALM is required (e.g. ad.example.com)}" "${SAMBA_ADMIN_PASSWORD:?}"
SAMBA_REALM="${AD_REALM^^}"
SAMBA_DOMAIN="${SAMBA_DOMAIN:-${SAMBA_REALM%%.*}}"
if [ "${#SAMBA_DOMAIN}" -gt 15 ]; then
  echo "NetBIOS domain name '$SAMBA_DOMAIN' exceeds 15 chars; set SAMBA_DOMAIN explicitly" >&2
  exit 1
fi
export SAMBA_REALM SAMBA_DOMAIN
PROVISIONED=/var/lib/samba/private/.provisioned

# If AD_REALM is changed on an already-provisioned volume, the domain stays the same while only the bind DN
# in ad-init.sh no longer matches, and startup fails with no obvious cause. Fail early and explicitly instead.
if [ -s "$PROVISIONED" ] && [ "$(cat "$PROVISIONED")" != "$SAMBA_REALM" ]; then
  echo "volume was provisioned for realm '$(cat "$PROVISIONED")' but AD_REALM is '$SAMBA_REALM'." >&2
  echo "to recreate the domain, delete its data volumes first:" >&2
  echo "  offline package : ./setup.sh reset" >&2
  echo "  this repository : docker compose down -v" >&2
  exit 1
fi

if [ ! -f "$PROVISIONED" ]; then
  rm -f /etc/samba/smb.conf
  # To align the SID and GUID with the source domain (lab up --like-source), pass them as environment variables.
  # They are only honored at creation time (the SID and GUID of an existing domain cannot be changed later).
  identity=()
  [ -z "${SAMBA_DOMAIN_SID:-}" ] || identity+=(--domain-sid="$SAMBA_DOMAIN_SID")
  [ -z "${SAMBA_DOMAIN_GUID:-}" ] || identity+=(--domain-guid="$SAMBA_DOMAIN_GUID")
  # Provisioning writes NT ACLs on sysvol as the security.NTACL xattr, which needs CAP_SYS_ADMIN in the initial
  # user namespace. Rootless docker grants it only inside its own namespace, so the write is refused and
  # provisioning fails. There, acl_xattr keeps the ACL under user.NTACL instead, which the file owner may write.
  # That is weaker (any process running as the owner could change an ACL), which does not matter for a disposable
  # lab. The tdb backend (--use-xattrs=no) was rejected: this Samba build offers it only with the NTVFS file server.
  # Probing rather than always switching keeps the usual rootful setup on Samba's default.
  acl_store=()
  if ! python3 -c 'import os, sys
os.setxattr(sys.argv[1], "security.ldapcronin-probe", b"1")
os.removexattr(sys.argv[1], "security.ldapcronin-probe")' /var/lib/samba 2>/dev/null; then
    echo "security xattrs are not writable here (rootless docker?); keeping NT ACLs in user.NTACL" >&2
    acl_store=(--option="acl_xattr:security_acl_name=user.NTACL")
  fi
  samba-tool domain provision \
    --use-rfc2307 \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --realm="$SAMBA_REALM" \
    --domain="$SAMBA_DOMAIN" \
    --adminpass="$SAMBA_ADMIN_PASSWORD" \
    ${acl_store[@]+"${acl_store[@]}"} \
    ${identity[@]+"${identity[@]}"}
  cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
  # Allow plain-text LDAP simple bind (writing passwords requires LDAPS)
  sed -i '/^\[global\]/a \\tldap server require strong auth = no' /etc/samba/smb.conf
  # Relax the password policy so that fixed passwords can be loaded
  samba-tool domain passwordsettings set --complexity=off --min-pwd-length=1 --min-pwd-age=0 --history-length=0
  echo "$SAMBA_REALM" > "$PROVISIONED"
fi

# Even on docker stop -> start or a snapshot restore, a leftover startup-complete marker from the previous run
# would make the container healthy before Samba is up. Remove it on every start.
rm -f /tmp/ad-ready

# Allow schema updates over LDAP so the Exchange-compatible extended schema can be loaded (also applied to existing volumes)
grep -q 'dsdb:schema update allowed' /etc/samba/smb.conf || \
  sed -i '/^\[global\]/a \\tdsdb:schema update allowed = yes' /etc/samba/smb.conf

/ad-init.sh &
exec samba -i
