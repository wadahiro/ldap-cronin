#!/bin/bash
set -euo pipefail

# The directory is created on the first start from LDAP_SUFFIX (e.g. dc=example,dc=org) and LDAP_ADMIN_PASSWORD.
# The rootdn cn=admin,<suffix> may use the relax control, so ldap-cronin can keep the source's entryUUID.
: "${LDAP_SUFFIX:?LDAP_SUFFIX is required (e.g. dc=example,dc=org)}" "${LDAP_ADMIN_PASSWORD:?}"
LDAP_OVERLAYS="${LDAP_OVERLAYS-memberof refint}"
CONF=/etc/ldap/slapd.d
DATA=/var/lib/ldap
CREATED=$DATA/.created
export LDAP_SUFFIX

# An existing volume of another suffix would start with a configuration that no longer matches what was asked.
if [ -s "$CREATED" ] && [ "$(cat "$CREATED")" != "$LDAP_SUFFIX" ]; then
  echo "volume was created for suffix '$(cat "$CREATED")' but LDAP_SUFFIX is '$LDAP_SUFFIX'." >&2
  echo "to recreate the directory, delete its data volumes first (lab reset)" >&2
  exit 1
fi

mkdir -p /run/slapd "$DATA/data" "$DATA/tls"
if [ ! -f "$CREATED" ]; then
  rm -rf "${CONF:?}"/* "$DATA/data"/*
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$(hostname)" \
    -keyout "$DATA/tls/key.pem" -out "$DATA/tls/cert.pem" 2>/dev/null
  hash=$(slappasswd -s "$LDAP_ADMIN_PASSWORD")
  modules="" overlays="" n=0
  for o in $LDAP_OVERLAYS; do
    modules+="olcModuleLoad: $o"$'\n'
    case "$o" in
      memberof) overlays+="
dn: olcOverlay={$n}memberof,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: {$n}memberof
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: groupOfNames
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf
" ;;
      refint) overlays+="
dn: olcOverlay={$n}refint,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcRefintConfig
olcOverlay: {$n}refint
olcRefintAttribute: member
olcRefintAttribute: uniqueMember
olcRefintAttribute: owner
olcRefintAttribute: manager
olcRefintAttribute: secretary
olcRefintAttribute: seeAlso
" ;;
      *) echo "unknown overlay in LDAP_OVERLAYS: $o (memberof, refint; add others with an LDIF in /schema.d)" >&2; exit 1 ;;
    esac
    n=$((n + 1))
  done
  # 8 GiB is only the upper bound of the memory map: the data file grows as it is used.
  slapadd -n 0 -F "$CONF" <<LDIF
dn: cn=config
objectClass: olcGlobal
cn: config
olcPidFile: /run/slapd/slapd.pid
olcArgsFile: /run/slapd/slapd.args
olcTLSCertificateFile: $DATA/tls/cert.pem
olcTLSCertificateKeyFile: $DATA/tls/key.pem

dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib/ldap
olcModuleLoad: back_mdb
$modules
dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

include: file:///etc/ldap/schema/core.ldif

include: file:///etc/ldap/schema/cosine.ldif

include: file:///etc/ldap/schema/nis.ldif

include: file:///etc/ldap/schema/inetorgperson.ldif

dn: olcDatabase={-1}frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: {-1}frontend
olcSizeLimit: unlimited

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {1}mdb
olcDbDirectory: $DATA/data
olcDbMaxSize: 8589934592
olcSuffix: $LDAP_SUFFIX
olcRootDN: cn=admin,$LDAP_SUFFIX
olcRootPW: $hash
olcLastMod: TRUE
olcDbIndex: objectClass eq
olcDbIndex: entryUUID eq
olcDbIndex: cn,uid eq
olcDbIndex: member,uniqueMember eq
olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break
olcAccess: {1}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {2}to * by users read by * none
$overlays
LDIF
  chown -R openldap:openldap "$CONF" "$DATA" /run/slapd
  chmod 600 "$DATA/tls/key.pem"
fi
chown -R openldap:openldap /run/slapd

# A leftover ready marker from the previous run would make the container healthy before slapd is up.
rm -f /tmp/ldap-ready

/ldap-init.sh &
exec slapd -h "ldap:/// ldaps:/// ldapi:///" -u openldap -g openldap -F "$CONF" -d 0
