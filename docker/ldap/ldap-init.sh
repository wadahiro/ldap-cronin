#!/bin/bash
# Initialization after slapd starts: on the first start, the suffix entry and the LDIFs in /schema.d; the sample
# data when SEED_SAMPLE_DATA=true. Then the ready marker for the health check.
set -uo pipefail

CREATED=/var/lib/ldap/.created
ADMIN=(-x -H ldap://127.0.0.1 -D "cn=admin,$LDAP_SUFFIX" -w "$LDAP_ADMIN_PASSWORD")
EXTERNAL=(-Q -Y EXTERNAL -H ldapi:///)

until ldapsearch "${EXTERNAL[@]}" -b cn=config -s base dn >/dev/null 2>&1; do sleep 0.5; done

if [ ! -f "$CREATED" ]; then
  # Schemas and configuration changes of the deployment (olcSchemaConfig entries, changetype: modify on cn=config),
  # in name order. -a: an entry without changetype is an add.
  for f in /schema.d/*.ldif; do
    [ -e "$f" ] || continue
    if ! ldapmodify "${EXTERNAL[@]}" -a -f "$f" >"/tmp/schema-$(basename "$f").log" 2>&1; then
      echo "failed to apply $f:" >&2
      cat "/tmp/schema-$(basename "$f").log" >&2
      kill 1
      exit 1
    fi
  done
  # The suffix entry: dc=... is a dcObject organization, o=... an organization, anything else an organizationalUnit.
  rdn=${LDAP_SUFFIX%%,*}
  attr=${rdn%%=*} value=${rdn#*=}
  case "${attr,,}" in
    dc) entry="objectClass: dcObject
objectClass: organization
dc: $value
o: $value" ;;
    o) entry="objectClass: organization
o: $value" ;;
    ou) entry="objectClass: organizationalUnit
ou: $value" ;;
    *) echo "unsupported suffix $LDAP_SUFFIX (the first RDN must be dc=, o= or ou=)" >&2; kill 1; exit 1 ;;
  esac
  printf 'dn: %s\n%s\n' "$LDAP_SUFFIX" "$entry" | ldapadd "${ADMIN[@]}" >/tmp/suffix.log 2>&1 || {
    cat /tmp/suffix.log >&2; kill 1; exit 1; }
  if [ "${SEED_SAMPLE_DATA:-false}" = "true" ]; then
    sed "s/@SUFFIX@/$LDAP_SUFFIX/g" /seed.ldif | ldapadd "${ADMIN[@]}" -c >/tmp/seed.log 2>&1 || {
      cat /tmp/seed.log >&2; kill 1; exit 1; }
  fi
  echo "$LDAP_SUFFIX" > "$CREATED"
fi

until ldapsearch "${ADMIN[@]}" -b "$LDAP_SUFFIX" -s base dn >/dev/null 2>&1; do sleep 0.5; done
touch /tmp/ldap-ready
