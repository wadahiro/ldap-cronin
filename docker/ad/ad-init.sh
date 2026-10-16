#!/bin/bash
# Initialization after Samba starts. Loads sample data for E2E only when SEED_SAMPLE_DATA=true. Idempotent.
set -uo pipefail

BASE_DN=$(echo "$SAMBA_REALM" | awk -F. '{for(i=1;i<=NF;i++){printf "%sDC=%s",(i>1?",":""),tolower($i)}}')
LDAP_ARGS=(-x -H ldap://127.0.0.1 -D "CN=Administrator,CN=Users,$BASE_DN" -w "$SAMBA_ADMIN_PASSWORD")

until ldapsearch "${LDAP_ARGS[@]}" -b "$BASE_DN" -s base dn >/dev/null 2>&1; do sleep 1; done

# Load the Exchange-compatible extended schema (extensionAttribute1-15, msExch*, etc.) into every instance.
# -c: continue past errors for existing schema (e.g. attributes Samba already defines).
for f in schema-attributes schema-objectclass; do
  sed "s/@BASE_DN@/$BASE_DN/g" "/schema/$f.ldif" | ldapmodify "${LDAP_ARGS[@]}" -c >"/tmp/$f.log" 2>&1
done

if [ "${SEED_SAMPLE_DATA:-false}" = "true" ]; then
  BASE_DN="$BASE_DN" LDAP_ARGS_STR="${LDAP_ARGS[*]}" /seed.sh
fi

touch /tmp/ad-ready
