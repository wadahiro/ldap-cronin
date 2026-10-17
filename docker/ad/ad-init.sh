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

# Index adminDisplayName, where ldap-cronin writes its markers, so diff finds a renamed or moved object without
# reading the whole directory. It runs before any data is loaded and on every start (a lab created before this was
# added gets it at its next start): Samba does not index values written before the index existed until a reindex,
# and markers are always written after this point.
MARKER_SCHEMA="CN=Admin-Display-Name,CN=Schema,CN=Configuration,$BASE_DN"
flags=$(ldapsearch "${LDAP_ARGS[@]}" -LLL -b "$MARKER_SCHEMA" -s base searchFlags 2>/dev/null | awk '/^searchFlags:/{print $2}')
if [ $(( ${flags:-0} & 1 )) -eq 0 ]; then
  printf 'dn: %s\nchangetype: modify\nreplace: searchFlags\nsearchFlags: %d\n' "$MARKER_SCHEMA" $(( ${flags:-0} | 1 )) |
    ldapmodify "${LDAP_ARGS[@]}" >/tmp/marker-index.log 2>&1 || echo "could not index adminDisplayName (see /tmp/marker-index.log)" >&2
fi

if [ "${SEED_SAMPLE_DATA:-false}" = "true" ]; then
  BASE_DN="$BASE_DN" LDAP_ARGS_STR="${LDAP_ARGS[*]}" /seed.sh
fi

touch /tmp/ad-ready
