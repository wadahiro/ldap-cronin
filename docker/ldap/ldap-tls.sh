#!/bin/bash
# ldap-tls.sh NAME...: the LDAPS certificate names the host, localhost and each NAME (its subject the first NAME),
# so a client that verifies it may connect by one of them. The certificate lives in the data volume, with the names
# it was made for, so snapshots carry it; the same names again change nothing. slapd takes the new one without a
# restart, once cn=config says where it is again.
set -euo pipefail

TLS=/var/lib/ldap/tls
names=("$(hostname)" localhost)
for n in "$@"; do
  if ! [[ "$n" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
    echo "not a DNS name: $n" >&2
    exit 2
  fi
  names+=("$n")
done
# Each name once, in order.
mapfile -t names < <(printf '%s\n' "${names[@]}" | awk '!seen[tolower($0)]++')
want="${names[*]}"
if [ -s "$TLS/names" ] && [ "$(cat "$TLS/names")" = "$want" ]; then
  echo "the LDAPS certificate names: $want (unchanged)"
  exit 0
fi

subject="${names[0]}"
[ $# -gt 0 ] && subject="$1"
san=$(printf 'DNS:%s,' "${names[@]}")
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$subject" -addext "subjectAltName=${san%,}" \
  -keyout "$TLS/key.new" -out "$TLS/cert.new" 2>/dev/null
chown openldap:openldap "$TLS/key.new" "$TLS/cert.new"
chmod 600 "$TLS/key.new"
mv "$TLS/key.new" "$TLS/key.pem"
mv "$TLS/cert.new" "$TLS/cert.pem"
echo "$want" > "$TLS/names"
ldapmodify -Q -Y EXTERNAL -H ldapi:/// >/dev/null <<LDIF
dn: cn=config
changetype: modify
replace: olcTLSCertificateFile
olcTLSCertificateFile: $TLS/cert.pem
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: $TLS/key.pem
-
LDIF
echo "the LDAPS certificate names: $want"
