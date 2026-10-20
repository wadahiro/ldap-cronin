#!/bin/bash
# Sample data for E2E. Includes cases that tend to trip up cloning.
set -uo pipefail
: "${BASE_DN:?}" "${SAMBA_ADMIN_PASSWORD:?}"
LDAP_ARGS=(-x -H ldap://127.0.0.1 -D "CN=Administrator,CN=Users,$BASE_DN" -w "$SAMBA_ADMIN_PASSWORD")
PW="${SEED_USER_PASSWORD:-Passw0rd!}"

ldapadd "${LDAP_ARGS[@]}" -c >/dev/null 2>&1 <<LDIF
dn: OU=IDM,$BASE_DN
objectClass: organizationalUnit
description: root of sample data

dn: OU=Users,OU=IDM,$BASE_DN
objectClass: organizationalUnit

dn: OU=Tokyo,OU=Users,OU=IDM,$BASE_DN
objectClass: organizationalUnit
l: Tokyo

dn: OU=営業部,OU=Users,OU=IDM,$BASE_DN
objectClass: organizationalUnit

dn: CN=Staff,OU=Users,OU=IDM,$BASE_DN
objectClass: container

dn: OU=Groups,OU=IDM,$BASE_DN
objectClass: organizationalUnit

dn: CN=Alice Admin,OU=Tokyo,OU=Users,OU=IDM,$BASE_DN
objectClass: user
sAMAccountName: alice
userPrincipalName: alice@${SAMBA_REALM,,}
givenName: Alice
sn: Admin
displayName: Alice Admin
mail: alice@example.com
telephoneNumber: 03-1234-5678
title: Manager
department: IT
carLicense: ALICE-001

dn: CN=Bob Staff,OU=Tokyo,OU=Users,OU=IDM,$BASE_DN
objectClass: user
sAMAccountName: bob
userPrincipalName: bob@${SAMBA_REALM,,}
givenName: Bob
sn: Staff
mail: bob@example.com
manager: CN=Alice Admin,OU=Tokyo,OU=Users,OU=IDM,$BASE_DN

dn: CN=Doe\, John,OU=営業部,OU=Users,OU=IDM,$BASE_DN
objectClass: user
sAMAccountName: jdoe
givenName: John
sn: Doe
mail: john.doe@example.com

dn: CN=山田 太郎,OU=営業部,OU=Users,OU=IDM,$BASE_DN
objectClass: user
sAMAccountName: yamada
givenName: 太郎
sn: 山田
displayName: 山田 太郎
mail: yamada@example.com

dn: CN=Carol Disabled,CN=Staff,OU=Users,OU=IDM,$BASE_DN
objectClass: user
sAMAccountName: carol
givenName: Carol

dn: CN=Dave NoExpire,CN=Staff,OU=Users,OU=IDM,$BASE_DN
objectClass: user
sAMAccountName: dave
givenName: Dave

dn: CN=Eng,OU=Groups,OU=IDM,$BASE_DN
objectClass: group
sAMAccountName: Eng
groupType: -2147483646
description: Engineering

dn: CN=AllStaff,OU=Groups,OU=IDM,$BASE_DN
objectClass: group
sAMAccountName: AllStaff
groupType: -2147483646
LDIF

# Set the password first, then finalize the UAC (enabled=512 / disabled=514 / never expires=66048)
set_uac() { # dn uac
  ldapmodify "${LDAP_ARGS[@]}" >/dev/null <<LDIF
dn: $1
changetype: modify
replace: userAccountControl
userAccountControl: $2
LDIF
}
for sam in alice bob jdoe yamada carol dave; do
  samba-tool user setpassword "$sam" --newpassword="$PW" >/dev/null 2>&1
done
set_uac "CN=Alice Admin,OU=Tokyo,OU=Users,OU=IDM,$BASE_DN" 512
set_uac "CN=Bob Staff,OU=Tokyo,OU=Users,OU=IDM,$BASE_DN" 512
set_uac "CN=Doe\\, John,OU=営業部,OU=Users,OU=IDM,$BASE_DN" 512
set_uac "CN=山田 太郎,OU=営業部,OU=Users,OU=IDM,$BASE_DN" 512
set_uac "CN=Carol Disabled,CN=Staff,OU=Users,OU=IDM,$BASE_DN" 514
set_uac "CN=Dave NoExpire,CN=Staff,OU=Users,OU=IDM,$BASE_DN" 66048

# An attribute that is not a link attribute but holds a DN as its value (seeAlso). Used to check that it is applied regardless of creation order
ldapmodify "${LDAP_ARGS[@]}" >/dev/null <<LDIF
dn: CN=Alice Admin,OU=Tokyo,OU=Users,OU=IDM,$BASE_DN
changetype: modify
add: seeAlso
seeAlso: CN=Bob Staff,OU=Tokyo,OU=Users,OU=IDM,$BASE_DN
seeAlso: CN=Eng,OU=Groups,OU=IDM,$BASE_DN
LDIF

# Membership: nested groups / members outside the scope (built-in)
ldapmodify "${LDAP_ARGS[@]}" >/dev/null <<LDIF
dn: CN=Eng,OU=Groups,OU=IDM,$BASE_DN
changetype: modify
add: member
member: CN=Alice Admin,OU=Tokyo,OU=Users,OU=IDM,$BASE_DN
member: CN=Doe\\, John,OU=営業部,OU=Users,OU=IDM,$BASE_DN
member: CN=山田 太郎,OU=営業部,OU=Users,OU=IDM,$BASE_DN

dn: CN=AllStaff,OU=Groups,OU=IDM,$BASE_DN
changetype: modify
add: member
member: CN=Eng,OU=Groups,OU=IDM,$BASE_DN
member: CN=Bob Staff,OU=Tokyo,OU=Users,OU=IDM,$BASE_DN
member: CN=Carol Disabled,CN=Staff,OU=Users,OU=IDM,$BASE_DN
member: CN=Domain Admins,CN=Users,$BASE_DN
LDIF
