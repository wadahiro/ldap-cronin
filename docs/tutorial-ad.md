# Tutorial: clone an Active Directory into a Samba4 lab, and into a test AD

This walks through a complete run against an AD source: one configuration file, a clone into the Samba4 lab
(with snapshots, so every test starts from the same data), and then the same clone into a real AD test domain.
The reference for each step is in [active-directory.md](active-directory.md), [lab.md](lab.md) and
[diff.md](diff.md).

Throughout, the source domain is `ad.example.com` (`DC=ad,DC=example,DC=com`) and the part to clone is
`OU=IDM,DC=ad,DC=example,DC=com`. Replace them with yours.

## What you need

- Go (to build the tool) and docker (for the lab).
- Network access to the source DC over LDAPS (636), and an account that can **read** everything under `base_dn`
  (a normal domain user can read most attributes; Domain Admins also sees the ones a delegation hides).
- For part 2, a test AD domain **with the same domain name** as the source (see below).

**The target must have the same domain name as the source.** `clone` writes every object at its source DN, and
references (`member`, `manager`) name source DNs, so the target's naming context must be `DC=ad,DC=example,DC=com`
too. The lab takes care of this (`--like-source`); a real AD target is an isolated test forest built with the
production domain name, never a domain that trusts or replicates with production.

## 1. Build the tool and the lab image

```sh
git clone https://github.com/wadahiro/ldap-cronin && cd ldap-cronin
make build                                    # bin/ldap-cronin
make image IMAGE_TAG=local                    # the Samba4 AD and OpenLDAP lab images
# on an ARM machine (Apple silicon): make image IMAGE_TAG=local PLATFORM=linux/arm64
```

For a machine without internet access, build the offline package instead (`make bundle`, see
[lab.md](lab.md#using-the-offline-package)); `setup.sh` in it then takes the place of `ldap-cronin lab`.

## 2. Write the configuration

Save this as `config.toml`. It is complete: every section the tool reads is here, with the defaults written out
where they matter. **Passwords never go in this file**: they are asked for at run time, or taken from
`LDAP_CRONIN_SOURCE_PASSWORD`, `LDAP_CRONIN_TARGET_PASSWORD` and `LDAP_CRONIN_USER_PASSWORD`.

```toml
[source]                                    # production (read only: the tool never writes to it)
url = "ldaps://dc01.ad.example.com:636"
bind_dn = "CN=svc-ldap-cronin,OU=Service Accounts,DC=ad,DC=example,DC=com"
ca_file = "corp-root-ca.pem"                # the CA that issued the DC certificate
timeout = "2m"                              # per LDAP operation

[target]                                    # the Samba4 lab (part 1); part 2 replaces this section
url = "ldaps://localhost:12636"
bind_dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
insecure_skip_verify = true                 # the lab's certificate is self-signed

[scope]
profile = "ad"                              # auto would ask the source; ad says it outright
base_dn = "OU=IDM,DC=ad,DC=example,DC=com"  # not the domain root: that would reach the built-in accounts
# objects = ["ou", "group", "user", "computer", "contact"]   # the default: every kind
references = "clone"                        # the default: a member outside base_dn is cloned too, so every
                                            # member is on the target and diff sees any change to it

# [scope.filters]                           # narrow a kind if you need to
# user = "(&(objectCategory=person)(objectClass=user)(!(employeeType=external)))"

[run]
workers = 8                                 # parallel connections to the target

[mapping]
mode = "auto"                               # on AD: a marker of the source object in adminDisplayName, so diff
attribute = "adminDisplayName"              # tells a renamed or recreated object from the cloned one

[attributes]
# The defaults (ldap-cronin list-attrs -profile ad) are the attributes Samba4 has out of the box. Add the ones
# your applications read; anything not listed is neither copied nor compared.
extra_include = ["extensionAttribute1", "extensionAttribute2"]
exclude = ["homeDirectory", "homeDrive", "profilePath", "scriptPath"]   # file server paths of production

[mask]
# Replaced with a fixed string on the target, and not compared by diff.
value = "********"
attributes = ["mail", "telephoneNumber", "mobile", "homePhone"]
```

Notes on the choices:

- `[mapping] mode = "auto"` writes `ldap-cronin:<source root>:<source key>` into `adminDisplayName` of every
  cloned object. Pick another attribute if your applications use that one; it must be a single-valued string
  attribute that is not in the allow lists.
- Masked attributes must be plain strings: `member`, `sAMAccountName`, `userPrincipalName` and the like cannot be
  masked (a fixed string would break them).
- `extensionAttribute1` and the like exist only with the Exchange schema. The lab has it; a target without it
  refuses those values.

## 3. Look before writing

```sh
./bin/ldap-cronin list-attrs -config config.toml             # what the source's entries hold, and what clone copies
./bin/ldap-cronin clone -config config.toml -dry-run > clone.ldif
```

`list-attrs -config` reads the entries under `base_dn` (no values are printed) and lists, per kind, each attribute
with the number of entries holding it:

```
[user] 1150 entries under OU=IDM,DC=ad,DC=example,DC=com
  not copied  acmeEmployeeCode         1102
  not copied  extensionAttribute3       870
  copied      sAMAccountName           1150
  masked      mail                      980
  never       objectGUID               1150  managed by the server
  never       objectSid                1150  managed by the server
  (and 12 attributes of the allow list that no entry holds; -all lists them)
```

`not copied` is what the clone would leave behind: add the ones your applications read to `extra_include`. Run it
again with `-target` once the target exists, to see which of them its schema lacks (`clone` refuses to start in
that case, naming them). How to carry an attribute of your own over is in
[Attributes of your own](#attributes-of-your-own-schema-extensions).

The dry-run connects only to the source. `clone.ldif` is what `clone` would write, as LDIF; the progress and the
counts go to the terminal:

```
added=1234 updated=0 unchanged=0 warnings=2
referenced objects outside the scope cloned: 3
  user      2
  computer  1
not cloned (matches no kind): 14
  msFVE-RecoveryInformation  12
  serviceConnectionPoint      2
```

- **referenced objects outside the scope**: members that live outside `base_dn` (a user in `CN=Users`, a computer
  in `OU=Workstations`). They are cloned as their kind, without their own references.
- **not cloned**: entries under `base_dn` of no kind, such as BitLocker recovery information. They stay on
  production.
- **warnings** name each reference that cannot be reproduced (a principal of a trusted domain, a built-in the
  target lacks).
- The LDIF holds no password: the users' password steps are comments.

## Part 1: the Samba4 lab

### 4. Start a lab with the source's domain

```sh
export SAMBA_ADMIN_PASSWORD='Lab-Adm1n-Passw0rd!'            # the lab's Administrator; or let the lab generate one
./bin/ldap-cronin lab up --like-source config.toml --image ldap-cronin/samba-ad:local
```

`--like-source` reads the domain name, NetBIOS name, domain SID and GUID from `[source]` (it asks for the source
password) and creates the Samba domain with them. `--realm ad.example.com` would do for a plain clone; the same
SID and GUID also allow `clone -native` later. The domain is fixed when the lab is created; `lab reset` starts
over.

`lab up` ends with the connection details and the `[target]` section to use, which is the one already in
`config.toml` (LDAPS on port 12636; `--ldaps-port` changes it).

### 5. Clone

```sh
export LDAP_CRONIN_TARGET_PASSWORD="$SAMBA_ADMIN_PASSWORD"
./bin/ldap-cronin clone -config config.toml
```

It asks for the source password and the **fixed password for cloned users**: every cloned user (and computer)
gets it, since password hashes are never copied. It must satisfy the target's password policy (the lab's is
Samba's default complexity).

What it does, in order: the OUs and parents, then groups, users, computers and contacts (users and computers are
added disabled, given the password, then their source `userAccountControl`), then `member`, `manager` and the other
references. It prints each write (`add`, `update`) and the counts at the end.

A run can be stopped with Ctrl-C and started again: `clone` only adds what is missing and updates what differs,
and never deletes. A second run right after the first writes nothing.

### 6. Check the clone

```sh
./bin/ldap-cronin diff -config config.toml; echo "exit=$?"
```

Right after a clone it reports no differences (exit code 0). The summary says what the comparison covered:

```
--- summary ---
compared objects : ou=12 group=40 user=1150 computer=30 contact=2
differences:
  ONLY_SOURCE : 0   (only in source: not cloned yet)
  ONLY_TARGET : 0   (only in target: not in source)
  DIFF        : 0   (in both, but attribute values differ)
  RENAMED     : 0   (same object, but its DN differs on target: renamed/moved)
rename/move check: on (markers in adminDisplayName)
referenced objects outside the scope compared: 3 (without their own references)
not compared (matches no kind, so clone does not copy it): 14
  msFVE-RecoveryInformation  12
  serviceConnectionPoint      2
references not compared (clone cannot write them: the target lacks their entries): 2
  member  2
compared attributes:
  ...
not compared:
  masked (config [mask]):
    mail
    ...
```

`references not compared` are the values the warnings of `clone` named: diff leaves them out, and compares every
other member.

### 7. Save the state

```sh
./bin/ldap-cronin lab snapshot baseline --note "right after clone"
```

### 8. The test cycle

```sh
# ... the program under test changes the lab (ldaps://localhost:12636) ...
./bin/ldap-cronin diff -config config.toml       # what it changed; exit code 1 when anything did
./bin/ldap-cronin lab restore baseline           # back to the clone, in a few seconds
```

`diff` shows every member removed or added (whatever the member is), attribute changes, objects created or
deleted, and renames and moves (`RENAMED`, found through the markers). How to read each line is in
[diff.md](diff.md).

For a test that checks the result in code, `diff -format json` writes one JSON object per difference and a summary
line ([diff.md](diff.md#json-output--format-json)). For example, the members a program removed from or added to
groups:

```sh
./bin/ldap-cronin diff -config config.toml -format json \
  | jq -c 'select(.kind == "DIFF" and .attr == "member") | {dn, removed: .only_source, added: .only_target}'
```

To run two tests side by side, start a second lab from the snapshot on other ports:
`lab restore baseline --instance dev2` ([lab.md](lab.md#starting-another-lab-from-a-snapshot-on-a-different-port)).

When the source changes and you want fresh data: `lab restore baseline`, `clone` again (it brings the lab up to
date with the source), and `lab snapshot baseline --force`. Objects deleted on the source stay on the lab
(nothing is deleted); for an exact copy, `lab reset -y` and start again from step 4.

## Part 2: a real AD test domain

The same configuration works against a Windows AD; only `[target]` and a few preparations change. There are no
snapshots here: restoring a test domain is your backup's job, and `clone` never deletes anything.

### 9. Prepare the test domain

- **Same domain name** as the source (`ad.example.com`), isolated from production: no trust, no replication, its
  own DNS.
- **LDAPS** on its DCs: setting `unicodePwd` requires it, and the LDAP signing policy usually refuses a simple bind
  without it. Keep the CA certificate of the DC certificate for `ca_file`.
- **The password policy** must accept the fixed password, or users stay disabled without one.
- **An account for the tool** that can create and modify objects under `base_dn`, and the parents above it if
  they do not exist yet. Domain Admins works; a delegated account is not verified yet.
- **Index the marker attribute** (once, as a Schema Admin), so `diff` finds a moved object without reading the whole
  domain. Check the current `searchFlags` of the attribute and add bit 1 (here it was 0):

  ```sh
  ldapsearch -H ldaps://dc01.test.ad.example.com -D 'CN=Administrator,CN=Users,DC=ad,DC=example,DC=com' -W \
    -b 'CN=Admin-Display-Name,CN=Schema,CN=Configuration,DC=ad,DC=example,DC=com' -s base searchFlags
  cat > index.ldif <<'EOF'
  dn: CN=Admin-Display-Name,CN=Schema,CN=Configuration,DC=ad,DC=example,DC=com
  changetype: modify
  replace: searchFlags
  searchFlags: 1
  EOF
  ldapmodify -H ldaps://dc01.test.ad.example.com -D 'CN=Administrator,CN=Users,DC=ad,DC=example,DC=com' -W -f index.ldif
  ```

  Without it `clone` warns and still works.
- The schema extensions your allow lists need (the Exchange schema for `extensionAttribute1`).

### 10. Point the configuration at it

```toml
[target]
url = "ldaps://dc01.test.ad.example.com:636"     # one DC: writes then replicate to the others
bind_dn = "CN=svc-clone,OU=Service Accounts,DC=ad,DC=example,DC=com"
ca_file = "test-root-ca.pem"
timeout = "2m"

[run]
workers = 4                                       # a real DC also serves others; start low
```

### 11. Dry-run, clone, diff

```sh
./bin/ldap-cronin clone -config config.toml -dry-run > clone.ldif   # unchanged from step 3
./bin/ldap-cronin clone -config config.toml
./bin/ldap-cronin diff -config config.toml
```

Run it outside business hours: every object is several writes, replicated to every DC (the load per user is in
[operations.md](operations.md#load-on-the-target-ad-clone)). Then test as in step 8, with `diff` against the test
domain; to start a test over, re-run `clone`, which puts back what was changed (it does not remove what the
program added: `diff` lists those as `ONLY_TARGET`).

## Attributes of your own (schema extensions)

Production ADs often carry attributes of their own (an employee code, a cost center) or of a product. The tool
copies only what an allow list names, so these stay behind until you ask for them, and the target needs them in
its schema.

### Find them

```sh
./bin/ldap-cronin list-attrs -config config.toml
```

Every `not copied` line is an attribute your entries hold that the clone leaves behind, with the number of entries
holding it. `extensionAttribute1`-`15` and `msExch*` come from the Exchange schema, which the lab already has; any
other name is a schema extension to carry over.

### Read how production defines them

Give the target the same definitions as the source: the same names and OIDs, so values compare and a later schema
update of production applies to the lab too. Read them from the source's schema (here for `acmeEmployeeCode`):

```sh
SRC='ldaps://dc01.ad.example.com'; BIND='CN=svc-ldap-cronin,OU=Service Accounts,DC=ad,DC=example,DC=com'
SCHEMA='CN=Schema,CN=Configuration,DC=ad,DC=example,DC=com'
# the attribute
ldapsearch -H "$SRC" -D "$BIND" -W -b "$SCHEMA" '(lDAPDisplayName=acmeEmployeeCode)' \
  cn lDAPDisplayName attributeID attributeSyntax oMSyntax isSingleValued rangeLower rangeUpper searchFlags
# the class that allows it, and the classes that class is attached to
ldapsearch -H "$SRC" -D "$BIND" -W -b "$SCHEMA" '(&(objectClass=classSchema)(mayContain=acmeEmployeeCode))' \
  cn lDAPDisplayName governsID objectClassCategory subClassOf mayContain
ldapsearch -H "$SRC" -D "$BIND" -W -b "$SCHEMA" '(auxiliaryClass=acmePerson)' lDAPDisplayName
```

An attribute is usable only through a class that allows it (`mayContain`): usually an auxiliary class of your own
(`objectClassCategory: 3`) attached to `user` in the schema (`auxiliaryClass`), as below. Sometimes it is added to
`user` itself; then copy that instead.

### Add them to the lab

Write what you read as LDIF. Each part ends with `schemaUpdateNow`, so the next part sees it:

```ldif
dn: CN=acme-Employee-Code,CN=Schema,CN=Configuration,DC=ad,DC=example,DC=com
changetype: add
objectClass: attributeSchema
cn: acme-Employee-Code
lDAPDisplayName: acmeEmployeeCode
attributeID: 1.3.6.1.4.1.99999.1.1
attributeSyntax: 2.5.5.12
oMSyntax: 64
isSingleValued: TRUE

dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
-

dn: CN=acme-Person,CN=Schema,CN=Configuration,DC=ad,DC=example,DC=com
changetype: add
objectClass: classSchema
cn: acme-Person
lDAPDisplayName: acmePerson
governsID: 1.3.6.1.4.1.99999.2.1
objectClassCategory: 3
subClassOf: top
mayContain: acmeEmployeeCode

dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
-

dn: CN=User,CN=Schema,CN=Configuration,DC=ad,DC=example,DC=com
changetype: modify
add: auxiliaryClass
auxiliaryClass: acmePerson
-

dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
-
```

```sh
LDAPTLS_REQCERT=never ldapmodify -H ldaps://localhost:12636 -x \
  -D 'CN=Administrator,CN=Users,DC=ad,DC=example,DC=com' -W -f acme-schema.ldif
```

The lab accepts schema changes over LDAP. Do it **before the first `clone`**, then take the snapshot as usual: a
snapshot carries the schema, and every restore or second instance has it. Without `ldapmodify` on your machine, copy
the file into the lab container (`docker cp acme-schema.ldif ldap-cronin-ad:/tmp/`) and run `ldapmodify` there
against `ldaps://localhost`.

For a real AD test domain (part 2), the same LDIF goes in as a member of Schema Admins, on the schema master.
**A schema change cannot be undone in AD** (an attribute or class can only be made defunct), so add exactly what
production has, and nothing to try things out.

### Copy and compare them

```toml
[attributes]
extra_include = ["acmeEmployeeCode"]        # every kind; or [attributes.include] user = [...] for one kind
```

```sh
./bin/ldap-cronin list-attrs -config config.toml -target   # acmeEmployeeCode: copied, no "not in the target schema"
./bin/ldap-cronin clone -config config.toml
./bin/ldap-cronin diff -config config.toml                  # compares acmeEmployeeCode too
```

- If the target still lacks one, `clone` refuses to start and names it; nothing is written.
- An attribute that holds DNs (`attributeSyntax: 2.5.5.1`, a custom `sponsor`, say) is found in the source schema
  and handled as a reference: applied after every object exists, compared like `member`.
- Personal data in a string attribute can be masked (`[mask] attributes`); an attribute that must stay unique or
  that holds DNs cannot.
- An auxiliary class attached to single objects (not to `user` in the schema) shows in their `objectClass`, which
  `clone` always copies: the target needs that class even when none of its attributes is in an allow list.

## When something goes wrong

| Message | What to do |
|---|---|
| `set password (LDAPS is required; ...)` | Use `ldaps://` (or `start_tls = true`) for the target, and a fixed password the target's policy accepts. Re-run `clone`: it sets the password of the users created without one |
| `the target schema lacks attributes that the source defines and the allow lists name: ...` | Nothing was written. Add the attributes to the target's schema ([Attributes of your own](#attributes-of-your-own-schema-extensions)), or leave them out with `[attributes] exclude` |
| `base_dn ... must be below the root` | `base_dn` is the domain root, or not in the domain; clone an OU |
| `... already exists on the target but its ... differs` | Only with `clone -native`: the lab holds another object at that DN. Use a fresh lab |
| `warning: [mapping] attribute adminDisplayName is not indexed on the target` | Index it (step 9); the lab does this itself |
| `x509: certificate signed by unknown authority` | Give the CA with `ca_file` |
| `skip member of ...: ... does not exist on target` | A member clone cannot reproduce (a principal of a trusted domain, a built-in the target lacks); `diff` counts it instead of comparing it |
| `lab up` refuses with a different domain | A lab already exists for another domain: `lab reset -y`, or use `--instance` |
