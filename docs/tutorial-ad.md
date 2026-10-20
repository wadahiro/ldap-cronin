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
# your applications read; anything not listed is neither copied nor compared. To copy every attribute instead,
# see "Copy everything" below.
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

`not copied` is what the clone would leave behind: add the ones your applications read to `extra_include`, or copy
them all with [`mode = "all"`](#copy-everything-mode--all). Run it again with `-target` once the target exists, to
see which of them its schema lacks (`clone` refuses to start in that case, naming them). How to carry an attribute of your own over is in
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

To review exactly what will be loaded and load it with `ldapmodify` yourself, instead of running `clone`, add
`-with-password`: the LDIF then carries the fixed password (asked for, or `[accounts] fixed_password`) and the
`userAccountControl` set after it, so it alone gives users that can log on. Load it over LDAPS, into an empty
target (`ldapmodify -H ldaps://... -D <admin> -W -f clone.ldif`), and keep the file where the password may be.
It does not read the target, so what the target lacks or refuses (`mode = "all"`, `userParameters` on Samba) is
still in it; `clone` leaves those out by itself.

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

### 5. Give the lab the source's schema extensions

Production may have attributes and classes the lab lacks: an extension of your own (an employee code), or a
product's. Do this **before the first `clone`**, so the snapshot of step 8 carries them and every restore has them.

```sh
export LDAP_CRONIN_TARGET_PASSWORD="$SAMBA_ADMIN_PASSWORD"
./bin/ldap-cronin schema -config config.toml > schema.ldif       # what the lab lacks; writes nothing
```

The summary on the terminal says what it found:

```
attributes to add: 2
  acmeEmployeeCode
  acmeSponsor
classes to add: 1
  acmePerson
classes to extend: 1
  user: auxiliaryClass acmePerson
```

`the target schema has every attribute and class of the source's extensions` means there is nothing to do: go on
to step 6. Otherwise look through `schema.ldif` ([what is in it](#give-the-target-their-definitions)), then write
it to the lab and check that nothing is left:

```sh
./bin/ldap-cronin schema -config config.toml -apply
./bin/ldap-cronin schema -config config.toml > /dev/null         # the target schema has every attribute and class ...
```

The lab's schema can be changed freely: if something went wrong, `lab reset -y` and start again from step 4.
Having the definitions does not copy the values yet: name the attributes in `[attributes] extra_include`, or copy
everything with [`mode = "all"`](#copy-everything-mode--all).

### 6. Clone

```sh
./bin/ldap-cronin clone -config config.toml
```

It asks for the source password and the **fixed password for cloned users** (unless `[accounts] fixed_password`
sets it): every cloned user (and computer) gets it, since password hashes are never copied. It must satisfy the target's password policy (the lab's is
Samba's default complexity).

Before the first write it shows where it is about to write, and asks:

```
clone adds and updates entries under base_dn on the target
  target (written): ldaps://localhost:12636 (server dc1.ad.example.com)
    bind_dn: CN=Administrator,CN=Users,DC=ad,DC=example,DC=com
    base_dn: OU=IDM,DC=ad,DC=example,DC=com
  source (read only): ldaps://dc01.ad.example.com:636 (server dc01.ad.example.com)
Write to this target? [y/N]:
```

Only `y` (or `yes`) goes on; Enter alone stops with nothing written. In a script, where nothing can answer, pass
`-y`. The source is never written to, whatever the command: its connection refuses every write.

What it does, in order: the OUs and parents, then groups, users, computers and contacts (users and computers are
added disabled, given the password, then their source `userAccountControl`), then `member`, `manager` and the other
references. It prints each write (`add`, `update`) and the counts at the end.

A run can be stopped with Ctrl-C and started again: `clone` only adds what is missing and updates what differs,
and never deletes. A second run right after the first writes nothing.

### 7. Check the clone

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

### 8. Save the state

```sh
./bin/ldap-cronin lab snapshot baseline --note "right after clone"
```

### 9. The test cycle

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

### 10. Prepare the test domain

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
- The source's schema extensions: step 12, once the configuration points at the test domain.

### 11. Point the configuration at it

```toml
[target]
url = "ldaps://dc01.test.ad.example.com:636"     # one DC: writes then replicate to the others
bind_dn = "CN=svc-clone,OU=Service Accounts,DC=ad,DC=example,DC=com"
ca_file = "test-root-ca.pem"
timeout = "2m"

[run]
workers = 4                                       # a real DC also serves others; start low
```

### 12. Give the test domain the source's schema extensions

Everything here is LDAP, so it is done from your machine like the clone. **A schema change cannot be undone in
AD**: an attribute or class can only be made defunct, and the schema belongs to the whole forest. Add only what
production has, to a forest that exists for testing.

1. **Find the schema master.** Schema changes are made on the DC that holds the schema master role; another DC
   refuses them.

   ```sh
   ldapsearch -H ldaps://dc01.test.ad.example.com -D 'CN=Administrator,CN=Users,DC=ad,DC=example,DC=com' -W \
     -b 'CN=Schema,CN=Configuration,DC=ad,DC=example,DC=com' -s base fSMORoleOwner
   # fSMORoleOwner: CN=NTDS Settings,CN=DC01,CN=Servers,... -> DC01 holds it
   ```

   On a Windows machine of the domain, `netdom query fsmo` says the same.

2. **An account in Schema Admins.** The tool's account of step 10 is not one, and should not be: add a
   test-domain administrator to Schema Admins for the change, and remove it afterwards. Membership takes effect at
   the next logon (bind).

3. **Write the file and read it.** The configuration of step 11 reads the test domain's schema through any DC:

   ```sh
   ./bin/ldap-cronin schema -config config.toml > schema.ldif
   ```

   Check the summary: every name under `attributes to add` and `classes to add` should be one production has on
   purpose. `left out` lists what will not be carried, with why ([what each means](#give-the-target-their-definitions)).

4. **Apply it to the schema master**, as the Schema Admin, over LDAPS:

   ```sh
   ldapmodify -H ldaps://dc01.test.ad.example.com \
     -D 'CN=Administrator,CN=Users,DC=ad,DC=example,DC=com' -W -f schema.ldif
   ```

   It stops at the first change the DC refuses and says why; the changes before it stay. Fix the cause, write
   the file again (step 3: it then holds only what is still missing) and apply that.

   The tool can write it too: copy `config.toml` to `schema.toml`, point its `[target]` at the schema master with
   the Schema Admin as `bind_dn`, and run `./bin/ldap-cronin schema -config schema.toml -apply`. On the DC itself,
   `ldifde -i -f schema.ldif` reads the same file.

5. **Check it, through the DC the clone writes to**, once the change has replicated there (the schema replicates
   like everything else; with one DC there is nothing to wait for):

   ```sh
   ./bin/ldap-cronin schema -config config.toml > /dev/null   # the target schema has every attribute and class ...
   ```

Then remove the account from Schema Admins.

### 13. Dry-run, clone, diff

```sh
./bin/ldap-cronin clone -config config.toml -dry-run > clone.ldif   # unchanged from step 3
./bin/ldap-cronin clone -config config.toml
./bin/ldap-cronin diff -config config.toml
```

Run it outside business hours: every object is several writes, replicated to every DC (the load per user is in
[operations.md](operations.md#load-on-the-target-ad-clone)). Then test as in step 9, with `diff` against the test
domain; to start a test over, re-run `clone`, which puts back what was changed (it does not remove what the
program added: `diff` lists those as `ONLY_TARGET`).

## Attributes of your own (schema extensions)

Production ADs often carry attributes of their own (an employee code, a cost center) or of a product. The target
needs their definitions in its schema, and the clone copies them once an allow list names them (or with
[`mode = "all"`](#copy-everything-mode--all)).

### Find them

```sh
./bin/ldap-cronin list-attrs -config config.toml -target
```

Every `not copied` line is an attribute your entries hold that the clone leaves behind, with the number of entries
holding it; `not in the target schema` marks the ones the target cannot hold yet. `extensionAttribute1`-`15` and
`msExch*` come from the Exchange schema, which the lab already has.

### Give the target their definitions

```sh
./bin/ldap-cronin schema -config config.toml > schema.ldif
```

`schema` reads the schema of `[source]` and of `[target]` and writes what the target lacks as LDIF; the summary goes
to the terminal:

```
attributes to add: 2
  acmeEmployeeCode
  acmeSponsor
classes to add: 1
  acmePerson
classes to extend: 1
  user: auxiliaryClass acmePerson
left out: 1
  attribute msDS-Example: part of a newer Windows Server base schema than the target's
```

- The definitions are the source's: the same names, OIDs, `schemaIDGUID` and `linkID`, so values compare and a
  later schema update of production applies to the target too.
- **classes to extend** is what makes an attribute usable: the class that allows it (`mayContain`), usually an
  auxiliary class of your own, attached to `user` in the schema (`auxiliaryClass`).
- **left out** names what cannot be carried and why. A definition of a newer Windows Server base schema than the
  target's is one: which level a server has is chosen when it is installed, not added piece by piece. A name or OID
  the target uses for something else is another.
- It writes nothing without `-apply`, and reads nothing but the two schemas.

The LDIF is plain `ldapmodify` input. Each step ends with `schemaUpdateNow`, so the next one can name what the step
before added:

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
schemaIDGUID:: 3rC5vDEJO0uFVO624K0WLg==

dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
-

dn: CN=acme-Person,CN=Schema,CN=Configuration,DC=ad,DC=example,DC=com
changetype: add
objectClass: classSchema
...
```

How to apply it: to the lab in [step 5](#5-give-the-lab-the-sources-schema-extensions), to a test AD in
[step 12](#12-give-the-test-domain-the-sources-schema-extensions).

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
  `schema` carries it like any other class.

## Copy everything (mode = "all")

When the test needs the objects as production has them, rather than the attributes your applications read, copy
every attribute instead of listing them:

```toml
[attributes]
mode = "all"
exclude = ["homeDirectory", "homeDrive", "profilePath", "scriptPath"]   # still applies
```

```sh
./bin/ldap-cronin schema -config config.toml -apply        # the lab: your extensions first (see above)
./bin/ldap-cronin list-attrs -config config.toml -target   # what each kind's entries hold, and what is copied
./bin/ldap-cronin clone -config config.toml
./bin/ldap-cronin diff -config config.toml
```

- "Every attribute" is what the source's schema lets a client write on the class of each kind (`user`, `group`,
  `computer`, ...): what the class, the classes it derives from and their auxiliary classes may contain, your
  extensions and `proxyAddresses`, `mS-DS-ConsistencyGuid` or `msDS-cloudExtensionAttribute*` included.
- Never copied all the same: what only the server writes (`systemOnly`, constructed attributes, back links such as
  `memberOf`), identifiers, every credential (`unicodePwd`, `userPassword`, LAPS, ...), and the marker attribute.
- An attribute the target's schema lacks is left out with a note at the start of `clone` and `diff`, instead of
  stopping the run: give the target your extensions with `schema` first. A dry-run reads no target, so its LDIF has
  them all.
- An attribute the target refuses over LDAP is left out the same way, with the reason: a Samba lab refuses
  `userParameters` (old RAS and Terminal Services settings), which a real AD takes.
- `diff` counts the compared attributes per kind instead of naming hundreds; `list-attrs -config -all` names them.
- Some attributes a client may write are refreshed by the server or the machine itself (`msDS-SupportedEncryptionTypes`
  of a live computer, say): they are copied once and may show as `DIFF` on a later diff. `exclude` them if they get
  in the way.
- `include` and `extra_include` do not go with `mode = "all"`; it is either the lists or everything.

## When something goes wrong

| Message | What to do |
|---|---|
| `set password (LDAPS is required; ...)` | Use `ldaps://` (or `start_tls = true`) for the target, and a fixed password the target's policy accepts. Re-run `clone`: it sets the password of the users created without one |
| `the target schema lacks attributes that the source defines and the allow lists name: ...` | Nothing was written. Give the target their definitions with `ldap-cronin schema` ([Attributes of your own](#attributes-of-your-own-schema-extensions)), or leave them out with `[attributes] exclude` |
| `aborted: nothing was written (pass -y to skip the confirmation)` | The answer to `Write to this target? [y/N]` was not `y`, or there was no terminal to ask on. Check the target it showed; in a script, pass `-y` |
| `... Constraint Violation ... setting userParameters is not supported over LDAP` | A Samba target refusing `userParameters`. This version leaves it out by itself; with an older one, `exclude` it. Re-run `clone`: it goes on from where it stopped |
| `base_dn ... must be below the root` | `base_dn` is the domain root, or not in the domain; clone an OU |
| `... already exists on the target but its ... differs` | Only with `clone -native`: the lab holds another object at that DN. Use a fresh lab |
| `warning: [mapping] attribute adminDisplayName is not indexed on the target` | Index it (step 10); the lab does this itself |
| `x509: certificate signed by unknown authority` | Give the CA with `ca_file` |
| `skip member of ...: ... does not exist on target` | A member clone cannot reproduce (a principal of a trusted domain, a built-in the target lacks); `diff` counts it instead of comparing it |
| `lab up` refuses with a different domain | A lab already exists for another domain: `lab reset -y`, or use `--instance` |
