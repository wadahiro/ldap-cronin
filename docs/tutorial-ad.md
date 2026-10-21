# Tutorial: clone an Active Directory into a Samba4 lab, and into a test AD

This walks through a complete run against an AD source: production read once into a dump file, one
configuration file, a clone into the Samba4 lab (with snapshots, so every test starts from the same data), and
then the same clone into a real AD test domain. The reference for each step is in
[active-directory.md](active-directory.md), [dump.md](dump.md), [lab.md](lab.md) and [diff.md](diff.md).

Throughout, the source domain is `ad.example.com` (`DC=ad,DC=example,DC=com`) and the part to clone is
`OU=IDM,DC=ad,DC=example,DC=com`. Replace them with yours.

## What you need

- Go (to build the tool) and docker (for the lab).
- For the dump, a machine that reaches the source DC over LDAPS (636), with the tool's binary alone, and an
  account that can **read** everything under `base_dn` (a normal domain user can read most attributes; Domain
  Admins also sees the ones a delegation hides).
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

If production has Exchange, give the image Exchange's schema from Exchange's setup image (the ISO of the version
production runs, from Microsoft's download site; Exchange Server SE and 2019 CU12 or later have the schema version
17003). `bsdtar` reads it (macOS has it; Debian and Ubuntu: `apt install libarchive-tools`):

```sh
make image IMAGE_TAG=local EXCHANGE_ISO=~/Downloads/ExchangeServerSE-x64.iso   # ldap-cronin/samba-ad:local-exchange
```

Every lab made from that image has the schema `/PrepareSchema` writes to a forest like Samba's (about 2,800
definitions), written when its domain is created, before Samba starts: the lab is up in about 30 seconds. The
image holds Microsoft's files: keep it on your machine, never push it. On a Windows test domain, Exchange's own
setup prepares the schema.

For a machine without internet access, build the offline package instead (`make bundle`, see
[lab.md](lab.md#using-the-offline-package)); `setup.sh` in it then takes the place of `ldap-cronin lab`.

## 2. Read production once: the dump

Every step after this one reads a file, not production:

- production is read **once**, at a time chosen for it, with an account that can only read;
- the lab and the test AD are made from **the same moment of production**: two clones read live, an hour apart,
  could differ, as production keeps changing in between; `diff` compares with that moment too, so a test can be
  repeated;
- the configuration can be tried and changed as often as needed (`check`, `clone` again) without touching
  production.

Run it where production can be reached; the binary is all it needs (it reads no configuration file):

```sh
export LDAP_CRONIN_SOURCE_PASSWORD='...'          # or asked for
ldap-cronin dump -url ldaps://dc01.ad.example.com:636 \
  -bind-dn 'CN=svc-ldap-cronin,OU=Service Accounts,DC=ad,DC=example,DC=com' -ca-file corp-root-ca.pem \
  -base-dn 'OU=IDM,DC=ad,DC=example,DC=com' -o prod.ldif.gz
# dumped 5123 entries to prod.ldif.gz (...; under the base DN 3502, referenced outside it 87, schema 1530)
```

- `-base-dn` is the most a clone of this dump can take: `[scope] base_dn` must be it or below it. Take the OU
  that holds everything the tests may need.
- The file holds the entries **as production has them, personal data included**, without any credential (password
  hashes, LAPS, BitLocker): keep it as you keep production's data (it is written readable by its owner only).
  `-mask mail,telephoneNumber` masks attributes in the file itself.
- For fresh data, dump again (step 8). What is in the file and how it is read: [dump.md](dump.md).

Carry `prod.ldif.gz` to the machine where the lab runs. To read production on every run instead, see
[Without a dump](#without-a-dump-reading-production-directly).

## 3. Write the configuration

Save this as `config.toml`, next to the dump. It is complete: every section the tool reads is here, with the
defaults written out where they matter. **Passwords never go in this file**: they are asked for at run time, or
taken from `LDAP_CRONIN_TARGET_PASSWORD` and `LDAP_CRONIN_USER_PASSWORD` (the only exception is the fixed
password of the cloned users, a test value, which `[accounts] fixed_password` may hold).

```toml
[source]                                    # production, as the dump of step 2 has it: no password is asked
ldif = "prod.ldif.gz"

[target]                                    # the Samba4 lab (part 1); part 2 replaces this section
url = "ldaps://localhost:12636"
bind_dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
insecure_skip_verify = true                 # the lab's certificate is self-signed

[target.lab]                                # the target is a lab: clone creates it like the source when it is missing
image = "ldap-cronin/samba-ad:local"        # what it is created from (step 1); ...:local-exchange for Exchange's schema
# native = true                             # write its database directly, keeping objectGUID and objectSid (step 5)

[scope]
profile = "ad"                              # auto would ask the source; ad says it outright
base_dn = "OU=IDM,DC=ad,DC=example,DC=com"  # not the domain root: that would reach the built-in accounts
# objects = ["ou", "group", "user", "computer", "contact"]   # the default: every kind
references = "clone"                        # the default: a member outside base_dn is cloned too, so every
                                            # member is on the target and diff sees any change to it

# [scope.filters]                           # narrow a kind if you need to
# user = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

[run]
workers = 8                                 # parallel connections to the target

[mapping]
mode = "auto"                               # on AD: a marker of the source object in adminDisplayName, so diff
attribute = "adminDisplayName"              # tells a renamed or recreated object from the cloned one

[attributes]
# The defaults (ldap-cronin list-attrs -profile ad) are what Active Directory Users and Computers shows; anything
# not listed is neither copied nor compared. check (step 4) prints the extra_include line for what your entries
# hold beyond them. To copy every attribute instead, see "Copy everything" below.
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
- `[target.lab]` makes the lab part of the target: `clone` creates it when it is missing, with the source's domain
  (name, NetBIOS name, domain SID and GUID) and the url's port, with the target password as the lab's
  Administrator password, and gives its schema what the source has beyond it. No `lab up` is needed.
- The filters are evaluated on the dump as the server would: `&`, `|`, `!`, equality, presence, substrings,
  `>=`/`<=` and AD's bitwise rules (`:1.2.840.113556.1.4.803:=`, `.804`). Anything else is refused, naming it.

## 4. Look before writing

```sh
export LDAP_CRONIN_TARGET_PASSWORD='Lab-Adm1n-Passw0rd!'      # the lab's Administrator (clone creates it with it)
./bin/ldap-cronin check -config config.toml
```

`check` writes nothing. It reads the entries under `base_dn` (no values are printed) and says, per kind, which
attributes they hold that `clone` would leave behind, with the number of entries holding each, and ends with what
to do next:

```
source: the dump prod.ldif.gz (server dc01.ad.example.com)
target: the lab ldap-cronin-ad does not exist yet: clone creates it like the source, and gives its schema the source's definitions it lacks

[ou] 12 entries: clone copies every attribute they hold that a client can write
[group] 40 entries: clone copies every attribute they hold that a client can write
[user] 1150 entries; 3 attributes they hold are not copied (no allow list names them):
  codePage             1150
  acmeEmployeeCode     1102
  extensionAttribute3   870
  (and 9 more only the server writes; -attrs lists every attribute)
...

next:
  1. to copy and compare what clone leaves behind, put in config.toml (keep only those you want):
       [attributes]
       extra_include = ["acmeEmployeeCode", "codePage", "extensionAttribute3"]
     or copy every attribute a client can write: [attributes] mode = "all"
  2. check again: ldap-cronin check -config config.toml
  3. clone: ldap-cronin clone -config config.toml (it creates it like the source first)
```

Put the line in `config.toml`, keeping the attributes your applications read (or every one), or copy them all with [`mode = "all"`](#copy-everything-mode--all). Once the
lab exists, `check` also says what its schema lacks and what it refuses. `-no-target` reads the source alone (on a
machine that reaches production only, say).
`-attrs` adds a table of every attribute of every kind, held or named, and what `clone` does with it.

To see the very LDIF `clone` would write:

```sh
./bin/ldap-cronin clone -config config.toml -dry-run > clone.ldif
```

The dry-run connects to nothing; the progress and the counts go to the terminal:

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

### 5. Clone

```sh
./bin/ldap-cronin clone -config config.toml
```

It asks for the **fixed password for cloned users** (unless `[accounts] fixed_password` sets it): every cloned user
(and computer) gets it, since password hashes are never copied. It must satisfy the target's password policy (the
lab's is Samba's default complexity).

Before it does anything, it says what it is about to do to the lab, and asks:

```
clone writes the lab ldap-cronin-ad:
  target (written): the lab ldap-cronin-ad (ldaps://localhost:12636)
    create it like the source: domain ad.example.com (NetBIOS AD), domain SID S-1-5-21-..., GUID ...
    give its schema the source's definitions it lacks
    add and update the entries under OU=IDM,DC=ad,DC=example,DC=com over LDAP
    base_dn: OU=IDM,DC=ad,DC=example,DC=com
  source (read only): the dump prod.ldif.gz (server dc01.ad.example.com)
Write to this target? [y/N]:
```

Only `y` (or `yes`) goes on; Enter alone stops with nothing done. In a script, where nothing can answer, pass `-y`.
The source is never written to, whatever the command.

Then, in order:

1. **The lab**, when it does not exist: a Samba AD with the source's domain name, NetBIOS name, domain SID and GUID
   (they can only be chosen when a domain is created, so this is the one moment to take them), listening on the
   port of `[target] url`, its Administrator password the target password. The domain is fixed from then on:
   `lab reset -y` and `clone` again start over. A lab that exists is used as it is (started if stopped); one of
   another domain is refused, untouched.
2. **The schema**: what the source's schema has beyond the lab's (an extension of your own, an Exchange version
   other than the image's) is added, as `ldap-cronin schema -apply` would. A lab's schema can be reset with the
   lab; a real AD's cannot, which is why part 2 does it by hand.
3. **The entries**: the OUs and parents, then groups, users, computers and contacts (users and computers are added
   disabled, given the password, then their source `userAccountControl`), then `member`, `manager` and the other
   references. It prints each write (`add`, `update`) and the counts at the end.

While it runs, the bottom of the terminal shows the phase, how many of how many, the rate and the time left;
`clone -config config.toml > clone.log` keeps the log in a file and the screen for the status alone.

A run can be stopped with Ctrl-C and started again: `clone` only adds what is missing and updates what differs,
and never deletes. A second run right after the first writes nothing.

### Or: keep the source's objectGUID and objectSid (`native = true`)

Over LDAP the lab gives every object its own `objectGUID` and `objectSid`. When the program under test keeps them
(a GUID as the key of a user, a SID in an ACL or a token), have the clone import them as they are:

```toml
[target.lab]
image = "ldap-cronin/samba-ad:local"
native = true                               # Samba lab only
# fast_password = true                      # see below
```

`clone` then does the same steps, but writes the entries into Samba's database directly: it stops the lab, writes
from a helper container of the lab image, and starts the lab again, also after a failure or Ctrl-C:

```
==> Stopping lab ldap-cronin-ad (only for the duration of the import; it resumes afterwards)
add    OU=IDM,DC=ad,DC=example,DC=com
...
native: dbcheck: Checked 3854 objects (0 errors) / largest imported RID=1110 (next allocation=1111)
==> Resuming lab ldap-cronin-ad
```

That is why the lab must have the source's domain SID (an objectSid is the domain SID and a number within it): a
lab created by `clone` has it; one created otherwise is refused before anything is written. At the end it runs
Samba's database check (`dbcheck`), and moves Samba's RID allocation past the imported RIDs, so a user the program
under test creates later does not collide with them. It writes no markers in `adminDisplayName`: `diff` matches the
objects by `objectGUID`, and its summary says so:

```
rename/move check: on (objectGUID preserved: the target holds the source's objectGUID)
```

It relies on Samba internals that are not a supported usage (verified on 4.19.5; a self-check at the start fails
before writing anything when they do not work), and it has no dry-run (there is no LDIF). The limitations are in
[lab.md](lab.md#importing-with-the-same-objectguid-and-objectsid-targetlab-native--true-samba-only).

**Faster: `fast_password = true`.** Giving the fixed password is most of the time of a user: Samba derives the NT
hash and the Kerberos keys from it. With it, the first user gets the password as usual and every other user gets
the NT hash it got, written directly. 5,000 users and 50 groups took 24s instead of 75s (an LDAP `clone` took 60s).

```
native: ... / fast_password: 4999 users got the NT hash directly (no Kerberos AES keys)
```

Those users have **no Kerberos AES keys**. They log on with the fixed password over LDAP and NTLM, and over Kerberos
with RC4, but not where only AES is allowed. When the test needs production's logon behavior, leave it off.

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
references not compared (clone cannot write them: the target lacks what they name): 2
  member: names an entry of class foreignSecurityPrincipal, which no kind copies  2
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

When you want fresh data from production: dump again (step 2) to the same file, `lab restore baseline`, `clone`
again (it brings the lab up to date with the new dump), and `lab snapshot baseline --force`. Objects deleted on the source stay on the lab
(nothing is deleted); for an exact copy, `lab reset -y` and start again from step 5.

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
- The source's schema extensions: step 11, once the configuration points at the test domain.

### 10. Point the configuration at it

Replace `[target]`, and remove `[target.lab]`: a test domain is a server `clone` writes over LDAP, never creates.

```toml
[target]
url = "ldaps://dc01.test.ad.example.com:636"     # one DC: writes then replicate to the others
bind_dn = "CN=svc-clone,OU=Service Accounts,DC=ad,DC=example,DC=com"
ca_file = "test-root-ca.pem"
timeout = "2m"

[run]
workers = 4                                       # a real DC also serves others; start low
```

### 11. Give the test domain the source's schema extensions

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

2. **An account in Schema Admins.** The tool's account of step 9 is not one, and should not be: add a
   test-domain administrator to Schema Admins for the change, and remove it afterwards. Membership takes effect at
   the next logon (bind).

3. **Write the file and read it.** The configuration of step 10 reads the test domain's schema through any DC:

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
   ./bin/ldap-cronin check -config config.toml    # exit code 0: clone can start
   ```

Then remove the account from Schema Admins.

### 12. Dry-run, clone, diff

```sh
./bin/ldap-cronin check -config config.toml                         # now against the test domain
./bin/ldap-cronin clone -config config.toml -dry-run > clone.ldif   # unchanged from step 4: the same dump
./bin/ldap-cronin clone -config config.toml
./bin/ldap-cronin diff -config config.toml
```

Run it outside business hours: every object is several writes, replicated to every DC (the load per user is in
[operations.md](operations.md#load-on-the-target-ad-clone)). Then test as in step 8, with `diff` against the test
domain; to start a test over, re-run `clone`, which puts back what was changed (it does not remove what the
program added: `diff` lists those as `ONLY_TARGET`).

## Without a dump: reading production directly

Every step works the same with `[source]` naming the server instead of a dump; each `check`, `clone` and `diff`
then reads production again (and asks for its password, or takes `LDAP_CRONIN_SOURCE_PASSWORD`):

```toml
[source]                                    # read only: the tool never writes to it
url = "ldaps://dc01.ad.example.com:636"
bind_dn = "CN=svc-ldap-cronin,OU=Service Accounts,DC=ad,DC=example,DC=com"
ca_file = "corp-root-ca.pem"                # the CA that issued the DC certificate
timeout = "2m"                              # per LDAP operation
```

It suits a single target kept close to production (a `clone` every night that brings the lab up to date), or a
filter a dump cannot evaluate. Each run then reads what production holds at that moment: two targets cloned at
different times are not of the same moment, and `diff` compares with production as it is now, so a change made
there shows as a difference too.

## Attributes of your own (schema extensions)

Production ADs often carry attributes of their own (an employee code, a cost center) or of a product. The target
needs their definitions in its schema, and the clone copies them once an allow list names them (or with
[`mode = "all"`](#copy-everything-mode--all)).

### Find them

```sh
./bin/ldap-cronin check -config config.toml
```

Every line under a kind is an attribute your entries hold that the clone leaves behind, with the number of entries
holding it; `the target schema lacks it` marks the ones the target cannot hold yet, and `next:` gives the
`extra_include` line that copies them. `extensionAttribute1`-`15` and
`msExch*` come from the Exchange schema, which a lab made from the image of step 1 has.

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

How to apply it: a lab gets it from `clone` itself ([step 5](#5-clone)); a test AD as in
[step 11](#11-give-the-test-domain-the-sources-schema-extensions).

### Copy and compare them

```toml
[attributes]
extra_include = ["acmeEmployeeCode"]        # every kind; or [attributes.include] user = [...] for one kind
```

```sh
./bin/ldap-cronin check -config config.toml                 # acmeEmployeeCode no longer listed; exit code 0
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
./bin/ldap-cronin schema -config config.toml -apply        # a test AD: your extensions first (a lab: clone does it)
./bin/ldap-cronin check -config config.toml -attrs         # what each kind's entries hold, and what is copied
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
- A reference into the configuration partition (`showInAddressBook` naming Exchange's address lists, `homeMDB`) is
  skipped with a warning per entry it names. For the lab, `[scope] configuration_refs = "clone"` creates those
  entries from the source once `schema` has given the lab Exchange's classes; or `exclude` the attributes.
- An attribute the target refuses over LDAP is left out the same way, with the reason: a Samba lab refuses
  `userParameters` (old RAS and Terminal Services settings), which a real AD takes.
- `diff` counts the compared attributes per kind instead of naming hundreds; `check -attrs` names them.
- Some attributes a client may write are refreshed by the server or the machine itself (`msDS-SupportedEncryptionTypes`
  of a live computer, say): they are copied once and may show as `DIFF` on a later diff. `exclude` them if they get
  in the way.
- `include` and `extra_include` do not go with `mode = "all"`; it is either the lists or everything.

## When something goes wrong

| Message | What to do |
|---|---|
| `set password (LDAPS is required; ...)` | Use `ldaps://` (or `start_tls = true`) for the target, and a fixed password the target's policy accepts. Re-run `clone`: it sets the password of the users created without one |
| `the target schema lacks attributes that the source defines and the allow lists name: ...` | Nothing was written. `ldap-cronin check` names the steps: give the target their definitions with `ldap-cronin schema` ([Attributes of your own](#attributes-of-your-own-schema-extensions)), or leave them out with `[attributes] exclude` |
| `[scope] base_dn ... is not in the dump, which holds ...` | `base_dn` is outside the dump's `-base-dn`: dump a wider OU, or clone one inside it |
| `... is not supported on a dump` | A filter the dump cannot evaluate (approximate, the in-chain rule, `:dn`): rewrite it with what it supports, or read production directly |
| `aborted: nothing was written (pass -y to skip the confirmation)` | The answer to `Write to this target? [y/N]` was not `y`, or there was no terminal to ask on. Check the target it showed; in a script, pass `-y` |
| `... Constraint Violation ... setting userParameters is not supported over LDAP` | A Samba target refusing `userParameters`. This version leaves it out by itself; with an older one, `exclude` it. Re-run `clone`: it goes on from where it stopped |
| `base_dn ... must be below the root` | `base_dn` is the domain root, or not in the domain; clone an OU |
| `... already exists on the target but its ... differs` | Only with `native = true`: the lab holds another object at that DN. Use a fresh lab (`lab reset -y`, then `clone`) |
| `the lab's domain differs from the source's ...` | `native = true` into a lab not made like the source (by `lab up --realm`, say): `lab reset -y`, then `clone` creates it like the source |
| `[target] url ... is not the lab ...` | `[target] url` and `[target.lab]` name different labs: give the lab's port in the url, or the url's lab in `[target.lab]` |
| `warning: [mapping] attribute adminDisplayName is not indexed on the target` | Index it (step 9); the lab does this itself |
| `x509: certificate signed by unknown authority` | Give the CA with `ca_file` |
| `skip member values naming ...: it names ...` | A reference clone cannot write, with what it names: a principal of a trusted domain (class `foreignSecurityPrincipal`), a built-in the target lacks, an entry of the configuration partition (`showInAddressBook` naming an Exchange address list). One warning per entry named; the summary counts the values per attribute and reason, and `diff` counts them instead of comparing them. `[attributes] exclude` an attribute the test does not need |
| `the existing container has different settings: domain ...` | The lab was made for another domain (or other ports): `lab reset -y`, then `clone` makes it anew |
