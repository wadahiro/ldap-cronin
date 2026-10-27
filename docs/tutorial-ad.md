# Tutorial: clone an Active Directory into a Samba4 lab, and into a Windows Server AD

This walks through a complete run against an AD source: production read once into a dump file, one
configuration file, a clone into the Samba4 lab (with snapshots, so every test starts from the same data), and
then the same clone into a Windows Server AD: a lab on Amazon EC2 that `lab` makes like the source, with snapshots
too, or a test domain of your own. The reference for each step is in
[active-directory.md](active-directory.md), [dump.md](dump.md), [lab.md](lab.md) and [diff.md](diff.md).

Throughout, the source domain is `ad.example.com` (`DC=ad,DC=example,DC=com`) and the part to clone is
`OU=IDM,DC=ad,DC=example,DC=com`. Replace them with yours.

## What you need

- Go (to build the tool) and docker (for the lab).
- For the dump, a machine that reaches the source DC over LDAPS (636), with the tool's binary alone, and an
  account that can **read** everything under `base_dn` (a normal domain user can read most attributes; Domain
  Admins also sees the ones a delegation hides).
- For part 2, an AWS account and the `aws` command with its Session Manager plugin (the EC2 lab), or a test AD
  domain **with the same domain name** as the source (see below).

**The target must have the same domain name as the source.** `clone` writes every object at its source DN, and
references (`member`, `manager`) name source DNs, so the target's naming context must be `DC=ad,DC=example,DC=com`
too. The labs take care of this (`lab up --config`, steps 5 and 11); a test domain of your own is an isolated test
forest built with the production domain name, never a domain that trusts or replicates with production.

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

### Where the lab runs has no internet access

Build an offline package on a machine that has it, and carry the one file over. It holds the tool for Linux
(amd64 and arm64), the lab images (Samba4 AD and OpenLDAP, with Exchange's schema when asked) and `setup.sh`;
the destination needs docker only.

```sh
# on the connected machine: PLATFORM is the destination's docker architecture (uname -m: x86_64 = amd64)
make bundle PLATFORM=linux/amd64
# with Exchange's schema in its Samba4 AD (the ISO of the version production runs, as above)
make bundle PLATFORM=linux/amd64 EXCHANGE_ISO=~/Downloads/ExchangeServerSE-x64.iso
# -> dist/ldap-cronin-offline-<version>-linux-amd64[-exchange].tar.gz
```

The `-exchange` package holds Microsoft's schema files inside its image: carry it into your own environment only,
never publish it or put it where others can download it.

At the destination, unpack it and work in its directory; the dump (step 2) goes there too:

```sh
tar xzf ldap-cronin-offline-*.tar.gz && cd ldap-cronin-offline-*
./setup.sh                 # checks the files, loads the images into docker, places ./ldap-cronin; starts nothing
cp /path/to/prod.ldif.gz . # the dump, taken where production can be reached
```

From there, `./ldap-cronin` takes the place of `./bin/ldap-cronin` in the steps below. Leave `image` out of
`[target.lab]` (step 3): run from the package's directory, `lab up --config` takes the package's image. Make the lab
with `lab up --config` only, not with `./setup.sh up`: that one starts a lab with a domain of its own, not the
source's (with `native = true`, `clone` refuses it), and only `lab reset` undoes it. The package's `README-OFFLINE.md` has the rest
([lab.md](lab.md#using-the-offline-package)).

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
  `-mask telephoneNumber,user:mail` masks attributes in the file itself (`user:mail` on users only, so a group's
  or a contact's mail stays).
- For fresh data, dump again (step 9). What is in the file and how it is read: [dump.md](dump.md).

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

[target.lab]                                # the target is a lab: lab up --config (step 5) makes it like the source
image = "ldap-cronin/samba-ad:local"        # what it is created from (step 1); ...:local-exchange for Exchange's schema;
                                            # leave it out in the offline package's directory (its image is used)
# native = true                             # write its database directly, keeping objectGUID and objectSid (step 6)

[scope]
profile = "ad"                              # auto would ask the source; ad says it outright
base_dn = "OU=IDM,DC=ad,DC=example,DC=com"  # or DC=ad,DC=example,DC=com for the whole domain
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
# Every attribute a client can write is copied and compared (your extensions too, once the target has their
# definitions); exclude takes some out. To copy only listed attributes, see "Every attribute (the default) or
# allow lists" below.
exclude = ["homeDirectory", "homeDrive", "profilePath", "scriptPath"]   # file server paths of production

[mask]
# Replaced with a fixed string on the target, and not compared by diff.
value = "********"
attributes = ["telephoneNumber", "mobile", "homePhone"]   # on every entry
[mask.kinds]
user = ["mail"]                             # on users only: a distribution group's or a contact's mail is kept
```

Notes on the choices:

- `[mapping] mode = "auto"` writes `ldap-cronin:<source root>:<source key>` into `adminDisplayName` of every
  cloned object. Pick another attribute if your applications use that one; it must be a single-valued string
  attribute, and it is neither copied nor compared.
- `user`, `group` and the other keys are the tool's [kinds](../README.md#kinds), not object classes:
  `ldap-cronin list-attrs` shows how each is told (on AD a `user` is never a computer).
- Masked attributes must be plain strings: `member`, `sAMAccountName`, `userPrincipalName` and the like cannot be
  masked (a fixed string would break them).
- `[target.lab]` says the target is a lab: `lab up --config config.toml` (step 5) makes it with the source's domain
  (name, NetBIOS name, domain SID and GUID), the url's port and the target password as the lab's Administrator
  password, and gives its schema what the source has beyond it. Nothing else is given to `lab up`.
- The filters are evaluated on the dump as the server would: `&`, `|`, `!`, equality, presence, substrings,
  `>=`/`<=` and AD's bitwise rules (`:1.2.840.113556.1.4.803:=`, `.804`). Anything else is refused, naming it.

## 4. Look before writing

```sh
export LDAP_CRONIN_TARGET_PASSWORD='Lab-Adm1n-Passw0rd!'      # the lab's Administrator (lab up --config makes it with it)
./bin/ldap-cronin check -config config.toml
```

`check` writes nothing. It reads the entries under `base_dn` (no values are printed) and says, per kind, which
attributes they hold that `clone` would leave behind, with the number of entries holding each, and ends with what
to do next:

```
source: the dump prod.ldif.gz (server dc01.ad.example.com)
target: the lab ldap-cronin-ad does not exist yet: ldap-cronin lab up --config config.toml creates it like the source

[ou] 12 entries: clone copies every attribute they hold that a client can write (mode = "all")
  (and 10 more only the server writes; -attrs lists every attribute)
  note: gPLink (3 entries): copied as it is; the GPOs it links are not (a new domain has the two default ones only); [attributes] exclude = ["gPLink", "gPOptions"] leaves both out
[group] 40 entries: clone copies every attribute they hold that a client can write (mode = "all")
[user] 1150 entries; 4 attributes they hold are not copied:
  homeDirectory  1150  [attributes] exclude names it
  homeDrive      1150  [attributes] exclude names it
  profilePath    1102  [attributes] exclude names it
  scriptPath      870  [attributes] exclude names it
  (and 12 more only the server writes; -attrs lists every attribute)
...

next:
  1. make the lab: ldap-cronin lab up --config config.toml
  2. check again: ldap-cronin check -config config.toml
  3. clone: ldap-cronin clone -config config.toml
```

Until the lab exists `check` exits with 1, as `clone` would refuse.

Everything else the entries hold is copied: what is listed is left out on purpose, each with why. With
[allow lists](#every-attribute-the-default-or-allow-lists) `check` lists what no list names instead, with the `extra_include` line that copies it. Once the
lab exists, `check` also says what its schema lacks (those attributes are left out until it has them) and what it refuses. `-no-target` reads the source alone (on a
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
not cloned (of no kind, or built-in): 14
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
It does not read the target, so what the target lacks or refuses (an attribute of an extension, `userParameters` on
Samba) is still in it; `clone` leaves those out by itself.

## Part 1: the Samba4 lab

### 5. Make the lab

```sh
./bin/ldap-cronin lab up --config config.toml
```

It makes the lab `[target.lab]` names like the source of `config.toml`, without connecting to production (the
source here is the dump):

1. **The lab**, when it does not exist: a Samba AD with the source's domain name, NetBIOS name, domain SID and GUID
   (they can only be chosen when a domain is created, so this is the one moment to take them), listening on the
   port of `[target] url`, its Administrator password the target password. The domain is fixed from then on:
   `lab reset -y` and `lab up --config` again start over. A stopped lab is started; one of another domain or other
   ports is refused, untouched.
2. **The schema**: what the source's schema has beyond the lab's (an extension of your own, an Exchange version
   other than the image's) is added, as `ldap-cronin schema -apply` would. A lab's schema goes with the lab; a real
   AD's cannot be undone, which is why part 2 does it by hand.

Run it again whenever the source's schema has gained something (a new dump): it adds that and nothing else.

```
==> Starting Samba4 AD (domain: ad.example.com / NetBIOS: AD)
==> Smoke test (searching as admin over LDAPS)
the lab's schema lacks definitions of the source's; adding them:
  attributes to add: 1
    acmeEmployeeCode
  ...
The lab ldap-cronin-ad is like the source of config.toml (ldaps://localhost:12636).
Next: ldap-cronin check -config config.toml, then ldap-cronin clone -config config.toml
```

`check -config config.toml` now reads the lab too, and says what it refuses (step 4).

### 6. Clone

```sh
./bin/ldap-cronin clone -config config.toml
```

It asks for the **fixed password for cloned users** (unless `[accounts] fixed_password` sets it): every cloned user
(and computer) gets it, since password hashes are never copied. It must satisfy the target's password policy (the
lab's is Samba's default complexity). Users who must change their password at the next logon on production must on
the target too. The cloned members of Domain Admins and the other built-in groups are members there too (next
paragraph), so the fixed password opens administrator accounts of the target: keep it as you keep the target.

Before the first write it shows where it is about to write, and asks:

```
clone adds and updates entries under base_dn on the target
  target (written): ldaps://localhost:12636 (server dc1.ad.example.com)
    bind_dn: CN=Administrator,CN=Users,DC=ad,DC=example,DC=com
    base_dn: OU=IDM,DC=ad,DC=example,DC=com
  source (read only): the dump prod.ldif.gz (server dc01.ad.example.com)
Write to this target? [y/N]:
```

Only `y` (or `yes`) goes on; Enter alone stops with nothing written. In a script, where nothing can answer, pass
`-y`. The source is never written to, whatever the command. A lab that `lab up --config` has not made (or that is
stopped) is refused with the command to run.

What it does, in order: the OUs and parents, then groups, users, computers and contacts (users and computers are
added disabled, given the password, then their source `userAccountControl`), then `member`, `manager` and the other
references, then the primary groups that are not Domain Users, then the groups outside `base_dn` that hold entries
of it (a user's group of another OU, Domain Admins: found through `memberOf`, created when not built-in, and given
those members only; `[scope] outside_groups` and `builtin_groups` turn them off). It prints each write (`add`,
`update`) and the counts at the end. A dump taken before groups outside its base DN were carried says so when it
is read: dump again (step 2).

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

`clone` then writes the entries into Samba's database directly instead of over LDAP: it stops the lab, writes
from a helper container of the lab image, and starts the lab again, also after a failure or Ctrl-C:

```
==> Stopping lab ldap-cronin-ad (only for the duration of the import; it resumes afterwards)
add    OU=IDM,DC=ad,DC=example,DC=com
...
native: dbcheck: Checked 3854 objects (0 errors) / largest imported RID=1110 (next allocation=1111)
==> Resuming lab ldap-cronin-ad
```

That is why the lab must have the source's domain SID (an objectSid is the domain SID and a number within it): a
lab made by `lab up --config` has it; one made otherwise is refused before anything is written. At the end it runs
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
not compared (of no kind, or built-in: clone does not copy it): 14
  msFVE-RecoveryInformation  12
  serviceConnectionPoint      2
references not compared (clone cannot write them): 2
  member: names an entry of class foreignSecurityPrincipal, which no kind copies  2
compared attributes:
  ...
not compared:
  masked (config [mask]):
    telephoneNumber
    ...
    mail (user)
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

When you want fresh data from production: dump again (step 2) to the same file, `lab restore baseline`, `clone`
again (it brings the lab up to date with the new dump), and `lab snapshot baseline --force`. Objects deleted on the source stay on the lab
(nothing is deleted); for an exact copy, `lab reset -y` and start again from step 5.

## Part 2: a Windows Server AD

Samba is AD-compatible, not Windows. When the test needs a real Windows Server domain controller, the same
configuration works against one; only `[target]` and `[target.lab]` change. Two ways:

- **The EC2 lab** (steps 10 to 13): `lab up --config` launches a Windows Server instance on Amazon EC2 and makes it
  a new forest like the source, as it made the Samba lab, with every preparation a target AD needs done for you,
  and snapshots. You pay for the instance while it runs, and for the volume and the snapshots while they exist.
- **A test domain of your own** (steps 14 to 17): you prepare it; no snapshots.

### 10. Describe the EC2 lab

Copy `config.toml` to `config-ec2.toml` and replace its `[target]` and `[target.lab]`:

```toml
[target]
url = "ldaps://localhost:12636"                   # where the tunnel to the instance listens (step 11)
bind_dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
insecure_skip_verify = true                       # the domain controller's certificate is self-signed

[target.lab]
platform = "ec2"
region = "ap-northeast-1"
subnet = "subnet-0123456789abcdef0"               # its instances must reach Systems Manager
instance_profile = "ldap-cronin-lab"              # an instance profile whose role has AmazonSSMManagedInstanceCore
# windows = "2022"                                # 2016, 2019, 2022 or 2025
# tags = { Owner = "me", Project = "idm-test" }   # what the account's tag policy requires
# public_ip = true                                # a subnet with an internet gateway and no NAT needs it
```

- The `aws` command needs credentials for the account, and the [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)
  for the tunnels. The permissions it uses are listed in [design/ec2-lab.md](design/ec2-lab.md).
- No inbound rule is needed: the instance is reached through Systems Manager only.
- `native` does not apply (Windows lets no one choose an `objectGUID` or a domain SID). Every setting:
  [lab.md](lab.md#a-windows-server-lab-on-amazon-ec2-targetlab-platform--ec2).

### 11. Make it

```sh
export LDAP_CRONIN_TARGET_PASSWORD='Lab-Adm1n-Passw0rd!'      # its Administrator's: Windows' complexity rule applies
./bin/ldap-cronin lab up --config config-ec2.toml --dry-run    # what it will do on AWS; nothing is done
./bin/ldap-cronin lab up --config config-ec2.toml              # about 20 minutes
```

It launches the instance, which makes itself the domain controller of a new forest with the source's domain
name, NetBIOS name and functional levels, and then does what step 14 asks of a test domain of your own: an
LDAPS certificate, a password policy that takes the fixed password, the marker attribute indexed. `lab up`
shows the last line of the instance's log meanwhile, and ends with the tunnel commands. Run each in a terminal
of its own, as `lab up` printed them, and keep them running while you use the lab:

```sh
aws ssm start-session --target i-0123456789abcdef0 --document-name AWS-StartPortForwardingSession \
  --parameters 'portNumber=636,localPortNumber=12636' --region ap-northeast-1
```

`lab status --config config-ec2.toml` shows the instance; `lab up --config` again uses the one there, or starts it
if it is stopped.

### 12. Schema extensions, then clone

The Samba lab got the source's schema extensions from `lab up --config`; the EC2 lab is not reachable until the
tunnel runs, so give them now. The lab is the forest's only domain controller, so it is the schema master, and
its Administrator is a Schema Admin:

```sh
./bin/ldap-cronin schema -config config-ec2.toml               # read what it would add
./bin/ldap-cronin schema -config config-ec2.toml -apply        # write it
./bin/ldap-cronin check -config config-ec2.toml                # exit code 0: clone can start
./bin/ldap-cronin clone -config config-ec2.toml
./bin/ldap-cronin diff -config config-ec2.toml                 # no differences
```

A schema change cannot be undone in AD, but this forest exists for the test: a snapshot taken after it keeps it,
and `lab reset` removes it with the lab. Measured on Windows Server 2019: Exchange's schema, from a Samba lab that
has it, went in whole (2,445 attributes, 314 classes, 20 classes extended) in about 4 minutes.

### 13. Save the state, and the test cycle

```sh
./bin/ldap-cronin lab snapshot baseline --config config-ec2.toml --note "right after clone"
# ... the program under test changes the lab (ldaps://localhost:12636, through the tunnel) ...
./bin/ldap-cronin diff -config config-ec2.toml                 # what it changed
./bin/ldap-cronin lab restore baseline --config config-ec2.toml   # back to the clone; open the tunnels again
```

- A snapshot is an EBS snapshot of the instance's root volume, taken with the instance stopped, so the domain's
  database is closed: a few minutes, then the lab is ready again. A restore replaces the root volume by one made from
  the snapshot; the instance keeps its id, so the tunnel commands are the same, but it restarts, so open them again
  (the old tunnels keep their local ports but forward nothing: stop them first).
- `lab down --config config-ec2.toml` stops the instance while you do not use it (its volume and snapshots are
  still billed); `lab up --config` starts it again.
- `lab reset --config config-ec2.toml` terminates it; add `--snapshots` to delete its snapshots too.

### Or: a test domain of your own

The same configuration works against a Windows AD you prepare; only `[target]` and a few preparations change.
There are no snapshots here: restoring a test domain is your backup's job, and `clone` never deletes anything.

### 14. Prepare the test domain

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
- The source's schema extensions: step 16, once the configuration points at the test domain.

### 15. Point the configuration at it

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

### 16. Give the test domain the source's schema extensions

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

2. **An account in Schema Admins.** The tool's account of step 14 is not one, and should not be: add a
   test-domain administrator to Schema Admins for the change, and remove it afterwards. Membership takes effect at
   the next logon (bind).

3. **Write the file and read it.** The configuration of step 15 reads the test domain's schema through any DC:

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

### 17. Dry-run, clone, diff

```sh
./bin/ldap-cronin check -config config.toml                         # now against the test domain
./bin/ldap-cronin clone -config config.toml -dry-run > clone.ldif   # unchanged from step 4: the same dump
./bin/ldap-cronin clone -config config.toml
./bin/ldap-cronin diff -config config.toml
```

Run it outside business hours: every object is several writes, replicated to every DC (the load per user is in
[operations.md](operations.md#load-on-the-target-ad-clone)). Then test as in step 9, with `diff` against the test
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
needs their definitions in its schema; the clone then copies them (with [allow lists](#every-attribute-the-default-or-allow-lists), once a list
names them).

### Find them

```sh
./bin/ldap-cronin check -config config.toml
```

Once the target is read, `check` names the attributes of the source's schema the target's lacks (`not copied or
compared: the target schema lacks ...`) and gives the `schema` command that adds them; until then they are left out.
`-attrs` marks each attribute your entries hold that the target cannot hold yet. `extensionAttribute1`-`15` and
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

How to apply it: the Samba lab gets it from `lab up --config` ([step 5](#5-make-the-lab)); the EC2 lab from
`schema -apply` ([step 12](#12-schema-extensions-then-clone)); a test domain of your own as in
[step 16](#16-give-the-test-domain-the-sources-schema-extensions).

### Copy and compare them

Nothing to configure: once the target has the definitions, they are copied and compared.

```sh
./bin/ldap-cronin check -config config.toml                 # the target lacks nothing; exit code 0
./bin/ldap-cronin clone -config config.toml
./bin/ldap-cronin diff -config config.toml                  # compares acmeEmployeeCode too
```

- With allow lists, name them (`extra_include = ["acmeEmployeeCode"]`); if the target then lacks one, `clone`
  refuses to start and names it, and nothing is written.
- An attribute that holds DNs (`attributeSyntax: 2.5.5.1`, a custom `sponsor`, say) is found in the source schema
  and handled as a reference: applied after every object exists, compared like `member`.
- Personal data in a string attribute can be masked (`[mask] attributes`, or `[mask.kinds]` for one kind's
  entries); an attribute that must stay unique or
  that holds DNs cannot.
- An auxiliary class attached to single objects (not to `user` in the schema) shows in their `objectClass`, which
  `clone` always copies: the target needs that class even when none of its attributes is copied.
  `schema` carries it like any other class.

## Every attribute (the default) or allow lists

The clone is there to hold the objects as production has them, so by default every attribute is copied rather than
the ones a list names:

```sh
./bin/ldap-cronin schema -config config.toml -apply        # a test AD: your extensions first (a lab: lab up --config does it)
./bin/ldap-cronin check -config config.toml -attrs         # what each kind's entries hold, and what is copied
./bin/ldap-cronin clone -config config.toml
./bin/ldap-cronin diff -config config.toml
```

- "Every attribute" is what the source's schema lets a client write on the class of each kind (`user`, `group`,
  `computer`, ...): what the class, the classes it derives from and their auxiliary classes may contain, your
  extensions and `proxyAddresses`, `mS-DS-ConsistencyGuid` or `msDS-cloudExtensionAttribute*` included.
- Never copied all the same: what only the server writes (`systemOnly`, constructed attributes, back links such as
  `memberOf`), identifiers, every credential (`unicodePwd`, `userPassword`, LAPS, ...), and the marker attribute.
- `gPLink` and `gPOptions` of an OU are copied as they are, but not the GPOs they link (`check` notes it; `exclude`
  them if they get in the way).
- An attribute the target's schema lacks is left out with a note at the start of `clone` and `diff`, instead of
  stopping the run: give the target your extensions with `schema` first. A dry-run reads no target, so its LDIF has
  them all.
- A reference into the configuration partition (`showInAddressBook` naming Exchange's address lists, `homeMDB`) is
  skipped with a warning per entry it names. For the lab, `[scope] configuration_refs = "clone"` creates those
  entries from the source once `schema` has given the lab Exchange's classes; or `exclude` the attributes.
- An attribute the target refuses over LDAP is left out the same way, with the reason: a Samba lab refuses
  `userParameters` (old RAS and Terminal Services settings), which a real AD takes, and the resource-based delegation
  (with `credentials = "copy"`), which a real AD lets a client write though its schema marks it `systemOnly`.
- `diff` counts the compared attributes per kind instead of naming hundreds; `check -attrs` names them.
- Some attributes a client may write are refreshed by the server or the machine itself (`msDS-SupportedEncryptionTypes`
  of a live computer, say): they are copied once and may show as `DIFF` on a later diff. `exclude` them if they get
  in the way.
- To copy only the attributes your applications read, use the allow lists: `[attributes] mode = "allowlist"`
  copies what Active Directory Users and Computers shows (`ldap-cronin list-attrs`), `extra_include` adds to every
  kind and `[attributes.include]` replaces a kind's list. `include` and `extra_include` go with it only: by default
  they have nothing to add, and `clone` refuses them, naming `mode = "allowlist"`. Then `check` lists what the
  entries hold and no list names, with the `extra_include` line that copies it.

## When something goes wrong

| Message | What to do |
|---|---|
| `set password (LDAPS is required; ...)` | Use `ldaps://` (or `start_tls = true`) for the target, and a fixed password the target's policy accepts. Re-run `clone`: it sets the password of the users created without one |
| `the target schema lacks attributes that the source defines and the allow lists name: ...` | Nothing was written. `ldap-cronin check` names the steps: give the target their definitions with `ldap-cronin schema` ([Attributes of your own](#attributes-of-your-own-schema-extensions)), or leave them out with `[attributes] exclude` |
| `[scope] base_dn ... is not in the dump, which holds ...` | `base_dn` is outside the dump's `-base-dn`: dump a wider OU, or clone one inside it |
| `... is not supported on a dump` | A filter the dump cannot evaluate (approximate, the in-chain rule, `:dn`): rewrite it with what it supports, or read production directly |
| `aborted: nothing was written (pass -y to skip the confirmation)` | The answer to `Write to this target? [y/N]` was not `y`, or there was no terminal to ask on. Check the target it showed; in a script, pass `-y` |
| `... Constraint Violation ... setting userParameters is not supported over LDAP` | A Samba target refusing `userParameters`. This version leaves it out by itself; with an older one, `exclude` it. Re-run `clone`: it goes on from where it stopped |
| `base_dn ... must be the root ... or below it` | `base_dn` is not in the domain of `root_dn` |
| `... already exists on the target but its ... differs` | Only with `native = true`: the lab holds another object at that DN. Use a fresh lab (`lab reset -y`, then `clone`) |
| `the lab's domain differs from the source's ...` | `native = true` into a lab not made like the source (by `lab up --realm`, say): `lab reset -y`, then `lab up --config` makes it like the source |
| `[target] url ... is not the lab ...` | `[target] url` and `[target.lab]` name different labs: give the lab's port in the url, or the url's lab in `[target.lab]` |
| `warning: [mapping] attribute adminDisplayName is not indexed on the target` | Index it (step 14); the labs do this themselves |
| `x509: certificate signed by unknown authority` | Give the CA with `ca_file` |
| `skip member values naming ...: it names ...` | A reference clone cannot write, with what it names: a principal of a trusted domain (class `foreignSecurityPrincipal`), a built-in the target lacks, an entry of the configuration partition (`showInAddressBook` naming an Exchange address list). One warning per entry named; the summary counts the values per attribute and reason, and `diff` counts them instead of comparing them. `[attributes] exclude` an attribute the test does not need |
| `the existing container has different settings: domain ...` | The lab was made for another domain (or other ports): `lab reset -y`, then `lab up --config` makes it anew |
| `the lab ... does not exist yet` / `is stopped` | `ldap-cronin lab up --config config.toml` makes (or starts) it, then `clone` |
