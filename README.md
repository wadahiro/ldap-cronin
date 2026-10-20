<p align="center">
  <img src="docs/logo.svg" width="420" alt="LDAP cRONIN">
</p>

# ldap-cronin (LDAP cRONIN)

A Go tool that clones the contents of a given subtree (OUs, groups and users, and on AD computers and contacts) from one LDAP directory to another over LDAP, and later **verifies what changed on the target**.
It works with **Active Directory** (a real AD or Samba4 AD) and with **generic LDAP servers** such as OpenLDAP and 389 Directory Server. The server type is detected automatically (the `ad` and `ldap` profiles).

Typical use: build a realistic, safe-to-break test copy of a directory (with fixed passwords and masked attributes), let another program change it, and check exactly what changed with `diff`.

The name is a pun on "clone" and "ronin", a masterless samurai: cRONIN is a **c**lone that has gone **ronin**, a standalone copy that is not tied to its source.

## Documentation

| File | Contents |
|---|---|
| [docs/active-directory.md](docs/active-directory.md) | Active Directory and Samba AD: how users are created, preparing a real AD as the target, limitations |
| [docs/generic-ldap.md](docs/generic-ldap.md) | Generic LDAP servers (OpenLDAP and others): passwords, preserved `entryUUID`, limitations |
| [docs/diff.md](docs/diff.md) | `diff` output and comparison rules (every pattern), rename and move detection |
| [docs/lab.md](docs/lab.md) | The test lab (`lab`): usage, **taking and restoring snapshots**, using the offline package |
| [docs/dump.md](docs/dump.md) | `dump`: read production once into a file, and clone and diff from it |
| [docs/operations.md](docs/operations.md) | Large data sets, load on the source and target AD, memory, performance figures |
| [offline/README-OFFLINE.md](offline/README-OFFLINE.md) | Procedure for air-gapped environments (shipped inside the offline package) |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | For developers: layout, build and test, CI, design decisions |

## Subcommands

| Command | Description |
|---|---|
| `clone [-config f] [-dry-run [-with-password]] [-y] [-progress m]` | Add and update. Before the first write it shows the target (and the server name its root DSE gives) and the source, and asks `[y/N]`: only `y` writes, and without a terminal it stops unless `-y`. `-dry-run` does not connect to the target; it writes LDIF to standard output (progress logs go to standard error); `-with-password` puts the users' fixed password in it, so `ldapmodify` alone completes them |
| `clone -native [-fast-password] [-lab-prefix p] [-lab-instance n]` | **Samba lab only**: import with the same `objectGUID` and `objectSid` as the source (into a lab created with `lab up --like-source`). Uses unsupported internals. `-fast-password` writes the fixed password's NT hash directly, about 3 times faster, without Kerberos AES keys. For the limitations see [docs/lab.md](docs/lab.md#importing-with-the-same-objectguid-and-objectsid-clone--native-samba-only) |
| `diff [-config f] [-format text\|json] [-max-values n] [-progress m]` | Compare the source and the target. Exit code 1 if there are differences (2 on error). `-format json` writes JSON Lines for a program to read. For how to read the output see [docs/diff.md](docs/diff.md) |
| `check -config f [-no-target] [-attrs]` | Say what `clone` would do, writing nothing: per object type the attributes the entries hold that it would leave behind (a schema extension of your own) with the `[attributes]` line that copies them, what the target's schema lacks and refuses, and the next steps to run. Exit code 1 when `clone` would refuse to start. `-no-target` reads the source alone; `-attrs` lists every attribute and what `clone` does with it |
| `list-attrs [-profile ad\|ldap]` | Show the default attributes (allow list) per object type, reading nothing |
| `schema -config f [-apply [-y]]` | **AD**: compare the source's schema with the target's and print what the target lacks (attributes, classes, what a class both have allows) as LDIF for `ldapmodify` or `ldifde`; `-apply` writes it, after the same `[y/N]` question as `clone`. For a lab before its first clone, or as a file to review for a test AD |
| `dump -url u -bind-dn d -base-dn b -o f [-mask a,b]` | Read a source, read only, into one LDIF file (credentials never): `[source] ldif = "f"` then makes clone, diff and the rest read it instead of the server. See [docs/dump.md](docs/dump.md) |
| `lab up / down / reset / status` | Start and stop a test lab on docker: Samba4 AD, or OpenLDAP with `--profile ldap`. See [docs/lab.md](docs/lab.md) |
| `lab snapshot / snapshots / restore` | Take, list and restore snapshots of the lab data |
| `version` | Print the version |

Objects are applied in this order: parent OUs/containers, then groups, users, computers and contacts, then `member`/`manager`/`managedBy`.
Parents above `base_dn` are created automatically if they do not exist on the target; a parent that is itself a user or group (a group under a user) is created as one, with its attributes and password. The target is expected to be empty, and nothing is ever deleted (add and update only).

## Usage

For a first run against Active Directory, follow the [tutorial](docs/tutorial-ad.md): a complete configuration, a
clone into the Samba4 lab with snapshots, and the same clone into a test AD.

```sh
cp config.example.toml config.toml   # edit it
make build                           # produces bin/ldap-cronin (requires Go)
./bin/ldap-cronin clone -dry-run    # check the LDIF first
./bin/ldap-cronin clone
./bin/ldap-cronin diff
```

The dry-run LDIF loads with `ldapmodify` into an empty target. By default it carries no password: on a generic server the users are created without one (and `clone` never adds one to an existing user); on AD the password and the `userAccountControl` that follows it are written as comments, and `clone` run against the loaded target sets them. With `-with-password` it carries the fixed password (`userPassword` in the add; on AD a `unicodePwd` modify, which needs LDAPS, then the `userAccountControl`), and `ldapmodify` alone gives users that can log on. Bind passwords are never in it.

Bind passwords are never kept in the configuration file; they are prompted for at run time. The fixed password of the cloned users, a test value, may be: `[accounts] fixed_password`. For non-interactive use set the environment variables `LDAP_CRONIN_SOURCE_PASSWORD` / `LDAP_CRONIN_TARGET_PASSWORD` / `LDAP_CRONIN_USER_PASSWORD` (the last one comes before `fixed_password`), and pass `-y` to `clone` and `schema -apply`.

The source is only read. Its connection refuses every write before anything is sent, whatever the command; still,
bind to it with an account that can only read, so the server refuses too.

`clone` and `diff` show how far they are on standard error. On a terminal a status stays at the bottom of the screen while the log scrolls above it: the phase (`[3/5] user`), the count and a bar, the rate and the time left, and the counts so far. Elsewhere (a CI log, `2> file`) a plain line is printed every 10 seconds. `-progress plain` asks for the lines, `-progress off` for nothing. With `clone > clone.log` the log goes to the file and the screen shows only the status. The time left is the current phase's, at its rate so far; the reference pass slows down on large groups.

Ctrl-C stops a run at its next LDAP operation and still finishes its cleanup (a mapping file is written, a lab stopped for an import is resumed); a re-run of `clone` continues from there. See [docs/operations.md](docs/operations.md#stopping-a-run-and-hung-servers).

## Server types (profiles)

`[scope] profile` is `auto` by default: the source's root DSE decides between `ad` (Active Directory, Samba AD) and `ldap` (any other RFC 4510 server).
The target must be of the same type. The profile selects the default filters and attribute lists, how a user's fixed password is set, how DN-valued attributes are discovered and which attribute identifies an object across renames (`objectGUID` or `entryUUID`).

| | `ad` (Active Directory, Samba AD) | `ldap` (generic) |
|---|---|---|
| Detection | root DSE `supportedCapabilities` contains `1.2.840.113556.1.4.800` | everything else |
| Users | `(&(objectCategory=person)(objectClass=user))` | `(objectClass=inetOrgPerson)` |
| Groups | `(objectClass=group)` | `groupOfNames`, `groupOfUniqueNames` or `posixGroup` |
| OUs | `organizationalUnit` | `organizationalUnit` |
| Computers, contacts | `(objectCategory=computer)`, `(objectClass=contact)` | none |
| System objects | excluded (`isCriticalSystemObject=TRUE`) | none (there is no such marker) |
| Fixed password | add (disabled), `unicodePwd` modify over LDAPS, then `userAccountControl` (users and computers) | `userPassword` sent with the plain value in the add (the server hashes it) |
| DN-valued attributes | schema `attributeSyntax=2.5.5.1` | subschema `attributeTypes`, syntax DN / Name and Optional UID, following `SUP` |
| Object identity (renames) | `objectGUID` | `entryUUID` |
| Large `member` values | `member;range=0-N` | plain read |
| `lab` | yes (Samba lab) | yes (OpenLDAP lab, `--profile ldap`) |
| `clone -native` | yes (Samba lab) | no (the relax control keeps `entryUUID` over LDAP) |

Details per server type: [docs/active-directory.md](docs/active-directory.md) and [docs/generic-ldap.md](docs/generic-ldap.md).

## How attributes are handled

- **Allow-list based.** Only the listed attributes are copied. On AD the defaults are what Active Directory Users and Computers shows on its property sheets, plus a few production directories use ([active-directory.md](docs/active-directory.md)). Adjust the defaults with `extra_include` (add), `exclude` (remove) and `include.<type>` (replace) in `[attributes]`.
- **Or every attribute** (AD): with `[attributes] mode = "all"`, every attribute the source's schema lets a client write on the class of each object type is copied and compared, your own extensions included; `exclude` still applies, and what the target's schema lacks is left out with a note. `ldap-cronin schema` gives the target the source's extensions first.
- Attributes that cannot be migrated (`objectGUID`, `objectSid`, `unicodePwd`, `userPassword`, ...) are an error if you list them.
- **Masking**: attributes in `[mask] attributes` are replaced with a fixed string on the target, and `diff` does not compare them. Identity, unique, DN-valued and non-string attributes cannot be masked.
- **Passwords** are never copied. Cloned users get the fixed password you enter (or `[accounts] fixed_password`), set when they are created and never reset by a re-run; how it is set depends on the server type (see the server docs).
- **DN-valued attributes** (`member`, `manager`, `managedBy`, and anything you add such as `seeAlso`) are detected from the source schema, not from a fixed list.
  They are applied after all objects exist, because a reference to a missing object fails. **Every member is reproduced**: an object outside the scope that a reference names (a member outside `base_dn`) is cloned too, as its kind and without its own references (`[scope] references`); a built-in the target holds is referenced as it is; a value that still cannot be written (on AD, a built-in the target lacks, or an entry of the configuration partition such as the Exchange address list `showInAddressBook` names) is skipped with one warning per entry it names, the summaries count the values per attribute and reason, and `diff` counts them instead of comparing them. `[scope] configuration_refs = "clone"` creates the entries of the configuration partition such values name, for a lab.
- Back links (`memberOf`, `directReports`, ...) and DN+binary / DN+string attributes are an error in the allow list.

## diff (verifying changes made on the target)

`diff` is read-only. It finds **changes made on the target after the clone** (attribute changes, creations, deletions, renames, moves) and exits with 1 if there are differences.

```
DIFF        CN=Alice,OU=Users,OU=IDM,DC=example,DC=com
            department:
              source: Sales Dept
                             ~~~
              target: Sales Div
                             ~~
ONLY_SOURCE CN=Dave,OU=Users,OU=IDM,DC=example,DC=com
RENAMED     source: CN=Cid,OU=Users,OU=IDM,DC=example,DC=com
            target: CN=Cid Renamed,OU=Users,OU=IDM,DC=example,DC=com   (renamed)
```

| Kind | Meaning |
|---|---|
| `DIFF` | Present on both sides, but an attribute value differs |
| `ONLY_SOURCE` / `ONLY_TARGET` | Present only in the source / only on the target |
| `RENAMED` | The same object has a different DN (renamed or moved) |
| `REPLACED` | A different object than the one cloned sits at the same DN |
| `UNMARKED` | The object at the same DN has no marker (AD): recreated, or added to the source after the clone |

Rename, move and recreation detection needs no setup: on AD, `clone` writes a marker of the source object into `adminDisplayName`; on OpenLDAP it keeps the source's `entryUUID` (and creation timestamps) with the relax control. See `[mapping]` in [docs/diff.md](docs/diff.md#how-rename-and-move-detection-works-and-its-configuration). All output patterns and comparison rules are in [docs/diff.md](docs/diff.md).

## The test lab and snapshots (`lab`)

A Samba4 AD (or, with `--profile ldap`, an OpenLDAP) on docker for testing, so that cloned data can be **restored to its original state in seconds**. It needs only docker.

```sh
ldap-cronin lab up --realm corp.example.local   # start a Samba4 AD (the domain name is fixed at this first start)
ldap-cronin clone -config config.toml           # create the data
ldap-cronin lab snapshot baseline               # save the state right after the clone (you can take several)
# ... another program modifies the target ...
ldap-cronin diff -config config.toml            # see what changed
ldap-cronin lab restore                         # pick from the list and restore the original state (about 7 seconds)
```

- You can keep several snapshots. While the current lab keeps running, `lab restore baseline --instance dev2` starts another lab in the snapshot's state on a different port.
- The markers `diff` uses are part of the data, so rename detection keeps working after a restore, in any instance.
- The domain name is chosen at the first start, not when the image is built.
- `lab up --like-source config.toml` then `clone -native` imports with the same `objectGUID` and `objectSid` as the source (Samba lab only, unsupported internals; see [docs/lab.md](docs/lab.md#importing-with-the-same-objectguid-and-objectsid-clone--native-samba-only)).

### Taking it into an air-gapped environment

Where there is no internet access, build a tar.gz with `make bundle` on a connected machine (the Samba4 and OpenLDAP images, the binaries and `setup.sh`) and carry it over. `setup.sh <command>` is the same as `ldap-cronin lab <command>`.

```sh
tar xzf ldap-cronin-offline-*.tar.gz && cd ldap-cronin-offline-*
./setup.sh --realm corp.example.local    # verify integrity -> docker load -> start -> health check
./setup.sh snapshot baseline
./setup.sh restore
```

See [offline/README-OFFLINE.md](offline/README-OFFLINE.md) for the receiving side.

## License

[MIT](LICENSE)
