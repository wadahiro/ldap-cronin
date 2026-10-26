# The test lab (`lab`) and snapshots

`ldap-cronin lab` makes a directory server to clone into, made like the source, and **takes snapshots of it to
restore at any time**: keep the state right after `clone`, and bring it back whenever another program has changed
the target. Three kinds:

| Lab | Runs on | For | Snapshot / restore |
|---|---|---|---|
| **Samba4 AD** (the default for an AD source) | docker on your machine | most AD tests; offline too ([offline package](#using-the-offline-package)); the source's `objectGUID` and `objectSid` with [`native = true`](#importing-with-the-same-objectguid-and-objectsid-targetlab-native--true-samba-only) | tar files of its volumes, seconds |
| **OpenLDAP** ([`--profile ldap`](#the-openldap-lab---profile-ldap), for a generic LDAP source) | docker | OpenLDAP, 389-ds and other generic sources | tar files of its volumes, seconds |
| **Windows Server AD** ([`platform = "ec2"`](#a-windows-server-lab-on-amazon-ec2-targetlab-platform--ec2)) | Amazon EC2, through the `aws` command | tests that need a real Windows domain controller | EBS snapshots of its root volume, minutes |

The docker labs need only docker (no docker compose). The EC2 lab needs the `aws` command, its Session Manager
plugin and an AWS account ([what it needs](design/ec2-lab.md)).

Every kind starts the same way: name the lab in the configuration (`[target.lab]`), and `lab up --config` makes it
like the source ([below](#the-lab-made-like-the-source-lab-up---config-and-targetlab)):

```sh
ldap-cronin lab up --config config.toml          # [target.lab]: the lab, like the source of config.toml
ldap-cronin clone -config config.toml            # the data
ldap-cronin lab snapshot baseline --config config.toml   # save the state right after the clone
# ... another program modifies the target ...
ldap-cronin diff -config config.toml             # see what it changed
ldap-cronin lab restore baseline --config config.toml    # back to the state of the snapshot
```

A docker lab can also be started by hand, without a configuration ([`lab up --realm`](#starting-a-docker-lab-by-hand-lab-up)),
and its commands then take no `--config`.

## The lab made like the source (`lab up --config` and `[target.lab]`)

```toml
[target]
url = "ldaps://localhost:12636"
bind_dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
insecure_skip_verify = true
[target.lab]
image = "ldap-cronin/samba-ad:local"     # what lab up --config creates it from (default: the offline package's image)
# instance = "dev2"                      # another instance (it must exist: instances come from snapshots)
# prefix = "ldap-cronin"
# native = true                          # see the next section
# fast_password = true
# server_attributes = "lab"              # native: the lab's own whenCreated, logons and lockout instead of the source's
# acl = "source"                         # native: the source's ACLs, the domain root's included (default: the lab's own)
```

```sh
ldap-cronin lab up --config config.toml   # the lab, like the source
ldap-cronin check -config config.toml     # what clone will do, reading the lab
ldap-cronin clone -config config.toml     # the data
```

`lab up --config <file>` takes everything from the config:

1. **It creates the lab when it does not exist** (the default instance only): the source's domain name, and on AD its
   NetBIOS name, domain SID and GUID, which can only be chosen when a domain is created; for a generic source an
   OpenLDAP lab with its naming context. It listens on the port of `[target] url` (the other port: the default, or
   `AD_LDAP_PORT` / `AD_LDAPS_PORT`), and its Administrator password is the target password
   (`LDAP_CRONIN_TARGET_PASSWORD`, or asked), saved in `.env` like a password given to `lab up`. The prefix,
   instance and image come from `[target.lab]` (`--prefix`, `--instance` and `--image` take precedence); the
   settings of a lab given by hand (`--realm`, the ports, ...) are refused with it. A stopped lab is started; a lab
   of another domain or other ports is refused, untouched.
2. **It gives the lab's schema the source's definitions it lacks**, as `schema -apply` would (a lab's schema goes with
   the lab; a real AD's cannot be undone, so there it stays a step of its own). Run again after a new dump, it adds
   what the source's schema has gained.

**An AD lab's password policy is the weakest a domain takes**, so `[accounts] fixed_password` may be any string,
one character even: complexity off, minimum length 1, no history, no minimum age, and passwords that never expire.
The Samba lab sets it when its domain is created, the EC2 lab when it is set up; `lab up --realm` and
`lab up --config` alike. The lab's own Administrator password is set before it, so it must meet Windows' default
complexity. A test domain of your own keeps its policy: the fixed password must meet that one.

For an EC2 lab (`platform = "ec2"`), `lab up --config` launches a Windows Server instance instead, with the same
domain name, NetBIOS name and functional levels ([below](#a-windows-server-lab-on-amazon-ec2-targetlab-platform--ec2)):
Windows lets no one choose a domain SID, so not the source's.

`[target.lab]` says the target is that lab: `[target] url` must be its, which `lab up --config`, `check` and `clone`
check against the lab's port. `check` says whether the lab exists and runs (exit code 1 until it does, with the
`lab up --config` to run), and reads it like any target. `clone` refuses a lab that does not exist or is stopped,
naming the command. `diff`, `schema` and `lab snapshot` work as with any target. `[target.lab]` belongs in the
configuration of a lab only: a real AD target has none.

## Commands

| Command | Docker lab (Samba4, OpenLDAP) | EC2 lab (with `--config`) |
|---|---|---|
| `lab load [--reload] [--skip-verify]` | Verifies the offline package's `SHA256SUMS` and loads its images into docker; starts nothing | |
| `lab up` | Loads the image (if missing), creates or starts the lab and checks LDAPS | Launches the instance (or starts a stopped one) and waits until it is a domain controller; prints the tunnel commands |
| `lab down` | Stops it; the data is kept and `up` resumes it | Stops the instance; `up` starts it again |
| `lab reset [-y] [--snapshots]` | Deletes the domain data and `.env` | Terminates the instance |
| `lab status` | The state of the lab (and its instances), the number of snapshots | The instance's state, type, root volume, addresses, the number of snapshots |
| `lab snapshot [name] [--note text] [--force]` | Writes its volumes to tar files (seconds) | An EBS snapshot of its root volume, the instance stopped meanwhile (minutes) |
| `lab snapshots` | Lists the snapshots | Lists the snapshots (with the state of one still pending) |
| `lab restore [name]` | Restores the volumes; without a name, pick from a list. **Creates the lab from the snapshot if it does not exist**, also as [another instance on other ports](#starting-another-lab-from-a-snapshot-on-a-different-port) | Replaces the root volume by one made from the snapshot (a name is needed), waits until it is ready |
| `lab snapshot-rm name` | Deletes a snapshot | Deletes a snapshot |

Snapshots are kept by `lab reset` unless `--snapshots` is given.

Options of the docker labs: `--profile` (`ad` or `ldap`; needed only for `up`, later commands take it from `.env` or
the container), `--state-dir` (where `.env` is placed; default `.`), `--snapshot-dir` (default
`<state-dir>/snapshots`), `--bundle-dir` (the location of the offline package; found automatically if omitted), and
`--instance` (the instance to operate on; the default lab if omitted). `lab help` shows all options.

## Starting a docker lab by hand (`lab up`)

```sh
ldap-cronin lab up                                  # asks for the domain name and the administrator password (interactive)
ldap-cronin lab up --realm corp.example.local       # specify the domain name
ldap-cronin lab up --with-sample-source             # also start a clone source with sample data, for trying the tool out
ldap-cronin lab up --config config.toml             # make it like the source of a config: the same domain name, SID and GUID ([target.lab], below)
```

- **The domain name is fixed at the first start, not at image build.** The same image can use a different domain name in each environment. To change it, run `lab reset` and create the lab again.
- The Kerberos realm (upper case), the NetBIOS name (the first label in upper case, at most 15 characters; use `--netbios` if it is long) and the base DN are derived from the domain name automatically.
- The administrator password is given by interactive input (twice), `--admin-password`, or the environment variable `SAMBA_ADMIN_PASSWORD`. **If none is given, a password that satisfies the complexity rules is generated and displayed.**
  The environment variable is recommended, because a command-line value stays in the shell history.
- The settings are saved in `.env` (permissions 600) and can be omitted from the second time on. Precedence: option > environment variable > `.env`. `lab reset` deletes `.env`.
- If a container already exists with a different domain name or ports, the command **refuses without damaging the data**. With the same settings it resumes, even from a stopped state.
- After starting, it prints the connection details and an example `[target]` setting. The LDAPS certificate is self-signed, so use `insecure_skip_verify = true` (or `ca_file`).
- The DC host name is fixed to `dc1`.
- **Exchange's schema**: an image built with `make image EXCHANGE_ISO=<Exchange setup .iso>` (tag `<tag>-exchange`) writes Exchange's schema, as `/PrepareSchema` does, to the domain of every lab it creates, before Samba starts (about 25 seconds more at the first start). A file it cannot write stops the first start with the reason in the container's log; `lab reset` starts over. The image holds Microsoft's files: keep it local, never push it.
- **Samba's databases are not fsynced** (`ldb:nosync = true`, set at every start, so labs created before get it too). A lab is disposable and snapshots restore it; every write is several times faster without it (Exchange's schema over LDAP took 12 minutes with it, 4 without). A crash of the container keeps the data; a crash of the host can leave the lab to be restored from a snapshot.

## The OpenLDAP lab (`--profile ldap`)

The same commands with an OpenLDAP 2.6 image of our own (`docker/ldap`, Ubuntu 24.04), for a generic LDAP source.

```sh
ldap-cronin lab up --profile ldap --suffix dc=example,dc=org        # start OpenLDAP; the admin is cn=admin,<suffix>
ldap-cronin lab up --profile ldap --schema-dir ./schema              # with the production schema and cn=config changes
ldap-cronin lab up --config config.toml                              # a generic source gives an OpenLDAP lab with its naming context
ldap-cronin lab snapshot baseline                                    # later commands need no --profile
```

- **The suffix is fixed at the first start** (`--suffix` or `LDAP_SUFFIX`; its first RDN must be `dc=`, `o=` or `ou=`), like the domain name of Samba. The password comes from `--admin-password`, `LDAP_ADMIN_PASSWORD`, or is generated.
- **The administrator `cn=admin,<suffix>` is the rootdn**, so `clone` keeps the source's `entryUUID` and creation metadata with the relax control (`[mapping] mode = "preserve"`, the default for generic LDAP) without any ACL change.
- **What is in it**: the `core`, `cosine`, `nis` and `inetorgperson` schemas; the `memberof` overlay (for `groupOfNames`, as production OpenLDAP usually has; `groupOfUniqueNames` members get no `memberOf`) and `refint`; equality indexes on `objectClass`, `entryUUID`, `cn`, `uid`, `member`, `uniqueMember`; no password policy (so the fixed password is accepted); LDAPS with a self-signed certificate. It needs no extra privileges, so rootless docker works.
- **`--schema-dir DIR`**: every `*.ldif` in it is applied in name order when the directory is created: schemas as `olcSchemaConfig` entries (`cn=<name>,cn=schema,cn=config`), and `changetype: modify` against `cn=config` for overlays, ACLs, indexes or `ppolicy`. A failing file stops the container, and `lab up` shows its log. The result lives in the configuration volume, so snapshots and other instances carry it; it is ignored for a lab that already exists.
- **Ports** default to 13389 / 13636 (the sample source 14389 / 14636), so it can run next to a Samba lab. The two kinds need separate `--state-dir`, since `.env` holds one lab's settings.
- **Snapshots** hold `/var/lib/ldap` (the database and the certificate) and `/etc/ldap/slapd.d` (the configuration). They record the kind, so restoring one into a Samba lab is refused; a new instance (`lab restore NAME --instance dev2`) takes the snapshot's kind by itself.
- `native = true` does not apply: the relax control already keeps `entryUUID` over LDAP.

## Snapshots of a docker lab

A snapshot of a docker lab is the contents of the lab's docker volumes (the Samba databases) written out to files on the host.

```
snapshots/
  baseline/
    private.tar      contents of /var/lib/samba (the domain data)
    etc.tar          contents of /etc/samba (the configuration)
    snapshot.json    name, note, time taken, domain, NetBIOS name, host name, image, size and SHA-256 of each file
```

### Taking one (`lab snapshot`)

```sh
ldap-cronin lab snapshot                          # the name is generated from the date and time (snapshot-20261016-221530)
ldap-cronin lab snapshot baseline --note "right after clone"
ldap-cronin lab snapshot baseline --force         # overwrite the same name (without --force it is refused)
```

1. If the lab is running, Samba is **stopped cleanly** (`docker stop`) so the database files are not copied while being written.
2. The two volumes are written to tar files, and their SHA-256 is recorded.
3. If the lab was running, it is **started again** and the command waits until it is healthy. If it was stopped, it stays stopped.
4. On failure, the original state is restored and no half-written snapshot is left behind.

### Listing and choosing (`lab snapshots` / `lab restore`)

A name consists of letters, digits, `_`, `.` and `-`, at most 64 characters.

```
$ ldap-cronin lab snapshots
NAME                     CREATED              DOMAIN                       SIZE  NOTE
baseline                 2026-10-16 22:34:54  corp.example.local         44.4MB  right after clone
after-delete             2026-10-16 22:35:04  corp.example.local         44.4MB  after deleting 4 users
```

`DOMAIN` is the domain of the lab the snapshot was taken from; you can restore only into a lab with the same domain (or a newly created lab).

Without a name, `lab restore` lets you choose by number (newest first; Enter selects it, `q` cancels).

```
$ ldap-cronin lab restore
Which snapshot to restore:
       NAME                     CREATED              DOMAIN                       SIZE  MAP  NOTE
 *  1) after-delete             2026-10-16 22:35:04  corp.example.local         44.4MB  -    after deleting 4 users
    2) baseline                 2026-10-16 22:34:54  corp.example.local         44.4MB  yes  right after clone
Enter a number [1] (q to cancel): 2
```

Without a terminal (script, CI) it prints the candidates and asks for a name.

### Restoring (`lab restore`)

1. **Verifies the SHA-256** of the snapshot. If it is corrupt, the command fails **without touching the current data**.
2. Checks that the lab's domain name matches the snapshot's (refuses if not).
3. Stops Samba if it is running.
4. Empties the two volumes and extracts the tar files.
5. Starts Samba, waits until it is healthy, and checks that an administrator search over LDAPS works. Even if the lab was stopped before, it is **started** after the restore.

A restore discards every change made since the snapshot. You can restore any snapshot any number of times.

Ctrl-C does not interrupt steps 3 to 5 of a restore, or the restart at the end of a snapshot: a half-written volume or a lab left stopped would be worse than waiting the few seconds they take. The command stops once they are done (a second Ctrl-C ends it at once). An interrupted snapshot is discarded; the lab is restarted.

### Starting another lab from a snapshot on a different port

While the current lab keeps running, you can start another lab in the snapshot's state next to it, on different host ports. It uses separate volumes, so the two do not affect each other. Name it with `--instance` and `restore`.

```sh
ldap-cronin lab restore baseline --instance dev2 --ldaps-port 22636    # start a lab in baseline's state on different ports
ldap-cronin lab restore --instance dev2                                # pick from the list; free ports are chosen automatically
ldap-cronin lab status                                                 # show all instances
ldap-cronin lab snapshot --instance dev2 after-test                    # you can take snapshots of dev2 too
ldap-cronin lab reset --instance dev2 -y                               # delete only dev2 (the original lab, .env and snapshots are untouched)
```

```
$ ldap-cronin lab status
lab main       ldap-cronin-ad          status=running  domain=corp.example.local  LDAP=12389 LDAPS=12636
lab dev2       ldap-cronin-ad-dev2     status=running  domain=corp.example.local  LDAP=40113 LDAPS=40114
snapshots: 2 (snapshots)
```

- Uses: run tests in parallel from the same baseline, or compare the before and after states side by side.
- If an instance with the same name exists, only that instance is overwritten.
- Ports are set with `--ldap-port` / `--ldaps-port`; if omitted, free ones are chosen. Ports used by other instances are refused before starting.
- The domain name, NetBIOS name and host name (`dc1`) are inherited from the snapshot. **The administrator password is the one in effect when the snapshot was taken**, taken from `--admin-password`, `SAMBA_ADMIN_PASSWORD`, or `.env`, in that order.
- Both labs have the same domain and DC name and do not replicate with each other, so this cannot be used where the two need to talk.
- An instance name consists of lower-case letters, digits and hyphens, at most 31 characters (`main` is the default lab and cannot be used). `up` is only for the default lab; other instances are created with `restore`.
- With no default lab (after `lab reset`), `lab restore` creates one from the snapshot.

### How long it takes

About 7 seconds each to take and to restore with about 44 MB of data (Samba's initial state plus a few users). It grows with the data (roughly 60 MB for 1600 users).

### Location and handling

- Stored in `<state-dir>/snapshots/` (`--snapshot-dir`) as host files, so `docker volume prune` does not delete them. Copy them to another machine to restore there (same image and domain name).
- **A snapshot contains the domain data as it is, including users' password hashes.** File permissions are 600; handle with care.
- `lab reset` keeps snapshots unless `--snapshots` is given.
- `docker volume prune` deletes the lab's volumes after `lab down`, so **take a snapshot right after `clone`**.

### Rename detection after a restore

`clone` writes a marker of the source object into `adminDisplayName` of every object it creates ([docs/diff.md](diff.md#how-rename-and-move-detection-works-and-its-configuration)). The markers are part of the data, so **a restore, into this lab or another instance on another port, keeps `diff`'s rename and move detection working** with nothing to carry beside the snapshot.
With `[mapping] mode = "preserve"` (the OpenLDAP lab) the identifiers are the source's, which is part of the data too. With `mode = "file"` the local file is a ledger of every object `clone` created from each source object, so it serves every snapshot and instance as it is.

The lab image indexes `adminDisplayName` when the domain is created, before any data exists (Samba does not index values written before the index existed until a reindex), and on every start of an older lab. If you configure another marker attribute (`[mapping] attribute`), index it before the first `clone` as on a real AD ([active-directory.md](active-directory.md#when-the-target-is-a-real-ad)); for a lab that already holds markers in it, run `samba-tool dbcheck --reindex` in the container once afterwards.

## Importing with the same objectGUID and objectSid (`[target.lab] native = true`, Samba only)

A normal `clone` creates objects over LDAP, so the target assigns new `objectGUID` and `objectSid` values. **For a lab (Samba) only, you can import with the same `objectGUID` and `objectSid` as the source**, for testing applications that depend on them.

```toml
[target.lab]
native = true
```

```sh
ldap-cronin lab up --config config.toml   # the lab, with the source's domain SID and GUID
ldap-cronin clone -config config.toml     # imports into its database
ldap-cronin diff -config config.toml      # matches objects by objectGUID directly (it is the same on both sides)
```

- `[attributes] credentials = "copy"` copies the credentials the source returns, as over LDAP; the import writes as
  the system, so it also carries what Samba lets only the system write (the resource-based delegation), with the
  SIDs it names meaning the same in the lab.
- An `objectSid` is the domain's SID and a number within it, so the lab must have the source's domain SID: a lab
  `lab up --config` made has it. **It is chosen only when the domain is created**; a lab made otherwise
  (`lab up --realm`) is refused before anything is written: `lab reset`, then `lab up --config` again.
- `clone` names the lab and lists what it will do before stopping it (`-y` skips the question). The lab container is stopped only during the import and resumed afterwards, also on failure. If the lab's domain (root DN, SID, GUID) differs from the source, it refuses without writing anything.
- It has no dry-run: nothing goes over LDAP, so there is no LDIF.
- After the import it runs `dbcheck` (Samba's database check) and fails on errors. It also advances the RID allocation so RIDs of users created over LDAP later do not collide with imported ones.
- It can be re-run: an object that already exists with the same `objectGUID` gets only its attribute differences updated. **If an object with a different `objectGUID` exists at the same DN, it fails without rewriting** (`objectGUID` cannot be changed).
- It writes no marker and no mapping file: neither is needed when the `objectGUID` is the same.
- `fast_password = true` makes it about 3 times faster: 5,000 users and 50 groups took 24s instead of 75s (an LDAP `clone`
  took 60s). Most of the time of a user goes into the hashes Samba derives from the password (the NT hash, and the
  Kerberos keys salted with the account name). With it the first user gets the fixed password as usual; the
  others get the NT hash it got, written directly. **Those users then have no Kerberos AES keys:** they log on over
  LDAP, NTLM and Kerberos with RC4, but not where only AES is allowed. Leave it off when the test needs the
  production behavior. The self-check at the start also tries it (and rolls it back), and the summary says how many
  users got the hash directly.
- `diff` switches to matching by `objectGUID` automatically when the `objectGUID` is the same on both sides; the summary shows `rename/move check: on (objectGUID preserved ...)`. The decision uses the `objectGUID` of the first object `diff` compares under `base_dn`, found with the configured filters (`base_dn` itself only when nothing is under it, because a container that exists in the lab from the start, such as `CN=Users`, has the lab's own `objectGUID`). **The domain GUID alone is not enough**: after a plain LDAP `clone` into a lab made by `lab up --config`, the domain GUID matches but the objects' GUIDs differ.

### Importing in slices (`-time-limit`)

A large import can outlast the session it runs in (a cloud shell closes an idle session, and its docker data goes
with it). `clone -time-limit 15m` stops before the first object it would start after 15 minutes, with exit code 3:
everything it wrote is complete, object by object, and running `clone` again goes on.

```sh
until ldap-cronin clone -config config.toml -y -time-limit 15m; do
  [ $? -eq 3 ] || break                         # 3: stopped at the limit; anything else is an error
  ldap-cronin lab snapshot slice --force         # what is done so far, kept outside the session
done
```

- From a dump (`[source] ldif`), the import keeps a journal in the lab's volume of the objects it finished (and
  of their references), and the next run skips them without reading the lab again: its summary says how many
  (`skipped, done by an earlier run`). Being in the volume, a snapshot carries exactly the journal of its data,
  so a lab restored from an older snapshot resumes from that snapshot's progress. The journal is valid for the same
  dump and the same config only; with another it is dropped and every object is compared. It is removed when an
  import completes.
- From a server there is no journal (it may change between runs): the next run compares every object again.
- The end of a slice advances the RID allocation (the lab can be used and snapshotted as it is); `dbcheck`, which
  reads the whole database, runs once, at the end of the slice that completes the import. So do the ACLs
  (`[target.lab] acl = "source"`).
- An interrupted import (Ctrl-C, a lost session) keeps the journal too, but its last object may be half done:
  the next run compares that one and completes it.
- Done means done for the lab: do not write the lab between slices (a test run, a hand edit), or that object is
  not compared again until a complete import has removed the journal.
- The summary of every `clone` ends with how long each phase took (`time: reading the source 42s, OUs and parents 3s, user
  12m4s, ...`), to see where a slow run spends its time.

### Limitations (read these)

- **Samba only.** It cannot be used with a real AD (Windows AD does not let you create an object with a chosen `objectGUID`, either over LDAP or directly).
- **This is not a supported way of using Samba.** It uses Samba internals (the replication path, with system privileges and the `provision` and `relax` controls). It depends on the Samba version, and only **4.19.5** has been verified.
  At the start of each run it tries the same operation (and rolls it back) and fails immediately if it does not work. On another version it warns and continues, provided this self-check passes.
- **Password hashes are not copied** (they cannot be read over LDAP). User passwords are the fixed password, as in a normal `clone` (with `fast_password`, without Kerberos AES keys).
- **The ACLs can be the source's too**, with `[target.lab] acl = "source"` (off by default: few tests read ACLs, and the domain root's changes the whole lab): each object's owner, group and DACL (`nTSecurityDescriptor`, read with the SD flags control, so no SACL), and those of the domain root and the containers above `base_dn`. Samba keeps what is written and computes the inherited ACEs from each object's parents, so with the parents above the source's too, the descriptors are the source's byte for byte (measured on 4.19.5, from a Samba source). `diff` then compares each object's owner, group, protected flag and explicit ACEs (not their order), and names the ACEs that differ. A dump carries the descriptors (taken before, it has none: the lab keeps its own, with a warning). The objects outside `base_dn` a reference or a membership brought keep the lab's. Over LDAP, `[attributes] acl = "copy"` copies the ACLs with each SID translated to the target's ([active-directory.md](active-directory.md#how-it-behaves)).
- **What the server keeps is the source's too** (`[target.lab] server_attributes = "lab"` leaves the lab's own): `whenCreated`, `lastLogonTimestamp`, `lastLogon`, `logonCount`, `lockoutTime`, `badPwdCount`, `sIDHistory` and `mS-DS-CreatorSID`. An add takes the time of the add as `whenCreated` whatever it is given, and the others are the server's, which over LDAP only the system may write (Windows refuses them all), so the helper sets them right after the add, as the system. The self-check at the start tries it. `diff` does not compare them (over LDAP they are the target's). Not settable: `whenChanged` (every change gives it the time again), `pwdLastSet` (0 or -1 only; a must-change user is reproduced), `uSNCreated` and `uSNChanged` (each DC's counters). `lastLogon` and `logonCount` are those of the DC the dump was taken from, as they are not replicated.
- **RIDs can collide.** If the RID of a source user is the same as that of one of the lab's standard objects (RID 1000, 1101, 1102), importing that object fails with an error that names the colliding object
  (it is never skipped silently). For a source built on Samba the configuration is the same, so collisions normally do not occur.
- The import runs in a helper container (Python from the lab image) with the volumes mounted, so **the lab image must have Python and Samba** (the offline package's image does).

## A Windows Server lab on Amazon EC2 (`[target.lab] platform = "ec2"`)

For tests that need a real Windows Server domain controller rather than Samba, `lab up --config` makes one on EC2
through the `aws` command: a new forest with the source's domain name, NetBIOS name and functional levels, its
Administrator password the target password, LDAPS reached through Systems Manager at the port of `[target] url`.
`check`, `clone` and `diff` then read and write it as any server, through that tunnel. Verified on Windows Server
2019: `lab up` from nothing to READY in about 20 minutes, then a clone diff clean ([design/ec2-lab.md](design/ec2-lab.md)).

```toml
[target]
url = "ldaps://localhost:12636"         # where the tunnel listens
bind_dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=com"
insecure_skip_verify = true             # the domain controller's certificate is self-signed
[target.lab]
platform = "ec2"
region = "ap-northeast-1"
subnet = "subnet-0123456789abcdef0"     # its instances must reach Systems Manager
instance_profile = "ldap-cronin-lab"    # a role with AmazonSSMManagedInstanceCore
# instance_type = "t3.large"
# windows = "2022"                      # 2016, 2019, 2022 or 2025
# disk_size = 50                         # the root volume in GiB, gp3 (default: the image's, 30)
# security_groups = ["sg-0123456789abcdef0"]   # attached to the instance (default: the VPC's default group);
#                                        # Systems Manager needs no inbound rule
# tags = { Owner = "me", CostCenter = "1234" }   # put on the instance and its volume too, as many as needed
#                                        # (an account's policy may require some); Name renames the instance
# public_ip = true                       # a public IPv4 address, for a subnet that reaches Systems Manager through
#                                        # an internet gateway only (no NAT, no VPC endpoints); without it the
#                                        # instance has none, whatever the subnet assigns
# ldaps_name = "ldap.test.example.com"  # one more DNS name of its LDAPS certificate (the DC's and the domain's are in it)
# ldap_port = 13389                      # the local port LDAP (389) is forwarded to too, for clients without LDAPS
# ldap_unsigned = true                   # a simple bind on 389 without signing taken (2025 refuses it by default)
# recycle_bin = true                     # the AD Recycle Bin enabled (forest level 2008 R2 or higher)
```

```sh
export LDAP_CRONIN_TARGET_PASSWORD='...'          # the Administrator's: Windows' complexity rule applies
ldap-cronin lab up --config config.toml --dry-run # the user data (no password in it) and the aws commands, nothing run
ldap-cronin lab up --config config.toml           # about 20 minutes; it ends with the tunnel commands
aws ssm start-session --target i-... --document-name AWS-StartPortForwardingSession \
  --parameters 'portNumber=636,localPortNumber=12636'   # in a terminal of its own, as lab up printed it
ldap-cronin check -config config.toml
ldap-cronin clone -config config.toml
ldap-cronin lab reset --config config.toml -y     # terminates the lab's instance (its snapshots stay)
```

- **lab up** finds the lab's instance by its tag (`ldap-cronin.lab`, terminated ones left out): a running one is
  used, a stopped one started, two are refused. Else it takes the latest image of `windows`, launches the
  instance (IMDSv2, the lab's tags and [target.lab] tags on it and its volume) with the user data that makes it the domain controller,
  and asks it through Systems Manager every 30 seconds until its user data says READY, showing the last line of its
  `C:\ldap-cronin\setup.log` meanwhile (45 minutes at most). It ends with the tunnel commands; the tunnels are
  yours to run, as long as the lab is used.
- **The password is in the user data**, written there by the user's choice, for a lab to test with: it is never an
  argument (the user data goes to `aws` in a file only its owner reads, removed right after) nor in a log or the
  dry-run (which shows `<the target password>`), but the instance's user data keeps it, which its metadata and
  `ec2:DescribeInstanceAttribute` read. It must pass Windows' complexity rule (at least 8 characters, three of
  upper case, lower case, digits and symbols): it becomes the Administrator's before the domain exists, so lab up
  refuses another before AWS is asked anything.
- **lab reset --config** terminates the instances of the lab's tag, after naming them (`-y` skips the question);
  `--snapshots` deletes the lab's snapshots too, which it otherwise keeps.
- **lab down, status, snapshot, snapshots, restore, snapshot-rm** take `--config` too:

  ```sh
  ldap-cronin lab snapshot base --config config.toml --note "after the first clone"
  ldap-cronin lab snapshots --config config.toml
  ldap-cronin lab restore base --config config.toml   # then open the tunnels again, as it prints them
  ldap-cronin lab down --config config.toml           # stopped; lab up --config starts it again
  ```

  A snapshot is an EBS snapshot of the instance's root volume, tagged with the lab, its name and note (and
  `[target.lab] tags`). A running instance is stopped for it, so that the domain's database is closed, and started
  again once it is taken: a few minutes, then READY as after lab up. It completes in the background; a restore of
  one still pending waits for it. A restore replaces the instance's root volume by one made from the snapshot (the
  instance restarts and keeps its id, so the tunnel commands are the same; the replaced volume is deleted) and
  waits for READY. The lab is its forest's only domain controller, so a return to a past disk is safe. Snapshots
  cost their stored size (a new domain is some 15 GB of the volume).
- LDAP (389) as well, for a client that does not use LDAPS: `ldap_port` is the local port the tunnel forwards the
  instance's 389 to (the instance listens on 389 whatever it is). Windows Server 2019 takes a simple bind there
  without signing by default, and StartTLS (measured), as 2022 should; 2025 requires signing for a new forest, so
  `ldap_unsigned = true` sets `LDAPServerIntegrity` to 1 (signing not required). Unverified on 2025: a domain
  controllers' policy enforcing signing would set it back.
- The forest has the source's functional levels (`forestFunctionality` and `domainFunctionality` of its root DSE,
  which a dump carries): Install-ADDSForest is given them as `-ForestMode` and `-DomainMode`. A level a Windows
  Server of today cannot make (below 2008) or that needs a newer one (2025's, on `windows = "2022"`) is refused
  before anything is made; a dump taken before the levels were carried leaves the highest the instance makes.
- `recycle_bin = true` enables the AD Recycle Bin once the domain is up (it cannot be turned off again).
- `native` and `image` are refused (Windows lets no one choose a domain SID or an objectGUID).
- What it needs (IAM) and what is still unverified: [design/ec2-lab.md](design/ec2-lab.md).

## Using the offline package

Carry the tar.gz built by `make bundle` into an environment with docker but no internet access.
`make bundle EXCHANGE_ISO=<Exchange setup .iso>` builds one whose Samba4 AD image has Exchange's schema (its name ends
in `-exchange`); it holds Microsoft's files, so it goes into your own environment only. In the unpacked directory,
`lab up --config` with a `[target.lab]` without `image` takes the package's image.
`setup.sh <command>` in the unpacked directory is the same as `ldap-cronin lab <command>`. With no arguments it runs
`lab load` and starts nothing: the lab to clone into is made by `lab up --config`, with the source's domain.

```sh
tar xzf ldap-cronin-offline-*.tar.gz && cd ldap-cronin-offline-*
./setup.sh                                    # = ldap-cronin lab load; places ./ldap-cronin for your architecture
./ldap-cronin lab up --config config.toml    # the lab with the source's domain name, NetBIOS name, SID and GUID
./ldap-cronin clone -config config.toml
./setup.sh snapshot baseline
./setup.sh restore                            # pick from the list
```

`./setup.sh up --realm corp.example.local` (= `lab up --realm ...`) starts a lab with a domain of its own, to try the
lab without a source. Do not start one before `lab up --config`: its domain is not the source's (with `[target.lab]
native = true`, `clone` refuses it: "the lab's domain differs from the source's"), and only `lab reset` undoes it.

The package holds both images (Samba4 AD and OpenLDAP) in one `images/lab.tar`, so the base layers they share are stored once; `./setup.sh up --profile ldap --suffix dc=example,dc=org` starts the OpenLDAP lab.
`lab load` and `lab up` verify the package's `SHA256SUMS` and then run `docker load` on `images/lab.tar` when an image is missing (`--skip-verify` skips the verification, `--reload` loads it again).
For how the package is built see [DEVELOPMENT.md](DEVELOPMENT.md); for the procedure on the receiving side see [README-OFFLINE.md](../offline/README-OFFLINE.md).

## Troubleshooting

| Symptom | Cause and remedy |
|---|---|
| `existing container has different settings` | The domain name (suffix) or ports differ from the lab that was created. The data is not lost. To recreate it, use `lab reset` (snapshots are kept) |
| `docker run failed (port in use ...)` | Specify free ports with `--ldap-port` / `--ldaps-port` |
| `cannot connect to the docker daemon` | docker is not running, or you lack permission (docker group, sudo) |
| The lab logs `security xattrs are not writable here (rootless docker?)` | Not an error. Under rootless docker (for example the default of lima), Samba cannot write NT ACLs as `security.*` extended attributes, so the lab keeps them as `user.NTACL` instead. That is weaker (the file owner could change an ACL), which does not matter for a disposable lab. Rootful docker keeps Samba's default |
| A restore failed halfway | The volumes are in an incomplete state. Run `lab restore` again |
| `password unknown` (when restore creates a new lab) | Give the password in effect when the snapshot was taken, with `--admin-password` or the environment variable `SAMBA_ADMIN_PASSWORD` (OpenLDAP: `LDAP_ADMIN_PASSWORD`) |
| `holds the settings of a ... lab; use another --state-dir` | `.env` in this directory belongs to the other kind of lab. Give the second kind its own `--state-dir` |
| The OpenLDAP lab exits at its first start, and the log shows `ldap_add` / `ldap_modify` errors | A file in `--schema-dir` failed. Fix it, then `lab reset` and `lab up` again |
| `port N is used by instance ...` | The host port overlaps with another instance. Change `--ldap-port` / `--ldaps-port` |
| A warning that the image architecture differs | Rebuild the package for the receiving machine's `uname -m` (for example `make bundle PLATFORM=linux/arm64`) |
| EC2: `lab up` keeps waiting, and the instance never shows in Systems Manager | The instance cannot reach Systems Manager: a subnet with an internet gateway and no NAT needs `public_ip = true`; else a NAT gateway or VPC endpoints. Its role needs `AmazonSSMManagedInstanceCore` |
| EC2: `Invalid IAM Instance Profile name` | `instance_profile` names an instance profile, not a role: `aws iam list-instance-profiles` lists them |
| EC2: `run-instances` refused by a tag policy | Give the tags the account requires in `[target.lab] tags`; they go on the instance, its volume and the snapshots |
| EC2: `lab up` keeps waiting, its last line of `setup.log` showing an error | The user data failed. `C:\ldap-cronin\setup.log` on the instance has the whole of it (a Session Manager shell reads it); `lab reset --config` and `lab up --config` start over. Without READY, `lab up` gives up after 45 minutes |
