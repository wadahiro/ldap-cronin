# The test lab (`lab`) and snapshots

`ldap-cronin lab` starts and stops an AD-compatible Samba4 for testing on docker, and lets you **take snapshots of the data and restore them at any time**.
Keep the data created by `clone` as a snapshot, and bring it back in a few seconds whenever another program modifies the target.

It needs only docker (no docker compose), and can be carried into an environment with no internet access ([offline package](#using-the-offline-package)).

```sh
ldap-cronin lab up --realm corp.example.local    # start a Samba4 AD
ldap-cronin clone -config config.toml            # create the data
ldap-cronin lab snapshot baseline                # save the state right after the clone
# ... another program modifies the target ...
ldap-cronin diff -config config.toml             # see what changed
ldap-cronin lab restore baseline                 # restore the original state (a few seconds)
```

## Commands

| Command | Description |
|---|---|
| `lab up` | Loads the image (if missing), starts the Samba4 AD and checks that it works over LDAPS |
| `lab down` | Stops it. The data is kept, and running `up` again resumes with the same settings |
| `lab reset [-y] [--snapshots]` | Deletes the domain data and the settings (`.env`). Snapshots are kept by default |
| `lab status` | Shows the state of the lab and the number of snapshots |
| `lab snapshot [name] [--note text] [--force] [--config f \| --guid-map f]` | Saves the current data as a snapshot. `--config` / `--guid-map` also include the GUID mapping |
| `lab snapshots` | Lists the snapshots |
| `lab restore [name]` | Restores the data to a snapshot's state. Without a name, you pick from a list. **If the target lab does not exist, it is created from the snapshot** ([starting another lab](#starting-another-lab-from-a-snapshot-on-a-different-port)) |
| `lab snapshot-rm name` | Deletes a snapshot |

Common options: `--state-dir` (where `.env` is placed; default `.`), `--snapshot-dir` (default `<state-dir>/snapshots`), `--bundle-dir` (the location of the offline package; found automatically if omitted),
and `--instance` (the instance to operate on; the default lab if omitted).
`lab help` shows all options.

## Starting (`lab up`)

```sh
ldap-cronin lab up                                  # asks for the domain name and the administrator password (interactive)
ldap-cronin lab up --realm corp.example.local       # specify the domain name
ldap-cronin lab up --with-sample-source             # also start a clone source with sample data, for trying the tool out
ldap-cronin lab up --like-source config.toml        # create it with the same domain name, SID and GUID as the source (for clone -native; see below)
```

- **The domain name is fixed at the first start, not at image build.** The same image can use a different domain name in each environment. To change it, run `lab reset` and create the lab again.
- The Kerberos realm (upper case), the NetBIOS name (the first label in upper case, at most 15 characters; use `--netbios` if it is long) and the base DN are derived from the domain name automatically.
- The administrator password is given by interactive input (twice), `--admin-password`, or the environment variable `SAMBA_ADMIN_PASSWORD`. **If none is given, a password that satisfies the complexity rules is generated and displayed.**
  The environment variable is recommended, because a command-line value stays in the shell history.
- The settings are saved in `.env` (permissions 600) and can be omitted from the second time on. Precedence: option > environment variable > `.env`. `lab reset` deletes `.env`.
- If a container already exists with a different domain name or ports, the command **refuses without damaging the data**. With the same settings it resumes, even from a stopped state.
- After starting, it prints the connection details and an example `[target]` setting. The LDAPS certificate is self-signed, so use `insecure_skip_verify = true` (or `ca_file`).
- The DC host name is fixed to `dc1`.

## Snapshots

A snapshot is the contents of the lab's docker volumes (the Samba databases) written out to files on the host.

```
snapshots/
  baseline/
    private.tar      contents of /var/lib/samba (the domain data)
    etc.tar          contents of /etc/samba (the configuration)
    guid-map.tsv     the GUID mapping (only when taken with --config / --guid-map)
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
NAME                     CREATED              DOMAIN                       SIZE  MAP  NOTE
baseline                 2026-10-16 22:34:54  corp.example.local         44.4MB  yes  right after clone
after-delete             2026-10-16 22:35:04  corp.example.local         44.4MB  -    after deleting 4 users
```

`DOMAIN` is the domain of the lab the snapshot was taken from; you can restore only into a lab with the same domain (or a newly created lab). `MAP` shows whether the GUID mapping is included.

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

### Starting another lab from a snapshot on a different port

While the current lab keeps running, you can start another lab in the snapshot's state next to it, on different host ports. It uses separate volumes, so the two do not affect each other. Name it with `--instance` and `restore`.

```sh
ldap-cronin lab restore baseline --instance dev2 --ldaps-port 22636    # start a lab in baseline's state on different ports
ldap-cronin lab restore --instance dev2                                # pick from the list; free ports are chosen automatically
ldap-cronin lab restore baseline --instance dev2 --guid-map guid-map-dev2.tsv   # write the mapping back to a file for dev2
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

### Including the GUID mapping in a snapshot

The GUID mapping that `diff` uses to detect renames and moves ([docs/diff.md](diff.md)) must match the restored data. Include it in the snapshot and **one restore brings back both**.

```sh
ldap-cronin clone -config config.toml                          # the mapping in [state] file is recorded
ldap-cronin lab snapshot baseline --config config.toml         # include the mapping with the data (--guid-map FILE also works)
ldap-cronin lab restore baseline --config config.toml          # restore the data and write the mapping back to [state] file (an existing mapping is moved to .bak)
```

- The mapping comes from `[state] file` in `--config`, or from `--guid-map`. If neither is given, it is neither included nor written back. Restoring a snapshot that contains one without either only reports where the mapping is and leaves your current one untouched.
- **When restoring into another instance, specify a different file** (`--instance dev2 --guid-map guid-map-dev2.tsv`) so the original lab's mapping is not overwritten.
- The mapping is keyed by the **domain** (the `objectGUID` of the domain root), not by host name and port, so it works for an instance on a different port. A mapping from a different domain (such as a recreated lab) is rejected.
- Restored `objectGUID` values are unchanged, so a snapshot with the mapping taken right after `clone` keeps `diff` rename/move detection correct after any restore.
- The mapping's checksum is verified before restoring; if corrupt, the current data is left untouched.

## Importing with the same objectGUID and objectSid (`clone -native`, Samba only)

A normal `clone` creates objects over LDAP, so the target assigns new `objectGUID` and `objectSid` values. **For a lab (Samba) only, you can import with the same `objectGUID` and `objectSid` as the source**, for testing applications that depend on them.

```sh
# 1. Create a lab with the same domain as the source (name, NetBIOS name, domain SID and GUID); this connects to the source and reads them
ldap-cronin lab up --like-source config.toml
# 2. Import into the lab (it does not connect to the target LDAP; it stops the lab and writes directly to the Samba database)
ldap-cronin clone -native -config config.toml
# 3. diff works without the mapping (objectGUID is the same, so GUIDs are matched directly)
ldap-cronin diff -config config.toml
```

- `lab up --like-source <config>` reads the domain's `objectSid` / `objectGUID`, the domain name and the NetBIOS name from `[source]` and creates Samba with the same values. `--domain-sid` / `--domain-guid` set them directly and take precedence. **They apply only when the domain is created** (to change them, `lab reset` and recreate).
- `clone -native` selects the lab with `-lab-prefix` (default `ldap-cronin`) and `-lab-instance`. The lab container is stopped only during the import and resumed afterwards, also on failure. If the lab's domain (root DN, SID, GUID) differs from the source, it refuses without writing anything.
- After the import it runs `dbcheck` (Samba's database check) and fails on errors. It also advances the RID allocation so RIDs of users created over LDAP later do not collide with imported ones.
- It can be re-run: an object that already exists with the same `objectGUID` gets only its attribute differences updated. **If an object with a different `objectGUID` exists at the same DN, it fails without rewriting** (`objectGUID` cannot be changed).
- It does not create the `[state] file` (GUID mapping); it is not needed when the `objectGUID` is the same.
- `diff` switches to mapping-free detection automatically when the `objectGUID` is the same on both sides; the summary shows `rename/move check: on (objectGUID preserved ...)`. The decision uses the `objectGUID` of the `base_dn` object (if `base_dn` is a container that exists in the lab from the start, such as `CN=Users`, the first object under it). **The domain GUID alone is not enough**: after a plain LDAP `clone` into a `--like-source` lab, the domain GUID matches but the objects' GUIDs differ.

### Limitations (read these)

- **Samba only.** It cannot be used with a real AD (Windows AD does not let you create an object with a chosen `objectGUID`, either over LDAP or directly).
- **This is not a supported way of using Samba.** It uses Samba internals (the replication path, with system privileges and the `provision` and `relax` controls). It depends on the Samba version, and only **4.19.5** has been verified.
  At the start of each run it tries the same operation (and rolls it back) and fails immediately if it does not work. On another version it warns and continues, provided this self-check passes.
- **Password hashes are not copied** (they cannot be read over LDAP). User passwords are the fixed password, as in a normal `clone`.
- `whenCreated` and `uSNCreated` become the lab's local values (not the source's).
- **RIDs can collide.** If the RID of a source user is the same as that of one of the lab's standard objects (RID 1000, 1101, 1102), importing that object fails with an error that names the colliding object
  (it is never skipped silently). For a source built on Samba the configuration is the same, so collisions normally do not occur.
- The import runs in a helper container (Python from the lab image) with the volumes mounted, so **the lab image must have Python and Samba** (the offline package's image does).

## Using the offline package

Carry the tar.gz built by `make bundle` into an environment with docker but no internet access.
`setup.sh <command>` in the unpacked directory is the same as `ldap-cronin lab <command>` (with no arguments, or a flag first, it runs `up`).

```sh
tar xzf ldap-cronin-offline-*.tar.gz && cd ldap-cronin-offline-*
./setup.sh --realm corp.example.local     # = ldap-cronin lab up --realm ...
./ldap-cronin clone -config config.toml  # setup.sh places the binary for your architecture here
./setup.sh snapshot baseline
./setup.sh restore                        # pick from the list
```

`lab up` verifies the package's `SHA256SUMS` and then runs `docker load` on `images/samba-ad.tar` (`--skip-verify` skips this, `--reload` loads it again).
For how the package is built see [DEVELOPMENT.md](DEVELOPMENT.md); for the procedure on the receiving side see [README-OFFLINE.md](../offline/README-OFFLINE.md).

## Troubleshooting

| Symptom | Cause and remedy |
|---|---|
| `existing container has different settings` | The domain name or ports differ from the lab that was created. The data is not lost. To recreate it, use `lab reset` (snapshots are kept) |
| `docker run failed (port in use ...)` | Specify free ports with `--ldap-port` / `--ldaps-port` |
| `cannot connect to the docker daemon` | docker is not running, or you lack permission (docker group, sudo) |
| A restore failed halfway | The volumes are in an incomplete state. Run `lab restore` again |
| `password unknown` (when restore creates a new lab) | Give the password in effect when the snapshot was taken, with `--admin-password` or the environment variable `SAMBA_ADMIN_PASSWORD` |
| `port N is used by instance ...` | The host port overlaps with another instance. Change `--ldap-port` / `--ldaps-port` |
| A warning that the image architecture differs | Rebuild the package for the receiving machine's `uname -m` (for example `make bundle PLATFORM=linux/arm64`) |
