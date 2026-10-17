<p align="center">
  <img src="docs/logo.svg" width="420" alt="LDAP cRONIN">
</p>

# ldap-cronin (LDAP cRONIN)

A Go tool that clones the contents of a given subtree (OUs, groups and users) from one LDAP directory to another over LDAP, and later **verifies what changed on the target**.
It works with **Active Directory** (a real AD or Samba4 AD) and with **generic LDAP servers** such as OpenLDAP and 389 Directory Server. The server type is detected automatically (the `ad` and `ldap` profiles).

Typical use: build a realistic, safe-to-break test copy of a directory (with fixed passwords and masked attributes), let another program change it, and check exactly what changed with `diff`.

The name is a pun on "clone" and "ronin", a masterless samurai: cRONIN is a **c**lone that has gone **ronin**, a standalone copy that is not tied to its source.

## Documentation

| File | Contents |
|---|---|
| [docs/generic-ldap.md](docs/generic-ldap.md) | Using a generic LDAP server (OpenLDAP and others): profiles, what differs from AD, limitations |
| [docs/diff.md](docs/diff.md) | `diff` output and comparison rules (every pattern), rename and move detection |
| [docs/lab.md](docs/lab.md) | The test lab (`lab`): usage, **taking and restoring snapshots**, using the offline package |
| [docs/operations.md](docs/operations.md) | Large data sets, load on the source and target AD, memory, performance figures |
| [offline/README-OFFLINE.md](offline/README-OFFLINE.md) | Procedure for air-gapped environments (shipped inside the offline package) |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | For developers: layout, build and test, CI, design decisions |

## Subcommands

| Command | Description |
|---|---|
| `clone [-config f] [-dry-run]` | Add and update. `-dry-run` does not connect to the target; it writes LDIF to standard output (progress logs go to standard error) |
| `clone -native [-lab-prefix p] [-lab-instance n]` | **Samba lab only**: import with the same `objectGUID` and `objectSid` as the source (into a lab created with `lab up --like-source`). Uses unsupported internals. For the limitations see [docs/lab.md](docs/lab.md#importing-with-the-same-objectguid-and-objectsid-clone--native-samba-only) |
| `diff [-config f] [-max-values n]` | Compare the source and the target. Exit code 1 if there are differences (2 on error). For how to read the output see [docs/diff.md](docs/diff.md) |
| `list-attrs [-profile ad\|ldap]` | Show the default attributes (allow list) per object type |
| `lab up / down / reset / status` | Start and stop a test lab on docker: Samba4 AD, or OpenLDAP with `--profile ldap`. See [docs/lab.md](docs/lab.md) |
| `lab snapshot / snapshots / restore` | Take, list and restore snapshots of the lab data |
| `version` | Print the version |

Objects are applied in this order: parent OUs/containers, then groups and users, then `member`/`manager`/`managedBy`.
Parents above `base_dn` are created automatically if they do not exist on the target. The target is expected to be empty, and nothing is ever deleted (add and update only).

## Usage

```sh
cp config.example.toml config.toml   # edit it
make build                           # produces bin/ldap-cronin (requires Go)
./bin/ldap-cronin clone -dry-run    # check the LDIF first
./bin/ldap-cronin clone
./bin/ldap-cronin diff
```

Passwords are never kept in the configuration file; they are prompted for at run time. For non-interactive use set the environment variables `LDAP_CRONIN_SOURCE_PASSWORD` / `LDAP_CRONIN_TARGET_PASSWORD` / `LDAP_CRONIN_USER_PASSWORD`.

Ctrl-C stops a run at its next LDAP operation and still finishes its cleanup (a mapping file is written, a lab stopped for an import is resumed); a re-run of `clone` continues from there. See [docs/operations.md](docs/operations.md#stopping-a-run-and-hung-servers).

## Server types (profiles)

`[scope] profile` is `auto` by default: the source's root DSE decides between `ad` (Active Directory, Samba AD) and `ldap` (any other RFC 4510 server).
The target must be of the same type. The profile selects the default filters and attribute lists, how a user's fixed password is set, how DN-valued attributes are discovered and which attribute identifies an object across renames (`objectGUID` or `entryUUID`).
The rest of this README describes AD; for a generic server see [docs/generic-ldap.md](docs/generic-ldap.md).

## How attributes are handled

- **Allow-list based.** Only the listed attributes are copied. Adjust the defaults with `extra_include` (add), `exclude` (remove) and `include.<type>` (replace) in `[attributes]`.
- Attributes that cannot be migrated (`objectGUID`, `objectSid`, `unicodePwd`, ...) are an error if you list them.
- **Masking**: attributes in `[mask] attributes` are replaced with a fixed string on the target, and `diff` does not compare them. Identity, unique, DN-valued and non-string attributes cannot be masked.
- AD users are created in three steps: add (disabled), set `unicodePwd` with a modify, then set `userAccountControl` to the source value. A real AD only accepts `unicodePwd` in a modify ([KB 269190](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/change-windows-active-directory-user-password)).
- **DN-valued attributes** (`member`, `manager`, `managedBy`, and anything you add such as `seeAlso`) are detected from the source schema, not from a fixed list.
  They are applied after all objects exist, because a reference to a missing object fails. References to objects outside the cloned scope that do not exist on the target are skipped with a warning.
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

## When the target is a real AD

- Setting a user's password (`unicodePwd`) **requires LDAPS**. Over `ldap://` the password change is rejected (Samba does the same).
- The fixed password must satisfy the target domain's password policy (complexity and so on). Otherwise setting the password after creating the user fails.
- The LDAP signing policy may reject a simple bind over `ldap://`. Use LDAPS or `start_tls`.
- For a self-signed certificate, pass the CA with `ca_file`. For testing only, `insecure_skip_verify` is also available.

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
