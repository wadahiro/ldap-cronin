# LDAP cRONIN package for air-gapped environments

A package for using `ldap-cronin` with a local AD-compatible Samba4 in an environment with no internet access. It needs only docker (no docker compose), and supports snapshots of the cloned data.

## Contents

| Path | Description |
|---|---|
| `setup.sh` | Entry point. Picks the `ldap-cronin` binary for your architecture and passes the arguments to the `lab` subcommand |
| `bin/ldap-cronin-linux-{amd64,arm64}` | The tool binaries (statically linked; nothing else is needed) |
| `images/samba-ad.tar` | The Samba4 AD docker image (produced by `docker save`) |
| `IMAGE` / `SHA256SUMS` | The image name / checksums to verify that nothing was corrupted in transit |
| `config.example.toml` | An example tool configuration |
| `README.md` / `docs/` | The full documentation of the tool. `docs/lab.md` has the details of this lab and of snapshots |

## Requirements

- docker
- The image is for the architecture chosen at build time (`linux-amd64` / `linux-arm64` in the file names). `uname -m`: `x86_64` is amd64, `aarch64` is arm64.

## Starting

```sh
tar xzf ldap-cronin-offline-*.tar.gz
cd ldap-cronin-offline-*
./setup.sh                              # asks for the domain name and the administrator password
./setup.sh --realm corp.example.local   # to specify the domain name
```

`setup.sh` runs `ldap-cronin lab up`: it does the following, then prints the connection details and an example `[target]` setting.

1. Verifies file integrity with `SHA256SUMS`
2. Runs `docker load` on `images/samba-ad.tar` (skipped if the image already exists)
3. Starts the Samba4 AD and checks that it can be searched over LDAPS

The binary for your architecture is also placed at `./ldap-cronin`.

## About the domain name

**The domain name is fixed at the first start, not at image build.** An existing domain cannot be renamed; to change it, delete the data:

```sh
./setup.sh reset                            # deletes the domain data and the saved settings (.env); snapshots are kept
./setup.sh --realm new.example.local        # create it again
```

The Kerberos realm, NetBIOS name (at most 15 characters; use `--netbios` if too long) and base DN are derived from the domain name.

## Using the tool

```sh
cp config.example.toml config.toml      # change [target] to the values printed by setup.sh
./ldap-cronin clone -config config.toml -dry-run
./ldap-cronin clone -config config.toml
./ldap-cronin diff  -config config.toml
```

Passwords are entered at run time, not written in the configuration file. See `README.md`.

## Snapshots (restore cloned data at any time)

```sh
./setup.sh snapshot baseline --note "right after clone"   # take one (you can take several; without a name it is named by date and time)
./setup.sh snapshots                                      # list
./setup.sh restore                                        # pick by number from the list and restore (you can also give a name)
./setup.sh snapshot-rm baseline                           # delete
```

- Taking or restoring stops Samba cleanly and starts it again; about 7 seconds (longer with more data). The checksum is verified before restoring.
- The GUID mapping used by `diff` can be stored too: `./setup.sh snapshot baseline --config config.toml` (or `--guid-map FILE`). Add the same option when restoring to write it back (an existing mapping is moved to `.bak`).
- Snapshots are stored in `./snapshots/`. They contain password hashes; handle with care.
- Another lab in the snapshot's state can run beside the current one: `./setup.sh restore baseline --instance dev2 --ldaps-port 22636` (omitted ports are chosen automatically). `./setup.sh reset --instance dev2 -y` deletes only dev2.

See `docs/lab.md` for details.

## Starting a clone source for testing at the same time

To try the tool out, start one more Samba with sample data (disposable; not saved).

```sh
./setup.sh --with-sample-source         # clone source: ldaps://localhost:11636 (same administrator password)
```

## Operations

```sh
./setup.sh status     # status
./setup.sh down       # stop (data is kept; running ./setup.sh again resumes with the same settings)
./setup.sh reset      # delete data and settings
./setup.sh help       # all options
```

## Notes

- The LDAPS certificate is a self-signed one created by Samba, so set `insecure_skip_verify = true` in the tool's configuration or specify `ca_file`.
- The administrator password is saved in `.env` (permissions 600). Handle it with care.
- `docker volume prune` can delete lab data. **Take a snapshot right after `clone`.**
- The Samba in this package has a relaxed password policy for testing. Do not use it as a substitute for production.

## Importing with the same objectGUID and objectSid as the source (Samba lab only)

Build a lab with the same domain SID and GUID as the source and import objects with their `objectGUID` and `objectSid` (the source must be reachable). No extra components are needed.

    ./ldap-cronin lab up --like-source config.toml
    ./ldap-cronin clone -native -config config.toml

This uses unsupported Samba internals. Read docs/lab.md for the limitations (Samba only, verified on 4.19.5, password hashes do not become identical).
