# LDAP cRONIN package for air-gapped environments

A package for using `ldap-cronin` with a local AD-compatible Samba4, or OpenLDAP, in an environment with no internet access. It needs only docker (no docker compose), and supports snapshots of the cloned data.

## Contents

| Path | Description |
|---|---|
| `setup.sh` | Entry point. Picks the `ldap-cronin` binary for your architecture and passes the arguments to the `lab` subcommand; with none, it loads the images (`lab load`) |
| `bin/ldap-cronin-linux-{amd64,arm64}` | The tool binaries (statically linked; nothing else is needed) |
| `images/lab.tar` | The Samba4 AD and OpenLDAP docker images (one `docker save`, so their shared layers are stored once). In a package whose name ends in `-exchange`, the Samba4 AD image writes Exchange's schema to every lab it creates; it holds Microsoft's files: keep the package in your own environment |
| `IMAGE` / `SHA256SUMS` | The image names (`ad=` / `ldap=`) / checksums to verify that nothing was corrupted in transit |
| `config.example.toml` | An example tool configuration |
| `README.md` / `docs/` | The full documentation of the tool. `docs/lab.md` has the details of this lab and of snapshots |

## Requirements

- docker
- The image is for the architecture chosen at build time (`linux-amd64` / `linux-arm64` in the file names). `uname -m`: `x86_64` is amd64, `aarch64` is arm64.

## Starting

```sh
tar xzf ldap-cronin-offline-*.tar.gz
cd ldap-cronin-offline-*
./setup.sh                              # verify the files and load the images; starts nothing
```

`setup.sh` with no arguments runs `ldap-cronin lab load`:

1. Verifies file integrity with `SHA256SUMS`
2. Runs `docker load` on `images/lab.tar` (skipped if the images already exist; `./setup.sh --reload` loads again)

It also places the binary for your architecture at `./ldap-cronin`, and starts no lab.

## Making the lab to clone into

The lab gets the domain of the source (its name, NetBIOS name, domain SID and GUID), read from the source or a dump
of it. Write `[source]`, `[target]` and `[target.lab]` in config.toml (see `config.example.toml` and `README.md`), then:

```sh
./ldap-cronin lab up --config config.toml   # makes the lab like the source, then prints the next steps
./ldap-cronin check -config config.toml
./ldap-cronin clone -config config.toml -dry-run   # the LDIF clone would write (over LDAP only; refused with native = true)
./ldap-cronin clone -config config.toml
./ldap-cronin diff  -config config.toml
```

Passwords are entered at run time, not written in the configuration file.

## Trying the lab without a source

`./setup.sh up` starts a lab with a domain of its own (`ldap-cronin lab up`); it asks for the domain name and the
administrator password, then prints the connection details and an example `[target]` setting.

```sh
./setup.sh up                              # asks for the domain name and the administrator password
./setup.sh up --realm corp.example.local   # to specify the domain name
./setup.sh up --profile ldap --suffix dc=example,dc=org   # an OpenLDAP lab instead (for a generic LDAP source)
./setup.sh up --with-sample-source         # also a disposable clone source with sample data: ldaps://localhost:11636
```

**Do not start this lab when you mean to clone a source.** Its domain is not the source's, and the domain is fixed
when the lab is created: an existing domain cannot be renamed. To change it, delete the data:

```sh
./setup.sh reset                            # deletes the domain data and the saved settings (.env); snapshots are kept
./ldap-cronin lab up --config config.toml   # create it again like the source
```

The Kerberos realm, NetBIOS name (at most 15 characters; use `--netbios` if too long) and base DN are derived from the domain name.

## Snapshots (restore cloned data at any time)

```sh
./setup.sh snapshot baseline --note "right after clone"   # take one (you can take several; without a name it is named by date and time)
./setup.sh snapshots                                      # list
./setup.sh restore                                        # pick by number from the list and restore (you can also give a name)
./setup.sh snapshot-rm baseline                           # delete
```

- Taking or restoring stops Samba cleanly and starts it again; about 7 seconds (longer with more data). The checksum is verified before restoring.
- The markers `diff` uses to detect renames are part of the data, so detection keeps working after a restore.
- Snapshots are stored in `./snapshots/`. They contain password hashes; handle with care.
- Another lab in the snapshot's state can run beside the current one: `./setup.sh restore baseline --instance dev2 --ldaps-port 22636` (omitted ports are chosen automatically). `./setup.sh reset --instance dev2 -y` deletes only dev2.

See `docs/lab.md` for details.

## Operations

```sh
./setup.sh status     # status
./setup.sh down       # stop (data is kept; ./setup.sh up, or lab up --config, resumes it with the same settings)
./setup.sh reset      # delete data and settings
./setup.sh help       # all options
```

## Notes

- The LDAPS certificate is a self-signed one created by Samba, so set `insecure_skip_verify = true` in the tool's configuration or specify `ca_file`.
- The administrator password is saved in `.env` (permissions 600). Handle it with care.
- `docker volume prune` can delete lab data. **Take a snapshot right after `clone`.**
- The Samba in this package has a relaxed password policy for testing. Do not use it as a substitute for production.

## Importing with the same objectGUID and objectSid as the source (Samba lab only)

Name the lab in config.toml with `native = true`; `lab up --config` builds it with the same domain SID and GUID as the source (read from the source, or a dump of it), and `clone` imports objects with their `objectGUID` and `objectSid`. No extra components are needed.

    [target.lab]
    native = true

    ./ldap-cronin lab up --config config.toml
    ./ldap-cronin clone -config config.toml

This uses unsupported Samba internals. Read docs/lab.md for the limitations (Samba only, verified on 4.19.5, password hashes do not become identical).
`clone -dry-run` is refused with `native = true`: it writes the lab's database directly, so there is no LDIF.
