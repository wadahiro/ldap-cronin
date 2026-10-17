# An OpenLDAP lab (lab --profile ldap)

Status: implemented. Where the code differs from the proposal below, section 8 says how and why.

## 1. Goal

`lab` gives an AD source a disposable, snapshot-able Samba target. A generic LDAP source has nothing comparable:
the e2e tests pull `osixia/openldap:1.5.0` (OpenLDAP 2.4, unmaintained) from the network, and a user has to build
their own target. The goal is the same experience for `profile = "ldap"`: our own image, built like the Samba one,
started, snapshotted, restored and carried into an air-gapped network by the same `lab` commands.

Out of scope: `clone -native` (not needed: the relax control already keeps `entryUUID` over LDAP), 389-ds, and
replication.

## 2. The image (`docker/ldap/`)

| Decision | Choice | Why |
|---|---|---|
| Base | `ubuntu:24.04`, `slapd` + `ldap-utils` from the distribution | Same base as the Samba image, so a bundle that saves both images stores the base layers once. Gives OpenLDAP 2.6.10, the version the relax control was verified on |
| Process | `tini` -> `entrypoint.sh` -> `slapd -d 0` in the foreground | As in the Samba image: signals reach slapd, which closes the database cleanly on `docker stop` (snapshots rely on that) |
| Configuration | `cn=config` (`/etc/ldap/slapd.d`), generated on the first start from the environment | Like Samba's provisioning: the suffix and the admin password are fixed when the directory is created. `slapd.conf` was rejected: 2.6 deprecates it, and production servers use `cn=config` |
| Database | `mdb`, suffix from the environment, `olcRootDN: cn=admin,<suffix>` | The rootdn may use the relax control, so `[mapping] mode = "preserve"` works without an ACL change |
| Schemas | `core`, `cosine`, `nis`, `inetorgperson` (the profile's default kinds need them), plus every `*.ldif` in `/schema.d` | A production deployment usually has its own schema; without it the first Add of such an object fails. Files under `/schema.d` are loaded once, at creation, in name order |
| Overlays | `memberof` and `refint` on by default; `ppolicy` off | `memberOf` is what applications read, and production OpenLDAP almost always has it. `ppolicy` would refuse the fixed password under a strict policy; a deployment that needs it adds it with an LDIF in `/schema.d` (see 6) |
| Indexes | `objectClass`, `entryUUID`, `cn`, `uid`, `member`, `uniqueMember` (eq) | `entryUUID` is what diff searches for a moved object |
| TLS | A self-signed certificate generated at creation; LDAPS on 636, StartTLS on 389 | Same as the Samba lab: passwords are sent, and the tool's TLS options are exercised |
| Health | `/tmp/ldap-ready`, removed on every start, written after a search as the rootdn succeeds | Same pattern as `/tmp/ad-ready`, for the same reason (a stale marker made the container healthy too early) |
| Privileges | None (no `--cap-add`) | slapd needs no xattrs, so rootless docker works without the Samba workaround |
| Sample data | `seed.ldif` loaded when `SEED_SAMPLE_DATA=true`: nested OUs, users with non-ASCII and escaped RDNs, `groupOfNames` and `groupOfUniqueNames`, a `posixGroup`, `manager` and `seeAlso` references | For `--with-sample-source` and e2e, as `seed.sh` for Samba |

Environment: `LDAP_SUFFIX` (`dc=example,dc=org`), `LDAP_ADMIN_PASSWORD` (passed with `-e NAME`, never as a value),
`SEED_SAMPLE_DATA`. An existing volume with another suffix fails at start, as Samba does for another realm.

Volumes: `/var/lib/ldap` (the database and the certificate, under `tls/`) and `/etc/ldap/slapd.d` (the
configuration). Both are needed for a restore: the configuration holds the suffix, schemas, overlays and indexes.

## 3. `lab` with two server types

Everything that differs between the Samba and the OpenLDAP lab becomes one value of a `lab.Server` type, chosen by
the profile name, in the same way `profile.Profile` is chosen. Shared code (stop, write volumes, start, checksums,
instances, ports, labels, the bundle) does not branch on the name.

```go
package lab

// Server is one kind of lab server.
type Server struct {
	Profile   string           // "ad" or "ldap", as in [scope] profile
	ImageKey  string           // the IMAGE file's key and the images/<key>.tar name
	Volumes   []Volume         // what a snapshot holds
	Env       func(Settings) []string
	Secrets   func(Settings) []string // NAME=value pairs passed with -e NAME
	ExtraArgs []string         // "--cap-add SYS_ADMIN" for Samba
	Ready     string           // the health file
	Smoke     func(Settings) Cmd
	Hostname  string           // dc1 for Samba (baked into the data); ldap1
	Settings  SettingsSpec     // what up asks for and validates, and how .env stores it
	Summary   func(io.Writer, Settings)
}

var Samba, OpenLDAP Server
```

| | Samba (`ad`) | OpenLDAP (`ldap`) |
|---|---|---|
| Container | `<prefix>-ad[-<instance>]` (unchanged) | `<prefix>-ldap[-<instance>]` |
| Asked by `up` | domain name, NetBIOS name, admin password | suffix, admin password |
| Admin DN | `CN=Administrator,CN=Users,<base>` | `cn=admin,<suffix>` |
| Default ports | 12389 / 12636 | 13389 / 13636 |
| `--like-source` | domain name, SID, GUID | suffix (the source's naming context); see 7 for the schema |
| `clone -native` | yes | no (refused with the reason) |

- **Selecting it.** `lab up --profile ldap` (default `ad`, so nothing changes for current users). The choice is
  stored in `.env` (`LAB_PROFILE`) and as a container label (`ldap-cronin.profile`); every later command
  (`down`, `snapshot`, `restore`, `status`) takes it from the label, so the flag is needed only on `up` and when
  restoring into a new instance. `status` lists both kinds.
- **Both at once.** The container names differ, so an AD lab and an LDAP lab can run side by side with one prefix.
  `.env` holds one lab's settings; a second kind uses another `--state-dir`, which is what `up` says when it finds
  `.env` of the other kind.
- **Snapshots** record the profile and the suffix (`snapshot.json`: `profile`, and `realm` becomes `domain`, the
  realm or the suffix). Restoring a snapshot into a lab of the other kind, or of another suffix, is refused before
  anything is touched, as a realm mismatch is now. Old snapshots without `profile` are read as `ad`.
- **Settings.** `Settings` keeps one set of fields; `Realm` is renamed `Domain` and holds the realm or the suffix,
  `NetBIOS`, `DomainSID` and `DomainGUID` are Samba-only and refused for `ldap`. Splitting `Settings` per server was
  rejected: `.env`, labels and snapshots would each need two shapes for one optional field.

## 4. The carry-in bundle

- `make image` builds both images; `make bundle` saves them **into one tar** (`docker save A B`), so the shared
  Ubuntu layers are stored once. `images/lab.tar` replaces `images/samba-ad.tar`.
- The `IMAGE` file becomes one line per server: `ad=ldap-cronin/samba-ad:<v>` and `ldap=ldap-cronin/openldap:<v>`.
  An old single-line `IMAGE` is read as `ad=` (an old bundle keeps working with a new binary).
- `offline/setup.sh` passes `--profile` through; README-OFFLINE.md gets the LDAP variant of the first start.

## 5. Tests

- `docker-compose.yml` gets `ldap` and `ldap-src` (with `SEED_SAMPLE_DATA`) next to `ad` and `ad-src`.
- `TestGenericLDAPCloneWithOpenLDAP` runs against them instead of pulling `osixia/openldap`; `E2E_OPENLDAP_IMAGE`
  goes away, and the test no longer skips when the network is unavailable.
- New: a non-rootdn bind with `manage` (the image adds such an account only when `SEED_SAMPLE_DATA=true`) proves
  preserve without the rootdn, and a bind with only `write` proves that clone stops with the remedy. Both were
  verified by hand on 2.6.10 earlier and are not covered by e2e today.
- `TestLabSnapshotAndRestoreWithRealDocker` gains an `ldap` pass: up, data, snapshot, change, restore, another
  instance on another port, a suffix mismatch refused.
- Unit tests keep using the fake docker: the command sequences of both servers, profile from the label, refusal
  of a cross-kind restore.

## 6. What a deployment can adjust

| Need | How |
|---|---|
| Production schema | `*.ldif` (cn=config format, `olcAttributeTypes` / `olcObjectClasses`) in a directory mounted with `lab up --schema-dir DIR`, loaded at creation |
| Other overlays, `ppolicy`, ACLs, indexes | The same directory: any `*.ldif` with `changetype: modify` against `cn=config` is applied at creation, after the schemas |
| No `memberof` / `refint` | `LDAP_OVERLAYS=` (empty), or a list |

`--schema-dir` is copied into the configuration volume at creation, so snapshots and other instances need no mount.

## 7. Open questions

- **Copying the source's schema with `--like-source`.** The source's subschema subentry (readable by any bind) lists
  its attribute types and object classes in RFC 4512 form, which `olcAttributeTypes` / `olcObjectClasses` accept
  almost verbatim. `up --like-source` could install the ones the lab lacks, so a production schema needs no file.
  Risks: definitions that depend on `olcObjectIdentifier` macros, and server-internal types that must not be
  redefined. Worth a measurement before deciding.
- `memberof` is deprecated in 2.5+ in favor of `dynlist` emulating `memberOf`. Which one production uses decides
  whether a `memberOf` on the lab looks the same; the default here is `memberof` because it is still the common one.
- Whether `ppolicy` with `ppolicy_hash_cleartext` should be a switch: it decides whether the fixed password is
  stored hashed, as on most production servers.
- Architecture: both images for amd64 and arm64, as now (`PLATFORM`).

## 8. As implemented

- **`lab.Server`** (`internal/lab/server.go`) has the fields the code needed rather than the sketch in 3: `Profile`,
  `Product`, `DomainLabel`, `DefaultDomain`, `ValidateDomain`, `BaseDN`, `AdminDN`, `DomainIdentity`, `Env` (the
  .env and environment names), `Ports`, `Hostname`, `SourceHostname`, `Volumes`, `Ready`, `ExtraArgs`,
  `ContainerEnv`, `SchemaDir`. The values are `lab.Samba` and `lab.OpenLDAP`; a nil `Lab.Server` is Samba.
- **Choosing the kind** is `Lab.ChooseServer(ctx, flag)`: the flag; for the default lab, `LAB_PROFILE` in `.env`;
  otherwise the instance's existing container; otherwise Samba, "not fixed", so a restore into a new instance takes
  the snapshot's kind. `restore` therefore needs no `--profile`. `cmd` calls it for every command but `status`,
  `snapshots` and `snapshot-rm`, which do not depend on the kind.
- **Settings** kept one shape: `Realm` became `Domain`, and `Profile` was added. Stored names were kept where they
  are data in users' labs: the container label `ldap-cronin.realm` (it holds the domain or suffix) and Samba's `.env`
  keys (`AD_REALM`, `SAMBA_ADMIN_PASSWORD`, `AD_LDAP_PORT`, ...). The OpenLDAP lab uses `LDAP_SUFFIX`,
  `LDAP_ADMIN_PASSWORD`, `LDAP_PORT`, `LDAPS_PORT`. `snapshot.json` has `profile` and `domain`; an old one's
  `realm` is read into `domain` and a missing `profile` is `ad`.
- **`up` takes `--suffix`** for OpenLDAP (`--realm` stays Samba's; giving the other one is an error). Samba-only
  settings (NetBIOS, domain SID and GUID) are refused for OpenLDAP.
- **`--schema-dir` is not copied into the configuration volume** as 6 said: the image applies the files when the
  directory is created, and what they change (`cn=config`) is already in that volume. A failing file stops the
  container; `lab up` prints its log. `LDAP_OVERLAYS` exists in the image but has no `lab` flag: other overlays go
  through `--schema-dir`.
- **Tests.** `TestGenericLDAPCloneWithOpenLDAP` runs on our image and covers the `manage` and `write`-only accounts
  (through `/schema.d`, as a user's ACL would be). The lab is covered by a separate `TestOpenLDAPLabWithRealDocker`
  (up with `--schema-dir` and the sample source, clone and diff, snapshot, restore, another instance, a suffix
  refused) instead of a second pass of the Samba test. `docker-compose.yml` has an `ldap` service under the `ldap`
  profile for development; the e2e tests start their own containers with `docker run`, as the Samba lab tests do.
- **Container names** are `<prefix>-ad[-<instance>]` and `<prefix>-ldap[-<instance>]`; host names `ldap1` /
  `ldap2` (the sample source).
- The open questions of 7 remain open.
