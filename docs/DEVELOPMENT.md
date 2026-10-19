# Developer guide

For people who develop and maintain ldap-cronin. For usage see [README.md](../README.md).

## Layout

```
cmd/ldap-cronin/    CLI: flags, passwords (prompt or environment), the signal context, exit codes. Nothing else
internal/
  app/               assembling a run: connections, profile resolution, the job, the [mapping] mode; clone, diff and native entry points
  config/            TOML loading and validation; JobFor builds the job once the profile is known
  profile/           server types (ad, ldap): kinds and attribute lists as data, strategies for identity, schema, root, accounts, values
  identity/          identifier schemes (objectGUID, entryUUID), the marker, Resolver (by identifier, marker or file), and the mapping file
  plan/              Job (what to process) and Plan (containers, target DN set Scope, DN references); traversal and attribute differences
  clone/             applying (containers -> leaves -> DN reference attributes)
  diff/              matching (RENAMED / REPLACED / UNMARKED), comparison, formatting, summary; ChooseResolver
  compare/           value equivalence under a normalizer (knows no attribute names)
  directory/         the operations abstraction (Directory)
  ldapdir/           go-ldap implementation (connection pool, paging, member range retrieval, timeouts)
  dryrun/            Directory that prints writes as LDIF
  lab/               test labs on docker (Samba4 AD, OpenLDAP; what differs is lab.Server), snapshots and restore (needs only the docker command)
  ad/                AD-only helpers: binary objectGUID / objectSid, the domain identity
  fakedir/           in-memory Directory for tests (behaves like a real server where clone depends on it; see below)
  dn/ ldif/ mask/ prompt/ workpool/
docker/ad/           the Samba4 image (Dockerfile, entrypoint.sh, ad-init.sh, seed.sh, extended schema)
docker/ldap/         the OpenLDAP image (Dockerfile, entrypoint.sh builds cn=config, ldap-init.sh, seed.ldif, schema.d/)
offline/             setup.sh for air-gapped environments (thin entry point calling lab) and README-OFFLINE.md
e2e/ tests/e2e.sh    E2E tests against real Samba and OpenLDAP servers
docs/                documents referenced from the README
```

Dependencies point one way: `directory <- identity <- profile <- plan <- clone, diff <- app <- cmd`.
`clone`, `diff` and `app` go through `Directory`, so unit tests run on `fakedir` without a real server, `app` and `cmd` included (with a fake `Dialer`).

What the unit tests hold `clone` to, beyond the per-feature tests:

| Test | Property |
|---|---|
| `clone/fault_test.go` | A target failure at any step (each kind of add, the password, `userAccountControl`, reference reads and writes) stops the run with that error, and a re-run ends where an unfailed run would |
| `clone/random_test.go` | For random trees (escaped and non-ASCII names, nested and self-referencing groups, references outside the scope): clone, then diff finds nothing, and a re-run writes nothing |
| `clone/limits_test.go` | `member` is added 500 values per modify; a reference outside the scope is read once; warnings are capped |
| `clone/ops_test.go` | Operations per user on the target |
| `clone/ldifapply_test.go` | The dry-run LDIF loads with an `ldapmodify` stand-in into an empty target (groups that require a member included) and, after `clone` on AD, diffs clean |
| `cmd/ldap-cronin/main_test.go` | Exit codes, a dry-run's standard output holds only LDIF, passwords come from the environment and are never printed |
| `dn` fuzz test | `go test ./internal/dn -fuzz FuzzDNOperationsAgree`: normalizing, splitting and the descendant check agree |

`fakedir` behaves like a real server where clone depends on it: it rejects an add without a parent, a duplicate value and a missing required attribute, gives an AD user `pwdLastSet=0` until `unicodePwd` is set, and with `IDPrefix` two fakes never hand out the same identifier (give each target its own, or diff takes the target for a native import).

## Build and test

`make help` lists the targets.

| Target | Description |
|---|---|
| `make check` | Same as CI: formatting, vet, `go mod tidy` diff, unit tests (`-race`), build |
| `make build` / `make dist` | Build into `bin/` / build for each OS and architecture into `dist/` (with SHA256SUMS) |
| `make test` / `make cover` | Unit tests / with coverage |
| `make e2e` | Start two Samba servers and run the E2E tests (needs docker and docker compose; about 2 minutes) |
| `make image` / `make bundle` | Build the lab images (Samba4 AD, OpenLDAP) / build the tar.gz for air-gapped environments |

CI (`.github/workflows/ci.yml`) runs `verify`, `build` and `e2e` (`tests/e2e.sh`).

## Test environment (docker compose)

`docker-compose.yml` is the environment for testing in this repository (development and CI). It is not part of the offline bundle.

```sh
cp .env.example .env     # changing only AD_REALM changes the domain name
docker compose up -d --build                 # clone target (empty AD): ldap 12389 / ldaps 12636
docker compose --profile e2e up -d --build   # plus the clone source (with sample data): ldap 11389 / ldaps 11636
```

- `AD_REALM` is the domain name (for example `ad.example.com`); the Kerberos realm, NetBIOS name (first label, at most 15 characters) and BASE_DN are derived. After changing it, run `docker compose down -v` (a mismatch with an existing volume stops startup).
- Every instance gets an Exchange-compatible extended schema (`extensionAttribute1-15`, `msExch*`, `mailNickname`) from `docker/ad/schema/`.
- Sample data is only in `ad-src` (`SEED_SAMPLE_DATA=true`): nested OUs, users in a `CN=` container, CNs containing `,` or non-ASCII characters, disabled and never-expiring users, nested groups.
- The password policy is relaxed. LDAPS uses Samba's self-signed certificate, which can have a negative serial number that Go rejects by default, so `go.mod` sets `godebug x509negativeserial=1` (no effect on a real AD).

## E2E tests

`make e2e` (`tests/e2e.sh`) starts two new Samba servers (`ad-src` -> `ad`), runs `go test -tags e2e ./e2e/...` and cleans up (`KEEP=1` leaves them).

| Test | What it checks |
|---|---|
| `TestDefaultAttributesExistInSambaSchema` | Every attribute in the default allow list exists in the Samba schema |
| `TestReferenceAttributesAreDetectedFromSambaSchema` | DN reference attributes are detected from the schema |
| `TestCloneThenDiffThenIdempotentThenDetectTamper` | clone -> 0 diffs -> re-run gives 0 changes -> diff detects a manual change; login over LDAPS with the fixed password works |
| `TestBulkUsersPagingAndLargeGroupRanges` | 1600 users (paging) and a group of 1600 members (several range retrievals, range size 500) |
| `TestRenameAndMoveOnTargetAreDetectedWithTheMarkers` | Renames, moves, OU moves and child deletions on the target are detected through the markers; the image indexes `adminDisplayName` |
| `TestRecreatedObjectsOnTargetAreNotMistakenForTheOriginals` | An object deleted and recreated at the same DN is `UNMARKED`; an OU moved and recreated under the same name is `RENAMED` plus `ONLY_TARGET` |
| `TestLabSnapshotCarriesTheMarkersToAnotherInstanceOnAnotherPort` | clone -> snapshot -> restore into another instance on another port -> a rename there is found through the markers |
| `TestLabSnapshotAndRestoreWithRealDocker` | `lab up` -> data -> snapshots -> modify -> restore; data survives `down` -> `up`; domain name mismatch is refused; another lab starts from a snapshot on a different port |
| `TestNativeImportKeepsObjectGUIDAndObjectSid` | Native import of a sample (14 objects), re-run, rename detection, snapshot restore, creating a user over LDAP afterwards |
| `TestGenericLDAPCloneWithOpenLDAP` | Clone between two throw-away OpenLDAP servers of our image (`E2E_LDAP_IMAGE`, built by `tests/e2e.sh`): password, references, diff, `entryUUID` and creation metadata kept with the relax control by an account with `manage` (not the rootdn), a `write`-only account stopped with the remedy, rename detection by the preserved identifier |
| `TestOpenLDAPLabWithRealDocker` | The OpenLDAP lab: `up` with `--schema-dir` and the sample source -> clone and diff the sample data -> snapshot -> change -> restore -> another instance on another port -> a different suffix refused |

Environment variables: `E2E_SRC_URL` (default `ldaps://localhost:11636`), `E2E_DST_URL` (default `ldaps://localhost:12636`), `E2E_DOMAIN_DN`, `SAMBA_ADMIN_PASSWORD`.
The `lab` E2E does not use docker compose and picks its own prefix and ports. It takes the image from `E2E_LAB_IMAGE` (built by `tests/e2e.sh`) and the host from `E2E_LAB_HOST` (default `localhost`; `docker` in CI's docker-in-docker).
`E2E_BULK_USERS` and `E2E_WORKERS` vary the bulk test and print per-phase times (`go test -tags e2e -run Bulk -v ./e2e/` after `docker compose --profile e2e up -d --wait`).

## How the offline package is built

`make bundle` builds the tar.gz on a machine with connectivity (`PLATFORM=linux/arm64` selects the image architecture; default linux/amd64):

1. `make image` (both images), then one `docker save` writes `images/lab.tar`, so the Ubuntu layers they share are stored once.
2. Collect the tool binaries (linux amd64 / arm64, `CGO_ENABLED=0`), `offline/setup.sh`, `offline/README-OFFLINE.md`, `config.example.toml`, `README.md` and `docs/`.
3. Add `IMAGE` (`ad=` and `ldap=` lines; an old single line is read as the Samba image) and `SHA256SUMS` (images, binaries, `setup.sh`).

`docker-compose.yml` is excluded because the receiving side may not have docker compose.

`offline/setup.sh` is a thin entry point that runs `ldap-cronin lab <arguments>` with the bundled binary for its architecture (`lab up` when there are no arguments or the first is a flag). The logic (`SHA256SUMS` check, `docker load`, start, snapshots) is in `internal/lab`, so shell quirks affect only this script, which must work with bash 3.x (macOS) and 4.2 (old RHEL).

## Design decisions (including alternatives we rejected)

| Decision | Reason |
|---|---|
| LDAP through go-ldap, not external commands (ldapsearch etc.) | Parsing LDIF (line breaks, base64, folding) is cumbersome |
| Attributes use an allow list, not an exclude list | An exclude list would silently copy unexpected attributes such as `extensionAttribute*` |
| Entries are not held in memory (`Directory.Walk` streams page by page; only the DN hash set and OUs stay resident) | The old implementation used about 3.3 KB per user (about 660 MB for 200,000 users); now about 10 MB (`internal/clone/memory_test.go`) |
| Users are created in three steps: add -> password (modify) -> UAC | Samba accepts `unicodePwd` in an add, but Microsoft specifies it can only be set with a modify (KB 269190); Samba-only behavior would fail on a real AD |
| DN reference attributes are applied after all objects exist and detected from the schema (`attributeSyntax=2.5.5.1`) | Adding fails if the DN does not exist yet; a fixed list would break attributes added through `extra_include` |
| The source is searched sequentially on one connection; only target work is parallel | Keeps load on the source low; the paging cookie is also tied to the connection |
| Writes to the target are parallel, but Samba does not get faster | Samba serializes writes (`ldapmodify` with 1 and 8 connections: same). Reads (diff) do speed up |
| `diff` output order is not stabilized with server-side sorting | The sort key cannot be the DN, collation differs between AD and Samba, parallelism breaks the order, and AD limits temporary tables for sorting (not verified on a real AD). Client-side sorting is an option if needed |
| The target carries its source identity: the source identifier itself (OpenLDAP, relax control) or a marker attribute (AD: `adminDisplayName`). A local file is only the `mode = "file"` fallback | The file lived beside the target: it had to be configured, travelled with snapshots (one per instance), was lost when diff ran elsewhere or the target was rebuilt, and a dry-run LDIF had none. See [design/identity-carrier.md](design/identity-carrier.md) |
| OpenLDAP preserving copies `createTimestamp`, `modifyTimestamp`, `creatorsName`, `modifiersName` by default | The tool exists to test against a copy that looks like production. They are written at creation only and never compared (any change updates `modifyTimestamp`) |
| A refused relax control stops clone | Falling back to new identifiers would leave a target that looks like production but is not |
| The marker names the source by its root key; the marker attribute is configurable and validated (not copied, compared or masked; on AD a single-valued string of at least 53 characters) | A marker from another source is told apart without a header, and a dry-run writes markers too. A probe object was rejected for validation: the tool never deletes |
| An entry without a marker is searched for once elsewhere before it is called `UNMARKED` | Finding the cloned object elsewhere turns an ambiguous case into a certain move; unmarked entries are few, so the extra (possibly unindexed) searches are too |
| The mapping header identifies the source by the identifier of its naming-context root, not by URL, and does not name the target | The URL changes when the lab is recreated or started from a snapshot on another port; the data does not. Identifiers are globally unique, so one file serves every target cloned from the source |
| The mapping file is a ledger of every pair clone recorded, not the current state; diff accepts any recorded key | A restore returns the target to a state an earlier clone produced, so a state file had to travel with the snapshot (the old `.bak` move-aside). Identifiers are never reused, so membership is exact. See [design/mapping-ledger.md](design/mapping-ledger.md) |
| `clone` does not follow source-side renames and does not delete | Continuous cloning would need deletion handling; the purpose is verifying changes made on the target |
| Case-only differences count as differences, marked `(case only)` | A real change must never be overlooked. Per-attribute case-insensitive comparison is not implemented |
| DN reference attributes are compared after all objects are matched | AD rewrites references on rename, so references to renamed objects must be translated back to the original DN first, or false differences appear |
| `member` is always retrieved with an explicit range on AD | AD splits large groups automatically, Samba does not; always being explicit uses one path for both, so CI exercises the multi-fetch path |
| Samba stores NT ACLs as `user.NTACL` when `security.*` xattrs are not writable | Rootless docker (lima's default) grants `CAP_SYS_ADMIN` only inside its user namespace, so provisioning failed. The tdb backend (`--use-xattrs=no`) was rejected: Samba 4.19 offers it only with the NTVFS file server. A probe keeps rootful setups on Samba's default |
| One `lab` for both server kinds; the differences are one `lab.Server` value each (volumes, environment, health file, admin DN, ports, settings) | Stop, write volumes, start, checksums, instances, ports and the bundle are the same for any server; a second copy of them was rejected. The kind is recorded in `.env`, as a container label and in `snapshot.json`, so only `up` needs `--profile` |
| The OpenLDAP lab image is our own (`docker/ldap`, Ubuntu 24.04 `slapd`), not `osixia/openldap` | osixia is OpenLDAP 2.4 and unmaintained, and e2e had to pull it. The same base as the Samba image shares layers in the bundle, and gives OpenLDAP 2.6.10, the version the relax control was verified on |
| The OpenLDAP directory is created on the first start from `LDAP_SUFFIX` (`cn=config` by `slapadd -n0`), like Samba's provisioning | The same image serves any suffix. `slapd.conf` was rejected: 2.6 deprecates it and production servers use `cn=config` |
| `--schema-dir` is copied in with `docker create` + `docker cp` before the first start | The image applies it when the directory is created and the result lives in the configuration volume, so no bind mount is needed and snapshots carry it |
| docker compose is limited to the test environment | The receiving side may lack it; what is carried in is `lab`, which needs only `docker run` |
| `lab` calls the `docker` command, not the docker SDK | The SDK has large dependencies; a fake command sequence lets the order (stop -> write out -> start) be unit-tested. Passwords go through environment variables (`-e NAME`), not arguments, and are hidden from error messages |
| Snapshots write volume contents to tar files on the host | See the table below. `docker commit` leaves the password in the image's environment variables and has a layer limit |
| Snapshots are taken after cleanly stopping Samba | Copying tdb / ldb files while being written can capture an inconsistent state |
| A restore verifies the checksum first | A corrupt snapshot must never wipe the current data |
| Another instance is created by extracting a snapshot into separate volumes (`--instance`) | A snapshot is a host file independent of the original volumes. State is kept in container labels (domain, ports, instance), which allows listing and detecting mismatches and port conflicts |
| The DC host name is fixed to `dc1` | It is baked into the domain data (`CN=DC1`, DNS records); changing it still starts, but the original name remains |
| `/tmp/ad-ready` is removed on every container start | A leftover marker makes the container healthy before Samba has started |

## Choosing the snapshot method (measured)

Real docker and Samba, 1600 users (about 60 MB); seconds; restore is the total from stop until healthy and LDAP responding.

| Method | Take | Restore | Notes |
|---|---|---|---|
| Copy volume to volume | 2.1 | 5.5 | Unused volumes are deleted by `docker volume prune` |
| `docker commit` (no volumes) | 1.4 | 4.0 | Password stays in the image's environment variables; layer limit (127); deleting the container deletes the data |
| **Volume contents to tar files on the host** (adopted) | 7.5 | 6.6 | Survives prune, portable as files, host files owned by you (no bind mount) |

Starting Samba (about 3 seconds) dominates every method; the differences are a few seconds. When reconsidering, measure again under the same conditions.

## Research notes: can Samba create objects with a chosen objectGUID / objectSid? (measured)

Tried on Samba 4.19.5 to make target objects carry the source's `objectGUID` / `objectSid`.

| Method | Result |
|---|---|
| LDAP add specifying `objectGUID` | Rejected: `replmd_add: it's not allowed to add an object with objectGUID!` (53) |
| LDAP add specifying `objectSid` | Rejected: the server assigns the SID itself |
| Direct add to `sam.ldb` with Samba's Python API (`SamDB(session_info=system_session())`), no controls, or only `provision` | Rejected |
| Same, with **both `provision` and `relax` controls** | **Succeeded** for users and groups, with the specified `objectGUID` and `objectSid` (domain SID + RID) |

Objects created this way: duplicate GUIDs / SIDs are rejected by the indexes; `objectGUID` search over LDAP, group membership and `unicodePwd` work, also after a restart; `samba-tool dbcheck --cross-ncs` reported 0 errors across 3863 objects. `whenCreated`, `uSNCreated` and `pwdLastSet` become the target's local values.

Limits:

- It cannot be done over LDAP; `sam.ldb` must be manipulated on the Samba host (in practice Python in the container via `docker exec`). It cannot be used with a real AD.
- Source password hashes are not readable over LDAP (`unicodePwd` is not returned). Copying them requires joining the target as a DC of the source's domain and replicating (`samba-tool domain join`, DRS), which adds a DC to the production AD and replicates the whole domain.
- Matching `objectSid` also requires the same domain SID (`samba-tool domain provision --domain-sid=... --domain-guid=...`).
- It depends on Samba's internal replication path, is not a supported use, and may break across versions.
- Not verified: `whenCreated` and the like, ACLs (`nTSecurityDescriptor`), large numbers of objects, other Samba versions.

If it works, `diff` can match by GUID without a marker, and applications keyed on `objectGUID` / `objectSid` (for example an IdM whose AD connector identifies objects by `objectGUID`) see matching identifiers against the lab.

## Implementation notes (quirks of Samba and AD)

- Setting `unicodePwd` requires LDAPS; Samba rejects it over plain LDAP.
- Installing the extended schema needs `dsdb:schema update allowed = yes` (`docker/ad/entrypoint.sh`).
- Samba does not split `member` into ranges automatically but answers an explicit `member;range=0-499`; an out-of-range value returns nothing.
- Samba's server-side sort control can be combined with paged searches (collation differs from AD).

## Design of the native import (`clone -native`)

A Samba-only, optional `lab` feature built on the research above: it imports into the lab with the same `objectGUID` and `objectSid` as the source.

- `internal/lab/native_helper.py` (`go:embed`): manipulates the lab volume's `sam.ldb` through Samba's Python API. One JSON request per line in, one response per line out; values are base64; library output goes to standard error so the protocol on standard output is not broken.
- `internal/lab/native.go` (`Lab.OpenNative` -> `Native`): stops the lab container, starts a helper container with the same volumes (`docker run -i --rm --entrypoint python3`) and exposes it as a `directory.Directory`. `Close` ends the helper and resumes the lab, even after a failure. `Finish` advances the RID allocation and runs `dbcheck`.
- `clone.Options.Native`: also reads the profile's carried-over attributes (`identity.Scheme.CarryOver`: `objectGUID`, `objectSid`) from the source and passes them to Add. If an existing object's `objectGUID` differs, it fails instead of falling back to an update.
- `identity.ByIdentity` as the `diff` resolver: matches by the identifier itself. `diff.ChooseResolver` decides, whatever the `[mapping]` mode.
- `app.Session.Native` runs it: it reads the source domain through `profile.NativeSupport` (implemented with `internal/ad`), checks the lab is the same domain, and resumes the lab in every case.
- `lab up --like-source` / `--domain-sid` / `--domain-guid`: `entrypoint.sh` passes them to `samba-tool domain provision`.
- No marker and no mapping file are written: neither is needed.

Decisions:

- **Stop the container and open the volume from a helper container**, rather than `docker exec` in the running one: another process opening `sam.ldb` alongside a running Samba is unsafe (locking assumptions differ). LDAP is down only during the import.
- **Self-check at the start**: it tries the same operation and rolls back, so a Samba version change fails at the start, not midway.
- **Advance the RID** (`rIDNextRID`): imported RIDs do not advance Samba's allocation, so a user created over LDAP afterwards fails with `unique index violation on objectSid`. `Finish` moves it past the largest imported RID.
- **Always run `dbcheck`**: the `relax` control loosens integrity checks, so this is the last line of defense; any error fails the whole import.
- **A RID collision fails with the colliding object's name** instead of being skipped. The lab's standard objects with RID 1000 or more are only 1000, 1101 and 1102.
- **The `diff` switch is not decided by the domain GUID.** A lab created with `--like-source` and cloned over LDAP has the same domain GUID but different object GUIDs, so everything would be `REPLACED`. The decision is whether the `objectGUID` of the first object `diff` itself compares matches, found with the job's filters (so a built-in or filtered-out object never decides); `base_dn` itself only when nothing is below it, since a container the lab already had (`CN=Users`) has the lab's own GUID.
- **The helper is not killed on Ctrl-C.** Killing it could interrupt a write to `sam.ldb`; the import checks the context between requests instead, and `Close` ends the helper by closing its standard input and resumes the lab.

Measured on Samba 4.19.5. Not verified: large numbers of objects, ACLs (`nTSecurityDescriptor`), other Samba versions.

## Server profiles (AD and generic LDAP)

Everything that differs between AD and a plain LDAP server is in `internal/profile`, and shared code never branches on a server name. **Lists are data**: the kinds (name, role, default filter, default attributes, creation order, whether they are accounts), the required, never-clone, never-mask and password attributes, the ancestor attributes, the built-in DN references, the ranged attributes. They are what a deployment adjusts and what `list-attrs` prints. **Behavior is a strategy**: `identity.Scheme` (how objects are identified), `RefDiscoverer` (DN-valued attributes from the schema), `RootResolver` (where the naming context starts), `Account` (how a user gets the fixed password), per-attribute value normalizers, `Preserver` (how an Add keeps the source identifier; nil on AD), `MarkerCheck` (validating a marker attribute against the target schema), and `NativeSupport` (nil when `clone -native` is impossible). `Marker` is the default marker attribute. A third server type is a third `Profile` value.

- **Lists as data, behavior as strategies.** An earlier version kept the behavior as flags too (password mode, schema mode, identifier-is-text, leaf order, supports-native), and every package interpreted them with its own `switch`; adding one variation meant editing every interpreter. Lists stayed data because a deployment changes them, not the code.
- **A profile per protocol family, not per product.** OpenLDAP / 389-ds profiles were rejected: RFC-level behavior is the same, and per-deployment differences (object classes, attributes) are handled by `[scope.filters]` and `[attributes]`.
- **Kinds have roles; the shared code knows only the roles.** A container is created shallowest first and held in memory; a leaf is streamed. The kind names (`ou`, `group`, `user`, `computer`, `contact`) are labels for the config file. A create-only ancestor is read with `AncestorAttrs`, not with the OU allow list, which a non-OU parent may not fit.
- **`auto` detects through the source's root DSE** (`supportedCapabilities` contains the AD capability OID; Samba AD advertises it). The target is checked too, because cloning an AD source into a generic server would silently mis-map attributes.
- **`entryUUID` is text, `objectGUID` is 16 raw bytes.** Each `identity.Scheme` parses only its own form into a 16-byte `identity.Key`, so markers and the mapping file serve both and nothing guesses a value's form. The scheme also builds the search filter.
- **Groups that must have a member at creation** (`groupOfNames`) use a retry, not a per-server rule: Add without DN references first; on `directory.ErrSchemaViolation`, retry with the references into the cloned scope. The common AD path stays one Add.
- **`member;range=` is AD-only.** OpenLDAP does not implement it and returns an empty attribute. `ldapdir.Client.With(ranged)` returns a view of the same connections that asks for ranges; the plain client never does. Reconfiguring a shared client in place was rejected (it had to happen before any goroutine used it, and forgetting it emptied `member` on OpenLDAP). A second dial with the profile known was rejected because it costs one more bind on the source.
- **Accounts are an `Account` strategy.** AD creates a user disabled, sets `unicodePwd` with a modify, then `userAccountControl` (KB 269190 forbids `unicodePwd` in an add). A generic server gets the plain `userPassword` in the add itself: a user can then never exist without the password, so there is no interrupted state to detect and an existing user's password is never reset. "Set it when `userPassword` is absent" was rejected because an ACL that hides `userPassword` would reset every password on every run; "always set it" fails under a ppolicy `pwdInHistory` and undoes changes made by the program under test. The password modify extended operation (RFC 3062) was rejected because not every server enables it.
- **The naming-context root** is `root_dn` or the profile's `RootResolver`: AD uses the trailing `DC=` run; a generic server the longest `namingContexts` value, then the trailing `dc=` run.

## Cancellation and timeouts

- **Every `Directory` operation takes a `context.Context`**, and `cmd` cancels it on the first Ctrl-C or SIGTERM (a second one ends the process). The point is that deferred cleanup runs: a mapping file is written, a lab stopped for a native import is resumed. Without it the process ended on Ctrl-C with neither.
- **Cancellation is checked between operations, not inside them.** go-ldap v3.4.15 takes a context only in `SearchAsync`; `Add`, `Modify` and `Search` take none, so an operation already sent runs to completion. `ldapdir.Walk` checks between pages; moving it to `SearchAsync` was rejected, as it would mean rewriting the paging and range loop for sub-page cancellation nobody needs.
- **`workpool` cancels the running workers on the first error** (like `errgroup.WithContext`, without the dependency), so they stop at their next operation instead of finishing their item.
- **A hung server is a timeout, not a cancellation.** `[source]` / `[target] timeout` (default 2 minutes) is applied with `Conn.SetTimeout`, since a context cannot bound an `Add` or a `Modify`.
- **`lab` critical sections run under `context.WithoutCancel`**: stop, write volumes and start in `restore`; the restart in `snapshot`; `Native.Close`. A half-written volume or a stopped lab is worse than a few seconds' wait. Other docker commands use `exec.CommandContext`.
- **An interrupted `diff` prints no summary**: a partial result would read as "no differences" in the part it did not reach.
