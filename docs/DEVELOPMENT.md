# Developer guide

For people who develop and maintain ldap-cronin. For usage see [README.md](../README.md).

## Layout

```
cmd/ldap-cronin/    CLI (clone / diff / list-attrs / lab / version)
internal/
  config/            TOML loading and validation
  attrs/             attribute allow list, attributes that cannot be masked or copied
  plan/              deciding the targets (OUs, parent containers, target DN set Scope, DN reference attribute detection)
  clone/             applying (parent OUs -> groups and users -> DN reference attributes)
  diff/              comparison and output (RENAMED / REPLACED detection, summary)
  compare/           value equivalence (normalizing DNs, objectClass, userAccountControl)
  directory/         the operations abstraction (Directory) and the LDIF output used by dry-run
  ldapdir/           go-ldap implementation (connection pool, paging, member range retrieval)
  guidmap/           GUID mapping between source and target (fixed-length file, binary search, external sort)
  lab/               Samba4 test environment on docker, snapshots and restore (needs only the docker command)
  profile/           server-type profiles (ad, ldap): filters, default attributes, identity attribute, password mode, schema discovery
  fakedir/           in-memory Directory for tests (rejects adds without a parent and references to missing objects, like a real server)
  dn/ ldif/ mask/ prompt/ workpool/
docker/ad/           the Samba4 image (Dockerfile, entrypoint.sh, ad-init.sh, seed.sh, extended schema)
offline/             setup.sh for air-gapped environments (thin entry point calling lab) and README-OFFLINE.md
e2e/ tests/e2e.sh    E2E tests against a real Samba
docs/                documents referenced from the README
```

`clone` and `diff` go through `Directory`, so unit tests run on `fakedir` without a real server.

## Build and test

`make help` lists the targets.

| Target | Description |
|---|---|
| `make check` | Same as CI: formatting, vet, `go mod tidy` diff, unit tests (`-race`), build |
| `make build` / `make dist` | Build into `bin/` / build for each OS and architecture into `dist/` (with SHA256SUMS) |
| `make test` / `make cover` | Unit tests / with coverage |
| `make e2e` | Start two Samba servers and run the E2E tests (needs docker and docker compose; about 2 minutes) |
| `make image` / `make bundle` | Build the Samba4 image / build the tar.gz for air-gapped environments |

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
| `TestRenameAndMoveOnTargetAreDetectedWithTheGUIDMapping` | Renames, moves, OU moves and child deletions on the target are detected via the GUID mapping |
| `TestRecreatedObjectsOnTargetAreNotMistakenForTheOriginals` | Objects deleted and recreated at the same DN, and an OU moved and recreated under the same name, are different objects |
| `TestLabSnapshotAndRestoreWithRealDocker` | `lab up` -> data -> snapshots -> modify -> restore; data survives `down` -> `up`; domain name mismatch is refused; another lab starts from a snapshot on a different port |
| `TestNativeImportKeepsObjectGUIDAndObjectSid` | Native import of a sample (14 objects), re-run, rename detection, snapshot restore, creating a user over LDAP afterwards |
| `TestGenericLDAPCloneWithOpenLDAP` | Clone between two throw-away OpenLDAP servers (`E2E_OPENLDAP_IMAGE`, set by `tests/e2e.sh` when the image is available): password, references, diff, rename detection |

Environment variables: `E2E_SRC_URL` (default `ldaps://localhost:11636`), `E2E_DST_URL` (default `ldaps://localhost:12636`), `E2E_DOMAIN_DN`, `SAMBA_ADMIN_PASSWORD`.
The `lab` E2E does not use docker compose and picks its own prefix and ports. It takes the image from `E2E_LAB_IMAGE` (built by `tests/e2e.sh`) and the host from `E2E_LAB_HOST` (default `localhost`; `docker` in CI's docker-in-docker).
`E2E_BULK_USERS` and `E2E_WORKERS` vary the bulk test and print per-phase times (`go test -tags e2e -run Bulk -v ./e2e/` after `docker compose --profile e2e up -d --wait`).

## How the offline package is built

`make bundle` builds the tar.gz on a machine with connectivity (`PLATFORM=linux/arm64` selects the image architecture; default linux/amd64):

1. `make image`, then `docker save` writes `images/samba-ad.tar`.
2. Collect the tool binaries (linux amd64 / arm64, `CGO_ENABLED=0`), `offline/setup.sh`, `offline/README-OFFLINE.md`, `config.example.toml`, `README.md` and `docs/`.
3. Add `IMAGE` and `SHA256SUMS` (image, binaries, `setup.sh`).

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
| The source GUID is kept in a local mapping, not in a target attribute | Borrowing a target attribute would clash with real use. The mapping is fixed-length and ordered by GUID so `diff` can binary-search it (constant memory) |
| The GUID mapping header is the domain's identifier (`objectGUID` of the domain root), not a URL | The URL changes when the lab is recreated or started from a snapshot on another port; the domain data does not. A different domain can still be rejected |
| The GUID mapping can be included in a snapshot | It is a companion of the data, so one restore brings back both. For another instance it goes to a different file |
| `clone` does not follow source-side renames and does not delete | Continuous cloning would need deletion handling; the purpose is verifying changes made on the target |
| Case-only differences count as differences, marked `(case only)` | A real change must never be overlooked. Per-attribute case-insensitive comparison is not implemented |
| DN reference attributes are compared after all objects are matched | AD rewrites references on rename, so references to renamed objects must be translated back to the original DN first, or false differences appear |
| `member` is always retrieved with an explicit range | AD splits large groups automatically, Samba does not; always being explicit uses one path for both |
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

If it works, `diff` can match by GUID without the mapping, and applications keyed on `objectGUID` / `objectSid` (for example an IdM whose AD connector identifies objects by `objectGUID`) see matching identifiers against the lab.

## Implementation notes (quirks of Samba and AD)

- Setting `unicodePwd` requires LDAPS; Samba rejects it over plain LDAP.
- Installing the extended schema needs `dsdb:schema update allowed = yes` (`docker/ad/entrypoint.sh`).
- Samba does not split `member` into ranges automatically but answers an explicit `member;range=0-499`; an out-of-range value returns nothing.
- Samba's server-side sort control can be combined with paged searches (collation differs from AD).

## Design of the native import (`clone -native`)

A Samba-only, optional `lab` feature built on the research above: it imports into the lab with the same `objectGUID` and `objectSid` as the source.

- `internal/lab/native_helper.py` (`go:embed`): manipulates the lab volume's `sam.ldb` through Samba's Python API. One JSON request per line in, one response per line out; values are base64; library output goes to standard error so the protocol on standard output is not broken.
- `internal/lab/native.go` (`Lab.OpenNative` -> `Native`): stops the lab container, starts a helper container with the same volumes (`docker run -i --rm --entrypoint python3`) and exposes it as a `directory.Directory`. `Close` ends the helper and resumes the lab, even after a failure. `Finish` advances the RID allocation and runs `dbcheck`.
- `plan.Options.KeepIdentity`: also reads `objectGUID` / `objectSid` from the source and passes them to Add. If an existing object's `objectGUID` differs, it fails instead of falling back to an update.
- `diff.RunWith` + `guidmap.Identity`: matches without the mapping. The switch is `identityPreserved` in `cmd/ldap-cronin/native.go`.
- `lab up --like-source` / `--domain-sid` / `--domain-guid`: `entrypoint.sh` passes them to `samba-tool domain provision`.
- The `[state] file` is not created, since the mapping is unnecessary.

Decisions:

- **Stop the container and open the volume from a helper container**, rather than `docker exec` in the running one: another process opening `sam.ldb` alongside a running Samba is unsafe (locking assumptions differ). LDAP is down only during the import.
- **Self-check at the start**: it tries the same operation and rolls back, so a Samba version change fails at the start, not midway.
- **Advance the RID** (`rIDNextRID`): imported RIDs do not advance Samba's allocation, so a user created over LDAP afterwards fails with `unique index violation on objectSid`. `Finish` moves it past the largest imported RID.
- **Always run `dbcheck`**: the `relax` control loosens integrity checks, so this is the last line of defense; any error fails the whole import.
- **A RID collision fails with the colliding object's name** instead of being skipped. The lab's standard objects with RID 1000 or more are only 1000, 1101 and 1102.
- **The `diff` switch is not decided by the domain GUID.** A lab created with `--like-source` and cloned over LDAP has the same domain GUID but different object GUIDs, so everything would be `REPLACED`. The decision is whether the `objectGUID` of the `base_dn` object (for a container, its first child) matches.

Measured on Samba 4.19.5. Not verified: large numbers of objects, ACLs (`nTSecurityDescriptor`), other Samba versions.

## Server profiles (AD and generic LDAP)

Everything that differs between AD and a plain LDAP server is data in `internal/profile`: default filters and attribute lists, never-clone and never-mask lists, identifier attribute (`objectGUID` / `entryUUID`), password mode, DN-attribute discovery, and group/user creation order. Shared code asks the profile (`plan.Options.P()`) instead of branching on a server name.

- **A profile per protocol family, not per product.** OpenLDAP / 389-ds profiles were rejected: RFC-level behavior is the same, and per-deployment differences (object classes, attributes) are handled by `[clone.filters]` and `[attributes]`.
- **`auto` detects through the source's root DSE** (`supportedCapabilities` contains the AD capability OID; Samba AD advertises it). The target is checked too, because cloning an AD source into a generic server would silently mis-map attributes.
- **`entryUUID` is text, `objectGUID` is 16 raw bytes.** `guidmap.Hex` converts both to the same 16-byte key so one fixed-size mapping file serves both; `entryUUID` search filters use the text form (`guidmap.UUIDText`).
- **Groups that must have a member at creation** (`groupOfNames`) use a retry, not a per-server rule: Add without DN references first; on `directory.ErrSchemaViolation`, retry with the references into the cloned scope. The common AD path stays one Add.
- **`member;range=` is AD-only.** OpenLDAP does not implement it and returns an empty attribute, so `ldapdir.Client.SetRangedAttrs` is set from the profile.
- **The fixed password is a plain `userPassword` modify.** The password modify extended operation (RFC 3062) was rejected because not every server enables it.
- **The naming-context root** is `root_dn` or derived (`namingContexts`, then trailing `dc=`); AD keeps using the trailing `DC=` run.
