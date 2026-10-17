# Where the source identity lives (replacing the local mapping file)

Status: implemented. Where the code differs from the proposal below, section 7 says how and why.

## 1. Problem

To report RENAMED and REPLACED, `diff` must know which source object each target object was cloned from.
The target assigns its own identifier (`objectGUID`, `entryUUID`), so today `clone` records source-key -> target-key
pairs in a local file (`[mapping] file`).

Every pain point comes from that file living somewhere other than the target:
it must be configured, it only exists if clone ran with it, it travels with lab snapshots (and needs a separate file
per lab instance), it is lost or stale when diff runs from another machine or after the target is recreated,
a dry-run LDIF loaded with `ldapmodify` has none, and a native import needs a separate code path.

## 2. The idea

`diff` needs one fact per target object: the source key it was created from.
Instead of keeping that fact beside the target, the target carries it.
There are two ways, and the profile and the server decide which one applies:

- **Preserved identifier**: the target object is created with the source's own identifier, so its identifier *is*
  the source key. A native import into the Samba lab already does this; OpenLDAP can do it over LDAP (section 4.1).
- **Marker**: clone writes the source key into an attribute of the target object (section 4.2). The attribute is
  configurable.

The local file remains only as an explicit fallback for servers that allow neither.

## 3. Verified facts

Measured on real servers before writing this (OpenLDAP 2.4.57 and 2.6.10 in `osixia/openldap`, Samba 4.19.5 in the lab image).

**OpenLDAP**, relax control (`1.3.6.1.4.1.4203.666.5.12`, an expired Internet-Draft, effectively OpenLDAP-only):

| Test | Result |
|---|---|
| Add with `entryUUID`, no relax | refused, 19 `no user modification allowed` |
| Add with `entryUUID` and relax, as rootdn | accepted; the given value is stored, indexed equality search finds it |
| Same as a non-root bind with `write` | refused, 50 `no write access to entry` |
| Same with `manage` | accepted |
| `createTimestamp`, `modifyTimestamp`, `creatorsName`, `modifiersName` with relax | accepted, stored as given |
| `entryCSN`, `structuralObjectClass`, `entryDN`, `hasSubordinates` with relax | refused, 19 `not manageable` |
| Duplicate `entryUUID` with relax | **accepted**: the server does not enforce uniqueness |
| Malformed `entryUUID` with relax | refused, 21 |
| modrdn | `entryUUID` unchanged |
| Root DSE `supportedControl` | relax is **not** advertised (2.4 and 2.6) |
| go-ldap `NewControlString(oid, true, "")` | works |

**Samba**, over LDAP:

| Test | Result |
|---|---|
| Add with `objectGUID` | refused, 53 `replmd_add: it's not allowed to add an object with objectGUID!` |
| Same with relax and/or the provision control, critical | refused, 12 `critical non-registered control` |
| Same, non-critical | control ignored, 53 |

So on AD and on a Samba target cloned over LDAP, only a marker can carry the source key.

**`adminDisplayName` as the marker on Samba** (AD schema attribute `1.2.840.113556.1.2.194`, single-valued,
`rangeUpper` 256, `searchFlags` 0, in `top`'s `systemMayContain`; not part of RFC schemas):

| Test | Result |
|---|---|
| Written in the Add of an OU, a container, a group, a user | accepted |
| Written with a modify on an existing user | accepted |
| Value over 256 characters | refused, 21 |
| Rename, move to another parent, rename of the parent container, restart | value kept |
| Equality search | found; matching ignores case |
| `searchFlags: 1` set over LDAP | accepted |
| **Values written before `searchFlags` was set** | **not found by the indexed search** until `samba-tool dbcheck --reindex` or a restart |

Not verified (no real AD at hand): a delegated (non schema admin) account writing it; unindexed searches completing on
a real AD; Exchange, Entra Connect and ADUC's "copy user" leaving it alone.

## 4. Design

### 4.1 Preserved identifier (OpenLDAP)

clone sends every Add with the relax control and the source's `entryUUID`.
The target object then has the source key as its own identifier, and diff matches identifiers directly
(`identity.Identity`, as after a native import). No file, no marker.

Because the purpose of the tool is a test copy that looks like production, the same Add also carries, by default,
the operational attributes relax lets a client set: `createTimestamp`, `modifyTimestamp`, `creatorsName`,
`modifiersName`. They are written at creation only and never compared (any change on the target updates
`modifyTimestamp`, which would make diff report every touched entry). `entryCSN` cannot be set and keeps the clone
time. Not copied on purpose: `memberOf` (the memberof overlay derives it from the groups' `member`, which clone
copies, so it ends up equal to production anyway), and password-policy state such as `pwdChangedTime` (the password
was replaced with the fixed one; production's value would be wrong, and could expire it at once).

Relax needs `manage` access (or the rootdn) and is not advertised in the root DSE, so support is learned from the
first Add. A refusal (50) stops clone with a message that names the remedy (grant `manage`, or set
`[mapping] mode`); silently falling back would leave a target that looks like production but is not.

### 4.2 Marker (AD, Samba over LDAP, and any server the user configures)

clone writes `ldap-cronin:<first 8 hex digits of the source root key>:<32 hex digits of the source key>` into the
marker attribute of every object it creates or finds (the Add carries it; an existing object without it gets a
Replace). The prefix lets diff tell a marker from another source apart (`identity.ErrForeign`) without a header.

**The attribute is configurable** (`[mapping] attribute`). The profile supplies the default:
`adminDisplayName` for `ad`, none for `ldap` (no RFC attribute is allowed on every object class the tool clones;
a deployment with an extended schema can name one). It was chosen over the alternatives because:
`adminDescription` is used by Entra Connect's default filtering, `mS-DS-ConsistencyGuid` is Entra Connect's
sourceAnchor, `extensionAttributeN` exist only with the Exchange schema and are what IdM products use most, and
`employeeID`, `employeeNumber`, `description`, `info` are in the default allow lists.

The configured attribute is validated before anything is written:

- it is not in any kind's allow list and not masked (it would be copied, compared or replaced);
- on AD, the target's `attributeSchema` says it is a single-valued string syntax with `rangeUpper` of at least 53 (the marker's length),
  and it is reported (a warning, not an error) when `searchFlags` has no index bit, since then every lookup by
  marker is a full scan;
- an object class that does not allow it fails the first Add with an object class violation, which clone reports
  with the attribute's name. Probing with a test object was rejected: the tool never deletes.

The marker attribute goes into the profile's never-clone and never-mask checks for the run, like the identifier.

**Lookup.** diff reads the marker of the entry at the source DN. If it is missing there, it first tries the expected
DN (the entry's RDN under its parent's current DN, which the locator already knows for moved OUs), then searches
`(<attribute>=<marker>)` across the naming context. With an unindexed attribute (a real AD by default) the expected-DN
probe keeps OU moves from turning into one full scan per child.

**What a marker cannot tell.** An entry at the source DN without a marker may have been deleted and recreated, had its
marker removed by the program under test, or been added to the source after the clone. The local file could tell these
apart by the server-assigned identifier; a marker cannot. diff therefore reports it as a new kind, `UNMARKED`, keeps
comparing its attributes, and counts it in the summary. `REPLACED` stays for the unambiguous cases: an entry whose
marker names another source object, or (preserved identifiers, file) whose identifier differs.

**Duplicates.** A marker copied onto a new object by the program under test gives two hits; the one at the source DN
wins, otherwise the first, with a warning. The same rule applies to duplicate `entryUUID` values on OpenLDAP, which
the server does not refuse.

**Ancestors.** Create-only ancestors that match the profile's `SystemFilter` (AD's `CN=Users` and the like) get no
marker and are matched by DN; AD does not let them be renamed anyway. Other ancestors get one.

**Samba lab index.** The lab image sets `searchFlags: 1` on the default marker attribute during provisioning, before
any data exists, so no value is ever missed by the indexed search. A lab whose data predates that, or a different
configured attribute, needs `samba-tool dbcheck --reindex` once after the schema change; `lab` does both together.

### 4.3 Choosing the carrier

```toml
[mapping]
# mode = "auto"                  # auto | preserve | marker | file | off
# attribute = "adminDisplayName" # the marker attribute (default: the profile's; required for marker on ldap)
# operational = true             # preserve: also copy createTimestamp, modifyTimestamp, creatorsName, modifiersName
# file = "mapping"               # only for mode = "file"
```

`auto` resolves to: `preserve` for a profile that can preserve identifiers over LDAP (`ldap`), `marker` for a profile
with a default marker attribute (`ad`). A native import always preserves identifiers and writes no marker.
diff does not need the mode: it checks, on the first object it compares, whether the identifiers match, then whether
the configured marker is present, then whether a file is configured, and says in the summary which one it used.

## 5. Changes to the code

Dependencies keep pointing one way: `directory <- identity <- profile <- plan <- clone, diff <- app <- cmd`.

```go
package identity

// Carrier says where a target object carries its source key.
type Carrier interface {
	Attr() string                 // objectGUID / entryUUID / the marker attribute
	Encode(source Key) string     // the stored value, also the filter's assertion value
	Decode(v string) (Key, error) // ErrForeign: a marker of another source
	Filter(source Key) string
	Written() bool                // true: clone writes it (marker); false: the server holds it (preserved)
}

func Marker(attr string, sourceRoot Key) Carrier
func Preserved(s Scheme) Carrier

// Resolver is what diff needs. The file fallback fits the same shape.
type Resolver interface {
	Attrs() []string                                        // attributes to read on target entries
	Same(source Key, e directory.Entry) (same, known bool)  // known=false: no key on the entry
	Filter(source Key) (string, bool)                       // false: cannot be searched
	Describe() string                                       // for the summary
}

func ByCarrier(c Carrier) Resolver
func ByMap(m *Map, s Scheme) Resolver
```

- `directory`: `Add` takes controls (`Add(ctx, e, controls ...Control)`); `dryrun` writes them as `control:` lines,
  `fakedir` honors relax for `entryUUID` and the operational attributes, `ldapdir` maps them to go-ldap.
- `profile`: `Marker string` (default marker attribute; `ad`: `adminDisplayName`, `ldap`: empty) and
  `Preserve IdentityPreserver` (`ldap`: the relax control and the copied operational attributes; `ad`: nil).
- `clone`: `Options.Carrier` replaces `Mapping`; `track` and the post-add read disappear.
- `diff`: `Options.Resolver` replaces `Lookup`; `UNMARKED`; the expected-DN probe in `locate`;
  `ChooseResolver` replaces `ChooseLookup`.
- `app`, `config`: the `[mapping]` keys above; validation of the marker attribute against the target schema.
- `lab`: the mapping file in snapshots, `installMapping`, `--config` / `--mapping` go away;
  the image indexes the default marker attribute at provisioning; a reindex step for configured attributes.
- `identity.Map` and the file stay only behind `mode = "file"`.

## 6. Open questions

- Real AD: delegated write of the marker attribute, unindexed searches, interference by Exchange, Entra Connect and
  "copy user". Until verified, the docs say so.
- 389-ds: whether a client can set `nsUniqueId` or `entryUUID` at add time. If not, `marker` with a configured
  attribute, or `file`.
- Whether `UNMARKED` should be refined with server timestamps (an entry created after the clone finished), which
  would need one header entry on the target. Left out of the first step.

## 7. As implemented

- **Diff uses the mode, plus the identifier probe.** Section 4.3 said diff needs no mode. It does use the resolved
  mode (marker, file, off), but first probes whether identifiers are the source's (`diff.ChooseResolver`), which
  wins whatever the mode: a native import into an AD lab (mode `marker`) and a preserving clone are both matched by
  identifier. Only `off` turns matching off. Probing for markers was dropped: the mode already says where they are.
- **An unmarked entry is searched for once** (reversing "What a marker cannot tell"). With no search, an OU moved and
  recreated under the same name gave the recreated OU `UNMARKED`, the moved one `ONLY_TARGET` and its children
  `RENAMED`. Unmarked entries are the few the program under test recreated or added, so one search each is
  affordable even unindexed; if it finds the cloned object, the entry at the DN is `ONLY_TARGET` and the original
  `RENAMED`. Ancestors are still matched by DN without a search.
- **The marker is 53 characters**, not 52 (`identity.MarkerLen`, used by the validator).
- **Code shape.** `identity.Marker` is a struct (`NewMarker`, `Encode`, `Decode`, `Filter`); there is no `Carrier`
  interface, since the preserved identifier is written by passing the source's attribute through. Resolvers are
  `ByIdentity`, `ByMarker` and `ByMap`; `Same` returns `(same, known, err)`. `directory.Add` takes variadic
  `Control`s; ldapdir maps results 50 and 12 to `ErrInsufficientAccess` and `ErrControlUnsupported`, on which clone
  stops with the profile's `Preserver.Remedy`. The profile has `Preserve *Preserver`, `Marker` and `MarkerCheck`.
  `[mapping] attribute`, `operational` and `file` are refused with a mode they do not apply to.
- **Ancestors** follow a simpler rule than the `SystemFilter` one in 4.2: a create-only ancestor that clone creates
  gets a marker; one that already exists on the target (`CN=Users`, or a parent created by hand) is left untouched,
  and diff matches it by DN, never calling it `UNMARKED` and never searching for it.
- **Duplicates** are counted in the summary rather than warned per object.
- **The lab does not reindex a configured attribute.** The image indexes `adminDisplayName` in `ad-init.sh` before
  seeding and on every start (no reindex is needed: markers are always written after it); for another attribute,
  docs/lab.md gives the two steps. A `lab` command for it was left out until someone needs it.
- **OpenLDAP `modifyTimestamp`** is the source's only for entries not modified after creation: references applied
  later and the memberof overlay (which rewrites members' `memberOf` when a group is added) update it.
- Verified by `make e2e`: markers on Samba over LDAP (rename, move, recreation, snapshot to another instance, the
  image's index) and preserving on OpenLDAP 2.4 (`osixia/openldap:1.5.0`, rootdn bind).
