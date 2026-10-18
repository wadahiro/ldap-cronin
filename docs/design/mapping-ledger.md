# The mapping file as a ledger (`[mapping] mode = "file"`)

Status: implemented.

## 1. Problem

`mode = "file"` is the fallback for servers on which clone can neither keep the source identifier nor write a marker
(see identity-carrier.md). The file maps each source key to **one** target key, the latest one clone recorded
(`compact` keeps the newer value for the same key). A target, though, can be rewound: a lab restore, or another
instance restored from the same snapshot, holds the keys of an *earlier* clone. Only clone writes the file, so the
file and the data diverge exactly when clone ran after the snapshot that is later restored. The header (scheme,
source root, target root, `base_dn`) cannot see this: a restore keeps the target root key.

Before 71f7c93 the snapshot carried a copy of the file and `lab restore --config` wrote it back, moving the existing
file aside to `<file>.bak`. That needed the config at snapshot and restore time, a separate file per instance, and
still overwrote another instance's file when given the wrong path. The `.bak` itself solved nothing: the data it
belonged to was gone. 71f7c93 removed the coupling and left these cases:

| Case | Today | Severity |
|---|---|---|
| clone (X -> x1) -> snapshot -> X deleted on the target -> clone (X -> x2, file now X -> x2) -> restore (X is x1) -> diff | `Same` is false and `x2` is found nowhere: **false `REPLACED`**; a rename of X shows as `ONLY_SOURCE` + `ONLY_TARGET` | Wrong output |
| Two instances from one snapshot, one file; a new source object Y is cloned into both (Y -> y_dev2, then Y -> y_main) -> diff dev2 | **false `REPLACED`** for Y; a rename on dev2 is missed | Wrong output |
| `lab reset` + `up` (new target root) -> clone | `ErrHeaderMismatch`: **clone fails** until the file is deleted by hand | Awkward |
| A pair whose target key no longer exists anywhere | `ONLY_SOURCE` | Correct (missed detection at worst) |

The package comment's claim that a stale mapping "never causes a false detection" is false for the first two rows.

## 2. The idea

Record history, not state. The file becomes a ledger of **every** (source key, target key) pair clone ever
created or adopted; a source key may have several target keys. diff calls a target object the source's when its key
is **any** of the recorded ones.

This is exact because servers never reuse an `objectGUID` or `entryUUID`. A key once recorded for X can reappear on
a target only through a restore, or in a sibling instance restored from the same snapshot, which is the match we
want. An object the program under test recreated has a key that was never recorded, so it is still `REPLACED`.
There is no case in which the set says "same" where the single value would have said otherwise correctly.

Consequences:

- Restores, sibling instances and recreated labs need nothing. No `.bak`, no `--config` on restore, no copy in the
  snapshot; `lab` keeps knowing nothing about `[mapping]` or `identity`.
- The file is monotone: clone only adds pairs, never replaces one.
- One file serves every target cloned from one source, so the target no longer belongs in the header.

## 3. Design

### 3.1 Data layout

- Records stay **fixed-length, 66 bytes** (`<source hex>\t<target hex>\n`), now sorted by **(source, target)**.
  A source with two target keys has two adjacent records; a record is always one pair, never a list:

  ```
  # ldap-cronin mapping v5 scheme=objectGUID source-root=...
  1111...1111	aaaa...aaaa
  2222...2222	bbbb...bbbb   <- source 2222 was cloned twice:
  2222...2222	cccc...cccc   <- two records, each 66 bytes
  3333...3333	dddd...dddd
  ```
- Header: `# ldap-cronin mapping v5 scheme=<attr> source-root=<key>`. `TargetRoot` and `BaseDN` are dropped (keys are
  globally unique, so pairs of other targets or other base DNs simply never match). `Scheme` and `SourceRoot` stay:
  a file of another source is refused (`ErrHeaderMismatch`), the same boundary as the marker's `ErrForeign`.
- `formatVersion = 5`. A v4 file gets the existing `ErrOldFormat` note (compatibility is not a concern).

### 3.2 Performance

The lookup stays a binary search on the file; the only change is how it ends.

- **Lookup** (`Targets(source)`): a lower-bound binary search for the first record with that source (about 20
  `ReadAt`s of 66 bytes for a million records, as today), then a forward scan while the source matches. The last
  step reads two records at once (132 bytes), so a source with one target key, which is nearly every source, costs
  exactly what it does today; each further key adds one adjacent record, normally on the same page.
- **Memory** stays constant: nothing is loaded; the external sort keeps `chunkRecords` records at a time.
- **Size**: one record per object, plus one per time an object was recreated and cloned again. A clone that only
  updates adds nothing. Growth is linear in recreations, which are what the program under test does to a few
  objects, not to the whole tree.
- **clone**: `Record` already looks the source up before appending; it now checks membership instead of equality,
  at the same cost. `compact` compares whole records instead of keys and drops identical pairs instead of keeping
  the newer one: the same external sort and merge.
- **diff**: the move search (`Filter`) becomes `(|(objectGUID=x1)(objectGUID=x2))` for a source with several keys,
  still one search per moved object.

No index or second file is needed. A pruning command is left out: nothing can tell which instances still hold an
old key.

### 3.3 Concurrent clones

With one file serving several instances, two clones into two instances at the same time become plausible. Today
they truncate each other's `.delta`, and the second `compact` rewrites the table from a stale copy and drops the
first one's pairs.

`Open` creates `<file>.lock` with `O_EXCL` (portable, Windows included; it holds the PID, host and time) and `Close`
removes it. A second clone refuses: `mapping file is in use by another clone (<file>.lock: pid ... since ...);
if no clone is running, delete it`. diff only reads and takes no lock: `compact` replaces the table by rename, so a
reader keeps the file it opened. (On Windows the rename fails while a diff holds the file open; clone then reports
it, and the pairs stay in `.delta` for the next `Open` to merge.)

A leftover `.delta` from an interrupted clone is still merged by the next `Open`, as today.

### 3.4 Changes to the code

| Where | Change |
|---|---|
| `internal/identity/mapfile.go` | Package comment (ledger rationale; drop the "never causes a false detection" claim). `Header` loses `TargetRoot` and `BaseDN`; `formatVersion = 5`. `Target(source) (Key, bool)` becomes `Targets(source) []Key`. `Record` appends only a new pair. `sortDeltaIntoRuns` and `merge` order and deduplicate on the whole record. The lock file |
| `internal/identity/carrier.go` | `byMap.Same`: the entry's key is in `Targets(source)` (an unmapped source stays `same, known`). `byMap.Filter`: one filter, or an OR of `Scheme.Filter` for several keys |
| `internal/app/run.go` | `mappingHeader` reads only the source root (one target read fewer, and clone into an empty target no longer needs its root). The `ErrHeaderMismatch` note says "another source" |
| `internal/clone`, `internal/diff`, `internal/lab` | Unchanged |

Docs: `docs/diff.md` (the **file** bullets: a ledger, restores need nothing, the header, the lock, the OR search);
`docs/lab.md` "Rename detection after a restore" (one sentence each for preserve and file); `docs/DEVELOPMENT.md`
(the header decision row changes; a new row: "The mapping file is a ledger of every pair, not the current state |
a restore returns the target to a state an earlier clone produced, and identifiers are never reused"); a bullet in
identity-carrier.md section 7.

### 3.5 Edge cases

- **A source object deleted and recreated on the source** (new key X', same DN): clone finds the cloned object at
  the DN and records X' -> x1, so x1 is listed under X and X'. diff for X' sees x1: same. Correct: clone did map X'
  onto it.
- **clone over an object the program recreated** adopts the key at the DN (as today), so that object counts as the
  source's from then on. Documented.
- **Duplicates**: a key exists at most once per target, so several hits mean the OpenLDAP duplicate-`entryUUID`
  case, counted as today.

## 4. Alternatives rejected

| Alternative | Why not |
|---|---|
| A generation written on the target (an attribute on `base_dn`, a probe object) | File mode exists for servers where clone may write nothing extra |
| A generation kept by `lab` (state dir, `snapshot.json`) | diff also runs against non-lab servers, and it couples `lab` to `[mapping]` again |
| Snapshots carry the file and restore picks it automatically | Needs the path at snapshot time and a copy per instance; the `.bak` problem in another form |
| One file per header in a directory | Fixes only the reset case, not the two wrong-output cases |
| Remove file mode | Simpler, but 389-ds (can a client set `nsUniqueId`/`entryUUID`?) and an AD where `adminDisplayName` may not be written are open; the change is small |

## 5. Tests

- `internal/identity/mapfile_test.go`: two target keys of one source survive `compact`; recording an existing pair
  does not grow the file; the search returns every key of a source and none of its neighbours (first and last
  record, a source with three keys across a chunk boundary with a small `chunkRecords`); v4 header -> `ErrOldFormat`;
  another source root -> `ErrHeaderMismatch`; the lock refuses a second `Open` and is removed by `Close`.
- `internal/identity/carrier_test.go`: `byMap.Same` true for any recorded key, false for another; `Filter` is plain
  for one key and an OR for two.
- `internal/clone` (fakedir, next to the entryUUID rename test; fakedir gets a `Copy()`): clone -> copy ("snapshot")
  -> delete alice, clone again -> put the copy back ("restore") -> diff: no differences; rename alice -> `RENAMED`.
  Two targets cloned with one file: each diffs clean, a rename on either is found.
- `internal/app`: clone in file mode into a target whose root differs from the one the file was first written for
  succeeds.
- e2e (`e2e/lab_test.go`, Samba with `mode = "file"`; no file-mode e2e exists today): clone -> snapshot -> delete a
  user -> clone -> restore -> diff reports no differences; rename -> `RENAMED`.
