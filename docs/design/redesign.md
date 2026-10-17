# Redesign of the middle layer (profile / plan / clone / diff / cmd)

Status: implemented. Section 7 lists where the implementation departs from the text below.

ldap-cronin was written for Active Directory first and generalized to plain LDAP afterwards.
An architecture review found that the AD-first origin survives mainly in one place: `internal/profile` describes server differences as flags and attribute-name lists, and `plan`, `clone`, `diff`, `compare`, `config` and `cmd` each interpret those flags with their own `if`/`switch`.
This document redesigns that middle layer from scratch.
The tool is a prototype, so the redesign does not keep compatibility with the current config file, mapping file or internal APIs (section 2).

## 1. What is redesigned and what is kept

The redesign was done from zero, and the following packages were re-adopted because the review found nothing structurally wrong with them:
`directory` (the operation interface; it already encodes "add/update only" by having no Delete or ModifyDN), `ldapdir`, `fakedir`, `lab`, `dn`, `ldif`, `mask`, `workpool`.
They keep their structure; what changes in them is a `context.Context` on every operation (4.11), how `ldapdir` is told about ranged attributes (4.6), connection timeouts in `ldapdir`, and the mapping file header (4.4).
The streaming memory model (page-by-page `Walk`, 8-byte DN hash `Scope`, back-pressure in `workpool.Feed`, the fixed-length sorted mapping) and the concurrency model (one sequential source connection; parallelism only on the target; no re-entry into a `Directory` from inside its `Walk` callback) are kept as they are.

Redesigned: `profile`, `attrs`, `compare` (its AD rules), `plan`, `clone`, `diff`, `guidmap` (renamed to `identity`), `config` (schema and validation), `cmd`, and the AD-only code currently in `cmd/ldap-cronin/native.go`.

## 2. Constraints

### 2.1 Kept on purpose

These are design properties, not compatibility promises; the redesign keeps them because the reasons in `docs/DEVELOPMENT.md` still hold:

- Constant memory for leaves; a single sequential source connection; add/update only; DN references applied after all objects exist.
- The 3-step AD user creation (add disabled → `unicodePwd` modify → `userAccountControl`), because a real AD refuses `unicodePwd` in an Add (KB 269190).
- `lab` and `clone -native` stay AD/Samba only.
- Commands, the `diff` output format and summary, exit codes (0 / 1 / 2), dry-run LDIF on standard output with progress on standard error. Nothing in the review calls for changing them.

### 2.2 Allowed to change

- **Config keys** (4.10). Old config files are not read; an unknown key is an error that names the new key.
- **Mapping file format** (4.4). An old file is rejected with an error saying to run `clone` again; there is no converter.
- **Internal APIs**, including the `Directory` interface (4.11).
- **How the generic LDAP profile sets the fixed password** (4.3).

## 3. Problems this design removes

| # | Problem (file:line in the current tree) | Consequence |
|---|---|---|
| P1 | The user finishing step is hard-coded in `clone` (`clone.go:26-33, 97-113, 176, 322-360`): `userAccountControl` and `pwdLastSet` are read and stripped for every profile; only `setPassword` looks at `PasswordMode` | **Bug on generic LDAP**: `finishUser` re-sets the password only when `pwdLastSet=0`. OpenLDAP has no `pwdLastSet`, so a user whose Add succeeded but whose password modify failed never gets a password on re-run |
| P2 | `Profile` is a bag of flags (`Password`, `Schema`, `IDIsText`, `LeafOrder`, `SupportsNative`, `RangedAttrs`) interpreted in 6 places | A third server type, or one new variation (e.g. a different password mechanism), means editing every interpreter |
| P3 | Branches on the profile name in shared code (`plan.go:375`, `config.go:130`); zero-value `plan.Options` means AD (`plan.go:27, 51-56`, `config.go:191-202`, four AD-default wrappers in `attrs`) | Violates the rule in AGENTS.md; tests that forget `Profile` silently test AD only |
| P4 | Identifier encoding spread over `profile` (`IDAttr`, `IDIsText`), `guidmap.Hex` (guesses the format from the value's shape), `diff` (`idText`), `fakedir` (understands only `objectGUID=` filters) | The generic-LDAP rename detection cannot be unit-tested; only the OpenLDAP E2E covers it |
| P5 | Two switches for one feature: `plan.Options.TrackGUID` and `clone.Options.GUIDMap`; `diff.RunWith` mutates `TrackGUID` | Passing a map without the flag produces an empty mapping file with no error |
| P6 | `KeepIdentity`, `objectGUID` / `objectSid` names inside `plan` and `clone` for a lab-only feature | Lab knowledge in the shared core |
| P7 | Kinds `ou` / `group` / `user` are tied to roles: `plan.go:187` branches on `KindOU`, `diff.go:159` lists `{group, user}`, `clone.go:97` branches on `KindUser`; ancestors are read with the OU allow list (`plan.go:212`) | A new object type touches about 7 places; an ancestor with a structural attribute outside the OU list cannot be created |
| P8 | Depth-ordered structure processing duplicated (`clone.go:124-145`, `diff.go:124-157`); attribute difference loops duplicated (`clone.go:206-220`, `diff.go:396-416`); in-scope reference filtering duplicated (`clone.go:374-395`, `diff.go:453-461`) | The rule "references are deferred" lives in three places |
| P9 | `diff.go` (723 lines) holds orchestration, matching, comparison, formatting and summary; `check` takes 11 arguments | Hard to change one concern without reading all |
| P10 | `ldapdir.Client.SetRangedAttrs` must be called after dial and before sharing (`ldapdir.go:36-49`, `cmd/profile.go:20,27`); the default is AD's `member` | Forgetting it on OpenLDAP returns an empty `member` |
| P11 | Session assembly in `cmd` (`main.go:89-299`, `cmd/profile.go`), with `os.Stderr` written directly; `identityPreserved` (`native.go:163-213`) uses `plan.DefaultFilters` and ignores `[clone.filters]` and `SystemFilter` | Untested orchestration; the identity decision can probe an object that `diff` will not compare |
| P12 | No signal handling and no cancellation: Ctrl-C ends the process without running `defer`; `workpool.Feed` lets in-flight work continue after the first error; `lab/docker.go` uses `exec.Command`; `ldapdir` never calls `SetTimeout` | Interrupting `clone -native` leaves the lab container stopped (`Native.Close` never runs); a long `clone` cannot be stopped cleanly; a hung server blocks forever |
| P13 | Config sections named after one command: `[clone]` holds the scope and `workers` that `diff` uses too; `[state] file` is the mapping | The config describes the tool's history, not its model |

## 4. Design

### 4.1 Packages and dependency direction

```
cmd/ldap-cronin/   flags, signal context, prompting (Secrets), exit codes. Nothing else.
internal/
  app/             session assembly: dial, resolve profile, build the Job, open/load the mapping; Clone, Diff, Native entry points
  profile/         Profile = data + strategies. profile.go (types), ad.go, ldap.go
  identity/        identifier Scheme, Key, Lookup, mapping file Map (replaces guidmap)
  plan/            Job, Plan, traversal (EachLevel / EachLeaf / WalkRefs), attribute differences (Changes), InScope
  clone/           applies a Plan: upsert, account steps, references
  diff/            matcher.go (locator), compare.go, format.go, summary.go, lookup.go (identity decision)
  compare/         generic value equivalence; per-attribute normalizers are supplied by the profile
  ad/              AD-only helpers: GUID/SID text (old adguid), domain identity (old cmd domainIdentity/realmOf/netbiosOf)
  dryrun/          old directory.DryRun
  directory/ ldapdir/ fakedir/ dn/ ldif/ mask/ workpool/ lab/ config/ prompt/
```

Dependencies point one way: `directory ← identity ← profile ← plan ← clone, diff ← app ← cmd`.
`profile/ad.go` may import `ad`; `ad` imports only `directory`. `lab` is used only by `app`.
`directory.DryRun` moves to `internal/dryrun` so the interface package holds no implementation.

### 4.2 profile: data for lists, interfaces for behavior

Lists stay data, because they are what a deployment tweaks and what `list-attrs` prints.
Every behavioral difference becomes a strategy value, so shared code calls it instead of interpreting a flag.

```go
package profile

type Role int

const (
	RoleContainer Role = iota // created shallowest first, held in memory (OUs)
	RoleLeaf                  // streamed (groups, users)
)

type KindSpec struct {
	Name    string   // "ou", "group", "user": the label used by config keys
	Role    Role
	Filter  string
	Default []string // default allow list (without Rules.Required)
	Order   int      // creation order among leaves (AD: group=0,user=1; LDAP: user=0,group=1)
	Account bool     // the Account strategy applies to entries of this kind
}

type AttrRules struct {
	Required, NeverClone, NoMask, PasswordAttrs []string
	SystemFilter  string
	AncestorAttrs []string // what is read and written for a create-only ancestor (objectClass + naming attributes)
}

type Profile struct {
	Name     string
	Kinds    []KindSpec
	Rules    AttrRules
	Identity identity.Scheme
	Refs     RefDiscoverer
	Account  Account
	Values   map[string]compare.Normalizer // lowercase attribute -> value normalizer (AD: userAccountControl, accountExpires)
	Root     RootResolver
	Ranged   []string      // attributes always fetched with ;range= (AD: member). See 4.6
	Native   NativeSupport // nil: clone -native is refused
}

type RefDiscoverer interface {
	// Discover returns the DN-valued attributes and the attributes that must be rejected in an allow list.
	// ok=false means the schema could not be read (test directories); built-in refs are then used alone.
	Discover(ctx context.Context, src directory.Directory) (refs map[string]RefInfo, backLinks, unsupported map[string]bool, ok bool, err error)
}

type RootResolver interface {
	Root(ctx context.Context, src directory.Directory, baseDN string) (string, error) // [scope] root_dn, when set, bypasses this
}

type NativeSupport interface {
	Domain(ctx context.Context, src directory.Directory, root string) (DomainIdentity, error)
}
type DomainIdentity struct{ Root, SID, GUID, Realm, NetBIOS string }
```

`ByName`, `Detect` and `Resolve` stay. `Profile` values are built once in `ad.go` / `ldap.go`; there is no zero-value default, and `plan.Build` returns an error for a `Job` without a profile.
`attrs.ResolveFor` / `IsMaskableFor` / `DefaultsFor` become methods of `Profile` (`p.Resolve(kind, override)`, `p.Maskable(name)`); the AD-default wrappers are deleted.
`compare.Equal` loses its `member` / `manager` / `managedby` special case (references are routed by `plan`) and its `userAccountControl` / `accountExpires` rules, which move into `profile.AD.Values`.

### 4.3 Account: the user finishing steps

```go
type Account interface {
	// AddEntry returns what to send in the Add for a new account (strip, add or encode attributes).
	AddEntry(e directory.Entry, password string) directory.Entry
	// ReadExtra lists attributes to read with the existing entry, for Finish.
	ReadExtra() []string
	// Finish runs after a successful Add (cur == nil) or on an existing entry. It returns whether it changed anything.
	Finish(ctx context.Context, dst directory.Directory, want directory.Entry, password string, cur *directory.Entry) (changed bool, err error)
	// Owned lists allow-listed attributes that only Finish writes (AD: userAccountControl; LDAP: none).
	// clone excludes them from the generic comparison so Finish is their only writer.
	Owned() []string
}
```

`clone` calls `AddEntry` → `Add` → `Finish` for kinds with `Account: true` and knows no attribute names.
The order and the "existing entry" read stay in `clone`; what each step does belongs to the profile.

`AddEntry` shapes the Add only. For an existing entry, `clone` compares the resolved allow list minus `Owned()`, never the `AddEntry` output; otherwise the LDAP `userPassword` would be read back (hidden by ACL or hashed), differ on every run and be reset.
`userPassword` cannot enter the allow list anyway, because `PasswordAttrs` is a subset of `NeverClone`.
`compare.SetDiff` takes the same profile normalizers as `Equal`, so multi-valued differences keep their normalization when `userAccountControl` leaves `compare`.

**AD (`adAccount`)**:
`AddEntry` strips `userAccountControl` (the account is created disabled).
`ReadExtra` is `userAccountControl`, `pwdLastSet`.
`Finish` sets `unicodePwd` with a modify when created or when `pwdLastSet=0` (an interrupted creation), then replaces `userAccountControl` with the sanitized source value if it differs.

**Generic LDAP (`ldapAccount`)**:
`AddEntry` puts the fixed password into the Add as `userPassword`.
`ReadExtra` is empty and `Finish` does nothing.

This removes P1 structurally: an LDAP user cannot exist without the password, so there is no interrupted state to detect, and an existing user's password is never reset on re-run.
The 3-step split exists only because AD refuses `unicodePwd` in an Add; no generic server has that restriction.
Two alternatives were rejected: "set the password when `userPassword` is absent" misfires when the bind DN's ACL hides `userPassword` (every run would reset every password), and "always set it" fails under a ppolicy `pwdInHistory` and rolls back passwords changed by the program under test.
What the server stores is the same as with a modify: a plain value in an Add is hashed by 389-ds and by OpenLDAP with `ppolicy_hash_cleartext`, and stored as is otherwise.
Things to adjust with it: the `ErrSchemaViolation` retry rebuilds its entry from the `AddEntry` output, so the password is kept; dry-run LDIF redacts the profile's `PasswordAttrs` instead of the hard-coded `unicodepwd` (`ldif.go:36`), passed in by `dryrun`; `TestInterruptedUserGetsPasswordOnRerun` becomes AD-only and an LDAP test asserts that `userPassword` is in the Add.

### 4.4 identity: one place for identifier encoding

```go
package identity

type Key [16]byte // objectGUID raw bytes and entryUUID text map to the same key

type Scheme interface {
	Attr() string                  // objectGUID / entryUUID
	Key(value string) (Key, error) // each scheme parses only its own format; no shape guessing
	Filter(k Key) string           // (objectGUID=\ab\cd...) / (entryUUID=xxxxxxxx-xxxx-...)
	CarryOver() []string           // attributes kept by a native import (AD: objectGUID, objectSid; LDAP: none)
}

type Lookup interface {
	Target(source Key) (Key, bool)
	Len() int
	Preserved() bool // true for the identity mapping (native import)
}

type Identity struct{} // Preserved() == true; replaces the type assertion in diff
type Map struct{ /* Open, Load, Record, Close, external sort: as guidmap.Map */ }

type Header struct {
	Version    int    // format version; a mismatch is "run clone again", not a silent misread
	Scheme     string // Scheme.Attr(); a mapping recorded under objectGUID is never read under entryUUID
	SourceRoot Key    // identifier of the source naming-context root
	TargetRoot Key
	BaseDN     string
}

func RootKey(ctx context.Context, d directory.Directory, root string, s Scheme) (Key, error) // old RootID
```

The record layout (fixed-length, sorted by source key, binary search) stays; the header gains `Version` and `Scheme`, and the roots are stored as `Key` instead of AD-specific text.
`fakedir` evaluates equality filters through the same `Scheme.Filter` output for both schemes, so a generic-profile rename test runs without a server (P4).
`plan.GUIDAttr`, `SIDAttr`, `TrackGUID`, `guidAttr()` and `guidmap.DomainID` disappear.

### 4.5 plan: what to process, and how to traverse it

```go
package plan

// Job is what to clone or compare. It holds no run-time switches.
type Job struct {
	Profile profile.Profile
	RootDN  string // explicit [scope] root_dn, or empty
	BaseDN  string
	Kinds   []Kind // enabled kinds, filters and allow lists resolved from config
	Masker  mask.Masker
}

type Kind struct {
	profile.KindSpec
	Filter string   // after the [scope.filters] override, with SystemFilter
	Attrs  []string // resolved allow list
}

// Read says which extra source attributes the run needs.
type Read struct {
	Identity  bool // the Scheme attribute (mapping record, identity decision, native)
	CarryOver bool // Scheme.CarryOver() as well (native only)
}

type Node struct {
	Entry      directory.Entry
	Kind       *Kind // nil for a create-only ancestor
	CreateOnly bool
}

type Plan struct {
	Root       string
	Containers []Node // ancestors and container kinds, shallowest first
	Scope      *Scope
}

func Build(ctx context.Context, src directory.Directory, job Job, read Read) (*Plan, error)

// EachLevel processes Containers one depth at a time, entries of a depth in parallel.
func (p *Plan) EachLevel(ctx context.Context, workers int, fn func(context.Context, Node) error) error
// EachLeaf streams leaf kinds in Order, reading the source sequentially and applying fn with at most workers in flight.
func (p *Plan) EachLeaf(ctx context.Context, workers int, fn func(context.Context, *Kind, directory.Entry) error) error
func (p *Plan) WalkRefs(ctx context.Context, k *Kind, fn func(directory.Entry) error) error

// Changes compares want with got over names. Reference attributes are returned separately, because they can only be
// applied (clone) or judged (diff) after every object is matched.
type Change struct{ Name string; Want, Got []string }
func (p *Plan) Changes(want, got directory.Entry, names []string, skip func(string) bool) (plain, refs []Change)
func (p *Plan) InScope(values []string) []string
func (p *Plan) IsRef(name string) bool
func (p *Plan) Equal(name string, a, b []string) bool // refs as DNs, others through Profile.Values
```

`Build` branches on `Role`, never on a kind name.
Ancestors are read with `Rules.AncestorAttrs` plus the identity attribute, not with the OU allow list (P7).
Roles exist so a new object type is a new `KindSpec`; letting users declare kinds in `config.toml` is out of scope, but nothing in the design prevents it later.

### 4.6 Ranged attributes without mutable client state

Explicit `member;range=` requests stay: Samba never splits a large `member`, so being explicit is the only way the multi-fetch path runs in CI.
The mutable `SetRangedAttrs` goes. `ldapdir.Client.With(opts View) *Client` returns an immutable view that shares the connection pool; `app` resolves the profile on the plain source client and from then on hands only the views (`With(View{Ranged: p.Ranged})`) to `plan`, `clone` and `diff`.
`Session.Target` returns a view too, because `clone` and `diff` read `member` from the target.
A view without `Ranged` requests no ranges, so the AD default `defaultRanged = member` is removed from the transport.
A second dial for `auto` was rejected because it costs one more bind on the source, which the tool keeps to one connection.

### 4.7 clone

```go
package clone

type Options struct {
	Workers  int
	Password string
	Mapping  *identity.Map // non-nil records the mapping; this alone decides Read.Identity (P5)
	Native   bool          // send Scheme.CarryOver(); an existing object with another identifier is an error
}

func Run(ctx context.Context, src, dst directory.Directory, job plan.Job, opt Options, log io.Writer) (*Report, error)
```

`Run` builds the plan with `Read{Identity: opt.Mapping != nil || opt.Native, CarryOver: opt.Native}`, then
`p.EachLevel(ensure)` → `p.EachLeaf(upsert, then Account.Finish when Kind.Account)` → references.
`upsert` uses `p.Changes` for the Replace, `Account.AddEntry` for the Add, and `job.Profile.Identity` for identifier checks; the strings `objectGUID`, `objectSid`, `userAccountControl`, `pwdLastSet`, `unicodePwd` and `userPassword` no longer appear in `clone`.
On cancellation `Run` returns the report so far together with `ctx.Err()`; the caller still closes the mapping, so every recorded pair is kept and a re-run continues from there (clone is idempotent).

### 4.8 diff

```go
package diff

type Options struct {
	Workers int
	Lookup  identity.Lookup // nil: no rename/move detection
}

func Run(ctx context.Context, src, dst directory.Directory, job plan.Job, opt Options, emit func(Difference)) (Summary, error)

// ChooseLookup decides between the identity mapping and the mapping file (old cmd identityPreserved).
// It probes the first object that diff itself will compare: Job filters and SystemFilter included (P11).
func ChooseLookup(ctx context.Context, src, dst directory.Directory, job plan.Job, mapping identity.Lookup) (identity.Lookup, string, error)
```

`Run` and `RunWith` merge into one. `Summary.Identity` comes from `Lookup.Preserved()`.
The run state (summary, mutex, pending references, locator) is one `runner` struct; `check` becomes its method.
Files: `diff.go` (Run), `matcher.go` (locator, rename/move classification, `translateBack`), `compare.go` (uses `plan.Changes`, defers references), `format.go`, `summary.go`.
The pending-reference list stays in memory; its bound is documented and `memory_test.go` gains groups with differing `member` so the claim matches the test (review H-1).
An interrupted `diff` exits with 2 and prints no summary, since a partial comparison would read as "no differences" in the part not reached.

### 4.9 app and cmd

```go
package app

type Secrets struct{ SourceBind, TargetBind, UserPassword func() (string, error) }
type Dialer func(ctx context.Context, ep config.Endpoint, password string, conns int) (*ldapdir.Client, error)

type Session struct {
	Cfg  *config.Config
	Job  plan.Job
	Src  directory.Directory // the ranged view
	Warn io.Writer           // replaces direct writes to os.Stderr
}

func Open(ctx context.Context, cfg *config.Config, s Secrets, dial Dialer, warn io.Writer) (*Session, error) // source only: dry-run and native never touch the target over LDAP
func (s *Session) Target(ctx context.Context, dial Dialer) (directory.Directory, io.Closer, error)           // checks the target type matches
func (s *Session) Clone(ctx context.Context, dst directory.Directory, dryRun bool, log io.Writer) (*clone.Report, error)
func (s *Session) Diff(ctx context.Context, dst directory.Directory, maxValues int, out io.Writer) (code int, err error)
func (s *Session) Native(ctx context.Context, lab LabRef, log io.Writer) (*clone.Report, error) // old cmd native.go
```

`cmd` keeps flag parsing, prompting and exit codes, and creates the root context with `signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)`.
`run(args, stdout, stderr)` becomes testable end to end with a `Dialer` that returns `fakedir`.
`Native` checks `Job.Profile.Native != nil` instead of a name, takes the domain identity from it (implemented in `internal/ad`), and converts it into `lab.Settings`.

### 4.10 config

The sections follow the model, not the command that first used them:

```toml
[source]                    # unchanged: url, bind_dn, ca_file, insecure_skip_verify, start_tls
[target]                    # unchanged
                            # both gain: timeout = "30s" (per LDAP operation; 4.11)

[scope]                     # was [clone]; used by clone and diff alike
profile = "auto"
# root_dn = "o=acme"
base_dn = "OU=IDM,DC=ad,DC=example,DC=com"
objects = ["ou", "group", "user"]
# [scope.filters]           # was [clone.filters]

[run]
workers = 8                 # was [clone] workers; diff uses it too

[mapping]
# file = "mapping.bin"      # was [state] file; covers objectGUID and entryUUID

[attributes]                # unchanged
[mask]                      # unchanged
```

`validate` drops the `profile == "ad"` branch; a root that cannot be derived from `base_dn` is reported by `RootResolver` when the source is read.
The cost: with `profile = "ad"` and a `base_dn` without `DC=` components, the user is prompted for the source password before seeing the error.
`PlanOptions()` (auto assumed AD) is deleted; `app` builds the `Job` after the profile is resolved.
`config.example.toml`, `README.md`, `docs/` and the E2E configs are updated together.

### 4.11 Cancellation and timeouts

Every `Directory` method takes a `context.Context` first:

```go
type Directory interface {
	Walk(ctx context.Context, base, filter string, attrs []string, fn func(Entry) error) error
	Get(ctx context.Context, dn string, attrs []string) (*Entry, error)
	Add(ctx context.Context, e Entry) error
	Replace(ctx context.Context, dn string, attrs map[string][]string) error
	AddValues(ctx context.Context, dn, attr string, values []string) error
}
```

What a cancellation can and cannot do is bounded by go-ldap v3.4.15: only `SearchAsync` takes a context; `Add`, `Modify`, `Search` and `SearchWithPaging` do not.

- `ldapdir.Walk` checks `ctx` between pages; `Get` / `Add` / `Replace` / `AddValues` check it before sending. An operation already sent finishes, so a stop takes at most one operation per worker. Moving `Walk` to `SearchAsync` was rejected: it buys sub-page cancellation, which the page-sized granularity does not need, at the cost of rewriting the paging and range loop.
- A hung server is a separate problem that a context does not solve for `Add` / `Modify`. `ConnConfig.Timeout` (from `[source]` / `[target] timeout`) is applied with `Conn.SetTimeout` on every pooled connection.
- `workpool.Feed` / `Each` take `ctx` and derive a child context that is cancelled on the first error, like `errgroup.WithContext`, so in-flight workers stop at their next operation instead of running to the end.
- `fakedir` and `dryrun` check `ctx` at the start of each method so cancellation paths are unit-testable.
- `lab` runs docker with `exec.CommandContext`. The critical sections, `restore` and `snapshot` (stop → write volumes → start) and `Native.Close` (resume the lab), run under `context.WithoutCancel`: interrupting them half way would leave a broken volume or a stopped lab, which is worse than waiting a few seconds.
- The native helper container (`docker run -i --rm ... python3`) is started under `context.WithoutCancel` too. Killing it would interrupt a write to `sam.ldb`; instead `Native` checks `ctx` before each request, like `ldapdir`, and on cancellation `Close` ends the helper by closing its standard input, then resumes the lab.

## 5. Out of scope

- User-defined kinds in `config.toml` (4.5).
- Changing the `diff` output format.

## 6. Migration

Each step passes `make check`; steps touching `ldapdir`, `lab`, `clone`, `diff` or `profile` also pass `make e2e`.
Without compatibility to keep, no step adds shims or transitional names.

1. Add `context.Context` to `Directory`, `workpool` and `lab`'s docker runner; signal context in `cmd`; `ConnConfig.Timeout`. Mechanical first, so every later step is written once in its final form (P12).
2. Split `diff.go` into files and fold `check` into a `runner` struct (P9).
3. Add `plan.EachLevel` / `EachLeaf` / `Changes` / `InScope`; move `clone` and `diff` onto them (P8).
4. Create `identity` from `guidmap` with `Scheme` and the new header; teach `fakedir` both filter forms; add a generic-profile rename unit test (P4).
5. Introduce `Account`; move the AD steps into `profile/ad.go`; put `userPassword` in the LDAP Add; profile-driven dry-run redaction (P1).
6. Replace `plan.Options` with `Job` + `Read`; delete `TrackGUID`, `KeepIdentity`, the zero-value default and the `attrs` wrappers (P3, P5, P6).
7. Replace the remaining flags with strategies: `RefDiscoverer`, `RootResolver`, `Values`, `KindSpec` roles; ancestors use `AncestorAttrs` (P2, P3, P7).
8. Add `ldapdir.Client.With`; remove `SetRangedAttrs` and `defaultRanged` (P10).
9. Create `app` and `internal/ad`; move orchestration, `identityPreserved` (as `diff.ChooseLookup`) and the native flow out of `cmd`; new config sections (P11, P13).
10. Update `README.md`, `config.example.toml`, `docs/DEVELOPMENT.md` (layout; "profile is data" becomes "lists are data, behavior is strategies"; the cancellation decisions) and `docs/generic-ldap.md` (password at creation).

Steps 2-4 are independent of each other. Step 7 needs the `Job` from step 6; step 9 needs 6 and 8.
A big-bang rewrite was rejected even without compatibility to keep: every step is checkable by the existing unit and E2E tests, which a rewrite would discard as a safety net.

## 7. Implementation notes

Where the code differs from the design above, and why:

- `Account.Finish` returns the names of the attributes it changed rather than a boolean, so the update log says what changed.
- The mapping header has no `Version` field: the version is part of the header line (`# ldap-cronin mapping v4 ...`), and any other line, including the old `guid-map v3`, is `identity.ErrOldFormat`.
- `app.Dialer` returns a `Conn` with `View(ranged)` instead of taking the ranged attributes: the source must be dialed before the profile (and so its ranged attributes) is known, and a second dial was rejected in 4.6.
- `profile.NativeSupport` returns a `profile.Domain`; `internal/ad` reads it (`ad.ReadDomain`) and also holds the former `adguid` conversions.
- The lab's snapshot and restore options and the `lab` flags were renamed with the config (`Mapping`, `--mapping`); the file inside a snapshot is `mapping`.
- `docker/ad/entrypoint.sh` gained a rootless-docker fallback (`user.NTACL`), which the E2E environment of the time needed; see `docs/DEVELOPMENT.md`.
- The E2E tests still drive `clone` and `diff` directly rather than through `app`; `app` is covered by unit tests with a fake `Dialer`.
- `memory_test.go` did not gain groups with differing `member` (4.8). The bound is documented instead (the `diff` package comment and `docs/operations.md`): the pending values grow with the number of differing reference values, not with the directory.
