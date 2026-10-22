// Package plan decides "what to target", shared by clone and diff.
//
// To avoid OOM on large data sets, it does not hold every entry. It keeps only the containers (they must be created
// parents first) and the set of target DNs (Scope). Leaves are streamed page by page.
package plan

import (
	"context"
	"fmt"
	"hash/maphash"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/compare"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/mask"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// Job is what to clone or compare. It holds no run-time switches: those are Read, and the options of clone and diff.
type Job struct {
	Profile profile.Profile
	// RootDN is the top of the naming context that contains BaseDN. Empty means the profile's RootResolver decides.
	RootDN string
	BaseDN string
	// Kinds are the enabled kinds in the profile's order, with their filters and allow lists resolved.
	Kinds  []Kind
	Masker mask.Masker
	// References says what is done with a reference to an entry outside the scope: RefsClone (the default, also
	// for ""), RefsExisting or RefsSkip.
	References string
	// ConfigurationRefs says what is done with a reference naming the configuration partition (AD):
	// ConfigurationRefsSkip or ConfigurationRefsClone.
	ConfigurationRefs string
	// OutsideGroups says what is done with a group outside the scope that holds entries of it (in member, found
	// through their memberOf): OutsideGroupsClone (the default, also for ""), OutsideGroupsExisting or
	// OutsideGroupsSkip. BuiltinGroups says it for a built-in group (Domain Admins): BuiltinGroupsAdd (the default,
	// also for "") or BuiltinGroupsSkip.
	OutsideGroups, BuiltinGroups string
	// AllWritable is set when the allow lists are every attribute a client can write on the class of each kind
	// ([attributes] mode = "all"), so the summaries count them instead of naming hundreds.
	AllWritable bool
}

// The [scope] references settings.
const (
	// RefsClone clones a referenced entry of a kind outside the scope (without its own references), so the value
	// can be written; on a generic server a value naming nothing of a kind is written as it is.
	RefsClone = "clone"
	// RefsExisting writes a value only if the target holds its entry (or, on a generic server, as it is).
	RefsExisting = "existing"
	// RefsSkip writes only values that name an entry of the scope.
	RefsSkip = "skip"

	// ConfigurationRefsSkip (the default, also for "") leaves the values naming the configuration partition out.
	ConfigurationRefsSkip = "skip"
	// ConfigurationRefsClone creates the entries of the configuration partition such values name, and their parents,
	// on the target, so the values can be written: for a lab, which has none of production's Exchange objects.
	ConfigurationRefsClone = "clone"

	// OutsideGroupsClone creates a group outside the scope that holds entries of it, as a referenced entry is, and
	// gives it those entries.
	OutsideGroupsClone = "clone"
	// OutsideGroupsExisting gives them to such a group only if the target holds it.
	OutsideGroupsExisting = "existing"
	// OutsideGroupsSkip leaves such groups out.
	OutsideGroupsSkip = "skip"
	// BuiltinGroupsAdd adds the entries of the scope to the built-in groups that hold them (the target's own, of the
	// same domain), and touches nothing else of those groups.
	BuiltinGroupsAdd = "add"
	// BuiltinGroupsSkip leaves the built-in groups as they are.
	BuiltinGroupsSkip = "skip"
)

// Kind is a kind of the profile as configured for this job.
type Kind struct {
	profile.KindSpec
	// Filter is the search filter: the configured or default one, with the profile's SystemFilter.
	Filter string
	// Attrs is the resolved allow list.
	Attrs []string
}

// NewKind configures a kind of the profile. filter overrides the default filter when not empty.
func NewKind(p profile.Profile, spec profile.KindSpec, filter string, attrs []string) Kind {
	if filter == "" {
		filter = spec.Filter
	}
	return Kind{KindSpec: spec, Filter: "(&" + filter + p.SystemFilter + ")", Attrs: attrs}
}

// Kind returns the enabled kind with that name.
func (j Job) Kind(name string) (*Kind, bool) {
	for i := range j.Kinds {
		if j.Kinds[i].Name == name {
			return &j.Kinds[i], true
		}
	}
	return nil, false
}

// Read says which source attributes a run needs beyond the allow lists.
type Read struct {
	// Identity reads the identifier (to write a marker, preserve it, record or look up the mapping, or check a
	// native import).
	Identity bool
	// CarryOver also reads the attributes a native import keeps (objectGUID, objectSid) and passes them on.
	CarryOver bool
	// Extra are further source attributes outside the allow lists, such as the operational attributes a preserving
	// Add copies.
	Extra []string
}

// Root returns the top of the naming context that contains base_dn.
func Root(ctx context.Context, src directory.Directory, job Job) (string, error) {
	if job.RootDN != "" {
		return job.RootDN, nil
	}
	return job.Profile.Root.Root(ctx, src, job.BaseDN)
}

// Scope is the set of target DNs. It holds only an 8-byte hash per entry, so even a million entries fit in tens of MB.
// A collision would mistake an out-of-scope DN for an in-scope one, but then the reference target is missing at apply time and it fails loudly rather than corrupting silently.
type Scope struct {
	seed maphash.Seed
	set  map[uint64]struct{}
}

// NewScope returns an empty Scope.
func NewScope() *Scope { return &Scope{seed: maphash.MakeSeed(), set: map[uint64]struct{}{}} }

func (s *Scope) key(dnStr string) uint64 { return maphash.String(s.seed, dn.Normalize(dnStr)) }

// Add adds a DN. Do not call it from multiple goroutines at once (the caller must serialize).
func (s *Scope) Add(dnStr string) { s.set[s.key(dnStr)] = struct{}{} }

// Has is read-only and can be called from multiple goroutines (construction happens only inside Build).
func (s *Scope) Has(dnStr string) bool {
	_, ok := s.set[s.key(dnStr)]
	return ok
}

func (s *Scope) Len() int { return len(s.set) }

type Plan struct {
	Root string
	// Containers are the parents to create (create-only ancestors such as CN= containers, and parent leaves) and the
	// container kinds, shallowest first, with the allow list and masking applied. They are the only entries held in
	// memory.
	Containers []Node
	Scope      *Scope

	src  directory.Directory
	job  Job
	read Read
	refs map[string]profile.RefInfo // lowercase attribute name
	// holds pairs each back link with its forward link (profile.Schema.Holds).
	holds map[string]string
	// primary maps the RID of each source group to its DN (PrimaryGroupDN), read once.
	primaryOnce sync.Once
	primary     map[string]string
	primaryErr  error
	// parentLeaves are the normalized DNs of the leaves of the scope that are also ancestors, handled in
	// Containers instead of by EachLeaf.
	parentLeaves map[string]bool
	// leaves counts the entries of each leaf kind EachLeaf streams (by kind name), for the progress of a run.
	leaves map[string]int
	// configNC is the source's configuration partition (AD), "" where there is none.
	configNC string
	// writable caches, per object class, what a client can write on it (for the configuration entries clone creates).
	writableMu sync.Mutex
	writable   map[string][]string
}

// Job returns the job the plan was built for.
func (p *Plan) Job() Job { return p.job }

// Build walks the source and builds the plan. For leaves it reads only the DN and keeps no entities.
func Build(ctx context.Context, src directory.Directory, job Job, read Read) (*Plan, error) {
	if job.Profile.Name == "" {
		return nil, fmt.Errorf("plan: the job has no profile")
	}
	root, err := Root(ctx, src, job)
	if err != nil {
		return nil, err
	}
	p := &Plan{Root: root, Scope: NewScope(), src: src, job: job, read: read, leaves: map[string]int{}}
	if dn.Equal(job.BaseDN, root) || !dn.IsDescendant(job.BaseDN, root) {
		return nil, fmt.Errorf("base_dn %q must be below the root %q: cloning a whole naming context would overwrite built-in entries", job.BaseDN, root)
	}
	base, err := src.Get(ctx, job.BaseDN, []string{"objectClass"})
	if err != nil {
		return nil, fmt.Errorf("read base_dn %s: %w", job.BaseDN, err)
	}
	if base == nil {
		return nil, fmt.Errorf("base_dn %s does not exist on source", job.BaseDN)
	}
	if err := p.discoverRefs(ctx); err != nil {
		return nil, err
	}
	if job.Profile.ConfigurationNC != nil {
		if p.configNC, err = job.Profile.ConfigurationNC(ctx, src); err != nil {
			return nil, fmt.Errorf("read the configuration partition: %w", err)
		}
	}

	ancestors := map[string]string{} // normalized DN -> DN; candidates for create-only parents
	selected := map[string]bool{}
	noteAncestors := func(entryDN string) {
		for _, a := range dn.Ancestors(entryDN, root) {
			key := dn.Normalize(a)
			if _, seen := ancestors[key]; seen {
				break // anything above this is already recorded
			}
			ancestors[key] = a
		}
	}
	for i := range p.job.Kinds {
		k := &p.job.Kinds[i]
		if k.Role == profile.RoleContainer {
			err = src.Walk(ctx, job.BaseDN, k.Filter, p.withRead(k.Attrs), func(e directory.Entry) error {
				p.Containers = append(p.Containers, Node{Entry: job.Masker.Apply(e), Kind: k})
				p.Scope.Add(e.DN)
				selected[dn.Normalize(e.DN)] = true
				noteAncestors(e.DN)
				return nil
			})
		} else {
			err = src.Walk(ctx, job.BaseDN, k.Filter, []string{directory.NoAttrs}, func(e directory.Entry) error {
				p.leaves[k.Name]++
				p.Scope.Add(e.DN)
				noteAncestors(e.DN)
				return nil
			})
		}
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", k.Name, err)
		}
	}

	p.parentLeaves = map[string]bool{}
	for key, a := range ancestors {
		if selected[key] {
			continue
		}
		n, err := p.Ancestor(ctx, a)
		if err != nil {
			return nil, err
		}
		p.Containers = append(p.Containers, n)
		if n.Kind != nil && !n.Outside {
			p.parentLeaves[key] = true
			p.leaves[n.Kind.Name]-- // EachLevel handles it
		}
		p.Scope.Add(a)
	}
	// Map iteration made the ancestor order random; DN order keeps a level's work (and the logs) reproducible.
	sort.SliceStable(p.Containers, func(i, j int) bool {
		di, dj := dn.Depth(p.Containers[i].Entry.DN), dn.Depth(p.Containers[j].Entry.DN)
		if di != dj {
			return di < dj
		}
		return dn.Normalize(p.Containers[i].Entry.DN) < dn.Normalize(p.Containers[j].Entry.DN)
	})
	return p, nil
}

// Ancestor returns the node of an ancestor a of an entry to clone that is not selected as a container.
//
// An entry of a leaf kind is a parent leaf (a user holding Exchange's ActiveSync container, any entry on a server
// without structure rules): created with only the ancestor attributes it would miss what its kind requires (sn of
// inetOrgPerson, the account steps). One of the scope (scanned as a leaf) is handled as its kind; one outside it
// (narrowed out by the filter, or above base_dn) as a referenced object is, without its own references (Outside).
// Anything else is a create-only ancestor.
func (p *Plan) Ancestor(ctx context.Context, a string) (Node, error) {
	k, err := p.KindOf(ctx, a)
	if err != nil {
		return Node{}, fmt.Errorf("read ancestor %s: %w", a, err)
	}
	if k != nil && k.Role == profile.RoleLeaf {
		e, err := p.ReadReferenced(ctx, a, k)
		if err != nil {
			return Node{}, fmt.Errorf("read ancestor %s: %w", a, err)
		}
		if e == nil {
			return Node{}, fmt.Errorf("ancestor %s does not exist on source", a)
		}
		return Node{Entry: *e, Kind: k, Outside: !p.Scope.Has(a)}, nil
	}
	e, err := p.src.Get(ctx, a, p.withRead(p.job.Profile.AncestorAttrs))
	if err != nil {
		return Node{}, fmt.Errorf("read ancestor %s: %w", a, err)
	}
	if e == nil {
		return Node{}, fmt.Errorf("ancestor %s does not exist on source", a)
	}
	return Node{Entry: p.job.Masker.Apply(*e), CreateOnly: true}, nil
}

// CheckTargetSchema refuses a job whose allow lists name an attribute the source schema defines and the target's
// lacks. Found at the first object holding a value, it would stop clone half way, with what came before written. An
// attribute neither schema defines is no problem (no value is ever read), and a schema that cannot be read (the
// dry-run, test directories) skips the check.
func CheckTargetSchema(ctx context.Context, src, dst directory.Directory, job Job) error {
	missing, err := MissingOnTarget(ctx, src, dst, job)
	if err != nil || len(missing) == 0 {
		return err
	}
	return fmt.Errorf("the target schema lacks attributes that the source defines and the allow lists name: %s; add them to the target's schema (ldap-cronin schema prints them as LDIF, -apply writes them), or leave them out with [attributes] exclude; ldap-cronin check names every step", strings.Join(missing, ", "))
}

// MissingOnTarget names the attributes CheckTargetSchema refuses, as "name (kinds)", sorted.
func MissingOnTarget(ctx context.Context, src, dst directory.Directory, job Job) ([]string, error) {
	lister := job.Profile.SchemaAttrs
	if lister == nil {
		return nil, nil
	}
	have, ok, err := lister.Attributes(ctx, dst)
	if err != nil || !ok {
		return nil, err
	}
	defined, ok, err := lister.Attributes(ctx, src)
	if err != nil || !ok {
		return nil, err
	}
	missing := map[string][]string{} // attribute -> kinds
	var names []string
	note := func(attr, kind string) {
		key := strings.ToLower(attr)
		if !defined[key] || have[key] {
			return
		}
		if _, seen := missing[attr]; !seen {
			names = append(names, attr)
		}
		for _, k := range missing[attr] {
			if k == kind {
				return
			}
		}
		missing[attr] = append(missing[attr], kind)
	}
	for _, k := range job.Kinds {
		for _, a := range k.Attrs {
			note(a, k.Name)
		}
	}
	for _, a := range job.Profile.AncestorAttrs {
		note(a, "parents")
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s (%s)", n, strings.Join(missing[n], ", "))
	}
	return parts, nil
}

// Unselected counts, by structural object class, the entries under base_dn that clone does not copy: those of no
// enabled kind (BitLocker recovery information, ActiveSync devices, a kind left out of [scope] objects) and the
// built-in ones. The parents it creates are not counted. It is one more paged search, reading only the classes.
func (p *Plan) Unselected(ctx context.Context) (map[string]int, error) {
	var any strings.Builder
	for _, k := range p.job.Kinds {
		any.WriteString(k.Filter)
	}
	out := map[string]int{}
	err := p.src.Walk(ctx, p.job.BaseDN, "(!(|"+any.String()+"))", []string{"objectClass", "structuralObjectClass"}, func(e directory.Entry) error {
		if !p.Scope.Has(e.DN) {
			out[structural(e)]++
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("count the entries of no kind: %w", err)
	}
	return out, nil
}

// WriteCounts prints a heading with the total, then one name per line with its count, the largest first, so a
// long list stays readable in the summaries of clone and diff:
//
//	not cloned (matches no kind): 14
//	  msFVE-RecoveryInformation  12
//	  serviceConnectionPoint      2
func WriteCounts(w io.Writer, heading string, m map[string]int) {
	names := make([]string, 0, len(m))
	total, width := 0, 0
	for n, c := range m {
		names = append(names, n)
		total += c
		width = max(width, len(n))
	}
	sort.Slice(names, func(i, j int) bool {
		if m[names[i]] != m[names[j]] {
			return m[names[i]] > m[names[j]]
		}
		return names[i] < names[j]
	})
	fmt.Fprintf(w, "%s: %d\n", heading, total)
	digits := len(strconv.Itoa(total))
	for _, n := range names {
		fmt.Fprintf(w, "  %-*s  %*d\n", width, n, digits, m[n])
	}
}

// structural is the structural object class of e: the last value of structuralObjectClass, which OpenLDAP gives as
// one value and AD as the chain from top down to the structural class; otherwise the last objectClass value, which
// AD lists the same way.
func structural(e directory.Entry) string {
	if v := e.Values("structuralObjectClass"); len(v) > 0 {
		return v[len(v)-1]
	}
	if v := e.Values("objectClass"); len(v) > 0 {
		return v[len(v)-1]
	}
	return "(no objectClass)"
}

// withRead adds the attributes Read asks for to names.
func (p *Plan) withRead(names []string) []string {
	var extra []string
	scheme := p.job.Profile.Identity
	if p.read.Identity || p.read.CarryOver {
		extra = append(extra, scheme.Attr())
	}
	if p.read.CarryOver {
		extra = append(extra, scheme.CarryOver()...)
	}
	extra = append(extra, p.read.Extra...)
	out := names
	for _, x := range extra {
		found := false
		for _, n := range out {
			if strings.EqualFold(n, x) {
				found = true
				break
			}
		}
		if !found {
			out = append(append([]string(nil), out...), x)
		}
	}
	return out
}

// discoverRefs determines from the source schema which attributes hold DNs, and rejects allow lists that name an
// attribute the tool cannot handle.
func (p *Plan) discoverRefs(ctx context.Context) error {
	p.refs = map[string]profile.RefInfo{}
	for k, info := range p.job.Profile.BuiltinRefs {
		p.refs[k] = info
	}
	schema, ok, err := p.job.Profile.Refs.Discover(ctx, p.src)
	if err != nil {
		return err
	}
	if !ok {
		return nil // the schema could not be read (e.g. test directories without a root DSE)
	}
	for k, info := range schema.Refs {
		p.refs[k] = info
	}
	for k := range schema.BackLinks {
		delete(p.refs, k)
	}
	p.holds = schema.Holds
	for _, k := range p.job.Kinds {
		for _, name := range k.Attrs {
			key := strings.ToLower(name)
			switch {
			case schema.BackLinks[key]:
				return fmt.Errorf("attribute %q is a back link computed by the server and cannot be cloned (clone the forward link instead)", name)
			case p.IsRef(name) && p.job.Masker.Masked(name):
				return fmt.Errorf("attribute %q holds DNs and cannot be masked", name)
			}
		}
	}
	return nil
}

// IsRef reports whether name is an attribute holding a DN (it depends on creation order, so it is applied after all objects are created).
func (p *Plan) IsRef(name string) bool {
	_, ok := p.refs[strings.ToLower(name)]
	return ok
}

// RefSingle reports whether a DN reference attribute is single-valued.
func (p *Plan) RefSingle(name string) bool { return p.refs[strings.ToLower(name)].Single }

// RefNames returns only the DN reference attributes in the allow list of k (excluded references are not applied).
func (p *Plan) RefNames(k *Kind) []string {
	var out []string
	for _, a := range k.Attrs {
		if p.IsRef(a) {
			out = append(out, a)
		}
	}
	return out
}

// Normalizer is how values of name compare: DN-valued attributes as DNs, objectClass ignoring case (true of every
// server), and whatever the profile says about the rest (AD's userAccountControl, accountExpires).
func (p *Plan) Normalizer(name string) compare.Normalizer {
	key := strings.ToLower(name)
	switch {
	case p.IsRef(name):
		return compare.DN
	case key == "objectclass":
		return compare.CaseIgnore
	}
	return p.job.Profile.Values[key]
}

// Equal is value equivalence according to attribute semantics.
func (p *Plan) Equal(name string, a, b []string) bool { return compare.Equal(p.Normalizer(name), a, b) }

// WalkRefs streams only entries that have DN reference attributes, fetching only those attributes.
// Filtering on the server side avoids re-reading the vast majority of entries that have no references.
func (p *Plan) WalkRefs(ctx context.Context, k *Kind, names []string, fn func(directory.Entry) error) error {
	if len(names) == 0 {
		return nil
	}
	return p.src.Walk(ctx, p.job.BaseDN, refsFilter(k, names), names, fn)
}

// CountRefs counts the entries of k that have one of the DN reference attributes names, as WalkRefs streams them,
// reading their DNs only.
func (p *Plan) CountRefs(ctx context.Context, k *Kind, names []string) (int, error) {
	if len(names) == 0 {
		return 0, nil
	}
	n := 0
	err := p.src.Walk(ctx, p.job.BaseDN, refsFilter(k, names), []string{directory.NoAttrs}, func(directory.Entry) error {
		n++
		return nil
	})
	return n, err
}

func refsFilter(k *Kind, names []string) string {
	var alts strings.Builder
	for _, n := range names {
		alts.WriteString("(" + n + "=*)")
	}
	return "(&" + k.Filter + "(|" + alts.String() + "))"
}

// Walk streams the entries of k page by page with masking applied and what Read asks for added to names.
func (p *Plan) Walk(ctx context.Context, k *Kind, names []string, fn func(directory.Entry) error) error {
	return p.src.Walk(ctx, p.job.BaseDN, k.Filter, p.withRead(names), func(e directory.Entry) error {
		return fn(p.job.Masker.Apply(e))
	})
}
