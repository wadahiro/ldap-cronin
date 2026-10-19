// Package plan decides "what to target", shared by clone and diff.
//
// To avoid OOM on large data sets, it does not hold every entry. It keeps only the containers (they must be created
// parents first) and the set of target DNs (Scope). Leaves are streamed page by page.
package plan

import (
	"context"
	"fmt"
	"hash/maphash"
	"sort"
	"strings"

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
	// parentLeaves are the normalized DNs of the leaves of the scope that are also ancestors, handled in
	// Containers instead of by EachLeaf.
	parentLeaves map[string]bool
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
	p := &Plan{Root: root, Scope: NewScope(), src: src, job: job, read: read}
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
	for _, k := range p.job.Kinds {
		for _, name := range k.Attrs {
			key := strings.ToLower(name)
			switch {
			case schema.BackLinks[key]:
				return fmt.Errorf("attribute %q is a back link computed by the server and cannot be cloned (clone the forward link instead)", name)
			case schema.Unsupported[key]:
				return fmt.Errorf("attribute %q holds DN-Binary/DN-String values, whose embedded DNs this tool cannot rewrite", name)
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
	var alts strings.Builder
	for _, n := range names {
		alts.WriteString("(" + n + "=*)")
	}
	filter := "(&" + k.Filter + "(|" + alts.String() + "))"
	return p.src.Walk(ctx, p.job.BaseDN, filter, names, fn)
}

// Walk streams the entries of k page by page with masking applied and what Read asks for added to names.
func (p *Plan) Walk(ctx context.Context, k *Kind, names []string, fn func(directory.Entry) error) error {
	return p.src.Walk(ctx, p.job.BaseDN, k.Filter, p.withRead(names), func(e directory.Entry) error {
		return fn(p.job.Masker.Apply(e))
	})
}
