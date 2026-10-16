// Package plan decides "what to target", shared by clone and diff.
//
// To avoid OOM on large data sets, it does not hold every entry. It keeps only
// OUs and parent containers (they must be created parents first) and the set of target DNs (Scope).
// Groups and users are streamed page by page via Walk.
package plan

import (
	"fmt"
	"hash/maphash"
	"sort"
	"strconv"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/attrs"
	"github.com/wadahiro/ldap-cronin/internal/compare"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/mask"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// DefaultFilters are the AD search filters per kind. user excludes computer (which also has objectClass=user).
var DefaultFilters = profile.AD.Filters

type Options struct {
	// Profile selects the server type. The zero value means AD.
	Profile profile.Profile
	// RootDN is the top of the naming context that contains BaseDN. Empty means it is detected (see DetectRoot).
	RootDN  string
	BaseDN  string
	Kinds   []string
	Filters map[string]string   // overrides of DefaultFilters
	Attrs   map[string][]string // resolved allow list per kind
	Masker  mask.Masker
	// When TrackGUID is true, objectGUID is also read from the source (to record and look up the mapping).
	// objectGUID is not copied.
	TrackGUID bool
	// When KeepIdentity is true, objectGUID and objectSid are also read from the source and included in the copy
	// (so a native import can create the target with the same values).
	KeepIdentity bool
}

// GUIDAttr is the AD attribute name of an object GUID. SIDAttr is that of a SID. For other servers see Options.IDAttr.
const (
	GUIDAttr = "objectGUID"
	SIDAttr  = "objectSid"
)

// P returns the profile in effect (AD when none was set).
func (o Options) P() profile.Profile {
	if o.Profile.Name == "" {
		return profile.AD
	}
	return o.Profile
}

// IDAttr is the attribute that identifies an object across renames and moves (objectGUID, entryUUID).
func (o Options) IDAttr() string { return o.P().IDAttr }

// withGUID adds objectGUID to the attributes to fetch when TrackGUID is set, and objectGUID and objectSid when KeepIdentity is set.
func (o Options) withGUID(names []string) []string {
	var extra []string
	if o.TrackGUID || o.KeepIdentity {
		extra = append(extra, o.IDAttr())
	}
	if o.KeepIdentity {
		extra = append(extra, SIDAttr)
	}
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

// Enabled reports whether a kind is targeted.
func (o Options) Enabled(kind string) bool {
	for _, k := range o.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// SearchFilter is the filter of a kind with a condition added that excludes system-required objects.
// A safeguard so that Administrator, krbtgt and the like are not overwritten even if base_dn is set to CN=Users or similar.
func (o Options) SearchFilter(kind string) string {
	f := o.P().Filters[kind]
	if custom, ok := o.Filters[kind]; ok && custom != "" {
		f = custom
	}
	return "(&" + f + o.P().SystemFilter + ")"
}

// Scope is the set of target DNs. It holds only an 8-byte hash per entry, so even a million entries fit in tens of MB.
// A collision would mistake an out-of-scope DN for an in-scope one, but then the reference target is missing at apply time and it fails loudly rather than corrupting silently.
type Scope struct {
	seed maphash.Seed
	set  map[uint64]struct{}
}

// NewScope returns an empty Scope.
func NewScope() *Scope { return newScope() }

func newScope() *Scope { return &Scope{seed: maphash.MakeSeed(), set: map[uint64]struct{}{}} }

func (s *Scope) key(dnStr string) uint64 { return maphash.String(s.seed, dn.Normalize(dnStr)) }

func (s *Scope) add(dnStr string) { s.set[s.key(dnStr)] = struct{}{} }

// Add adds a DN. Do not call it from multiple goroutines at once (the caller must serialize).
func (s *Scope) Add(dnStr string) { s.add(dnStr) }

// Has is read-only and can be called from multiple goroutines (construction happens only inside Build).
func (s *Scope) Has(dnStr string) bool {
	_, ok := s.set[s.key(dnStr)]
	return ok
}

func (s *Scope) Len() int { return len(s.set) }

type Plan struct {
	Domain    string
	OUs       []directory.Entry // allow list and masking applied; shallowest first
	Ancestors []directory.Entry // non-OU parents (CN= containers, etc.); shallowest first
	Scope     *Scope

	src  directory.Directory
	opt  Options
	refs map[string]refInfo // lowercase attribute name -> info on DN reference attributes
}

type refInfo struct{ single bool }

// attributeSyntax from the schema.
const (
	syntaxDN       = "2.5.5.1"  // DS-DN (member, manager, managedBy, seeAlso, etc.)
	syntaxDNBinary = "2.5.5.7"  // DN+binary; not supported because the DN inside the value cannot be rewritten
	syntaxDNString = "2.5.5.14" // DN+string; same as above
)

// Build walks the source and builds the plan. For groups and users it reads only the DN and keeps no entities.
func Build(src directory.Directory, opt Options) (*Plan, error) {
	root, err := DetectRoot(src, opt)
	if err != nil {
		return nil, err
	}
	p := &Plan{Domain: root, Scope: newScope(), src: src, opt: opt}
	if p.Domain == "" || dn.Equal(opt.BaseDN, p.Domain) || !dn.IsDescendant(opt.BaseDN, p.Domain) {
		return nil, fmt.Errorf("base_dn %q must be below the root %q: cloning a whole naming context would overwrite built-in entries", opt.BaseDN, p.Domain)
	}
	base, err := src.Get(opt.BaseDN, []string{"objectClass"})
	if err != nil {
		return nil, fmt.Errorf("read base_dn %s: %w", opt.BaseDN, err)
	}
	if base == nil {
		return nil, fmt.Errorf("base_dn %s does not exist on source", opt.BaseDN)
	}

	if err := p.discoverRefs(); err != nil {
		return nil, err
	}

	ancestors := map[string]string{} // normalized DN -> DN; candidates for non-OU parents
	ouSet := map[string]bool{}
	noteAncestors := func(entryDN string) {
		for _, a := range dn.Ancestors(entryDN, p.Domain) {
			key := dn.Normalize(a)
			if _, seen := ancestors[key]; seen {
				break // anything above this is already recorded
			}
			ancestors[key] = a
		}
	}

	for _, kind := range attrs.SortedKinds(opt.Kinds) {
		if kind == attrs.KindOU {
			err = src.Walk(opt.BaseDN, opt.SearchFilter(kind), opt.withGUID(opt.Attrs[kind]), func(e directory.Entry) error {
				p.OUs = append(p.OUs, opt.Masker.Apply(e))
				p.Scope.add(e.DN)
				ouSet[dn.Normalize(e.DN)] = true
				noteAncestors(e.DN)
				return nil
			})
		} else {
			err = src.Walk(opt.BaseDN, opt.SearchFilter(kind), []string{directory.NoAttrs}, func(e directory.Entry) error {
				p.Scope.add(e.DN)
				noteAncestors(e.DN)
				return nil
			})
		}
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", kind, err)
		}
	}

	for key, a := range ancestors {
		if ouSet[key] {
			continue
		}
		e, err := src.Get(a, opt.withGUID(opt.Attrs[attrs.KindOU]))
		if err != nil {
			return nil, fmt.Errorf("read ancestor %s: %w", a, err)
		}
		if e == nil {
			return nil, fmt.Errorf("ancestor %s does not exist on source", a)
		}
		p.Ancestors = append(p.Ancestors, opt.Masker.Apply(*e))
		p.Scope.add(a)
	}
	sortByDepth(p.OUs)
	sortByDepth(p.Ancestors)
	return p, nil
}

// discoverRefs determines from the source schema which attributes hold DNs.
// With a fixed list (member/manager/managedBy) alone, attributes added via extra_include such as seeAlso or
// Exchange publicDelegates would fail depending on the creation order of their targets, or show false differences in diff.
func (p *Plan) discoverRefs() error {
	p.refs = map[string]refInfo{}
	for k, single := range p.opt.P().BuiltinRefs {
		p.refs[k] = refInfo{single: single}
	}
	var (
		backLinks, unsupported map[string]bool
		err                    error
	)
	switch p.opt.P().Schema {
	case profile.SchemaSubschema:
		backLinks, unsupported, err = p.discoverSubschemaRefs()
	default:
		backLinks, unsupported, err = p.discoverADRefs()
	}
	if err != nil {
		return err
	}
	if backLinks == nil {
		return nil // the schema could not be read (e.g. test directories without a root DSE)
	}
	return p.validateAttrs(backLinks, unsupported)
}

func (p *Plan) discoverADRefs() (backLinks, unsupported map[string]bool, err error) {
	root, err := p.src.Get("", []string{"schemaNamingContext"})
	if err != nil {
		return nil, nil, fmt.Errorf("read root DSE: %w", err)
	}
	if root == nil || len(root.Values("schemaNamingContext")) == 0 {
		return nil, nil, nil
	}
	backLinks, unsupported = map[string]bool{}, map[string]bool{}
	filter := "(&(objectClass=attributeSchema)(|(attributeSyntax=" + syntaxDN + ")(attributeSyntax=" + syntaxDNBinary + ")(attributeSyntax=" + syntaxDNString + ")))"
	err = p.src.Walk(root.Values("schemaNamingContext")[0], filter,
		[]string{"lDAPDisplayName", "attributeSyntax", "linkID", "isSingleValued"}, func(e directory.Entry) error {
			name := first(e.Values("lDAPDisplayName"))
			if name == "" {
				return nil
			}
			key := strings.ToLower(name)
			switch first(e.Values("attributeSyntax")) {
			case syntaxDN:
				p.refs[key] = refInfo{single: strings.EqualFold(first(e.Values("isSingleValued")), "TRUE")}
			default:
				unsupported[key] = true
			}
			// An odd linkID marks a back link (memberOf, directReports, ...). The server computes it and it cannot be written.
			if id, err := strconv.Atoi(first(e.Values("linkID"))); err == nil && id%2 == 1 {
				backLinks[key] = true
				delete(p.refs, key)
			}
			return nil
		})
	if err != nil {
		return nil, nil, fmt.Errorf("read schema: %w", err)
	}
	return backLinks, unsupported, nil
}

func (p *Plan) validateAttrs(backLinks, unsupported map[string]bool) error {
	for _, kind := range p.opt.Kinds {
		for _, name := range p.opt.Attrs[kind] {
			key := strings.ToLower(name)
			switch {
			case backLinks[key]:
				return fmt.Errorf("attribute %q is a back link computed by the server and cannot be cloned (clone the forward link instead)", name)
			case unsupported[key]:
				return fmt.Errorf("attribute %q holds DN-Binary/DN-String values, whose embedded DNs this tool cannot rewrite", name)
			case p.IsRef(name) && p.opt.Masker.Masked(name):
				return fmt.Errorf("attribute %q holds DNs and cannot be masked", name)
			}
		}
	}
	return nil
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// IsRef reports whether name is an attribute holding a DN (it depends on creation order, so it is applied after all objects are created).
func (p *Plan) IsRef(name string) bool {
	_, ok := p.refs[strings.ToLower(name)]
	return ok
}

// RefSingle reports whether a DN reference attribute is single-valued.
func (p *Plan) RefSingle(name string) bool { return p.refs[strings.ToLower(name)].single }

// RefNames returns only the DN reference attributes in the allow list of kind (excluded references are not applied).
func (p *Plan) RefNames(kind string) []string {
	var out []string
	for _, a := range p.opt.Attrs[kind] {
		if p.IsRef(a) {
			out = append(out, a)
		}
	}
	return out
}

// Equal is value equivalence according to attribute semantics. DN reference attributes are compared as DNs.
func (p *Plan) Equal(attr string, a, b []string) bool {
	if p.IsRef(attr) {
		return compare.EqualDN(a, b)
	}
	return compare.Equal(attr, a, b)
}

// WalkRefs streams only entries that have DN reference attributes, fetching only those attributes.
// Filtering on the server side avoids re-reading the vast majority of entries that have no references.
func (p *Plan) WalkRefs(kind string, names []string, fn func(directory.Entry) error) error {
	if len(names) == 0 {
		return nil
	}
	var alts strings.Builder
	for _, n := range names {
		alts.WriteString("(" + n + "=*)")
	}
	filter := "(&" + p.opt.SearchFilter(kind) + "(|" + alts.String() + "))"
	return p.src.Walk(p.opt.BaseDN, filter, names, fn)
}

// Walk streams the entries of kind page by page with the allow list and masking applied.
// names limits the attributes to fetch (e.g. to re-fetch only the reference attributes).
func (p *Plan) Walk(kind string, names []string, fn func(directory.Entry) error) error {
	return p.src.Walk(p.opt.BaseDN, p.opt.SearchFilter(kind), p.opt.withGUID(names), func(e directory.Entry) error {
		return fn(p.opt.Masker.Apply(e))
	})
}

func sortByDepth(entries []directory.Entry) {
	sort.SliceStable(entries, func(i, j int) bool { return dn.Depth(entries[i].DN) < dn.Depth(entries[j].DN) })
}

// DetectRoot returns the top of the naming context that contains base_dn.
// For AD it is the run of trailing DC= components. For other servers it is the longest namingContexts value above
// base_dn, falling back to the trailing DC= run; a base_dn without either needs [clone] root_dn.
func DetectRoot(src directory.Directory, opt Options) (string, error) {
	if opt.RootDN != "" {
		return opt.RootDN, nil
	}
	if opt.P().Name == profile.NameAD {
		return dn.DomainRoot(opt.BaseDN), nil
	}
	rootDSE, err := src.Get("", []string{"namingContexts"})
	if err != nil {
		return "", fmt.Errorf("read root DSE: %w", err)
	}
	best := ""
	if rootDSE != nil {
		for _, nc := range rootDSE.Values("namingContexts") {
			if dn.IsDescendant(opt.BaseDN, nc) && dn.Depth(nc) > dn.Depth(best) {
				best = nc
			}
		}
	}
	if best == "" {
		best = dn.DomainRoot(opt.BaseDN)
	}
	if best == "" {
		return "", fmt.Errorf("cannot determine the naming context of base_dn %q: set [clone] root_dn", opt.BaseDN)
	}
	return best, nil
}
