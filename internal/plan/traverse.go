package plan

import (
	"context"
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/workpool"
)

// Node is one container or parent leaf of the plan.
type Node struct {
	Entry directory.Entry
	// Kind is the kind the entry is handled as; nil for a create-only ancestor.
	Kind *Kind
	// CreateOnly marks an ancestor above or between the selected entries (CN=Users, ...): it is created when missing
	// and otherwise left alone, and diff only checks that it exists.
	CreateOnly bool
	// Outside marks a parent leaf outside the scope (see Plan.Ancestor): it is handled as its kind without its own
	// references, as a referenced object is.
	Outside bool
}

// Leaf reports whether n is a parent leaf: an entry of a leaf kind that is the ancestor of another to clone.
func (n Node) Leaf() bool { return n.Kind != nil && n.Kind.Role == profile.RoleLeaf }

// EachLevel calls fn for every container and parent leaf, one depth at a time and shallowest first, with the
// entries of one depth in parallel. A level waits for the previous one because a child can only be created, or its
// expected location on the target known, once its parent has been handled.
func (p *Plan) EachLevel(ctx context.Context, workers int, fn func(context.Context, Node) error) error {
	items := p.Containers
	for len(items) > 0 {
		depth := dn.Depth(items[0].Entry.DN)
		n := 0
		for n < len(items) && dn.Depth(items[n].Entry.DN) == depth {
			n++
		}
		if err := workpool.Each(ctx, workers, items[:n], fn); err != nil {
			return err
		}
		items = items[n:]
	}
	return nil
}

// EachLeaf streams the enabled leaf kinds (groups, users) in the profile's creation order, without the parent
// leaves (EachLevel handles them). The source is read sequentially on one connection while fn runs on at most
// workers entries, so memory stays bounded by workers. Leaves do not depend on each other (references are applied
// afterwards), which is what makes the parallelism safe.
func (p *Plan) EachLeaf(ctx context.Context, workers int, fn func(ctx context.Context, k *Kind, e directory.Entry) error) error {
	for _, k := range p.Leaves() {
		err := workpool.Feed(ctx, workers, func(ctx context.Context, emit func(directory.Entry) error) error {
			return p.Walk(ctx, k, k.Attrs, func(e directory.Entry) error {
				if p.parentLeaves[dn.Normalize(e.DN)] {
					return nil // handled by EachLevel
				}
				return emit(e)
			})
		}, func(ctx context.Context, e directory.Entry) error {
			return fn(ctx, k, e)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// Leaves returns the enabled leaf kinds in creation order.
func (p *Plan) Leaves() []*Kind {
	var out []*Kind
	for i := range p.job.Kinds {
		if p.job.Kinds[i].Role == profile.RoleLeaf {
			out = append(out, &p.job.Kinds[i])
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	return out
}

// Change is one attribute whose values differ between the wanted (source) and the current (target) entry.
type Change struct {
	Name      string
	Want, Got []string
}

// Changes compares want with got over names and returns the attributes that differ. DN reference attributes come
// back separately: clone can only apply them, and diff only judge them, after every object has been matched.
// skip leaves out attributes the caller handles itself (masked ones, the RDN attribute, server-assigned ones).
func (p *Plan) Changes(want, got directory.Entry, names []string, skip func(name string) bool) (plain, refs []Change) {
	for _, name := range names {
		if skip != nil && skip(name) {
			continue
		}
		w, g := want.Values(name), got.Values(name)
		if p.Equal(name, w, g) {
			continue
		}
		c := Change{Name: name, Want: w, Got: g}
		if p.IsRef(name) {
			refs = append(refs, c)
		} else {
			plain = append(plain, c)
		}
	}
	return plain, refs
}

// InScope returns the values that name an object of the plan. References to anything else (built-in groups,
// objects outside base_dn) are neither created nor compared.
func (p *Plan) InScope(values []string) []string {
	var out []string
	for _, v := range values {
		if p.Scope.Has(v) {
			out = append(out, v)
		}
	}
	return out
}

// IsRDNAttr reports whether attr is the naming attribute of entryDN (cn for CN=..., ou for OU=...).
func IsRDNAttr(entryDN, attr string) bool {
	typ, _, ok := dn.FirstRDN(entryDN)
	return ok && strings.EqualFold(typ, attr)
}
