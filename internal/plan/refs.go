package plan

import (
	"context"
	"strings"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
)

// RefClass is what a DN reference value names, as far as cloning it goes. clone and diff classify values the same
// way, from the source and the target and nothing recorded in between, so what clone cannot reproduce is exactly
// what diff does not compare.
type RefClass int

const (
	// RefInScope names an entry of the plan.
	RefInScope RefClass = iota
	// RefReferenced names an entry outside the scope that is of a kind: clone creates it (without its own
	// references) so the value can be written, and diff compares it.
	RefReferenced
	// RefExisting names an entry clone does not create that the target holds at the same DN (a built-in of the
	// same domain).
	RefExisting
	// RefPrincipal names a principal every domain has (AD: a well-known foreign security principal), written in
	// the profile's form (<SID=...>) so the target creates its own.
	RefPrincipal
	// RefValueOnly names nothing clone creates, on a server that takes any DN: the value is written as it is.
	RefValueOnly
	// RefUnreproducible names an entry the target lacks, on a server that needs it (AD): clone skips the value
	// and diff does not compare it.
	RefUnreproducible
)

// Reproducible reports whether clone writes values of this class, and diff compares them.
func (c RefClass) Reproducible() bool { return c != RefUnreproducible }

// refCacheLimit bounds the classifications kept; beyond it a value is classified again each time it is seen.
const refCacheLimit = 100_000

// Classifier classifies reference values against one target. A value is looked up at most once, even by workers
// asking at the same time. It is safe for concurrent use.
type Classifier struct {
	p   *Plan
	dst directory.Directory

	mu   sync.Mutex
	seen map[string]*refCheck
}

type refCheck struct {
	once  sync.Once
	class RefClass
	kind  *Kind  // RefReferenced
	write string // RefPrincipal
	err   error
}

// Classifier returns a classifier of reference values against dst.
func (p *Plan) Classifier(dst directory.Directory) *Classifier {
	return &Classifier{p: p, dst: dst, seen: map[string]*refCheck{}}
}

// Class classifies v.
func (c *Classifier) Class(ctx context.Context, v string) (RefClass, error) {
	chk, err := c.check(ctx, v)
	if err != nil {
		return 0, err
	}
	return chk.class, nil
}

// Referenced returns the kind of a RefReferenced value.
func (c *Classifier) Referenced(ctx context.Context, v string) (*Kind, error) {
	chk, err := c.check(ctx, v)
	if err != nil || chk.class != RefReferenced {
		return nil, err
	}
	return chk.kind, nil
}

// Write returns the form in which clone writes v: the principal's form for a RefPrincipal, v otherwise.
func (c *Classifier) Write(ctx context.Context, v string) (string, error) {
	chk, err := c.check(ctx, v)
	if err != nil {
		return "", err
	}
	if chk.class == RefPrincipal {
		return chk.write, nil
	}
	return v, nil
}

func (c *Classifier) check(ctx context.Context, v string) (*refCheck, error) {
	if c.p.Scope.Has(v) {
		return &refCheck{class: RefInScope}, nil
	}
	key := dn.Normalize(v)
	c.mu.Lock()
	chk, ok := c.seen[key]
	if !ok {
		chk = &refCheck{}
		if len(c.seen) < refCacheLimit {
			c.seen[key] = chk
		}
	}
	c.mu.Unlock()
	chk.once.Do(func() { chk.err = c.classify(ctx, v, chk) })
	return chk, chk.err
}

// classify decides in the order of what the target would hold: a referenced entry clone creates, an entry the
// target holds, a principal it creates, a value it takes as it is.
func (c *Classifier) classify(ctx context.Context, v string, chk *refCheck) error {
	job := c.p.job
	prof := job.Profile
	mode := job.References
	if mode == "" {
		mode = RefsClone
	}
	if mode == RefsClone {
		k, err := c.p.KindOf(ctx, v)
		if err != nil {
			return err
		}
		if k != nil {
			chk.class, chk.kind = RefReferenced, k
			return nil
		}
	}
	if mode != RefsSkip {
		if !prof.RefsNeedEntry {
			chk.class = RefValueOnly // written either way, so whether the target holds it needs no read
			return nil
		}
		cur, err := c.dst.Get(ctx, v, []string{"objectClass"})
		if err != nil {
			return err
		}
		if cur != nil {
			chk.class = RefExisting
			return nil
		}
		if prof.Principal != nil {
			if w, ok := prof.Principal(v); ok {
				chk.class, chk.write = RefPrincipal, w
				return nil
			}
		}
	}
	chk.class = RefUnreproducible
	return nil
}

// KindOf reads the source entry entryDN names and returns the enabled kind it is of, by its object classes as the
// kind's Is says (without the configured narrowing of the filter); nil when it is outside the naming context,
// missing, built-in, or of no enabled kind.
func (p *Plan) KindOf(ctx context.Context, entryDN string) (*Kind, error) {
	prof := p.job.Profile
	if !dn.IsDescendant(entryDN, p.Root) {
		return nil, nil // another naming context (another domain of the forest): not read
	}
	attrs := []string{"objectClass"}
	if prof.SystemAttr != "" {
		attrs = append(attrs, prof.SystemAttr)
	}
	e, err := p.src.Get(ctx, entryDN, attrs)
	if err != nil || e == nil {
		return nil, err
	}
	if prof.SystemAttr != "" && strings.EqualFold(first(e.Values(prof.SystemAttr)), "TRUE") {
		return nil, nil // a built-in object is never created: the target has its own, or none
	}
	classes := e.Values("objectClass")
	for i := range p.job.Kinds {
		if k := &p.job.Kinds[i]; k.Is != nil && k.Is(classes) {
			return k, nil
		}
	}
	return nil, nil
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// Reproducible returns the values clone can write, and how many it cannot.
func (c *Classifier) Reproducible(ctx context.Context, values []string) ([]string, int, error) {
	var out []string
	skipped := 0
	for _, v := range values {
		class, err := c.Class(ctx, v)
		if err != nil {
			return nil, 0, err
		}
		if class.Reproducible() {
			out = append(out, v)
		} else {
			skipped++
		}
	}
	return out, skipped, nil
}

// ReadReferenced reads the source entry of a referenced value as its kind (with what Read asks for, masked).
func (p *Plan) ReadReferenced(ctx context.Context, v string, k *Kind) (*directory.Entry, error) {
	e, err := p.src.Get(ctx, v, p.withRead(k.Attrs))
	if err != nil || e == nil {
		return e, err
	}
	m := p.job.Masker.Apply(*e)
	return &m, nil
}
