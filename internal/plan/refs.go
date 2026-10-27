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
	// RefConfiguration names an entry of the configuration partition the target lacks, with
	// [scope] configuration_refs = "clone": clone creates it and its parents (plan.ReadConfiguration), and diff
	// compares the value.
	RefConfiguration
	// RefPlaceholder names an entry of the naming context the source does not return (AD removes a link to a deleted
	// object, so it is one the reading account may not read) and the target lacks, with [scope] unreadable_refs =
	// "placeholder": clone creates a placeholder there (plan.Placeholder), so the value can be written, and diff
	// compares the value, not the placeholder.
	RefPlaceholder
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

	configOnce sync.Once
	configNC   string // the target's configuration partition
	configErr  error

	wellKnownOnce    sync.Once
	wellKnownRefused bool // the target refuses a well-known principal in a cloned group (profile.WellKnownRefused)
	wellKnownErr     error
	// moved are the well-known groups dst holds under another DN (Plan.WellKnownMoves), read once.
	movedOnce sync.Once
	moved     map[string]Moved
	movedErr  error

	mu   sync.Mutex
	seen map[string]*refCheck
}

type refCheck struct {
	once  sync.Once
	class RefClass
	kind  *Kind  // RefReferenced
	write string // RefPrincipal; RefExisting: the target's DN of a well-known group it holds elsewhere
	why   string // RefUnreproducible: what the value names, so the summaries can say what to do about it
	err   error
}

// The reasons a value is RefUnreproducible.
const (
	WhyConfiguration = "names an entry of the configuration partition (an Exchange address list, say), which clone does not create"
	WhyOtherNC       = "names an entry of another naming context (another domain of the forest)"
	WhyMissing       = "names an entry missing or unreadable on the source"
	WhyBuiltin       = "names a built-in object the target lacks"
	WhySkipped       = "names an entry outside the scope ([scope] references = \"skip\")"
	WhyNotOnTarget   = "names an entry outside the scope the target lacks ([scope] references = \"existing\")"
	// WhyNameTaken: the target answers for the DN with another entry, under a name it takes as the same; written,
	// the value would name that one.
	WhyNameTaken = "names an entry the target holds another under the name of"
	// NameTakenWhy is why an entry of the source is not added: the target holds another under a name it takes as
	// the same.
	NameTakenWhy   = "the target holds another under a name it takes as the same"
	WhyFenced      = "names a schema definition or a partition of the forest, which clone never creates"
	WhyWellKnown   = "names a well-known principal (Everyone, Authenticated Users), which Windows takes only in a built-in group"
	WhyWrapped     = "names a well-known principal inside a DN-Binary or DN-String value, which clone does not write"
	WhyUnplaceable = "names an entry missing or unreadable on the source whose name no placeholder can take (not CN=)"
)

// whyClass is the reason for a value naming an entry of an object class no kind copies.
func whyClass(class string) string {
	return "names an entry of class " + class + ", which no kind copies"
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

// Why returns what a RefUnreproducible value names (one of the Why reasons), "" for any other.
func (c *Classifier) Why(ctx context.Context, v string) (string, error) {
	chk, err := c.check(ctx, v)
	if err != nil {
		return "", err
	}
	return chk.why, nil
}

// Write returns the form in which clone writes v: the principal's form for a RefPrincipal, v otherwise.
// v may be a DN-Binary or DN-String value (dn.SplitRef): it is classified by its DN, and written as it is.
func (c *Classifier) Write(ctx context.Context, v string) (string, error) {
	chk, err := c.check(ctx, v)
	if err != nil {
		return "", err
	}
	switch {
	case chk.class == RefPrincipal:
		return chk.write, nil
	case chk.write != "":
		return dn.RewrapRef(v, chk.write), nil
	}
	return v, nil
}

// Target is v as the target holds it once written: v, or the target's DN of a well-known group it holds elsewhere
// (Plan.WellKnownMoves). A principal's form (<SID=...>) is not one: the target holds the DN it is resolved to.
func (c *Classifier) Target(ctx context.Context, v string) (string, error) {
	chk, err := c.check(ctx, v)
	if err != nil {
		return "", err
	}
	if chk.class == RefExisting && chk.write != "" {
		return dn.RewrapRef(v, chk.write), nil
	}
	return v, nil
}

func (c *Classifier) check(ctx context.Context, v string) (*refCheck, error) {
	prefix, d := dn.SplitRef(v)
	if c.p.Scope.Has(d) {
		return &refCheck{class: RefInScope}, nil
	}
	key := dn.Normalize(d)
	if prefix != "" {
		key = "\x00" + key // a principal is written differently inside a DN-Binary value
	}
	c.mu.Lock()
	chk, ok := c.seen[key]
	if !ok {
		chk = &refCheck{}
		if len(c.seen) < refCacheLimit {
			c.seen[key] = chk
		}
	}
	c.mu.Unlock()
	chk.once.Do(func() {
		if chk.err = c.classify(ctx, d, chk); chk.err == nil && prefix != "" && chk.class == RefPrincipal {
			// Its SID form (<SID=...>) inside B:...: is not known to be taken.
			chk.class, chk.write, chk.why = RefUnreproducible, "", WhyWrapped
		}
	})
	return chk, chk.err
}

// classify decides in the order of what the target would hold: a referenced entry clone creates, an entry the
// target holds, a principal it creates, a value it takes as it is.
func (c *Classifier) classify(ctx context.Context, v string, chk *refCheck) error {
	job := c.p.job
	prof := job.Profile
	if prof.WellKnownRefused != nil && prof.IsWellKnown != nil && prof.IsWellKnown(v) {
		c.wellKnownOnce.Do(func() { c.wellKnownRefused, c.wellKnownErr = prof.WellKnownRefused(ctx, c.dst) })
		if c.wellKnownErr != nil {
			return c.wellKnownErr
		}
		if c.wellKnownRefused {
			chk.class, chk.why = RefUnreproducible, WhyWellKnown
			return nil
		}
	}
	mode := job.References
	if mode == "" {
		mode = RefsClone
	}
	if mode != RefsSkip {
		// A well-known group the target holds under another DN (moved on either side) is the target's own of its
		// RID: written there, neither missing nor created again.
		c.movedOnce.Do(func() { c.moved, c.movedErr = c.p.WellKnownMoves(ctx, c.dst) })
		if c.movedErr != nil {
			return c.movedErr
		}
		if m, ok := c.moved[dn.Normalize(v)]; ok {
			chk.class, chk.write = RefExisting, m.Target
			return nil
		}
	}
	switch mode {
	case RefsClone:
		k, why, err := c.p.kindOf(ctx, v)
		if err != nil {
			return err
		}
		if k != nil {
			chk.class, chk.kind = RefReferenced, k
			return nil
		}
		chk.why = why
	case RefsSkip:
		chk.why = WhySkipped
	default:
		chk.why = WhyNotOnTarget
	}
	if mode != RefsSkip {
		if !prof.RefsNeedEntry {
			chk.class = RefValueOnly // written either way, so whether the target holds it needs no read
			return nil
		}
		d := dn.RefDN(v)
		cur, err := c.dst.Get(ctx, d, append([]string{"objectClass"}, TargetDNAttrs(prof, d)...))
		if err != nil {
			return err
		}
		if cur != nil && !dn.Equal(TargetDN(prof, d, *cur), d) {
			chk.class, chk.why = RefUnreproducible, WhyNameTaken
			return nil
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
		if chk.why == WhyConfiguration && job.ConfigurationRefs == ConfigurationRefsClone {
			return c.configuration(ctx, v, chk)
		}
		if chk.why == WhyMissing && job.UnreadableRefs != UnreadableRefsSkip {
			if _, ok := Placeholder(v); ok {
				chk.class, chk.why = RefPlaceholder, ""
				return nil
			}
			chk.why = WhyUnplaceable
		}
	}
	chk.class = RefUnreproducible
	return nil
}

// configuration classifies a value naming the configuration partition, which clone is to create: it can when the
// source holds the entry and the target's partition is the source's (a lab made with lab up --config), as the
// value is written as it is.
func (c *Classifier) configuration(ctx context.Context, v string, chk *refCheck) error {
	c.configOnce.Do(func() {
		if f := c.p.job.Profile.ConfigurationNC; f != nil {
			c.configNC, c.configErr = f(ctx, c.dst)
		}
	})
	if c.configErr != nil {
		return c.configErr
	}
	chk.class = RefUnreproducible
	if c.p.Fenced(v) {
		chk.why = WhyFenced
		return nil
	}
	if c.configNC != "" && !dn.Equal(c.configNC, c.p.configNC) {
		chk.why = "names an entry of the configuration partition, and the target's is another (" + c.configNC + ")"
		return nil
	}
	e, err := c.p.src.Get(ctx, v, []string{"objectClass"})
	if err != nil {
		return err
	}
	if e == nil {
		chk.why = WhyMissing
		return nil
	}
	chk.class, chk.why = RefConfiguration, ""
	return nil
}

// KindOf reads the source entry entryDN names and returns the enabled kind it is of, by its object classes as the
// kind's Is says (without the configured narrowing of the filter); nil when it is outside the naming context,
// missing, built-in, or of no enabled kind.
func (p *Plan) KindOf(ctx context.Context, entryDN string) (*Kind, error) {
	k, _, err := p.kindOf(ctx, entryDN)
	return k, err
}

// kindOf is KindOf with the reason (one of the Why reasons) when there is no kind.
func (p *Plan) kindOf(ctx context.Context, entryDN string) (*Kind, string, error) {
	prof := p.job.Profile
	// Checked first: CN=Configuration,DC=... is below the domain's DN, but it is another partition.
	if p.InConfiguration(entryDN) {
		return nil, WhyConfiguration, nil
	}
	if !dn.IsDescendant(entryDN, p.Root) {
		return nil, WhyOtherNC, nil // another naming context (another domain of the forest): not read
	}
	attrs := []string{"objectClass"}
	if prof.SystemAttr != "" {
		attrs = append(attrs, prof.SystemAttr)
	}
	e, err := p.src.Get(ctx, entryDN, attrs)
	if err != nil {
		return nil, "", err
	}
	if e == nil {
		return nil, WhyMissing, nil
	}
	if prof.SystemAttr != "" && strings.EqualFold(first(e.Values(prof.SystemAttr)), "TRUE") {
		return nil, WhyBuiltin, nil // a built-in object is never created: the target has its own, or none
	}
	classes := e.Values("objectClass")
	for i := range p.job.Kinds {
		if k := &p.job.Kinds[i]; k.Is != nil && k.Is(classes) {
			return k, "", nil
		}
	}
	return nil, whyClass(lastOf(classes)), nil
}

// lastOf is the last value: the structural class of an AD objectClass, which lists the classes from top down.
func lastOf(v []string) string {
	if len(v) == 0 {
		return "(none)"
	}
	return v[len(v)-1]
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
	m := p.job.Masker.ApplyIn(k.Name, *e)
	return &m, nil
}
