package plan

import (
	"context"
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// A holder is an entry outside the scope that holds entries of it in a forward link: a group of another OU, or a
// built-in group (Domain Admins), whose member names a user of the scope. The membership is the group's value, so
// walking the scope never meets it; the entries' back links (memberOf) name the holders. clone gives a holder the
// values that name entries of the scope, and nothing else of its own; diff compares those values.
type Holder struct {
	DN string
	// Attrs are the forward links that hold entries of the scope (member, ...), those the group kind's allow list
	// names.
	Attrs []string
	// Kind is the holder's kind, a group: clone creates it as a referenced entry is, without its own references,
	// unless Builtin or Existing.
	Kind *Kind
	// Builtin is a built-in group: never created, the target's own (of the same domain) is given the values.
	Builtin bool
	// Existing is given the values only if the target holds it ([scope] outside_groups = "existing").
	Existing bool
	// Why, when set, is why the holder is not given its values (one of the Why reasons, or WhyHolder...).
	Why string
}

// Reasons a holder is not given its values.
const (
	WhyHolderSkipped   = "is a group outside the scope ([scope] outside_groups = \"skip\")"
	WhyBuiltinSkipped  = "is a built-in group ([scope] builtin_groups = \"skip\")"
	WhyHolderNotAGroup = "is not a group: only groups are given the entries of the scope they hold"
	WhyHolderConfig    = "is in the configuration partition"
	WhyHolderOtherNC   = "is in another naming context (another domain of the forest)"
	WhyHolderNoGroups  = "is a group, a kind [scope] objects leaves out"
	WhyHolderMissing   = "is missing on the source"
	// WhyHolderMissingOld is WhyHolderMissing of a dump taken before the groups were carried (Job.OldDump).
	WhyHolderMissingOld = WhyHolderMissing + " (a dump taken before groups outside its base DN were carried: dump again)"
)

// MissingPrimaryWhy says why the source may lack an account's primary group (Withheld.MissingPrimary).
func MissingPrimaryWhy(job Job) string {
	if job.OldDump {
		return "a dump taken before the groups outside its base DN were carried: dump again"
	}
	return "no group of the source has its RID: deleted, or one the source does not return"
}

// HolderLinks are the back links whose values name holders (memberOf), with the forward link of each, for those
// forward links the group kind's allow list names; empty when the schema pairs none or groups are not cloned.
func (p *Plan) HolderLinks() map[string]string {
	group, ok := p.job.Kind(profile.KindGroup)
	if !ok {
		return nil
	}
	allowed := profile.Set(group.Attrs)
	out := map[string]string{}
	for back, forward := range p.holds {
		if allowed[strings.ToLower(forward)] && p.IsRef(forward) {
			out[back] = forward
		}
	}
	return out
}

// Holders finds the holders of the scope's entries, sorted by DN, and decides what is done with each. It walks the
// entries of every kind that have a back link value, reading only those.
func (p *Plan) Holders(ctx context.Context) ([]Holder, error) {
	links := p.HolderLinks()
	if len(links) == 0 {
		return nil, nil
	}
	backs := make([]string, 0, len(links))
	for b := range links {
		backs = append(backs, b)
	}
	sort.Strings(backs)
	found := map[string]*Holder{} // normalized DN
	for i := range p.job.Kinds {
		k := &p.job.Kinds[i]
		err := WalkBases(ctx, p.src, p.job.BaseDNs, refsFilter(k, backs), backs, func(e directory.Entry) error {
			for _, b := range backs {
				for _, v := range e.Values(b) {
					d := dn.RefDN(v)
					if p.Scope.Has(d) {
						continue // a value of the scope: written with the entry that holds it
					}
					key := dn.Normalize(d)
					h := found[key]
					if h == nil {
						h = &Holder{DN: d}
						found[key] = h
					}
					if !containsFold(h.Attrs, links[b]) {
						h.Attrs = append(h.Attrs, links[b])
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	out := make([]Holder, 0, len(found))
	for _, h := range found {
		if err := p.classifyHolder(ctx, h); err != nil {
			return nil, err
		}
		sort.Strings(h.Attrs)
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool { return dn.Normalize(out[i].DN) < dn.Normalize(out[j].DN) })
	return out, nil
}

// Holder decides what is done with the group at d outside the scope, as for a holder (an account's primary group).
func (p *Plan) Holder(ctx context.Context, d string) (Holder, error) {
	h := Holder{DN: d}
	err := p.classifyHolder(ctx, &h)
	return h, err
}

func (p *Plan) classifyHolder(ctx context.Context, h *Holder) error {
	group, ok := p.job.Kind(profile.KindGroup)
	if !ok {
		h.Why = WhyHolderNoGroups
		return nil
	}
	if p.InConfiguration(h.DN) {
		h.Why = WhyHolderConfig
		return nil
	}
	if !dn.IsDescendant(h.DN, p.Root) {
		h.Why = WhyHolderOtherNC
		return nil
	}
	prof := p.job.Profile
	attrs := []string{"objectClass"}
	if prof.SystemAttr != "" {
		attrs = append(attrs, prof.SystemAttr)
	}
	if prof.PrimaryGroup != nil {
		attrs = append(attrs, "objectSid")
	}
	e, err := p.src.Get(ctx, h.DN, attrs)
	if err != nil {
		return err
	}
	if e == nil {
		h.Why = WhyHolderMissing
		if p.job.OldDump {
			h.Why = WhyHolderMissingOld
		}
		return nil
	}
	classes := e.Values("objectClass")
	if group.Is != nil && !group.Is(classes) {
		h.Why = WhyHolderNotAGroup
		return nil
	}
	h.Kind = group
	// A well-known RID is the domain's built-in group whatever the flag says: created, it would clash with the
	// target's own by name.
	wellKnown := false
	if pg := prof.PrimaryGroup; pg != nil {
		rid, ok := pg.RID(*e)
		wellKnown = ok && pg.WellKnown(rid)
	}
	if wellKnown || prof.SystemAttr != "" && strings.EqualFold(first(e.Values(prof.SystemAttr)), "TRUE") {
		h.Builtin = true
		if p.job.BuiltinGroups == BuiltinGroupsSkip {
			h.Why = WhyBuiltinSkipped
		}
		return nil
	}
	switch p.job.OutsideGroups {
	case OutsideGroupsSkip:
		h.Why = WhyHolderSkipped
	case OutsideGroupsExisting:
		h.Existing = true
	}
	return nil
}

// HolderValues reads the values of h's forward link name on the source and keeps those naming entries of the scope.
func (p *Plan) HolderValues(ctx context.Context, h Holder, name string) ([]string, error) {
	e, err := p.src.Get(ctx, h.DN, []string{name})
	if err != nil || e == nil {
		return nil, err
	}
	return p.InScope(e.Values(name)), nil
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// Moved is a well-known group the target holds under another DN than the source: the source's DN and the target's.
type Moved struct{ Source, Target string }

// WellKnownMoves maps each well-known group of the source (profile.PrimaryGrouper.WellKnown: Domain Admins, ...)
// that dst holds under another DN, by normalized source DN, to both DNs. A domain has each at its RID wherever
// an administrator moved it, so the target's own of that RID is the source's: told by its DN, a Domain Admins moved
// out of CN=Users would be a built-in group the target lacks. The source's groups are read once (PrimaryGroupDN),
// dst's on each call: a session clones and then diffs, so the caller keeps the result for its run.
func (p *Plan) WellKnownMoves(ctx context.Context, dst directory.Directory) (map[string]Moved, error) {
	pg := p.job.Profile.PrimaryGroup
	if pg == nil || dst == nil {
		return nil, nil
	}
	p.primaryOnce.Do(func() { p.primary, p.primaryErr = pg.Groups(ctx, p.src, p.Root) })
	if p.primaryErr != nil {
		return nil, p.primaryErr
	}
	theirs, err := pg.Groups(ctx, dst, p.Root)
	if err != nil {
		return nil, err
	}
	out := map[string]Moved{}
	for rid, d := range p.primary {
		if t := theirs[rid]; t != "" && pg.WellKnown(rid) && !dn.Equal(d, t) {
			out[dn.Normalize(d)] = Moved{Source: d, Target: t}
		}
	}
	return out, nil
}

// PrimaryGroupDN is the DN of the source group whose RID an account's primary group value (primaryGroupID) is, ""
// when the source has none of that RID. The groups are read once, on the first call.
func (p *Plan) PrimaryGroupDN(ctx context.Context, rid string) (string, error) {
	pg := p.job.Profile.PrimaryGroup
	if pg == nil {
		return "", nil
	}
	p.primaryOnce.Do(func() { p.primary, p.primaryErr = pg.Groups(ctx, p.src, p.Root) })
	return p.primary[rid], p.primaryErr
}
