package plan

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// Withheld are the source's values clone does not write because the target would refuse them: a value of a unique
// attribute (profile.UniqueRules) that a replication-conflict leftover shares with another object. It is decided
// from the source before anything is written, so the leftover loses the value whichever of the two comes first (the
// real object, added after the leftover, would otherwise be the one refused).
type Withheld struct {
	values map[string]map[string]map[string]bool // normalized DN -> lowercase attribute -> lowercase value
	// Values lists each value withheld, for the warnings and check.
	Values []WithheldValue
	Why    string
	// Refused lists the entries of the kinds the target refuses altogether (profile.UniqueRules.Refuses), with why.
	Refused []RefusedEntry
	refused map[string]string // normalized DN -> why, of Refused
	refuses func(e directory.Entry) string
}

// RefusedEntry is a source entry the target refuses, and why.
type RefusedEntry struct{ DN, Why string }

// Refuses reports whether the target refuses some names (whether RefusedWhy can say anything).
func (w *Withheld) Refuses() bool { return w != nil && w.refuses != nil }

// RefusedWhy says why the target refuses the entry of that DN, "" when it takes it: one of the kinds found so before
// anything was written, or what the DN alone decides.
func (w *Withheld) RefusedWhy(d string) string { return w.RefusedEntryWhy(directory.Entry{DN: d}) }

// RefusedEntryWhy is RefusedWhy of an entry read, whose values may decide too (one no kind took: a parent).
func (w *Withheld) RefusedEntryWhy(e directory.Entry) string {
	if w == nil || w.refuses == nil {
		return ""
	}
	if why := w.refused[dn.Normalize(e.DN)]; why != "" {
		return why
	}
	return w.refuses(e)
}

// WithheldValue is one value withheld from DN, with the other objects that hold it.
type WithheldValue struct {
	DN, Attr, Value string
	Others          []string
	// Why the target refuses it (the rule of the profile).
	Why string
}

// Clash is a value of a unique attribute that more than one object of the source holds and none of them is a
// leftover: which one keeps it cannot be decided, and the target refuses it on the second.
type Clash struct {
	Attr, Value string
	DNs         []string
	// Implied lists those of DNs that hold the value only as one implied (UniqueRules.Implied), and ImpliedHow
	// says how.
	Implied    []string
	ImpliedHow string
}

// ValuesOf are the values withheld from the entry at d.
func (w *Withheld) ValuesOf(d string) []WithheldValue {
	if w == nil || w.values[dn.Normalize(d)] == nil {
		return nil
	}
	var out []WithheldValue
	for _, v := range w.Values {
		if dn.Equal(v.DN, d) {
			out = append(out, v)
		}
	}
	return out
}

// Strip returns e without the values withheld from it, and the attributes it took values from.
func (w *Withheld) Strip(e directory.Entry) (directory.Entry, []string) {
	if w == nil || len(w.values) == 0 {
		return e, nil
	}
	held := w.values[dn.Normalize(e.DN)]
	if held == nil {
		return e, nil
	}
	out := directory.Entry{DN: e.DN, Attrs: make(map[string][]string, len(e.Attrs))}
	var stripped []string
	for n, vs := range e.Attrs {
		drop := held[strings.ToLower(n)]
		if drop == nil {
			out.Attrs[n] = vs
			continue
		}
		var keep []string
		for _, v := range vs {
			if !drop[strings.ToLower(v)] {
				keep = append(keep, v)
			}
		}
		if len(keep) < len(vs) {
			stripped = append(stripped, n)
		}
		if len(keep) > 0 {
			out.Attrs[n] = keep
		}
	}
	sort.Strings(stripped)
	return out, stripped
}

// unique finds, among the entries of the job's kinds, the values of rules' attributes that more than one holds: those a
// leftover shares are withheld from it (from all but the first by DN when only leftovers hold it), the rest are
// clashes. It is one more paged search, reading only those attributes.
func unique(ctx context.Context, src directory.Directory, job Job, rules profile.UniqueRules) (*Withheld, []Clash, error) {
	u := job.Profile.Unique
	w := &Withheld{values: map[string]map[string]map[string]bool{}, Why: rules.Why, refuses: rules.Refuses, refused: map[string]string{}}
	if u == nil || (len(rules.Attrs) == 0 && rules.Refuses == nil) {
		return w, nil, nil
	}
	groups := map[string]*group{}
	add := func(attr, value string, h holder) {
		key := strings.ToLower(attr) + "\x00" + strings.ToLower(value)
		g := groups[key]
		if g == nil {
			g = &group{attr: attr, value: value}
			groups[key] = g
		}
		g.holders = append(g.holders, h)
	}
	// One walk for every kind (a dump is read through on each), the kind of an entry told by its classes: only the
	// attributes its allow list names are written, and an entry holds the implied value of one its kind does not.
	var any strings.Builder
	copiedBy := make([]map[string]bool, len(job.Kinds))
	all := map[string]bool{}
	for i, k := range job.Kinds {
		any.WriteString(k.Filter)
		copiedBy[i] = profile.Set(k.Attrs)
		for a := range copiedBy[i] {
			all[a] = true
		}
	}
	attrs := append(append([]string{"objectClass"}, rules.Attrs...), u.Attrs()...)
	err := WalkBases(ctx, src, job.BaseDNs, "(|"+any.String()+")", attrs, func(e directory.Entry) error {
		copied := all // a kind its classes do not tell (a filter of its own): what any kind writes
		for i, k := range job.Kinds {
			if k.Is != nil && k.Is(e.Values("objectClass")) {
				copied = copiedBy[i]
				break
			}
		}
		if rules.Refuses != nil {
			if why := rules.Refuses(e); why != "" {
				// Not written, so it holds none of its values on the target.
				w.Refused = append(w.Refused, RefusedEntry{DN: e.DN, Why: why})
				w.refused[dn.Normalize(e.DN)] = why
				return nil
			}
		}
		leftover := u.Leftover(e)
		for _, a := range rules.Attrs {
			var vs []string
			if copied[strings.ToLower(a)] {
				vs = e.Values(a)
			}
			if len(vs) == 0 {
				if implied := rules.Implied[strings.ToLower(a)]; implied != nil {
					if v := implied(e); v != "" {
						add(a, v, holder{dn: e.DN, leftover: leftover})
					}
				}
				continue
			}
			seen := map[string]bool{}
			for _, v := range vs {
				if lv := strings.ToLower(v); !seen[lv] {
					seen[lv] = true
					add(a, v, holder{dn: e.DN, explicit: true, leftover: leftover})
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("read the values the target holds once: %w", err)
	}
	var clashes []Clash
	for _, g := range groups {
		if len(g.holders) < 2 {
			continue
		}
		sort.Slice(g.holders, func(i, j int) bool { return dn.Normalize(g.holders[i].dn) < dn.Normalize(g.holders[j].dn) })
		real := 0
		for _, h := range g.holders {
			if !h.leftover {
				real++
			}
		}
		var kept []holder
		for i, h := range g.holders {
			// A leftover loses the value to a real object; among leftovers alone, the first keeps it. An implied value
			// is not written, so it cannot be withheld.
			if h.leftover && h.explicit && (real > 0 || i > 0) {
				w.withhold(h.dn, g.attr, g.value, g.holders, rules.Why)
				continue
			}
			kept = append(kept, h)
		}
		if len(kept) > 1 {
			c := Clash{Attr: g.attr, Value: g.value, ImpliedHow: rules.ImpliedHow}
			for _, h := range kept {
				c.DNs = append(c.DNs, h.dn)
				if !h.explicit {
					c.Implied = append(c.Implied, h.dn)
				}
			}
			clashes = append(clashes, c)
		}
	}
	w.withholdAliases(groups, rules)
	sort.Slice(w.Values, func(i, j int) bool {
		if w.Values[i].DN != w.Values[j].DN {
			return w.Values[i].DN < w.Values[j].DN
		}
		return w.Values[i].Attr+w.Values[i].Value < w.Values[j].Attr+w.Values[j].Value
	})
	sort.Slice(clashes, func(i, j int) bool { return clashes[i].Attr+clashes[i].Value < clashes[j].Attr+clashes[j].Value })
	sort.Slice(w.Refused, func(i, j int) bool { return dn.Normalize(w.Refused[i].DN) < dn.Normalize(w.Refused[j].DN) })
	return w, clashes, nil
}

// withholdAliases withholds an SPN whose service class is an alias (http) of one another object's SPN of the same
// rest has (host/X), where the target refuses the pair across objects (rules.SPNAliases: Samba). Samba refuses
// host/X added after http/X and takes the reverse order, so which one fails depends on the order clone writes in;
// the alias is the one left out, as host/X is what a computer is known by.
func (w *Withheld) withholdAliases(groups map[string]*group, rules profile.UniqueRules) {
	if len(rules.SPNAliases) == 0 {
		return
	}
	split := func(v string) (class, rest string, ok bool) {
		class, rest, ok = strings.Cut(strings.ToLower(v), "/")
		return
	}
	// The entries that will hold each SPN of a class aliases name (host/X), not those it is withheld from.
	keyHolders := map[string][]string{}
	for _, g := range groups {
		if !strings.EqualFold(g.attr, "servicePrincipalName") {
			continue
		}
		class, rest, ok := split(g.value)
		if !ok || rules.SPNAliases[class] != "" {
			continue
		}
		for _, h := range g.holders {
			if h.explicit && !w.withheldFrom(h.dn, g.attr, g.value) {
				keyHolders[class+"/"+rest] = append(keyHolders[class+"/"+rest], h.dn)
			}
		}
	}
	for _, g := range groups {
		if !strings.EqualFold(g.attr, "servicePrincipalName") {
			continue
		}
		class, rest, ok := split(g.value)
		key := rules.SPNAliases[class]
		if !ok || key == "" {
			continue
		}
		holders := keyHolders[key+"/"+rest]
		for _, h := range g.holders {
			if !h.explicit || w.withheldFrom(h.dn, g.attr, g.value) {
				continue
			}
			var others []holder
			for _, d := range holders {
				if !dn.Equal(d, h.dn) {
					others = append(others, holder{dn: d})
				}
			}
			if len(others) > 0 {
				w.withhold(h.dn, g.attr, g.value, others, rules.AliasWhy)
			}
		}
	}
}

// withheldFrom reports whether value of attr is withheld from the entry at d.
func (w *Withheld) withheldFrom(d, attr, value string) bool {
	return w.values[dn.Normalize(d)][strings.ToLower(attr)][strings.ToLower(value)]
}

// group is a value of a unique attribute and the entries holding it.
type group struct {
	attr, value string
	holders     []holder
}

// holder is an entry holding a value of a unique attribute: written (explicit) or implied.
type holder struct {
	dn                 string
	explicit, leftover bool
}

func (w *Withheld) withhold(entryDN, attr, value string, holders []holder, why string) {
	key := dn.Normalize(entryDN)
	if w.values[key] == nil {
		w.values[key] = map[string]map[string]bool{}
	}
	la := strings.ToLower(attr)
	if w.values[key][la] == nil {
		w.values[key][la] = map[string]bool{}
	}
	w.values[key][la][strings.ToLower(value)] = true
	v := WithheldValue{DN: entryDN, Attr: attr, Value: value, Why: why}
	for _, h := range holders {
		if h.dn != entryDN {
			v.Others = append(v.Others, h.dn)
		}
	}
	w.Values = append(w.Values, v)
}

// ClashError says which values more than one real object of the source holds, and the ways out.
func ClashError(clashes []Clash) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%d values the target holds once are held by more than one object of the source, none of them left over from a replication conflict, so which one keeps the value cannot be decided:", len(clashes))
	for _, c := range clashes {
		holders := make([]string, len(c.DNs))
		for i, d := range c.DNs {
			holders[i] = d
			if slices.Contains(c.Implied, d) {
				holders[i] += " (" + c.ImpliedHow + ")"
			}
		}
		fmt.Fprintf(&b, "\n  %s %s: %s", c.Attr, c.Value, strings.Join(holders, "; "))
	}
	b.WriteString("\nLeave all but one of each out with [scope.filters], or the attribute with [attributes] exclude")
	return errors.New(b.String())
}

// Withholding decides, before anything is written, the values of the source the target would refuse to give a
// second object (profile.Uniqueness): those a replication-conflict leftover shares are withheld from it. The clashes
// are values more than one real object holds, which no rule gives to one of them (ClashError).
// dst nil (check -no-target) takes the strictest rules the profile knows.
func (p *Plan) Withholding(ctx context.Context, dst directory.Directory) (*Withheld, []Clash, error) {
	return Withholding(ctx, p.src, dst, p.job, p.Root)
}

// Withholding is Plan.Withholding without a plan: root is the source's naming context.
func Withholding(ctx context.Context, src, dst directory.Directory, job Job, root string) (*Withheld, []Clash, error) {
	u := job.Profile.Unique
	if u == nil {
		return &Withheld{}, nil, nil
	}
	rules, err := u.Rules(ctx, dst, root)
	if err != nil {
		return nil, nil, err
	}
	return unique(ctx, src, job, rules)
}

// TargetDN is the DN of e, read from a target by asked: a server may echo the DN asked for though the entry holds
// another name it takes as the same (Windows does: CN=ｻﾄｳ answered with CN=サトウ's entry), so the profile's DN
// attribute tells, and without one the RDN attribute's values (a value equal to the asked one but for case is the
// same name everywhere). TargetDNAttrs are the attributes it needs.
func TargetDN(prof profile.Profile, asked string, e directory.Entry) string {
	if prof.DNAttr != "" {
		if v := e.Values(prof.DNAttr); len(v) > 0 && v[0] != "" {
			return v[0]
		}
	}
	typ, val, ok := dn.FirstRDN(asked)
	if !ok {
		return e.DN
	}
	vals := e.Values(typ)
	if len(vals) == 0 {
		return e.DN
	}
	for _, v := range vals {
		if strings.EqualFold(v, val) {
			return e.DN
		}
	}
	return typ + "=" + ldap.EscapeDN(vals[0]) + "," + dn.Parent(asked)
}

// TargetDNAttrs are the attributes TargetDN reads of an entry read by asked.
func TargetDNAttrs(prof profile.Profile, asked string) []string {
	var out []string
	if prof.DNAttr != "" {
		out = append(out, prof.DNAttr)
	}
	if typ, _, ok := dn.FirstRDN(asked); ok {
		out = append(out, typ)
	}
	return out
}
