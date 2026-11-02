package profile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// PlanSchema compares the source's subschema with the target's and plans the attribute types and object classes the
// target lacks, each after what it depends on (SUP, the attributes a class names). The definitions are the source's
// as it returns them: a generic server has no base schema to tell apart from extensions as AD has, so everything the
// target lacks is carried, but what the target could not take as it is, each with why: an operational attribute (a
// server module's own, which comes with the module), a syntax or matching rule the target lacks, a name the target
// gives another definition, and what depends on one of those. An attribute both have is kept as the target has it. A
// class both have whose source definition lets hold more (a production that added its own attributes to
// inetOrgPerson's MAY rather than an auxiliary class) is changed to the source's, on a target whose schema is in
// cn=config: kept, every entry of the class holding one of those attributes would be refused, and leaving the
// attributes out would make the clone unlike production.
func (subschema) PlanSchema(ctx context.Context, src, dst directory.Directory) (SchemaChanges, bool, error) {
	s, ok, err := subschemaEntry(ctx, src, "attributeTypes", "objectClasses")
	if err != nil || !ok {
		return nil, ok, err
	}
	d, ok, err := subschemaEntry(ctx, dst, "attributeTypes", "objectClasses", "ldapSyntaxes", "matchingRules")
	if err != nil || !ok {
		return nil, ok, err
	}
	root, err := dst.Get(ctx, "", []string{"configContext"})
	if err != nil {
		return nil, false, fmt.Errorf("read root DSE: %w", err)
	}
	parent := ""
	if root != nil && first(root.Values("configContext")) != "" {
		parent = "cn=schema," + first(root.Values("configContext"))
	}
	var layout *configLayout
	why := "the target keeps its schema in no cn=config, where a class can be changed in place"
	if parent != "" {
		if layout, err = readConfigLayout(ctx, dst, parent); err != nil {
			why = fmt.Sprintf("%s cannot be read (%v)", parent, err)
		}
	}
	p := planSubschema(s, d, layout, why)
	p.parent, p.subentry = parent, d.DN
	return p, true, nil
}

// configLayout is where OpenLDAP's cn=config defines each attribute type and object class: the olcSchemaConfig
// entries, which slapd loads in the order of their {n} at every start, each entry's attribute types before its
// classes.
type configLayout struct {
	entries []configEntry
	// attrAt and classAt give the index of the entry that defines a definition, by OID and name (lowercase); one
	// the server builds in is in none, and loads before them all.
	attrAt, classAt map[string]int
}

type configEntry struct {
	dn    string
	index int // -1 for cn=schema itself, which holds what slapd builds in
	// classes are its olcObjectClasses values in order, without their {n}.
	classes []string
}

// orderPrefix is the {n} back-config puts before each value and RDN of an ordered attribute.
var orderPrefix = regexp.MustCompile(`^\{(-?[0-9]+)\}`)

// readConfigLayout reads the olcSchemaConfig entries under parent (cn=schema,cn=config).
func readConfigLayout(ctx context.Context, d directory.Directory, parent string) (*configLayout, error) {
	l := &configLayout{attrAt: map[string]int{}, classAt: map[string]int{}}
	err := d.Walk(ctx, parent, "(objectClass=olcSchemaConfig)", []string{"olcAttributeTypes", "olcObjectClasses"}, func(e directory.Entry) error {
		ce := configEntry{dn: e.DN, index: -1}
		if !strings.EqualFold(strings.ReplaceAll(e.DN, " ", ""), strings.ReplaceAll(parent, " ", "")) {
			rdn, _, _ := strings.Cut(e.DN, ",")
			_, value, _ := strings.Cut(rdn, "=")
			m := orderPrefix.FindStringSubmatch(value)
			if m == nil {
				return nil
			}
			fmt.Sscan(m[1], &ce.index)
		}
		for _, v := range e.Values("olcAttributeTypes") {
			if desc, ok := parseDescription(orderPrefix.ReplaceAllString(v, "")); ok {
				index(l.attrAt, desc.oid, desc.fields["NAME"], ce.index)
			}
		}
		for _, v := range e.Values("olcObjectClasses") {
			v = orderPrefix.ReplaceAllString(v, "")
			ce.classes = append(ce.classes, v)
			if desc, ok := parseDescription(v); ok {
				index(l.classAt, desc.oid, desc.fields["NAME"], ce.index)
			}
		}
		l.entries = append(l.entries, ce)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(l.entries) == 0 {
		return nil, errors.New("no olcSchemaConfig entry is visible")
	}
	slices.SortFunc(l.entries, func(a, b configEntry) int { return a.index - b.index })
	return l, nil
}

// entryAt is the entry of index i.
func (l *configLayout) entryAt(i int) *configEntry {
	for k := range l.entries {
		if l.entries[k].index == i {
			return &l.entries[k]
		}
	}
	return nil
}

// at is the index of the entry that defines name in m; -1 (loaded first) for what the server builds in.
func at(m map[string]int, name string) int {
	if i, ok := m[strings.ToLower(name)]; ok {
		return i
	}
	return -1
}

// subschemaPlan is what a generic target's schema lacks. Where the target keeps its configuration in a directory of
// its own (OpenLDAP's cn=config, which its root DSE names in configContext), the definitions go in one new
// olcSchemaConfig entry there, as a schema file loaded at run time does: OpenLDAP's subschema subentry refuses a
// modify. Elsewhere they are added to the subschema subentry, as RFC 4512 has it (389 Directory Server takes that;
// not verified).
type subschemaPlan struct {
	// parent is the entry the new schema entry goes under (cn=schema,cn=config); "" to modify subentry instead.
	parent, subentry string
	// attrs and classes are the definitions to add in a new entry, in the order the target takes them.
	attrs, classes []string
	// changes are the existing cn=config entries changed, in the order slapd loads them.
	changes        []configChange
	newAttrs       []string
	newClasses     []string
	changedClasses []string
	skipped        []string
}

// configChange changes an olcSchemaConfig entry: attribute types added (those a changed class names, which must load
// before it, so they go in the entry of the first class changed: an entry's attribute types load before its classes),
// and its classes replaced, all of them in their order with the changed ones the source's. A replace is one
// operation, so the classes are never without one of them in between, as a delete and an add of a value would leave
// them.
type configChange struct {
	dn      string
	attrs   []string
	classes []string // nil: unchanged; empty: every class moved out
	// addClasses are classes moved in, after its own: they name what it defines.
	addClasses []string
}

func (p *subschemaPlan) Empty() bool { return len(p.attrs)+len(p.classes)+len(p.changes) == 0 }

// name is the new schema entry's cn: from the definitions, so a later run adding others makes another entry rather
// than a second one of the same name, which the target would refuse.
func (p *subschemaPlan) name() string {
	h := sha256.Sum256([]byte(strings.Join(append(append([]string(nil), p.attrs...), p.classes...), "\n")))
	return "ldap-cronin-" + hex.EncodeToString(h[:4])
}

func (p *subschemaPlan) dn() string { return "cn=" + p.name() + "," + p.parent }

func (p *subschemaPlan) entry() directory.Entry {
	attrs := map[string][]string{"objectClass": {"olcSchemaConfig"}, "cn": {p.name()}}
	if len(p.attrs) > 0 {
		attrs["olcAttributeTypes"] = p.attrs
	}
	if len(p.classes) > 0 {
		attrs["olcObjectClasses"] = p.classes
	}
	return directory.Entry{DN: p.dn(), Attrs: attrs}
}

func (p *subschemaPlan) WriteSummary(w io.Writer) {
	if p.Empty() {
		fmt.Fprintln(w, "the target schema has every attribute and class of the source's it can take")
	}
	for _, l := range []struct {
		heading string
		names   []string
	}{{"attributes to add", p.newAttrs}, {"classes to add", p.newClasses}, {"classes to change to the source's", p.changedClasses}, {"left out", p.skipped}} {
		if len(l.names) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s: %d\n", l.heading, len(l.names))
		for _, n := range l.names {
			fmt.Fprintf(w, "  %s\n", n)
		}
	}
}

func (p *subschemaPlan) WriteLDIF(w io.Writer) error {
	fmt.Fprintln(w, "# ldap-cronin schema: what the source's schema has and the target's lacks")
	var b strings.Builder
	p.WriteSummary(&b)
	for _, l := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
		fmt.Fprintln(w, "# "+l)
	}
	if p.parent != "" {
		// cn=config is written by whoever manages the server, as root through ldapi in the usual set-up.
		fmt.Fprintln(w, "# apply: ldapmodify -Y EXTERNAL -H ldapi:/// -f <this file> (or as a DN that manages cn=config)")
		for _, c := range p.changes {
			fmt.Fprintf(w, "\ndn: %s\nchangetype: modify\n", c.dn)
			for _, l := range []struct {
				op, name string
				values   []string
			}{{"add", "olcAttributeTypes", c.attrs}, {"replace", "olcObjectClasses", c.classes}, {"add", "olcObjectClasses", c.addClasses}} {
				if len(l.values) == 0 && (l.op != "replace" || l.values == nil) {
					continue
				}
				fmt.Fprintf(w, "%s: %s\n", l.op, l.name)
				for _, v := range l.values {
					fmt.Fprintf(w, "%s: %s\n", l.name, v)
				}
				fmt.Fprintln(w, "-")
			}
		}
		if len(p.attrs)+len(p.classes) == 0 {
			return nil
		}
		e := p.entry()
		fmt.Fprintf(w, "\ndn: %s\nchangetype: add\n", e.DN)
		for _, n := range []string{"objectClass", "cn", "olcAttributeTypes", "olcObjectClasses"} {
			for _, v := range e.Attrs[n] {
				fmt.Fprintf(w, "%s: %s\n", n, v)
			}
		}
		return nil
	}
	fmt.Fprintf(w, "\ndn: %s\nchangetype: modify\n", p.subentry)
	for _, l := range []struct {
		name string
		defs []string
	}{{"attributeTypes", p.attrs}, {"objectClasses", p.classes}} {
		if len(l.defs) == 0 {
			continue
		}
		fmt.Fprintf(w, "add: %s\n", l.name)
		for _, v := range l.defs {
			fmt.Fprintf(w, "%s: %s\n", l.name, v)
		}
		fmt.Fprintln(w, "-")
	}
	return nil
}

func (p *subschemaPlan) Apply(ctx context.Context, dst directory.Directory, log io.Writer) error {
	if p.parent != "" {
		remedy := func(err error) error {
			return fmt.Errorf("%w; the bind DN needs to manage %s (the LDIF of ldap-cronin schema, without -apply, is for whoever does)", err, p.parent)
		}
		for _, c := range p.changes {
			fmt.Fprintf(log, "modify %s\n", c.dn)
			if len(c.attrs) > 0 {
				if err := dst.AddValues(ctx, c.dn, "olcAttributeTypes", c.attrs); err != nil {
					return remedy(err)
				}
			}
			if c.classes != nil {
				if err := dst.Replace(ctx, c.dn, map[string][]string{"olcObjectClasses": c.classes}); err != nil {
					return remedy(err)
				}
			}
			if len(c.addClasses) > 0 {
				if err := dst.AddValues(ctx, c.dn, "olcObjectClasses", c.addClasses); err != nil {
					return remedy(err)
				}
			}
		}
		if len(p.attrs)+len(p.classes) == 0 {
			return nil
		}
		fmt.Fprintf(log, "add    %s\n", p.dn())
		if err := dst.Add(ctx, p.entry()); err != nil {
			return remedy(err)
		}
		return nil
	}
	for _, l := range []struct {
		name string
		defs []string
	}{{"attributeTypes", p.attrs}, {"objectClasses", p.classes}} {
		if len(l.defs) == 0 {
			continue
		}
		fmt.Fprintf(log, "modify %s (add %d %s)\n", p.subentry, len(l.defs), l.name)
		if err := dst.AddValues(ctx, p.subentry, l.name, l.defs); err != nil {
			return err
		}
	}
	return nil
}

// numericOID is what a definition the target takes is named by: a descriptor in place of it (389's "x-oid") is a
// server's own spelling, which OpenLDAP refuses.
var numericOID = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+$`)

// planSubschema plans what the subschema subentry d lacks of s's definitions; layout is where the target's cn=config
// defines its own (nil, for why, when it has none to read), which a class both have is changed in.
func planSubschema(s, d *directory.Entry, layout *configLayout, why string) *subschemaPlan {
	p := &subschemaPlan{}
	known := func(values []string) map[string]bool {
		out := map[string]bool{}
		for _, def := range values {
			if desc, ok := parseDescription(def); ok {
				out[strings.ToLower(desc.oid)] = true
				for _, n := range desc.fields["NAME"] {
					out[strings.ToLower(n)] = true
				}
			}
		}
		return out
	}
	// A target that does not publish them is not checked for them: the add would say.
	var syntaxes, rules map[string]bool
	if v := d.Values("ldapSyntaxes"); len(v) > 0 {
		syntaxes = known(v)
	}
	if v := d.Values("matchingRules"); len(v) > 0 {
		rules = known(v)
	}

	dstTypes, srcTypes := map[string]attributeType{}, map[string]attributeType{}
	var order []attributeType
	raw := map[string]string{} // the source's definition by OID
	for _, def := range d.Values("attributeTypes") {
		if t, ok := parseAttributeType(def); ok {
			index(dstTypes, t.oid, t.names, t)
		}
	}
	for _, def := range s.Values("attributeTypes") {
		if t, ok := parseAttributeType(def); ok {
			index(srcTypes, t.oid, t.names, t)
			order = append(order, t)
			raw[strings.ToLower(t.oid)] = def
		}
	}

	// state of a source attribute (by OID): absent while not looked at, then whether the target has it or gets it.
	state := map[string]bool{}
	var hasAttr func(name string) (bool, string)
	resolve := func(t attributeType) bool {
		oid := strings.ToLower(t.oid)
		if ok, seen := state[oid]; seen {
			return ok
		}
		state[oid] = false // a SUP that loops back is not taken
		if _, ok := dstTypes[oid]; ok {
			state[oid] = true
			return true
		}
		name := t.names[0]
		for _, n := range t.names {
			if o, ok := dstTypes[strings.ToLower(n)]; ok {
				p.skipped = append(p.skipped, fmt.Sprintf("attribute %s: the target gives the name another definition (%s)", name, o.oid))
				return false
			}
		}
		why := ""
		switch {
		case t.serverOnly:
			why = "operational, the server's own or a module's, which brings it"
		case !numericOID.MatchString(t.oid):
			why = fmt.Sprintf("its OID %q is not numeric", t.oid)
		case t.syntax != "" && syntaxes != nil && !syntaxes[strings.ToLower(t.syntax)]:
			why = "syntax " + t.syntax + ", which the target lacks"
		}
		for _, r := range t.rules {
			if why == "" && rules != nil && !rules[strings.ToLower(r)] {
				why = "matching rule " + r + ", which the target lacks"
			}
		}
		if why == "" && t.sup != "" {
			if ok, w := hasAttr(t.sup); !ok {
				why = "SUP " + t.sup + w
			}
		}
		if why != "" {
			p.skipped = append(p.skipped, fmt.Sprintf("attribute %s: %s", name, why))
			return false
		}
		state[oid] = true
		p.attrs = append(p.attrs, raw[oid])
		p.newAttrs = append(p.newAttrs, name)
		return true
	}
	hasAttr = func(name string) (bool, string) {
		if _, ok := dstTypes[strings.ToLower(name)]; ok {
			return true, ""
		}
		if t, ok := srcTypes[strings.ToLower(name)]; ok && resolve(t) {
			return true, ""
		}
		return false, ", which the target lacks and does not get"
	}
	for _, t := range order {
		resolve(t)
	}

	dstClasses, srcClasses := map[string]objectClass{}, map[string]objectClass{}
	var classOrder []objectClass
	rawClass := map[string]string{}
	for _, def := range d.Values("objectClasses") {
		if c, ok := parseObjectClass(def); ok {
			index(dstClasses, c.oid, c.names, c)
		}
	}
	for _, def := range s.Values("objectClasses") {
		if c, ok := parseObjectClass(def); ok {
			index(srcClasses, c.oid, c.names, c)
			classOrder = append(classOrder, c)
			rawClass[strings.ToLower(c.oid)] = def
		}
	}
	// oidOf is an attribute's OID, by any of its names, for comparing what two definitions of a class name.
	oidOf := func(name string) string {
		for _, m := range []map[string]attributeType{dstTypes, srcTypes} {
			if t, ok := m[strings.ToLower(name)]; ok {
				return strings.ToLower(t.oid)
			}
		}
		return strings.ToLower(name)
	}
	classState := map[string]bool{}
	var candidates []classCandidate
	var resolveClass func(c objectClass) bool
	resolveClass = func(c objectClass) bool {
		oid := strings.ToLower(c.oid)
		if ok, seen := classState[oid]; seen {
			return ok
		}
		classState[oid] = false
		name := c.names[0]
		if have, ok := dstClasses[oid]; ok {
			classState[oid] = true
			var more []string
			for _, a := range append(append([]string(nil), c.must...), c.may...) {
				if !slices.ContainsFunc(append(append([]string(nil), have.must...), have.may...), func(b string) bool { return oidOf(a) == oidOf(b) }) {
					more = append(more, a)
				}
			}
			if len(more) == 0 {
				return true
			}
			if layout == nil {
				p.skipped = append(p.skipped, fmt.Sprintf("class %s: the source's allows %s besides; the target's is kept, as %s", name, strings.Join(more, ", "), why))
				return true
			}
			// slapd loads cn=config in order at every start: a class naming what loads after it would stop the next
			// start, so where it goes depends on the last entry defining what it names (change).
			cand := classCandidate{c: c, at: at(layout.classAt, oid)}
			cand.after = cand.at
			reason := ""
			if cand.at < 0 {
				reason = "the server builds it in"
			}
			for _, sup := range c.sup {
				if _, ok := dstClasses[strings.ToLower(sup)]; !ok {
					reason = "SUP " + sup + ", which the target lacks"
				}
				cand.after = max(cand.after, at(layout.classAt, sup))
			}
			for _, a := range append(append([]string(nil), c.must...), c.may...) {
				if reason != "" {
					break
				}
				if _, ok := dstTypes[strings.ToLower(a)]; ok {
					cand.after = max(cand.after, at(layout.attrAt, a))
					continue
				}
				if t, ok := srcTypes[strings.ToLower(a)]; ok && resolve(t) {
					cand.needs = append(cand.needs, strings.ToLower(t.oid))
					continue
				}
				reason = a + ", which the target lacks and does not get"
			}
			if reason != "" {
				p.skipped = append(p.skipped, fmt.Sprintf("class %s: the source's allows %s besides; the target's is kept: %s", name, strings.Join(more, ", "), reason))
				return true
			}
			candidates = append(candidates, cand)
			return true
		}
		for _, n := range c.names {
			if o, ok := dstClasses[strings.ToLower(n)]; ok {
				p.skipped = append(p.skipped, fmt.Sprintf("class %s: the target gives the name another definition (%s)", name, o.oid))
				return false
			}
		}
		why := ""
		if !numericOID.MatchString(c.oid) {
			why = fmt.Sprintf("its OID %q is not numeric", c.oid)
		}
		for _, sup := range c.sup {
			if why != "" {
				break
			}
			if _, ok := dstClasses[strings.ToLower(sup)]; ok {
				continue
			}
			if sc, ok := srcClasses[strings.ToLower(sup)]; !ok || !resolveClass(sc) {
				why = "SUP " + sup + ", which the target lacks and does not get"
			}
		}
		for _, field := range []struct {
			name  string
			attrs []string
		}{{"MUST", c.must}, {"MAY", c.may}} {
			for _, a := range field.attrs {
				if why != "" {
					break
				}
				if ok, w := hasAttr(a); !ok {
					why = field.name + " " + a + w
				}
			}
		}
		if why != "" {
			p.skipped = append(p.skipped, fmt.Sprintf("class %s: %s", name, why))
			return false
		}
		classState[oid] = true
		p.classes = append(p.classes, rawClass[oid])
		p.newClasses = append(p.newClasses, name)
		return true
	}
	for _, c := range classOrder {
		resolveClass(c)
	}
	if len(candidates) > 0 {
		p.change(layout, candidates, srcTypes, dstTypes, rawClass)
	}
	return p
}

// classCandidate is a class both have, to change to the source's definition.
type classCandidate struct {
	c     objectClass
	at    int      // the index of the entry that defines it
	after int      // the index of the last entry defining what the source's names, at least at
	needs []string // the OIDs of the attribute types it names that the target gets
}

// change plans the classes changed to the source's definitions. A class whose definition names only what loads
// before it is replaced where it is; one that names what loads after it (attribute types an earlier copy added in an
// entry of its own) moves to the last entry defining those, unless a class loaded in between derives from it. The
// new attribute types they name, and the ones those derive from, move from the new entry into the first entry a
// changed class is then in: an entry's attribute types load before its classes.
func (p *subschemaPlan) change(layout *configLayout, candidates []classCandidate, srcTypes, dstTypes map[string]attributeType, rawClass map[string]string) {
	type changed struct {
		c        objectClass
		at, dest int
		needs    map[string]bool
	}
	var list []changed
	first := -1
	for _, cand := range candidates {
		n := map[string]bool{}
		var add func(oid string)
		add = func(oid string) {
			if n[oid] {
				return
			}
			n[oid] = true
			if t := srcTypes[oid]; t.sup != "" {
				if _, ok := dstTypes[strings.ToLower(t.sup)]; !ok {
					add(strings.ToLower(srcTypes[strings.ToLower(t.sup)].oid))
				}
			}
		}
		for _, oid := range cand.needs {
			add(oid)
		}
		c := changed{cand.c, cand.at, cand.after, n}
		if derived := layout.derivedBetween(c.c, c.at, c.dest); c.dest > c.at && derived != "" {
			p.skipped = append(p.skipped, fmt.Sprintf("class %s: the target's is kept: what the source's names loads after it in cn=config, and %s derives from it in between", c.c.names[0], derived))
			continue
		}
		if len(n) > 0 && (first < 0 || c.dest < first) {
			first = c.dest
		}
		list = append(list, c)
	}
	moved := map[string]bool{}
	replace := map[int][]objectClass{} // by the entry changed in place
	leave := map[int][]objectClass{}   // by the entry a class moves out of
	join := map[int][]string{}         // by the entry a class moves into: the source's definitions
	for _, c := range list {
		reason := ""
		for oid := range c.needs {
			if t := srcTypes[oid]; t.sup != "" && !c.needs[strings.ToLower(srcTypes[strings.ToLower(t.sup)].oid)] {
				if at(layout.attrAt, t.sup) > first {
					reason = fmt.Sprintf("%s derives from %s, which loads after %s in cn=config", t.names[0], t.sup, layout.entryAt(first).dn)
				}
			}
		}
		if reason != "" {
			p.skipped = append(p.skipped, fmt.Sprintf("class %s: the target's is kept: %s", c.c.names[0], reason))
			continue
		}
		for oid := range c.needs {
			moved[oid] = true
		}
		if c.dest == c.at {
			replace[c.at] = append(replace[c.at], c.c)
		} else {
			leave[c.at] = append(leave[c.at], c.c)
			join[c.dest] = append(join[c.dest], rawClass[strings.ToLower(c.c.oid)])
		}
		p.changedClasses = append(p.changedClasses, c.c.names[0])
	}
	if len(p.changedClasses) == 0 {
		return
	}
	var early, rest []string
	for _, def := range p.attrs {
		if t, ok := parseAttributeType(def); ok && moved[strings.ToLower(t.oid)] {
			early = append(early, def)
		} else {
			rest = append(rest, def)
		}
	}
	p.attrs = rest
	for _, e := range layout.entries {
		c := configChange{dn: e.dn, addClasses: join[e.index]}
		if e.index == first {
			c.attrs = early
		}
		if replaced, gone := replace[e.index], leave[e.index]; len(replaced)+len(gone) > 0 {
			c.classes = []string{}
			for _, v := range e.classes {
				if desc, ok := parseDescription(v); ok {
					same := func(x objectClass) bool { return strings.EqualFold(x.oid, desc.oid) }
					if slices.ContainsFunc(gone, same) {
						continue
					}
					if k := slices.IndexFunc(replaced, same); k >= 0 {
						v = rawClass[strings.ToLower(replaced[k].oid)]
					}
				}
				c.classes = append(c.classes, v)
			}
		}
		if len(c.attrs)+len(c.addClasses) > 0 || c.classes != nil {
			p.changes = append(p.changes, c)
		}
	}
}

// derivedBetween names a class of the entries from..to (but c) that derives from c: moved past it, c would load after
// it, which stops the next start.
func (l *configLayout) derivedBetween(c objectClass, from, to int) string {
	for _, e := range l.entries {
		if e.index < from || e.index > to {
			continue
		}
		for _, v := range e.classes {
			o, ok := parseObjectClass(v)
			if !ok || strings.EqualFold(o.oid, c.oid) {
				continue
			}
			for _, sup := range o.sup {
				if strings.EqualFold(sup, c.oid) || slices.ContainsFunc(c.names, func(n string) bool { return strings.EqualFold(n, sup) }) {
					return o.names[0]
				}
			}
		}
	}
	return ""
}

// index keeps v under its OID and each of its names, lowercase.
func index[T any](m map[string]T, oid string, names []string, v T) {
	m[strings.ToLower(oid)] = v
	for _, n := range names {
		m[strings.ToLower(n)] = v
	}
}
