package profile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
// gives another definition, and what depends on one of those. A definition both have is kept as the target has it;
// a class the source's lets hold more is noted, as changing a server's own class would make a schema no release of it
// has.
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
	p := planSubschema(s, d)
	if root != nil && first(root.Values("configContext")) != "" {
		p.parent = "cn=schema," + first(root.Values("configContext"))
	}
	p.subentry = d.DN
	return p, true, nil
}

// subschemaPlan is what a generic target's schema lacks. Where the target keeps its configuration in a directory of
// its own (OpenLDAP's cn=config, which its root DSE names in configContext), the definitions go in one new
// olcSchemaConfig entry there, as a schema file loaded at run time does: OpenLDAP's subschema subentry refuses a
// modify. Elsewhere they are added to the subschema subentry, as RFC 4512 has it (389 Directory Server takes that;
// not verified).
type subschemaPlan struct {
	// parent is the entry the new schema entry goes under (cn=schema,cn=config); "" to modify subentry instead.
	parent, subentry string
	// attrs and classes are the definitions to add, in the order the target takes them.
	attrs, classes []string
	newAttrs       []string
	newClasses     []string
	skipped        []string
}

func (p *subschemaPlan) Empty() bool { return len(p.attrs)+len(p.classes) == 0 }

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
	}{{"attributes to add", p.newAttrs}, {"classes to add", p.newClasses}, {"left out", p.skipped}} {
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
		fmt.Fprintf(log, "add    %s\n", p.dn())
		if err := dst.Add(ctx, p.entry()); err != nil {
			return fmt.Errorf("%w; the bind DN needs to manage %s (the LDIF of ldap-cronin schema, without -apply, is for whoever does)", err, p.parent)
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

// planSubschema plans what the subschema subentry d lacks of s's definitions.
func planSubschema(s, d *directory.Entry) *subschemaPlan {
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
			if len(more) > 0 {
				p.skipped = append(p.skipped, fmt.Sprintf("class %s: the source's allows %s besides; the target's is kept", name, strings.Join(more, ", ")))
			}
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
	return p
}

// index keeps v under its OID and each of its names, lowercase.
func index[T any](m map[string]T, oid string, names []string, v T) {
	m[strings.ToLower(oid)] = v
	for _, n := range names {
		m[strings.ToLower(n)] = v
	}
}
