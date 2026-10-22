package ad

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// SchemaElement is one attributeSchema or classSchema entry of the schema naming context.
type SchemaElement struct {
	directory.Entry
	Name string // lDAPDisplayName
	OID  string // attributeID or governsID
}

func (e *SchemaElement) value(name string) string { return first(e.Values(name)) }

// base reports whether the element is part of a Windows Server base schema (FLAG_SCHEMA_BASE_OBJECT), as opposed
// to an extension (a product's, or one of the organization's own).
func (e *SchemaElement) base() bool {
	n, _ := strconv.Atoi(e.value("systemFlags"))
	return n&flagSchemaBaseObject != 0
}

const (
	flagSchemaBaseObject  = 0x10
	flagAttrIsConstructed = 0x4
)

// Schema is the attributes and classes of a schema naming context, by lowercase lDAPDisplayName. Defunct ones are
// left out: they cannot be used, and a name a defunct element held can be reused.
type Schema struct {
	NC         string
	Attributes map[string]*SchemaElement
	Classes    map[string]*SchemaElement
}

// The fields of a definition that a client sets when it creates one, in the order they are written. What the
// server assigns (msDS-IntId, objectGUID, the timestamps) is left out; systemFlags is read, not written.
var (
	attributeFields = []string{
		"cn", "lDAPDisplayName", "attributeID", "attributeSyntax", "oMSyntax", "oMObjectClass", "isSingleValued",
		"rangeLower", "rangeUpper", "searchFlags", "linkID", "mAPIID", "schemaIDGUID", "attributeSecurityGUID",
		"isMemberOfPartialAttributeSet", "systemOnly", "extendedCharsAllowed", "showInAdvancedViewOnly",
		"adminDisplayName", "adminDescription", "description",
	}
	classFields = []string{
		"cn", "lDAPDisplayName", "governsID", "objectClassCategory", "subClassOf", "rDNAttID", "mustContain",
		"mayContain", "possSuperiors", "auxiliaryClass", "defaultObjectCategory", "defaultSecurityDescriptor",
		"defaultHidingValue", "schemaIDGUID", "systemOnly", "showInAdvancedViewOnly", "adminDisplayName",
		"adminDescription", "description",
	}
	// systemFields are set when a class is created and never changed after; a new class gets their values in the
	// counterpart a client may set.
	systemFields = map[string]string{
		"systemMustContain": "mustContain", "systemMayContain": "mayContain",
		"systemPossSuperiors": "possSuperiors", "systemAuxiliaryClass": "auxiliaryClass",
	}
	// binaryFields are octet strings, always written as base64.
	binaryFields = map[string]bool{"schemaidguid": true, "attributesecurityguid": true, "omobjectclass": true}
)

// ReadSchema reads the schema naming context of d; nil when d has none (not an AD).
func ReadSchema(ctx context.Context, d directory.Directory) (*Schema, error) {
	root, err := d.Get(ctx, "", []string{"schemaNamingContext"})
	if err != nil {
		return nil, fmt.Errorf("read root DSE: %w", err)
	}
	if root == nil || first(root.Values("schemaNamingContext")) == "" {
		return nil, nil
	}
	s := &Schema{NC: first(root.Values("schemaNamingContext")), Attributes: map[string]*SchemaElement{}, Classes: map[string]*SchemaElement{}}
	read := func(class, oidAttr string, fields []string, into map[string]*SchemaElement) error {
		attrs := append(append([]string(nil), fields...), "systemFlags", "isDefunct")
		for f := range systemFields {
			attrs = append(attrs, f)
		}
		return d.Walk(ctx, s.NC, "(objectClass="+class+")", attrs, func(e directory.Entry) error {
			el := &SchemaElement{Entry: e, Name: first(e.Values("lDAPDisplayName")), OID: first(e.Values(oidAttr))}
			if el.Name == "" || strings.EqualFold(el.value("isDefunct"), "TRUE") {
				return nil
			}
			into[strings.ToLower(el.Name)] = el
			return nil
		})
	}
	if err := read("attributeSchema", "attributeID", attributeFields, s.Attributes); err != nil {
		return nil, fmt.Errorf("read the attributes of %s: %w", s.NC, err)
	}
	if err := read("classSchema", "governsID", classFields, s.Classes); err != nil {
		return nil, fmt.Errorf("read the classes of %s: %w", s.NC, err)
	}
	return s, nil
}

// Writable returns, sorted, the attributes an object of class may hold that a client can write: what the class,
// the classes it derives from and their auxiliary classes must or may contain, without what only the server writes
// (systemOnly), the constructed attributes, the back links, and those holding a DN inside a larger value
// (DN-Binary, DN-String). ok is false when the schema has no such class.
func (s *Schema) Writable(class string) ([]string, bool) {
	if s.Classes[strings.ToLower(class)] == nil {
		return nil, false
	}
	names := map[string]string{}
	seen := map[string]bool{}
	var visit func(name string)
	visit = func(name string) {
		c := s.Classes[strings.ToLower(name)]
		if c == nil || seen[strings.ToLower(name)] {
			return
		}
		seen[strings.ToLower(name)] = true
		for _, f := range []string{"mustContain", "systemMustContain", "mayContain", "systemMayContain"} {
			for _, v := range c.Values(f) {
				if a := s.Attributes[strings.ToLower(v)]; a != nil && writable(a) {
					names[strings.ToLower(a.Name)] = a.Name
				}
			}
		}
		visit(c.value("subClassOf"))
		for _, aux := range append(c.Values("auxiliaryClass"), c.Values("systemAuxiliaryClass")...) {
			visit(aux)
		}
	}
	visit(class)
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out, true
}

// writable is whether a client can write a: not systemOnly, constructed or a back link. A DN inside a larger value
// (DN-Binary, DN-String: authOrig, dLMemSubmitPerms) is written as a reference (dn.SplitRef).
func writable(a *SchemaElement) bool {
	flags, _ := strconv.Atoi(a.value("systemFlags"))
	link, _ := strconv.Atoi(a.value("linkID"))
	return !strings.EqualFold(a.value("systemOnly"), "TRUE") && flags&flagAttrIsConstructed == 0 && link%2 == 0
}

// SchemaChange is one step of a SchemaPlan: a new definition (Add), values added to a class the target has
// (Values), or a reload of the schema cache (Refresh), after which the definitions written before can be named.
type SchemaChange struct {
	DN      string
	Add     map[string][]string
	Values  map[string][]string
	Refresh bool
}

// SchemaPlan is what the target's schema lacks of the source's, as the changes that add it.
type SchemaPlan struct {
	SourceNC, TargetNC string
	Changes            []SchemaChange
	NewAttributes      []string
	NewClasses         []string
	// Extended is, per class both have, what is added to it ("user: auxiliaryClass acmePerson").
	Extended []string
	// Skipped is what cannot be carried, each with why.
	Skipped []string
	// left holds the lowercase names of the definitions left out, so a value naming one is not reported again.
	left map[string]bool
}

// Empty reports whether the target lacks nothing.
func (p *SchemaPlan) Empty() bool { return len(p.Changes) == 0 }

// PlanSchema compares the schemas by lDAPDisplayName and plans what the target lacks: the attributes, the classes
// (after the classes they derive from, with a reload in between), and the values of the classes both have
// (mayContain, auxiliaryClass, possSuperiors) the source's hold and the target's do not. A definition of the base
// schema of a Windows Server version is not carried: which one the target has is chosen when it is installed (the
// lab's provisioning), and adding it piece by piece would make a schema no server version has.
func PlanSchema(src, dst *Schema) *SchemaPlan {
	p := &SchemaPlan{SourceNC: src.NC, TargetNC: dst.NC, left: map[string]bool{}}
	attrOIDs, classOIDs := oidIndex(dst.Attributes), oidIndex(dst.Classes)

	var newAttrs []*SchemaElement
	hasAttr := map[string]bool{}
	for name := range dst.Attributes {
		hasAttr[name] = true
	}
	for _, name := range sortedNames(src.Attributes) {
		a := src.Attributes[name]
		if t, ok := dst.Attributes[name]; ok {
			if !strings.EqualFold(t.OID, a.OID) {
				p.skip("attribute %s: attributeID %s on the source, %s on the target", a.Name, a.OID, t.OID)
			} else if d := definitionDiffers(a, t); d != "" && !a.base() {
				p.skip("attribute %s: defined differently on the target (%s); a definition cannot be changed this way", a.Name, d)
			}
			continue
		}
		if other, ok := attrOIDs[strings.ToLower(a.OID)]; ok {
			p.leave(name, "attribute %s: the target has its attributeID %s as %s", a.Name, a.OID, other.Name)
			continue
		}
		if a.base() {
			p.leave(name, "attribute %s: part of a newer Windows Server base schema than the target's", a.Name)
			continue
		}
		newAttrs = append(newAttrs, a)
		hasAttr[name] = true
	}

	// The new classes, until no class depends on one left out.
	candidates := map[string]*SchemaElement{}
	for name, c := range src.Classes {
		if t, ok := dst.Classes[name]; ok {
			if !strings.EqualFold(t.OID, c.OID) {
				p.skip("class %s: governsID %s on the source, %s on the target", c.Name, c.OID, t.OID)
			}
			continue
		}
		if other, ok := classOIDs[strings.ToLower(c.OID)]; ok {
			p.leave(name, "class %s: the target has its governsID %s as %s", c.Name, c.OID, other.Name)
			continue
		}
		if c.base() {
			p.leave(name, "class %s: part of a newer Windows Server base schema than the target's", c.Name)
			continue
		}
		candidates[name] = c
	}
	hasClass := func(name string) bool {
		_, ok := dst.Classes[strings.ToLower(name)]
		_, isNew := candidates[strings.ToLower(name)]
		return ok || isNew
	}
	for changed := true; changed; {
		changed = false
		for _, name := range sortedNames(candidates) {
			c := candidates[name]
			if why := missingRequirement(c, hasClass, hasAttr); why != "" {
				p.leave(name, "class %s: %s", c.Name, why)
				delete(candidates, name)
				changed = true
			}
		}
	}

	for _, a := range newAttrs {
		p.NewAttributes = append(p.NewAttributes, a.Name)
		p.Changes = append(p.Changes, SchemaChange{DN: p.dnOf(a), Add: p.definition(a, "attributeSchema", attributeFields)})
	}
	if len(newAttrs) > 0 {
		p.Changes = append(p.Changes, SchemaChange{Refresh: true})
	}

	// A new class is added once the class it derives from is there; its auxiliary classes and superiors that are
	// new too come after every new class, so no order among them is needed.
	deferred := map[string]map[string][]string{}
	for _, level := range classLevels(candidates) {
		for _, c := range level {
			add := p.definition(c, "classSchema", classFields)
			for sys, field := range systemFields {
				setOrDelete(add, field, appendMissing(add[field], c.Values(sys)))
			}
			for _, field := range []string{"auxiliaryClass", "possSuperiors"} {
				var keep, later []string
				for _, v := range add[field] {
					switch {
					case candidates[strings.ToLower(v)] != nil:
						later = append(later, v)
					case hasClass(v):
						keep = append(keep, v)
					default:
						p.leftOut(c.Name, field, v)
					}
				}
				setOrDelete(add, field, keep)
				if len(later) > 0 {
					if deferred[c.Name] == nil {
						deferred[c.Name] = map[string][]string{}
					}
					deferred[c.Name][field] = later
				}
			}
			var may []string
			for _, v := range add["mayContain"] {
				if hasAttr[strings.ToLower(v)] {
					may = append(may, v)
				} else {
					p.leftOut(c.Name, "mayContain", v)
				}
			}
			setOrDelete(add, "mayContain", may)
			p.NewClasses = append(p.NewClasses, c.Name)
			p.Changes = append(p.Changes, SchemaChange{DN: p.dnOf(c), Add: add})
		}
		p.Changes = append(p.Changes, SchemaChange{Refresh: true})
	}

	// What the classes both have differ in, and what the new classes name of each other.
	extended := false
	for _, name := range sortedNames(src.Classes) {
		c, t := src.Classes[name], dst.Classes[name]
		if t == nil || !strings.EqualFold(t.OID, c.OID) {
			continue
		}
		values := map[string][]string{}
		var notes []string
		for _, field := range []string{"mayContain", "auxiliaryClass", "possSuperiors"} {
			have := lowerSet(append(t.Values(field), t.Values("system"+upperFirst(field))...))
			for _, v := range append(c.Values(field), c.Values("system"+upperFirst(field))...) {
				if have[strings.ToLower(v)] {
					continue
				}
				have[strings.ToLower(v)] = true
				ok := hasClass(v)
				if field == "mayContain" {
					ok = hasAttr[strings.ToLower(v)]
				}
				if !ok {
					p.leftOut(c.Name, field, v)
					continue
				}
				values[field] = append(values[field], v)
				notes = append(notes, field+" "+v)
			}
		}
		for _, v := range append(c.Values("mustContain"), c.Values("systemMustContain")...) {
			if !lowerSet(append(t.Values("mustContain"), t.Values("systemMustContain")...))[strings.ToLower(v)] {
				p.skip("class %s: mustContain %s, which a class the target has cannot be given", c.Name, v)
			}
		}
		if len(values) > 0 {
			p.Extended = append(p.Extended, c.Name+": "+strings.Join(notes, ", "))
			p.Changes = append(p.Changes, SchemaChange{DN: t.DN, Values: values})
			extended = true
		}
	}
	for _, name := range p.NewClasses {
		if v := deferred[name]; v != nil {
			p.Changes = append(p.Changes, SchemaChange{DN: p.dnOf(candidates[strings.ToLower(name)]), Values: v})
			extended = true
		}
	}
	if extended {
		p.Changes = append(p.Changes, SchemaChange{Refresh: true})
	}
	return p
}

func (p *SchemaPlan) skip(format string, args ...any) {
	p.Skipped = append(p.Skipped, fmt.Sprintf(format, args...))
}

// leave skips the definition named name (lowercase).
func (p *SchemaPlan) leave(name, format string, args ...any) {
	p.left[name] = true
	p.skip(format, args...)
}

// leftOut notes a value of class that names a definition the target lacks and will not get; when that definition
// is listed as left out already, the value is not listed again.
func (p *SchemaPlan) leftOut(class, field, value string) {
	if !p.left[strings.ToLower(value)] {
		p.skip("class %s: %s %s left out, the target lacks it", class, field, value)
	}
}

// dnOf is where e goes in the target's schema naming context.
func (p *SchemaPlan) dnOf(e *SchemaElement) string { return "CN=" + e.value("cn") + "," + p.TargetNC }

// definition is the entry that creates e on the target: the fields a client sets, with the DNs of the source's
// schema naming context moved to the target's.
func (p *SchemaPlan) definition(e *SchemaElement, class string, fields []string) map[string][]string {
	out := map[string][]string{"objectClass": {class}}
	for _, f := range fields {
		var vs []string
		for _, v := range e.Values(f) {
			vs = append(vs, p.rebase(v))
		}
		if len(vs) > 0 && !(f == "systemOnly" && strings.EqualFold(vs[0], "FALSE")) {
			out[f] = vs
		}
	}
	return out
}

func (p *SchemaPlan) rebase(v string) string {
	if strings.HasSuffix(strings.ToLower(v), ","+strings.ToLower(p.SourceNC)) {
		return v[:len(v)-len(p.SourceNC)] + p.TargetNC
	}
	return v
}

// definitionDiffers names what makes two definitions of an attribute hold different values.
func definitionDiffers(a, b *SchemaElement) string {
	var out []string
	for _, f := range []string{"attributeSyntax", "oMSyntax", "isSingleValued"} {
		if !strings.EqualFold(a.value(f), b.value(f)) {
			out = append(out, fmt.Sprintf("%s %s, source %s", f, b.value(f), a.value(f)))
		}
	}
	return strings.Join(out, "; ")
}

// missingRequirement names what a new class needs and the target will not have: the class it derives from, an
// attribute it must or may contain, its naming attribute.
func missingRequirement(c *SchemaElement, hasClass func(string) bool, hasAttr map[string]bool) string {
	if sup := c.value("subClassOf"); sup != "" && !hasClass(sup) {
		return "subClassOf " + sup + ", which the target lacks"
	}
	for _, f := range []string{"mustContain", "systemMustContain"} {
		for _, v := range c.Values(f) {
			if !hasAttr[strings.ToLower(v)] {
				return "mustContain " + v + ", which the target lacks"
			}
		}
	}
	if r := c.value("rDNAttID"); r != "" && !hasAttr[strings.ToLower(r)] {
		return "rDNAttID " + r + ", which the target lacks"
	}
	return ""
}

// classLevels orders new classes so that each comes after the new class it derives from: level 0 derives from a
// class the target has.
func classLevels(classes map[string]*SchemaElement) [][]*SchemaElement {
	depth := map[string]int{}
	var depthOf func(name string, seen int) int
	depthOf = func(name string, seen int) int {
		if d, ok := depth[name]; ok {
			return d
		}
		c := classes[name]
		sup := strings.ToLower(c.value("subClassOf"))
		d := 0
		if _, isNew := classes[sup]; isNew && sup != name && seen < len(classes) {
			d = depthOf(sup, seen+1) + 1
		}
		depth[name] = d
		return d
	}
	var levels [][]*SchemaElement
	for _, name := range sortedNames(classes) {
		d := depthOf(name, 0)
		for len(levels) <= d {
			levels = append(levels, nil)
		}
		levels[d] = append(levels[d], classes[name])
	}
	return levels
}

// Apply writes the plan to d, stopping at the first change the server refuses.
func (p *SchemaPlan) Apply(ctx context.Context, d directory.Directory, log io.Writer) error {
	for i, c := range p.Changes {
		var err error
		switch {
		case c.Refresh:
			err = d.AddValues(ctx, "", "schemaUpdateNow", []string{"1"})
		case c.Add != nil:
			fmt.Fprintf(log, "add %s\n", c.DN)
			err = d.Add(ctx, directory.Entry{DN: c.DN, Attrs: c.Add})
		default:
			for _, f := range sortedKeys(c.Values) {
				fmt.Fprintf(log, "modify %s: add %s %s\n", c.DN, f, strings.Join(c.Values[f], ", "))
				if err = d.AddValues(ctx, c.DN, f, c.Values[f]); err != nil {
					break
				}
			}
		}
		if err != nil {
			return fmt.Errorf("schema change %d of %d: %w (the changes before it are in place; a schema change cannot be undone)", i+1, len(p.Changes), err)
		}
	}
	return nil
}

// WriteLDIF prints the plan as LDIF for ldapmodify (or ldifde -i), with what it adds and leaves out as comments.
func (p *SchemaPlan) WriteLDIF(w io.Writer) error {
	fmt.Fprintf(w, "# ldap-cronin schema: what %s has and %s lacks\n", p.SourceNC, p.TargetNC)
	fmt.Fprintln(w, "# A schema change cannot be undone in AD: an attribute or class can only be made defunct.")
	p.writeComments(w)
	for _, c := range p.Changes {
		fmt.Fprintln(w)
		switch {
		case c.Refresh:
			fmt.Fprint(w, "dn:\nchangetype: modify\nadd: schemaUpdateNow\nschemaUpdateNow: 1\n-\n")
		case c.Add != nil:
			fmt.Fprintf(w, "%s\nchangetype: add\n", line("dn", c.DN))
			fmt.Fprintln(w, line("objectClass", c.Add["objectClass"][0]))
			fields := attributeFields
			if c.Add["objectClass"][0] == "classSchema" {
				fields = classFields
			}
			for _, f := range fields {
				for _, v := range c.Add[f] {
					fmt.Fprintln(w, line(f, v))
				}
			}
		default:
			fmt.Fprintf(w, "%s\nchangetype: modify\n", line("dn", c.DN))
			for _, f := range sortedKeys(c.Values) {
				fmt.Fprintf(w, "add: %s\n", f)
				for _, v := range c.Values[f] {
					fmt.Fprintln(w, line(f, v))
				}
				fmt.Fprintln(w, "-")
			}
		}
	}
	return nil
}

// WriteSummary lists what the plan adds and leaves out, one name per line.
func (p *SchemaPlan) WriteSummary(w io.Writer) {
	if p.Empty() {
		fmt.Fprintf(w, "the target schema has every attribute and class of the source's extensions\n")
	}
	for _, l := range []struct {
		heading string
		names   []string
	}{
		{"attributes to add", p.NewAttributes}, {"classes to add", p.NewClasses},
		{"classes to extend", p.Extended}, {"left out", p.Skipped},
	} {
		if len(l.names) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s: %d\n", l.heading, len(l.names))
		for _, n := range l.names {
			fmt.Fprintf(w, "  %s\n", n)
		}
	}
}

func (p *SchemaPlan) writeComments(w io.Writer) {
	var b strings.Builder
	p.WriteSummary(&b)
	for _, l := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
		fmt.Fprintln(w, "# "+l)
	}
}

// line is an LDIF line; an octet string is always base64, even when its bytes happen to be printable.
func line(name, value string) string {
	if binaryFields[strings.ToLower(name)] || !printable(value) {
		return name + ":: " + base64.StdEncoding.EncodeToString([]byte(value))
	}
	return name + ": " + value
}

func printable(v string) bool {
	if v == "" {
		return true
	}
	if v[0] == ' ' || v[0] == ':' || v[0] == '<' || v[len(v)-1] == ' ' {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

func oidIndex(m map[string]*SchemaElement) map[string]*SchemaElement {
	out := make(map[string]*SchemaElement, len(m))
	for _, e := range m {
		if e.OID != "" {
			out[strings.ToLower(e.OID)] = e
		}
	}
	return out
}

func sortedNames(m map[string]*SchemaElement) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func lowerSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[strings.ToLower(v)] = true
	}
	return out
}

func appendMissing(list, more []string) []string {
	have := lowerSet(list)
	for _, v := range more {
		if !have[strings.ToLower(v)] {
			list = append(list, v)
			have[strings.ToLower(v)] = true
		}
	}
	return list
}

func setOrDelete(m map[string][]string, k string, v []string) {
	if len(v) == 0 {
		delete(m, k)
		return
	}
	m[k] = v
}

func upperFirst(s string) string { return strings.ToUpper(s[:1]) + s[1:] }
