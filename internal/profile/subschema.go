package profile

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// Syntax OIDs (RFC 4517) of attributes whose values are DNs.
const (
	rfcSyntaxDN         = "1.3.6.1.4.1.1466.115.121.1.12" // DN
	rfcSyntaxNameAndUID = "1.3.6.1.4.1.1466.115.121.1.34" // Name and Optional UID (uniqueMember)
)

// attributeType is the part of an RFC 4512 AttributeTypeDescription that matters here.
type attributeType struct {
	oid    string
	names  []string
	sup    string
	syntax string
	single bool
	// rules are its EQUALITY, ORDERING and SUBSTR matching rules.
	rules []string
	// serverOnly: NO-USER-MODIFICATION, or a USAGE other than userApplications (operational).
	serverOnly bool
}

// objectClass is the part of an RFC 4512 ObjectClassDescription that matters here.
type objectClass struct {
	oid       string
	names     []string
	sup       []string
	must, may []string
}

// description is an RFC 4512 description split into its fields: each keyword with its values (a quoted string, a
// word, or a list in parentheses), and the keywords that take none.
type description struct {
	oid    string
	fields map[string][]string
	flags  map[string]bool
}

// parseDescription splits def. Quoted strings are kept whole, so a DESC that holds "SUP" or "MUST" is not taken for
// a keyword, as matching the keywords in the raw text would.
func parseDescription(def string) (description, bool) {
	toks := tokens(def)
	if len(toks) < 2 || toks[0] != "(" || toks[len(toks)-1] != ")" {
		return description{}, false
	}
	d := description{oid: toks[1], fields: map[string][]string{}, flags: map[string]bool{}}
	toks = toks[2 : len(toks)-1]
	for i := 0; i < len(toks); i++ {
		key := strings.ToUpper(toks[i])
		switch key {
		case "SINGLE-VALUE", "COLLECTIVE", "NO-USER-MODIFICATION", "OBSOLETE", "ABSTRACT", "STRUCTURAL", "AUXILIARY":
			d.flags[key] = true
			continue
		}
		if i+1 >= len(toks) {
			break
		}
		i++
		if toks[i] != "(" {
			d.fields[key] = []string{unquote(toks[i])}
			continue
		}
		for i++; i < len(toks) && toks[i] != ")"; i++ {
			if toks[i] != "$" {
				d.fields[key] = append(d.fields[key], unquote(toks[i]))
			}
		}
	}
	return d, true
}

// tokens splits a description into parentheses, dollars, quoted strings (with their quotes) and words.
func tokens(def string) []string {
	var out []string
	for i := 0; i < len(def); {
		switch c := def[i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')' || c == '$':
			out = append(out, string(c))
			i++
		case c == '\'':
			j := strings.IndexByte(def[i+1:], '\'')
			if j < 0 {
				return append(out, def[i:])
			}
			out = append(out, def[i:i+j+2])
			i += j + 2
		default:
			j := i
			for j < len(def) && !strings.ContainsRune(" \t\n\r()$'", rune(def[j])) {
				j++
			}
			out = append(out, def[i:j])
			i = j
		}
	}
	return out
}

func unquote(tok string) string {
	return strings.TrimSuffix(strings.TrimPrefix(tok, "'"), "'")
}

// parseAttributeType reads one value of the attributeTypes attribute.
func parseAttributeType(def string) (attributeType, bool) {
	d, ok := parseDescription(def)
	if !ok {
		return attributeType{}, false
	}
	t := attributeType{oid: d.oid, names: d.fields["NAME"], single: d.flags["SINGLE-VALUE"]}
	if v := d.fields["SUP"]; len(v) > 0 {
		t.sup = v[0]
	}
	if v := d.fields["SYNTAX"]; len(v) > 0 {
		t.syntax, _, _ = strings.Cut(v[0], "{") // the length bound: 1.3.6.1.4.1.1466.115.121.1.15{32768}
	}
	for _, k := range []string{"EQUALITY", "ORDERING", "SUBSTR"} {
		t.rules = append(t.rules, d.fields[k]...)
	}
	usage := d.fields["USAGE"]
	t.serverOnly = d.flags["NO-USER-MODIFICATION"] || len(usage) > 0 && !strings.EqualFold(usage[0], "userApplications")
	return t, len(t.names) > 0
}

// parseObjectClass reads one value of the objectClasses attribute.
func parseObjectClass(def string) (objectClass, bool) {
	d, ok := parseDescription(def)
	if !ok {
		return objectClass{}, false
	}
	c := objectClass{oid: d.oid, names: d.fields["NAME"], sup: d.fields["SUP"], must: d.fields["MUST"], may: d.fields["MAY"]}
	return c, len(c.names) > 0
}

// dnRefsFromSchema returns, for every attribute whose syntax is a DN (directly or through SUP), whether it is single-valued.
// Keys are lowercase names.
func dnRefsFromSchema(definitions []string) map[string]bool {
	byName := map[string]attributeType{}
	var all []attributeType
	for _, d := range definitions {
		t, ok := parseAttributeType(d)
		if !ok {
			continue
		}
		all = append(all, t)
		for _, n := range t.names {
			byName[strings.ToLower(n)] = t
		}
	}
	syntaxOf := func(t attributeType) string {
		for depth := 0; depth < 10; depth++ {
			if t.syntax != "" || t.sup == "" {
				return t.syntax
			}
			parent, ok := byName[strings.ToLower(t.sup)]
			if !ok {
				return ""
			}
			t = parent
		}
		return ""
	}
	out := map[string]bool{}
	for _, t := range all {
		if s := syntaxOf(t); s == rfcSyntaxDN || s == rfcSyntaxNameAndUID {
			for _, n := range t.names {
				out[strings.ToLower(n)] = t.single
			}
		}
	}
	return out
}

// subschema reads attributeTypes and objectClasses from the subschema subentry (RFC 4512). There is no back-link
// marker in a plain schema, so back links such as memberOf are excluded through the profile's never-clone list
// instead.
type subschema struct{}

// Attributes reads every name of every attributeTypes value of the subschema subentry.
func (subschema) Attributes(ctx context.Context, d directory.Directory) (map[string]bool, bool, error) {
	defs, ok, err := attributeTypes(ctx, d)
	if err != nil || !ok {
		return nil, ok, err
	}
	out := map[string]bool{}
	for _, def := range defs {
		if t, ok := parseAttributeType(def); ok {
			for _, n := range t.names {
				out[strings.ToLower(n)] = true
			}
		}
	}
	return out, true, nil
}

// attributeTypes reads the attributeTypes of the subschema subentry; ok=false when the server has none to read.
func attributeTypes(ctx context.Context, d directory.Directory) ([]string, bool, error) {
	sub, ok, err := subschemaEntry(ctx, d, "attributeTypes")
	if err != nil || !ok {
		return nil, ok, err
	}
	return sub.Values("attributeTypes"), true, nil
}

// subschemaEntry reads attrs of the subschema subentry the root DSE names; ok=false when there is none to read.
func subschemaEntry(ctx context.Context, d directory.Directory, attrs ...string) (*directory.Entry, bool, error) {
	root, err := d.Get(ctx, "", []string{"subschemaSubentry"})
	if err != nil {
		return nil, false, fmt.Errorf("read root DSE: %w", err)
	}
	if root == nil || first(root.Values("subschemaSubentry")) == "" {
		return nil, false, nil
	}
	sub, err := d.Get(ctx, first(root.Values("subschemaSubentry")), attrs)
	if err != nil {
		return nil, false, fmt.Errorf("read schema: %w", err)
	}
	return sub, sub != nil, nil
}

// extensibleObject may hold any user attribute (RFC 4512 4.3), which no MAY lists.
const extensibleObject = "extensibleobject"

// Writable gives each class what it, the classes above it (SUP) and their MUST and MAY name, without what only the
// server writes (NO-USER-MODIFICATION) and the operational attributes (a USAGE other than userApplications), which
// "*" does not return, so neither a clone nor a dump reads them: a subschema says that much of who writes what. A
// generic server keeps no list of auxiliary classes per class as AD does: an entry names its own, so they are asked
// for as classes of their own. A back link (an overlay's memberOf) may be declared a user attribute; the profile's
// never-clone list keeps it out.
func (subschema) Writable(ctx context.Context, src directory.Directory, classes []string) (map[string][]string, bool, error) {
	sub, ok, err := subschemaEntry(ctx, src, "attributeTypes", "objectClasses")
	if err != nil || !ok {
		return nil, ok, err
	}
	types := map[string]attributeType{}
	var all []attributeType
	for _, def := range sub.Values("attributeTypes") {
		if t, ok := parseAttributeType(def); ok {
			all = append(all, t)
			types[strings.ToLower(t.oid)] = t
			for _, n := range t.names {
				types[strings.ToLower(n)] = t
			}
		}
	}
	// RFC 4512 has a subtype take its supertype's usage; a server that leaves the flag off the subtype is followed.
	serverOnly := func(t attributeType) bool {
		for depth := 0; depth < 10; depth++ {
			if t.serverOnly {
				return true
			}
			parent, ok := types[strings.ToLower(t.sup)]
			if t.sup == "" || !ok {
				return false
			}
			t = parent
		}
		return false
	}
	ocs := map[string]objectClass{}
	for _, def := range sub.Values("objectClasses") {
		if c, ok := parseObjectClass(def); ok {
			ocs[strings.ToLower(c.oid)] = c
			for _, n := range c.names {
				ocs[strings.ToLower(n)] = c
			}
		}
	}
	out := map[string][]string{}
	for _, class := range classes {
		seen := map[string]bool{}
		var names []string
		add := func(name string) {
			t, ok := types[strings.ToLower(name)]
			if ok {
				name = t.names[0]
			}
			if key := strings.ToLower(name); !seen[key] && !(ok && serverOnly(t)) {
				seen[key] = true
				names = append(names, name)
			}
		}
		if _, ok := ocs[strings.ToLower(class)]; !ok {
			// A class the schema lacks lets hold nothing: a target without it gives what the others allow.
			continue
		}
		visited := map[string]bool{}
		for queue := []string{class}; len(queue) > 0; queue = queue[1:] {
			c, ok := ocs[strings.ToLower(queue[0])]
			if !ok || visited[strings.ToLower(c.oid)] {
				continue
			}
			visited[strings.ToLower(c.oid)] = true
			if strings.EqualFold(c.names[0], extensibleObject) {
				for _, t := range all {
					add(t.names[0])
				}
			}
			for _, n := range append(append([]string(nil), c.must...), c.may...) {
				add(n)
			}
			queue = append(queue, c.sup...)
		}
		sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
		out[class] = names
	}
	return out, true, nil
}

func (subschema) Discover(ctx context.Context, src directory.Directory) (Schema, bool, error) {
	defs, ok, err := attributeTypes(ctx, src)
	if err != nil || !ok {
		return Schema{}, ok, err
	}
	s := Schema{Refs: map[string]RefInfo{}, BackLinks: map[string]bool{}, Holds: map[string]string{}}
	for name, single := range dnRefsFromSchema(defs) {
		s.Refs[name] = RefInfo{Single: single}
	}
	// The memberof overlay of OpenLDAP (and 389-ds' plugin) keeps memberOf, operational, from member.
	if _, ok := s.Refs["memberof"]; ok {
		if _, ok := s.Refs["member"]; ok {
			s.Holds["memberOf"] = "member"
		}
	}
	return s, true, nil
}
