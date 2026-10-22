package profile

import (
	"context"
	"fmt"
	"regexp"
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
	names  []string
	sup    string
	syntax string
	single bool
}

var (
	reNames  = regexp.MustCompile(`NAME\s+(?:'([^']+)'|\(([^)]*)\))`)
	reSup    = regexp.MustCompile(`SUP\s+'?([A-Za-z0-9._-]+)'?`)
	reSyntax = regexp.MustCompile(`SYNTAX\s+'?([0-9.]+)`)
	reQuoted = regexp.MustCompile(`'([^']+)'`)
)

// parseAttributeType reads one value of the attributeTypes attribute.
func parseAttributeType(def string) (attributeType, bool) {
	var t attributeType
	m := reNames.FindStringSubmatch(def)
	if m == nil {
		return t, false
	}
	if m[1] != "" {
		t.names = []string{m[1]}
	} else {
		for _, q := range reQuoted.FindAllStringSubmatch(m[2], -1) {
			t.names = append(t.names, q[1])
		}
	}
	if m := reSup.FindStringSubmatch(def); m != nil {
		t.sup = m[1]
	}
	if m := reSyntax.FindStringSubmatch(def); m != nil {
		t.syntax = m[1]
	}
	t.single = strings.Contains(def, "SINGLE-VALUE")
	return t, len(t.names) > 0
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

// subschema reads attributeTypes from the subschema subentry (RFC 4512). There is no back-link marker in a plain
// schema, so back links such as memberOf are excluded through the profile's never-clone list instead.
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
	root, err := d.Get(ctx, "", []string{"subschemaSubentry"})
	if err != nil {
		return nil, false, fmt.Errorf("read root DSE: %w", err)
	}
	if root == nil || first(root.Values("subschemaSubentry")) == "" {
		return nil, false, nil
	}
	sub, err := d.Get(ctx, first(root.Values("subschemaSubentry")), []string{"attributeTypes"})
	if err != nil {
		return nil, false, fmt.Errorf("read schema: %w", err)
	}
	if sub == nil {
		return nil, false, nil
	}
	return sub.Values("attributeTypes"), true, nil
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
