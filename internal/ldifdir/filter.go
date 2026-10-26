package ldifdir

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
)

// matcher evaluates an RFC 4515 filter against the entries of a dump as a directory server would for the filters
// this tool sends and a user writes in [scope.filters]: and, or, not, equality, presence, substrings, ordering, and
// AD's bitwise matching rules. Anything else (approximate matches, other matching rules) is an error naming it,
// never a silent match: a filter that narrows a scope must not widen it.
type matcher struct {
	// categories maps a class's lDAPDisplayName (lowercase) to its defaultObjectCategory, normalized: AD takes
	// objectCategory=person for CN=Person,CN=Schema,..., which is what an entry holds.
	categories map[string]string
}

func (m *matcher) compile(filter string) (*ber.Packet, error) {
	p, err := ldap.CompileFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("filter %s: %w", filter, err)
	}
	if err := supported(p); err != nil {
		return nil, fmt.Errorf("filter %s: %w", filter, err)
	}
	return p, nil
}

func supported(p *ber.Packet) error {
	switch p.Tag {
	case ldap.FilterAnd, ldap.FilterOr, ldap.FilterNot:
		for _, c := range p.Children {
			if err := supported(c); err != nil {
				return err
			}
		}
		return nil
	case ldap.FilterEqualityMatch, ldap.FilterPresent, ldap.FilterSubstrings, ldap.FilterGreaterOrEqual, ldap.FilterLessOrEqual:
		return nil
	case ldap.FilterExtensibleMatch:
		rule, attr, _, dnAttrs := extensible(p)
		if (rule == bitAnd || rule == bitOr) && attr != "" && !dnAttrs {
			return nil
		}
		return fmt.Errorf("the matching rule %q is not supported on a dump (%s and %s, AD's bitwise and and or, are)", rule, bitAnd, bitOr)
	}
	return fmt.Errorf("%s is not supported on a dump (and, or, not, equality, presence, substrings, ordering and AD's bitwise matching rules are)", ldap.FilterMap[uint64(p.Tag)])
}

// AD's bitwise matching rules: every bit of the value is set (and), or any of them is (or).
const (
	bitAnd = "1.2.840.113556.1.4.803"
	bitOr  = "1.2.840.113556.1.4.804"
)

// extensible reads an extensible match: (attr:rule:=value), with ":dn" when dnAttrs.
func extensible(p *ber.Packet) (rule, attr, value string, dnAttrs bool) {
	for _, c := range p.Children {
		switch c.Tag {
		case ldap.MatchingRuleAssertionMatchingRule:
			rule = c.Data.String()
		case ldap.MatchingRuleAssertionType:
			attr = c.Data.String()
		case ldap.MatchingRuleAssertionMatchValue:
			value = c.Data.String()
		case ldap.MatchingRuleAssertionDNAttributes:
			dnAttrs = true
		}
	}
	return
}

func (m *matcher) match(p *ber.Packet, e *directory.Entry) bool {
	switch p.Tag {
	case ldap.FilterAnd:
		for _, c := range p.Children {
			if !m.match(c, e) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, c := range p.Children {
			if m.match(c, e) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return !m.match(p.Children[0], e)
	case ldap.FilterPresent:
		return len(e.Values(p.Data.String())) > 0
	case ldap.FilterEqualityMatch:
		attr := p.Children[0].Value.(string)
		want := equalityValue(p.Children[1])
		for _, v := range e.Values(attr) {
			if m.equal(attr, v, want) {
				return true
			}
		}
		return false
	case ldap.FilterSubstrings:
		attr := p.Children[0].Value.(string)
		for _, v := range e.Values(attr) {
			if substrings(strings.ToLower(v), p.Children[1].Children) {
				return true
			}
		}
		return false
	case ldap.FilterGreaterOrEqual, ldap.FilterLessOrEqual:
		attr := p.Children[0].Value.(string)
		want := equalityValue(p.Children[1])
		for _, v := range e.Values(attr) {
			c := compare(v, want)
			if c == 0 || (c > 0) == (p.Tag == ldap.FilterGreaterOrEqual) {
				return true
			}
		}
		return false
	case ldap.FilterExtensibleMatch:
		rule, attr, value, _ := extensible(p)
		want, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return false
		}
		for _, v := range e.Values(attr) {
			have, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			if rule == bitAnd && have&want == want || rule == bitOr && have&want != 0 {
				return true
			}
		}
		return false
	}
	return false
}

// compare orders two values as AD and an RFC 4519 server order the attributes a filter compares: integers
// (uSNChanged, the account times) as numbers, the rest (generalized times, names) as text ignoring case, which
// orders times of the same form (whenChanged's 20261021091233.0Z) by time.
func compare(have, want string) int {
	h, herr := strconv.ParseInt(have, 10, 64)
	w, werr := strconv.ParseInt(want, 10, 64)
	if herr == nil && werr == nil {
		switch {
		case h < w:
			return -1
		case h > w:
			return 1
		}
		return 0
	}
	return strings.Compare(strings.ToLower(have), strings.ToLower(want))
}

func equalityValue(p *ber.Packet) string {
	if s, ok := p.Value.(string); ok {
		return s
	}
	return p.Data.String()
}

// equal compares a stored value with a filter's, as AD and an RFC 4519 server compare the attributes this tool
// filters on: objectCategory by the class's short name, a DN as a DN, binary values byte for byte, and the rest
// (names, booleans, OIDs) ignoring case.
func (m *matcher) equal(attr, have, want string) bool {
	if have == want {
		return true
	}
	if strings.EqualFold(attr, "objectCategory") && !strings.Contains(want, "=") {
		if cat, ok := m.categories[strings.ToLower(want)]; ok {
			return dn.Normalize(have) == cat
		}
		// A dump without the class (one of a schema-less source, as the tests' directories are): AD names a
		// class's category after the class, Person for person, Organizational-Unit for organizationalUnit.
		_, rdn, _ := dn.FirstRDN(have)
		return strings.EqualFold(strings.ReplaceAll(rdn, "-", ""), want)
	}
	text := utf8.ValidString(have) && utf8.ValidString(want)
	// A binary value (an objectSid) may hold the byte '=' without being a DN.
	if text && strings.Contains(want, "=") && strings.Contains(have, "=") {
		return dn.Equal(have, want)
	}
	return text && strings.EqualFold(have, want)
}

// substrings matches the initial, any and final parts in order, ignoring case.
func substrings(v string, parts []*ber.Packet) bool {
	pos := 0
	for i, part := range parts {
		s := strings.ToLower(part.Data.String())
		switch part.Tag {
		case ldap.FilterSubstringsInitial:
			if !strings.HasPrefix(v, s) {
				return false
			}
			pos = len(s)
		case ldap.FilterSubstringsAny:
			at := strings.Index(v[pos:], s)
			if at < 0 {
				return false
			}
			pos += at + len(s)
		case ldap.FilterSubstringsFinal:
			if !strings.HasSuffix(v[pos:], s) || (i == 0 && len(v) < len(s)) {
				return false
			}
			pos = len(v)
		}
	}
	return true
}

// filterAttrs adds to into the attributes (lowercase) filter p tests.
func filterAttrs(p *ber.Packet, into map[string]bool) map[string]bool {
	switch p.Tag {
	case ldap.FilterAnd, ldap.FilterOr, ldap.FilterNot:
		for _, c := range p.Children {
			filterAttrs(c, into)
		}
	case ldap.FilterPresent:
		into[strings.ToLower(p.Data.String())] = true
	case ldap.FilterEqualityMatch, ldap.FilterSubstrings, ldap.FilterGreaterOrEqual, ldap.FilterLessOrEqual:
		if a, ok := p.Children[0].Value.(string); ok {
			into[strings.ToLower(a)] = true
		}
	case ldap.FilterExtensibleMatch:
		if _, attr, _, _ := extensible(p); attr != "" {
			into[strings.ToLower(attr)] = true
		}
	}
	return into
}
