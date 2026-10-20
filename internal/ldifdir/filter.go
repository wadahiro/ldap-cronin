package ldifdir

import (
	"fmt"
	"strings"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
)

// matcher evaluates an RFC 4515 filter against the entries of a dump as a directory server would for the filters
// this tool sends and a user writes in [scope.filters]: and, or, not, equality, presence and substrings. Anything
// else (ordering, approximate and extensible matches) is an error naming it, never a silent match: a filter that
// narrows a scope must not widen it.
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
	case ldap.FilterEqualityMatch, ldap.FilterPresent, ldap.FilterSubstrings:
		return nil
	}
	return fmt.Errorf("%s is not supported on a dump (and, or, not, equality, presence and substrings are)", ldap.FilterMap[uint64(p.Tag)])
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
	}
	return false
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
	if strings.Contains(want, "=") && strings.Contains(have, "=") {
		return dn.Equal(have, want)
	}
	return utf8.ValidString(have) && utf8.ValidString(want) && strings.EqualFold(have, want)
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
