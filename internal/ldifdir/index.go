package ldifdir

import (
	"sort"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// rec is what the index keeps of an entry, built by the one read of the dump when it is opened: where it starts, its
// DN, the attributes it holds and the values of the few the tool's filters test. A clone walks the dump many times
// (the plan, each kind, the holders, the references), and a dump of AD is large (every object's descriptor), so most
// filters are decided from the index and only the entries they take are read: on a small CPU, reading every entry a
// dozen times took minutes before anything was written.
type rec struct {
	at    int64
	dn    string
	key   string   // dn.Normalize(dn)
	names []uint16 // the attributes it holds (Dir.ids), sorted
	vals  [len(indexed)][]string
}

// indexed are the attributes whose values the index keeps: what the kinds' filters and the system filter test.
var indexed = [...]string{"objectclass", "objectcategory", "iscriticalsystemobject"}

func indexOf(attr string) int {
	for i, a := range indexed {
		if a == attr {
			return i
		}
	}
	return -1
}

// id is the number of an attribute name (lowercase) in the index.
func (d *Dir) id(name string) uint16 {
	if n, ok := d.ids[name]; ok {
		return n
	}
	n := uint16(len(d.ids))
	d.ids[name] = n
	return n
}

// has reports whether r holds the attribute (lowercase).
func (d *Dir) has(r *rec, attr string) bool {
	n, ok := d.ids[attr]
	if !ok {
		return false
	}
	i := sort.Search(len(r.names), func(i int) bool { return r.names[i] >= n })
	return i < len(r.names) && r.names[i] == n
}

// indexRec builds the index record of an entry from its lines, decoding only the indexed values.
func (d *Dir) indexRec(at int64, entryDN string, lines []string) rec {
	r := rec{at: at, dn: entryDN}
	seen := map[uint16]bool{}
	for _, l := range lines[1:] {
		name, _, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(name)
		if n := d.id(name); !seen[n] {
			seen[n] = true
			r.names = append(r.names, n)
		}
		if i := indexOf(name); i >= 0 {
			if _, v, err := field(l); err == nil {
				r.vals[i] = append(r.vals[i], v)
			}
		}
	}
	sort.Slice(r.names, func(i, j int) bool { return r.names[i] < r.names[j] })
	return r
}

// entry is r as an entry holding its indexed values only.
func (r *rec) entry() *directory.Entry {
	e := &directory.Entry{DN: r.dn, Attrs: map[string][]string{}}
	for i, a := range indexed {
		if len(r.vals[i]) > 0 {
			e.Attrs[a] = r.vals[i]
		}
	}
	return e
}

// tri is a filter's outcome on an index record: it matches, it does not, or the entry must be read to tell.
type tri int8

const (
	no tri = iota
	yes
	unknown
)

// eval decides p on r where the index can: a test of an indexed attribute, or of one r does not hold (absent, it
// matches no assertion and is not present), is decided; one of a value the index does not keep is unknown.
func (d *Dir) eval(p *ber.Packet, r *rec) tri {
	switch p.Tag {
	case ldap.FilterAnd:
		out := yes
		for _, c := range p.Children {
			switch d.eval(c, r) {
			case no:
				return no
			case unknown:
				out = unknown
			}
		}
		return out
	case ldap.FilterOr:
		out := no
		for _, c := range p.Children {
			switch d.eval(c, r) {
			case yes:
				return yes
			case unknown:
				out = unknown
			}
		}
		return out
	case ldap.FilterNot:
		switch d.eval(p.Children[0], r) {
		case yes:
			return no
		case no:
			return yes
		}
		return unknown
	}
	attr := strings.ToLower(leafAttr(p))
	if attr == "" {
		return unknown
	}
	if indexOf(attr) < 0 && d.has(r, attr) {
		return unknown
	}
	if d.match.match(p, r.entry()) {
		return yes
	}
	return no
}

// leafAttr is the attribute a leaf of a filter tests, "" when it names none.
func leafAttr(p *ber.Packet) string {
	switch p.Tag {
	case ldap.FilterPresent:
		return p.Data.String()
	case ldap.FilterEqualityMatch, ldap.FilterSubstrings, ldap.FilterGreaterOrEqual, ldap.FilterLessOrEqual:
		if a, ok := p.Children[0].Value.(string); ok {
			return a
		}
	case ldap.FilterExtensibleMatch:
		_, attr, _, _ := extensible(p)
		return attr
	}
	return ""
}
