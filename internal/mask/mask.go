// Package mask replaces the values of the specified attributes with a fixed string.
package mask

import (
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// Masker masks attributes on every entry (set), and others on the entries of a kind only (kinds). A kind's list
// adds to the global one, never takes from it: masking is a safeguard.
type Masker struct {
	Value string
	set   map[string]bool
	kinds map[string]map[string]bool // kind -> lowercase attribute names
}

func New(value string, attributes []string) Masker {
	return Masker{Value: value, set: lowerSet(attributes)}
}

// WithKinds returns m with attributes masked on the entries of a kind only (kind name -> attributes).
func (m Masker) WithKinds(kinds map[string][]string) Masker {
	if len(kinds) == 0 {
		return m
	}
	m.kinds = make(map[string]map[string]bool, len(kinds))
	for k, attrs := range kinds {
		m.kinds[strings.ToLower(k)] = lowerSet(attrs)
	}
	return m
}

func lowerSet(attributes []string) map[string]bool {
	set := make(map[string]bool, len(attributes))
	for _, a := range attributes {
		set[strings.ToLower(a)] = true
	}
	return set
}

// Masked reports whether attr is masked on every entry.
func (m Masker) Masked(attr string) bool { return m.set[strings.ToLower(attr)] }

// MaskedIn reports whether attr is masked on an entry of kind ("" for an entry of no kind: the global ones only).
func (m Masker) MaskedIn(kind, attr string) bool {
	return m.Masked(attr) || m.kinds[strings.ToLower(kind)][strings.ToLower(attr)]
}

// Kinds returns, per kind, the attributes masked on its entries only, sorted (for the summaries).
func (m Masker) Kinds() map[string][]string {
	out := map[string][]string{}
	for k, set := range m.kinds {
		for a := range set {
			out[k] = append(out[k], a)
		}
		sort.Strings(out[k])
	}
	return out
}

// Apply returns a copy of e with the attributes masked on every entry masked, without modifying e.
func (m Masker) Apply(e directory.Entry) directory.Entry { return m.ApplyIn("", e) }

// ApplyIn returns a masked copy of e, an entry of kind, without modifying e. A multi-valued attribute collapses
// into a single masked value.
func (m Masker) ApplyIn(kind string, e directory.Entry) directory.Entry {
	out := directory.Entry{DN: e.DN, Attrs: make(map[string][]string, len(e.Attrs))}
	for name, values := range e.Attrs {
		if m.MaskedIn(kind, name) && len(values) > 0 {
			out.Attrs[name] = []string{m.Value}
			continue
		}
		out.Attrs[name] = values
	}
	return out
}
