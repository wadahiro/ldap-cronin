// Package mask replaces the values of the specified attributes with a fixed string.
package mask

import (
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

type Masker struct {
	Value string
	set   map[string]bool
}

func New(value string, attributes []string) Masker {
	set := make(map[string]bool, len(attributes))
	for _, a := range attributes {
		set[strings.ToLower(a)] = true
	}
	return Masker{Value: value, set: set}
}

func (m Masker) Masked(attr string) bool { return m.set[strings.ToLower(attr)] }

// Apply returns a masked copy of e without modifying e. A multi-valued attribute collapses into a single masked value.
func (m Masker) Apply(e directory.Entry) directory.Entry {
	out := directory.Entry{DN: e.DN, Attrs: make(map[string][]string, len(e.Attrs))}
	for name, values := range e.Attrs {
		if m.Masked(name) && len(values) > 0 {
			out.Attrs[name] = []string{m.Value}
			continue
		}
		out.Attrs[name] = values
	}
	return out
}
