// Package directory abstracts the directory operations that clone and diff depend on.
// Implementations are ldapdir (go-ldap), LDIF output for dry-run, and an in-memory one for tests.
package directory

import (
	"errors"
	"strings"
)

var ErrExists = errors.New("entry already exists")

// ErrSchemaViolation is returned by Add when the server rejects the entry because a required attribute is missing
// (object class violation). Generic LDAP groups such as groupOfNames must have a member at creation.
var ErrSchemaViolation = errors.New("object class violation")

// The Attrs keys of an Entry use the requested attribute name (canonical case).
type Entry struct {
	DN    string
	Attrs map[string][]string
}

// Values returns the values for an attribute name, ignoring case.
func (e Entry) Values(name string) []string {
	for k, v := range e.Attrs {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

// NoAttrs requests no attributes, so that only the DN is returned (LDAP "1.1").
const NoAttrs = "1.1"

type Directory interface {
	// Walk searches under base (inclusive) with filter and passes entries to fn one at a time.
	// To avoid accumulating all entries in memory, only one page is held at a time. fn is called sequentially from a single goroutine and
	// must not re-enter the same Directory (the connection would stay borrowed).
	// A missing base is treated as zero entries rather than an error (so a target can be diffed before clone).
	Walk(base, filter string, attrs []string, fn func(Entry) error) error
	// Get fetches one entry by dn. If it does not exist, it returns nil, nil.
	Get(dn string, attrs []string) (*Entry, error)
	// Add may return ErrExists.
	Add(e Entry) error
	Replace(dn string, attrs map[string][]string) error
	AddValues(dn, attr string, values []string) error
}

// Collect returns all results of Walk as a slice. It is meant only for small counts (tests, small lookups)
// and is not used on paths with large data sets.
func Collect(d Directory, base, filter string, attrs []string) ([]Entry, error) {
	var out []Entry
	err := d.Walk(base, filter, attrs, func(e Entry) error {
		out = append(out, e)
		return nil
	})
	return out, err
}
