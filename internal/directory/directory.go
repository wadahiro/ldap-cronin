// Package directory abstracts the directory operations that clone and diff depend on.
// Implementations are ldapdir (go-ldap), LDIF output for dry-run, and an in-memory one for tests.
package directory

import (
	"context"
	"errors"
	"strings"
)

var ErrExists = errors.New("entry already exists")

// ErrSchemaViolation is returned by Add when the server rejects the entry because a required attribute is missing
// (object class violation). Generic LDAP groups such as groupOfNames must have a member at creation.
var ErrSchemaViolation = errors.New("object class violation")

// ErrInsufficientAccess is returned when the server refuses an operation for lack of rights (result 50). With the
// relax control it means the bind may write the entry but not the attributes the control unlocks.
var ErrInsufficientAccess = errors.New("insufficient access")

// ErrControlUnsupported is returned when the server does not know a control sent as critical (result 12).
var ErrControlUnsupported = errors.New("critical control not supported")

// Control is a request control sent with an operation, independent of the LDAP library.
type Control struct {
	OID      string
	Critical bool
}

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

// Every method takes a context. Implementations check it before sending an operation; an operation already sent
// runs to completion, because go-ldap cannot abandon an Add or a Modify. A stop therefore costs at most one
// operation per connection, which is fine for a tool whose operations are small.
type Directory interface {
	// Walk searches under base (inclusive) with filter and passes entries to fn one at a time.
	// To avoid accumulating all entries in memory, only one page is held at a time. fn is called sequentially from a single goroutine and
	// must not re-enter the same Directory (the connection would stay borrowed).
	// A missing base is treated as zero entries rather than an error (so a target can be diffed before clone).
	Walk(ctx context.Context, base, filter string, attrs []string, fn func(Entry) error) error
	// Get fetches one entry by dn. If it does not exist, it returns nil, nil.
	Get(ctx context.Context, dn string, attrs []string) (*Entry, error)
	// Add may return ErrExists, ErrSchemaViolation, ErrInsufficientAccess or ErrControlUnsupported.
	// controls are sent with the request.
	Add(ctx context.Context, e Entry, controls ...Control) error
	Replace(ctx context.Context, dn string, attrs map[string][]string) error
	AddValues(ctx context.Context, dn, attr string, values []string) error
}

// Collect returns all results of Walk as a slice. It is meant only for small counts (tests, small lookups)
// and is not used on paths with large data sets.
func Collect(ctx context.Context, d Directory, base, filter string, attrs []string) ([]Entry, error) {
	var out []Entry
	err := d.Walk(ctx, base, filter, attrs, func(e Entry) error {
		out = append(out, e)
		return nil
	})
	return out, err
}
