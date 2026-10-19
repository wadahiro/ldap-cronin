// Package dryrun is a Directory that only prints the writes as LDIF that can be passed to ldapmodify.
package dryrun

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/ldif"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// required are the MUST attributes of group classes (RFC 4519) a server refuses to create without. The dry-run
// cannot ask the server, so it refuses such an Add itself, and clone retries it with the members in scope, as it
// does against a real server.
var required = map[string]string{"groupofnames": "member", "groupofuniquenames": "uniqueMember"}

// Dir assumes the target is empty and never connects: Get reports "not found", so every object is an Add, except
// for the required values it wrote itself, which it remembers so the reference pass does not add them twice.
//
// The LDIF loads with ldapmodify. Writes that need the users' password are written as comments, since the password
// is never printed: on AD the password and the userAccountControl that follows it. A user loaded from the LDIF is
// then a disabled account without a password, which a clone run against the loaded target completes.
type Dir struct {
	w        ldif.Writer
	deferred []string // set after the password (the profile's account-owned attributes)

	mu      sync.Mutex                     // guards written, and serializes the writes: clone calls from its workers
	written map[string]map[string][]string // normalized DN -> required attribute -> values written at Add
}

// New writes to out for a target of profile p. The values of its password attributes are never printed.
func New(out io.Writer, p profile.Profile) *Dir {
	d := &Dir{w: ldif.Writer{W: out, Secret: p.PasswordAttrs}, written: map[string]map[string][]string{}}
	if p.Account != nil {
		d.deferred = p.Account.Owned()
	}
	return d
}

func (d *Dir) Walk(ctx context.Context, _, _ string, _ []string, _ func(directory.Entry) error) error {
	return ctx.Err()
}

func (d *Dir) Get(ctx context.Context, entryDN string, attrs []string) (*directory.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	w, ok := d.written[dn.Normalize(entryDN)]
	if !ok {
		return nil, nil
	}
	e := directory.Entry{DN: entryDN, Attrs: map[string][]string{}}
	for _, a := range attrs {
		for n, v := range w {
			if strings.EqualFold(n, a) {
				e.Attrs[a] = v
			}
		}
	}
	return &e, nil
}

func (d *Dir) Add(ctx context.Context, e directory.Entry, controls ...directory.Control) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var kept map[string][]string
	for _, c := range e.Values("objectClass") {
		must, ok := required[strings.ToLower(c)]
		if !ok {
			continue
		}
		v := e.Values(must)
		if len(v) == 0 {
			return fmt.Errorf("add %s: %w (%s requires %s)", e.DN, directory.ErrSchemaViolation, c, must)
		}
		if kept == nil {
			kept = map[string][]string{}
		}
		kept[must] = v
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if kept != nil {
		d.written[dn.Normalize(e.DN)] = kept
	}
	d.w.Add(e.DN, e.Attrs, controls...)
	return nil
}

func (d *Dir) Replace(ctx context.Context, entryDN string, attrs map[string][]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for n := range attrs {
		if d.needsPassword(n) {
			d.w.Deferred(entryDN, attrs, "clone sets this after the password; run clone against the loaded target")
			return nil
		}
	}
	d.w.Replace(entryDN, attrs)
	return nil
}

// needsPassword reports whether writing name needs the password, which the LDIF does not carry: the password itself,
// or an account attribute set after it (AD refuses to enable an account that has none).
func (d *Dir) needsPassword(name string) bool {
	for _, a := range append(append([]string(nil), d.w.Secret...), d.deferred...) {
		if strings.EqualFold(a, name) {
			return true
		}
	}
	return false
}

func (d *Dir) AddValues(ctx context.Context, entryDN, attr string, values []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.w.AddValues(entryDN, attr, values)
	return nil
}

var _ directory.Directory = (*Dir)(nil)
