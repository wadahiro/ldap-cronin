package directory

import (
	"io"

	"github.com/wadahiro/ldap-cronin/internal/ldif"
)

// DryRun is a Directory that only prints writes as LDIF.
// It assumes the target is empty and never connects (Get always reports "not found").
type DryRun struct{ Out io.Writer }

func (d DryRun) Walk(string, string, []string, func(Entry) error) error { return nil }
func (d DryRun) Get(string, []string) (*Entry, error)                   { return nil, nil }

func (d DryRun) Add(e Entry) error {
	ldif.Add(d.Out, e.DN, e.Attrs)
	return nil
}

func (d DryRun) Replace(dn string, attrs map[string][]string) error {
	ldif.Replace(d.Out, dn, attrs)
	return nil
}

func (d DryRun) AddValues(dn, attr string, values []string) error {
	ldif.AddValues(d.Out, dn, attr, values)
	return nil
}
