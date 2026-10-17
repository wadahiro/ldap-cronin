// Package dryrun is a Directory that only prints the writes as LDIF that can be passed to ldapmodify.
package dryrun

import (
	"context"
	"io"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/ldif"
)

// Dir assumes the target is empty and never connects: Get always reports "not found", so every object is an Add.
type Dir struct{ w ldif.Writer }

// New writes to out. The values of secret (the profile's password attributes) are never printed.
func New(out io.Writer, secret []string) Dir { return Dir{w: ldif.Writer{W: out, Secret: secret}} }

func (d Dir) Walk(ctx context.Context, _, _ string, _ []string, _ func(directory.Entry) error) error {
	return ctx.Err()
}

func (d Dir) Get(ctx context.Context, _ string, _ []string) (*directory.Entry, error) {
	return nil, ctx.Err()
}

func (d Dir) Add(ctx context.Context, e directory.Entry, controls ...directory.Control) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.w.Add(e.DN, e.Attrs, controls...)
	return nil
}

func (d Dir) Replace(ctx context.Context, dn string, attrs map[string][]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.w.Replace(dn, attrs)
	return nil
}

func (d Dir) AddValues(ctx context.Context, dn, attr string, values []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.w.AddValues(dn, attr, values)
	return nil
}

var _ directory.Directory = Dir{}
