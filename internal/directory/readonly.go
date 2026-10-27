package directory

import (
	"context"
	"errors"
	"fmt"
)

// ErrReadOnly is returned by every write to a ReadOnly directory.
var ErrReadOnly = errors.New("refused: this directory is read-only")

// ReadOnly passes the reads to the directory it wraps and refuses every write with ErrReadOnly, before anything is
// sent. The source is opened through it, so no code path, today's or a later one, can write to it by mistake.
type ReadOnly struct{ Directory }

func (ReadOnly) Add(_ context.Context, e Entry, _ ...Control) error {
	return fmt.Errorf("add %s: %w", e.DN, ErrReadOnly)
}

func (ReadOnly) Replace(_ context.Context, dn string, _ map[string][]string) error {
	return fmt.Errorf("modify %s: %w", dn, ErrReadOnly)
}

func (ReadOnly) AddValues(_ context.Context, dn, attr string, _ []string) error {
	return fmt.Errorf("modify %s (%s): %w", dn, attr, ErrReadOnly)
}

func (ReadOnly) DeleteValues(_ context.Context, dn, attr string, _ []string) error {
	return fmt.Errorf("modify %s (delete %s): %w", dn, attr, ErrReadOnly)
}
