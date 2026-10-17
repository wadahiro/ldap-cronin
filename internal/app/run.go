package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dryrun"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

// Exit codes of diff.
const (
	ExitSame = 0
	ExitDiff = 1
)

// Clone adds and updates the target. With dryRun it connects nowhere but the source and writes LDIF to out.
// Progress goes to log (standard error for a dry-run, so its standard output can be passed to ldapmodify).
func (s *Session) Clone(ctx context.Context, dryRun bool, out, log io.Writer) (*clone.Report, error) {
	opt := clone.Options{UserPassword: "<fixed-password>", Workers: s.Cfg.Run.Workers}
	var dst directory.Directory = dryrun.New(out, s.Job.Profile.PasswordAttrs)
	if !dryRun {
		var err error
		if opt.UserPassword, err = s.secrets.UserPassword(); err != nil {
			return nil, err
		}
		target, closeTarget, err := s.Target(ctx)
		if err != nil {
			return nil, err
		}
		defer closeTarget()
		dst = target
		if s.Cfg.Mapping.File != "" {
			header, err := s.mappingHeader(ctx, dst)
			if err != nil {
				return nil, err
			}
			if opt.Mapping, err = identity.Open(s.Cfg.Mapping.File, header); err != nil {
				return nil, err
			}
		}
	}
	report, err := clone.Run(ctx, s.Src, dst, s.Job, opt, log)
	// Closed even after a failure or an interruption: every pair recorded so far is kept, and a re-run continues.
	if opt.Mapping != nil {
		if cerr := opt.Mapping.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("write mapping file: %w", cerr)
		}
	}
	return report, err
}

// Diff compares source and target, writes the differences and the summary to out, and returns ExitSame or ExitDiff.
// An interrupted comparison returns the error and no summary: a partial result would read as "no differences" in
// the part it did not reach.
func (s *Session) Diff(ctx context.Context, maxValues int, out io.Writer) (int, error) {
	dst, closeTarget, err := s.Target(ctx)
	if err != nil {
		return 0, err
	}
	defer closeTarget()

	mapping, err := s.loadMapping(ctx, dst)
	if err != nil {
		return 0, err
	}
	var fromFile identity.Lookup // a nil *Map must stay a nil interface, or diff would think tracking is on
	if mapping != nil {
		defer mapping.Close()
		fromFile = mapping
	}
	lookup, why, err := diff.ChooseLookup(ctx, s.Src, dst, s.Job, fromFile)
	if err != nil {
		return 0, err
	}
	if lookup == nil && why != "" {
		fmt.Fprintf(s.Warn, "note: cannot say the %ss are identical (%s)\n", s.Job.Profile.Identity.Attr(), why)
	}
	sum, err := diff.Run(ctx, s.Src, dst, s.Job, diff.Options{Workers: s.Cfg.Run.Workers, Lookup: lookup},
		func(d diff.Difference) { diff.Format(out, d, maxValues) })
	if err != nil {
		return 0, err
	}
	total := sum.Differences[diff.OnlySource] + sum.Differences[diff.OnlyTarget] + sum.Differences[diff.Differ]
	if total == 0 {
		fmt.Fprintln(out, "no differences")
	}
	diff.WriteSummary(out, s.Job, sum, s.Cfg.Attributes.Exclude)
	if total == 0 {
		return ExitSame, nil
	}
	return ExitDiff, nil
}

// mappingHeader identifies the source/target pair by the identifiers of their naming-context roots.
func (s *Session) mappingHeader(ctx context.Context, dst directory.Directory) (identity.Header, error) {
	root, err := plan.Root(ctx, s.Src, s.Job)
	if err != nil {
		return identity.Header{}, err
	}
	scheme := s.Job.Profile.Identity
	srcKey, err := identity.RootKey(ctx, s.Src, root, scheme)
	if err != nil {
		return identity.Header{}, fmt.Errorf("source: %w", err)
	}
	dstKey, err := identity.RootKey(ctx, dst, root, scheme)
	if err != nil {
		return identity.Header{}, fmt.Errorf("target: %w", err)
	}
	return identity.Header{Scheme: scheme.Attr(), SourceRoot: srcKey, TargetRoot: dstKey, BaseDN: s.Job.BaseDN}, nil
}

// loadMapping opens the mapping for diff. If it is not configured, missing, of another format or of another pair,
// diff runs without rename and move detection and the reason goes to Warn.
func (s *Session) loadMapping(ctx context.Context, dst directory.Directory) (*identity.Map, error) {
	file := s.Cfg.Mapping.File
	if file == "" {
		return nil, nil
	}
	header, err := s.mappingHeader(ctx, dst)
	if err != nil {
		fmt.Fprintf(s.Warn, "note: cannot identify the directories, so rename and move detection is not used: %v\n", err)
		return nil, nil
	}
	m, err := identity.Load(file, header)
	switch {
	case err == nil:
		return m, nil
	case errors.Is(err, os.ErrNotExist):
		fmt.Fprintf(s.Warn, "note: %s not found; rename/move detection is off (run clone with [mapping] file to record it)\n", file)
		return nil, nil
	case errors.Is(err, identity.ErrOldFormat):
		fmt.Fprintf(s.Warn, "note: %v; rename/move detection is off\n", err)
		return nil, nil
	case errors.Is(err, identity.ErrHeaderMismatch):
		fmt.Fprintf(s.Warn, "note: %s belongs to a different source/target or base_dn; rename/move detection is off\n", file)
		return nil, nil
	}
	return nil, err
}
