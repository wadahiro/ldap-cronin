package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
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
	mode, attr, err := s.Cfg.MappingFor(s.Job.Profile)
	if err != nil {
		return nil, err
	}
	switch mode {
	case config.MappingPreserve:
		opt.Preserve, opt.Operational = true, s.Cfg.Mapping.Operational()
	case config.MappingMarker:
		// The marker names the source by its root key, read from the source: a dry-run writes markers too, so an
		// LDIF loaded with ldapmodify gives diff the same view as a clone.
		m, err := s.marker(ctx, attr)
		if err != nil {
			return nil, err
		}
		opt.Marker = &m
	}
	var dst directory.Directory = dryrun.New(out, s.Job.Profile)
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
		if opt.Marker != nil && s.Job.Profile.MarkerCheck != nil {
			warning, err := s.Job.Profile.MarkerCheck.CheckMarker(ctx, dst, attr, identity.MarkerLen)
			if err != nil {
				return nil, err
			}
			if warning != "" {
				fmt.Fprintf(s.Warn, "warning: %s\n", warning)
			}
		}
		if mode == config.MappingFile {
			header, err := s.mappingHeader(ctx)
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

// DiffOutput is how diff writes its result.
type DiffOutput struct {
	// JSON writes JSON Lines (one object per difference, then the summary) instead of text.
	JSON bool
	// MaxValues caps the values shown per direction in the text output; 0 shows all. JSON never cuts values.
	MaxValues int
}

// Diff compares source and target, writes the differences and the summary to out, and returns ExitSame or ExitDiff.
// An interrupted comparison returns the error and no summary: a partial result would read as "no differences" in
// the part it did not reach.
func (s *Session) Diff(ctx context.Context, o DiffOutput, out io.Writer) (int, error) {
	dst, closeTarget, err := s.Target(ctx)
	if err != nil {
		return 0, err
	}
	defer closeTarget()

	res, closeRes, err := s.resolver(ctx, dst)
	if err != nil {
		return 0, err
	}
	defer closeRes()
	var js *diff.JSON
	var werr error // a failed write (a closed pipe) fails the run instead of being taken for "no differences"
	emit := func(d diff.Difference) { diff.Format(out, d, o.MaxValues) }
	if o.JSON {
		js = diff.NewJSON(out)
		emit = func(d diff.Difference) {
			if err := js.Difference(d); err != nil && werr == nil {
				werr = err
			}
		}
	}
	sum, err := diff.Run(ctx, s.Src, dst, s.Job, diff.Options{Workers: s.Cfg.Run.Workers, Resolver: res}, emit)
	if err == nil {
		err = werr
	}
	if err != nil {
		return 0, err
	}
	// Every kind counts: a rename alone is a change made on the target, and turning detection on must not hide it
	// from a script (without detection it shows as ONLY_SOURCE + ONLY_TARGET).
	total := 0
	for _, n := range sum.Differences {
		total += n
	}
	if js != nil {
		if err := js.Summary(s.Job, sum, s.Cfg.Attributes.Exclude); err != nil {
			return 0, err
		}
	} else {
		if total == 0 {
			fmt.Fprintln(out, "no differences")
		}
		diff.WriteSummary(out, s.Job, sum, s.Cfg.Attributes.Exclude)
	}
	if total == 0 {
		return ExitSame, nil
	}
	return ExitDiff, nil
}

// resolver decides how diff matches target objects to source objects. Whatever the mode, identifiers shown to be
// the source's (a native import, a preserving clone) are matched directly; otherwise the marker or the mapping file
// of the mode is used. Only mode = "off" turns matching off altogether.
// The returned func releases the mapping file.
func (s *Session) resolver(ctx context.Context, dst directory.Directory) (identity.Resolver, func(), error) {
	release := func() {}
	mode, attr, err := s.Cfg.MappingFor(s.Job.Profile)
	if err != nil || mode == config.MappingOff {
		return nil, release, err
	}
	var fallback identity.Resolver // a nil *Map must stay a nil interface, or diff would think matching is on
	switch mode {
	case config.MappingMarker:
		m, err := s.marker(ctx, attr)
		if err != nil {
			return nil, release, err
		}
		fallback = identity.ByMarker(m)
	case config.MappingFile:
		m, err := s.loadMapping(ctx, dst)
		if err != nil {
			return nil, release, err
		}
		if m != nil {
			release = func() { m.Close() }
			fallback = identity.ByMap(m, s.Job.Profile.Identity)
		}
	}
	res, why, err := diff.ChooseResolver(ctx, s.Src, dst, s.Job, fallback)
	if err != nil {
		release()
		return nil, func() {}, err
	}
	if mode == config.MappingPreserve && why != "" {
		fmt.Fprintf(s.Warn, "note: cannot say the %ss are the source's (%s); rename/move detection is off\n", s.Job.Profile.Identity.Attr(), why)
	}
	return res, release, nil
}

// marker is the marker of objects cloned from this source.
func (s *Session) marker(ctx context.Context, attr string) (identity.Marker, error) {
	root, err := plan.Root(ctx, s.Src, s.Job)
	if err != nil {
		return identity.Marker{}, err
	}
	key, err := identity.RootKey(ctx, s.Src, root, s.Job.Profile.Identity)
	if err != nil {
		return identity.Marker{}, fmt.Errorf("source: %w", err)
	}
	return identity.NewMarker(attr, key), nil
}

// mappingHeader identifies the source by the identifier of its naming-context root. The target is not part of it: one
// mapping file serves every target cloned from the source.
func (s *Session) mappingHeader(ctx context.Context) (identity.Header, error) {
	root, err := plan.Root(ctx, s.Src, s.Job)
	if err != nil {
		return identity.Header{}, err
	}
	scheme := s.Job.Profile.Identity
	srcKey, err := identity.RootKey(ctx, s.Src, root, scheme)
	if err != nil {
		return identity.Header{}, fmt.Errorf("source: %w", err)
	}
	return identity.Header{Scheme: scheme.Attr(), SourceRoot: srcKey}, nil
}

// loadMapping opens the mapping for diff. If it is not configured, missing, of another format or of another source,
// diff runs without rename and move detection and the reason goes to Warn.
func (s *Session) loadMapping(ctx context.Context, dst directory.Directory) (*identity.Map, error) {
	file := s.Cfg.Mapping.File
	if file == "" {
		return nil, nil
	}
	header, err := s.mappingHeader(ctx)
	if err != nil {
		fmt.Fprintf(s.Warn, "note: cannot identify the source, so rename and move detection is not used: %v\n", err)
		return nil, nil
	}
	m, err := identity.Load(file, header)
	switch {
	case err == nil:
		return m, nil
	case errors.Is(err, os.ErrNotExist):
		fmt.Fprintf(s.Warn, "note: %s not found; rename/move detection is off (clone records it with [mapping] mode = \"file\")\n", file)
		return nil, nil
	case errors.Is(err, identity.ErrOldFormat):
		fmt.Fprintf(s.Warn, "note: %v; rename/move detection is off\n", err)
		return nil, nil
	case errors.Is(err, identity.ErrHeaderMismatch):
		fmt.Fprintf(s.Warn, "note: %s belongs to another source; rename/move detection is off\n", file)
		return nil, nil
	}
	return nil, err
}
