package app

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/ldifdir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/progress"
)

// DumpOptions are what ldap-cronin dump is given on its command line: it reads no config file, so it can be run on
// production's side with nothing but the binary.
type DumpOptions struct {
	Conn ldapdir.ConnConfig // without the password, asked by Dump
	// BaseDNs are what to dump (dump.Options.BaseDNs).
	BaseDNs []string
	Out     string // .gz is compressed
	// MaskValue and Masked mask attributes in the file itself.
	MaskValue string
	Masked    []string
	Version   string
	Progress  *progress.Bar
	// Credentials dumps the credentials the source returns (the profile's Secrets), for a clone with
	// [attributes] credentials = "copy".
	Credentials bool
	// From is a dump to read instead of a server (Conn unset): a dump of it is that of the same moment of
	// production with more attributes masked, so a value let through by the first need not mean reading production
	// again.
	From string
}

// Dump reads the source o.Conn names, read only, or the dump o.From, and writes the dump to o.Out. It writes to a
// temporary file next to it and renames it at the end, so o.Out is never a dump cut off by an error or Ctrl-C.
func Dump(ctx context.Context, o DumpOptions, password func() (string, error), log io.Writer) (dump.Counts, error) {
	if o.From != "" {
		return redump(ctx, o, log)
	}
	pw, err := password()
	if err != nil {
		return dump.Counts{}, err
	}
	o.Conn.Password = pw
	c, err := ldapdir.Dial(o.Conn, 1)
	if err != nil {
		return dump.Counts{}, err
	}
	defer c.Close()
	prof, err := profile.Detect(ctx, c)
	if err != nil {
		return dump.Counts{}, err
	}
	if o.Credentials {
		if len(prof.Secrets) == 0 {
			return dump.Counts{}, fmt.Errorf("-with-credentials: the %s profile has no credentials a client can copy", prof.Name)
		}
		prof = prof.WithSecrets()
	}
	src := directory.ReadOnly{Directory: c.With(prof.Ranged)}
	return writeDump(ctx, src, prof, o.Out, dump.Options{BaseDNs: o.BaseDNs, MaskValue: o.MaskValue, Masked: o.Masked,
		Server: o.Conn.URL, Version: o.Version, Now: time.Now, Progress: o.Progress}, log)
}

// redump writes the dump o.From again with the masks o adds: what is read from it is what was read from the
// server then, so the new dump is the one dump would have written with those masks, of the same server and the same
// moment (its dumped-at and server lines), which diff compares the target with.
func redump(ctx context.Context, o DumpOptions, log io.Writer) (dump.Counts, error) {
	if o.Conn.URL != "" || o.Conn.BindDN != "" {
		return dump.Counts{}, errors.New("-from reads a dump: no -url or -bind-dn")
	}
	if same, err := samePath(o.From, o.Out); err != nil || same {
		if err == nil {
			err = fmt.Errorf("-o %s is the dump -from reads: write the new dump beside it", o.Out)
		}
		return dump.Counts{}, err
	}
	d, err := ldifdir.Open(o.From)
	if err != nil {
		return dump.Counts{}, err
	}
	defer d.Close()
	m := d.Meta()
	if !m.Holders {
		return dump.Counts{}, fmt.Errorf("%s was taken before dumps carried the groups outside the base DN that hold its entries: dump the server again", o.From)
	}
	// The profile it was dumped with, which its header names: told again from its root DSE, a server type a dump
	// cannot tell for sure (a generic server answers with no vendor) could come out another, and the new dump would
	// leave out what the first kept, or keep what it left out.
	prof, err := profile.ByName(m.Profile)
	if err != nil {
		return dump.Counts{}, fmt.Errorf("%s: %w", o.From, err)
	}
	if o.Credentials {
		// The credentials the dump carries, which it took with -with-credentials; without the flag they are left out,
		// as a dump of a server leaves them out.
		if len(m.Credentials) == 0 {
			return dump.Counts{}, fmt.Errorf("-with-credentials: %s carries no credentials (it was dumped without -with-credentials)", o.From)
		}
		prof = prof.WithSecrets()
	}
	bases := o.BaseDNs
	if len(bases) == 0 {
		bases = m.BaseDNs
	}
	for _, b := range bases {
		if !slices.ContainsFunc(m.BaseDNs, func(mb string) bool { return dn.Equal(b, mb) || dn.IsDescendant(b, mb) }) {
			return dump.Counts{}, fmt.Errorf("-base-dn %s is not in %s, which holds %s", b, o.From, strings.Join(m.BaseDNs, "; "))
		}
	}
	masked := m.Masked
	if len(m.Masked) > 0 && o.MaskValue != m.MaskValue {
		// The header has one value for every masked attribute.
		return dump.Counts{}, fmt.Errorf("-mask-value %q: %s masks with %q, which the new dump keeps", o.MaskValue, o.From, m.MaskValue)
	}
	for _, a := range o.Masked {
		if !slices.ContainsFunc(masked, func(x string) bool {
			return strings.EqualFold(strings.ReplaceAll(x, " ", ""), strings.ReplaceAll(a, " ", ""))
		}) {
			masked = append(masked, a)
		}
	}
	at, err := time.Parse(time.RFC3339, m.DumpedAt)
	if err != nil {
		return dump.Counts{}, fmt.Errorf("%s: dumped-at %q: %w", o.From, m.DumpedAt, err)
	}
	return writeDump(ctx, directory.ReadOnly{Directory: d}, prof, o.Out, dump.Options{BaseDNs: bases, MaskValue: o.MaskValue, Masked: masked,
		Server: m.Server, Version: o.Version, Now: func() time.Time { return at }, Progress: o.Progress}, log)
}

// samePath reports whether a and b are the same file (b need not exist).
func samePath(a, b string) (bool, error) {
	sa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	sb, err := os.Stat(b)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(sa, sb), nil
}

// writeDump writes the dump of src to out, through a temporary file renamed when complete.
func writeDump(ctx context.Context, src directory.Directory, prof profile.Profile, out string, opt dump.Options, log io.Writer) (dump.Counts, error) {
	dir, base := filepath.Split(out)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return dump.Counts{}, err
	}
	done := false
	defer func() {
		if !done {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return dump.Counts{}, err
	}
	var w io.Writer = tmp
	var z *gzip.Writer
	if strings.HasSuffix(out, ".gz") {
		z = gzip.NewWriter(tmp)
		w = z
	}
	counts, err := dump.Write(ctx, src, prof, opt, w)
	if err != nil {
		return counts, err
	}
	if z != nil {
		if err := z.Close(); err != nil {
			return counts, err
		}
	}
	if err := tmp.Close(); err != nil {
		return counts, err
	}
	if err := os.Rename(tmp.Name(), out); err != nil {
		return counts, err
	}
	done = true
	fmt.Fprintf(log, "dumped %d entries to %s (%s; under the base DN %d, referenced outside it %d, schema %d)\n",
		counts.Total(), out, prof.Name, counts.Base, counts.Referenced, counts.Schema)
	if counts.Unreadable > 0 {
		fmt.Fprintf(log, "warning: %d entries a clone needs were not returned by the source (the account may not read them); they are listed at the end of the dump (# unreadable:), and clone creates placeholders where references name them\n", counts.Unreadable)
	}
	return counts, nil
}
