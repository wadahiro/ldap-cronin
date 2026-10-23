package app

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
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
}

// Dump reads the source o.Conn names, read only, and writes the dump to o.Out. It writes to a temporary file next to
// it and renames it at the end, so o.Out is never a dump cut off by an error or Ctrl-C.
func Dump(ctx context.Context, o DumpOptions, password func() (string, error), log io.Writer) (dump.Counts, error) {
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
	src := directory.ReadOnly{Directory: c.With(prof.Ranged)}

	dir, base := filepath.Split(o.Out)
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
	if strings.HasSuffix(o.Out, ".gz") {
		z = gzip.NewWriter(tmp)
		w = z
	}
	counts, err := dump.Write(ctx, src, prof, dump.Options{BaseDNs: o.BaseDNs, MaskValue: o.MaskValue, Masked: o.Masked,
		Server: o.Conn.URL, Version: o.Version, Now: time.Now, Progress: o.Progress}, w)
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
	if err := os.Rename(tmp.Name(), o.Out); err != nil {
		return counts, err
	}
	done = true
	fmt.Fprintf(log, "dumped %d entries to %s (%s; under the base DN %d, referenced outside it %d, schema %d)\n",
		counts.Total(), o.Out, prof.Name, counts.Base, counts.Referenced, counts.Schema)
	if counts.Unreadable > 0 {
		fmt.Fprintf(log, "warning: %d entries a clone needs were not returned by the source (the account may not read them); they are listed at the end of the dump (# unreadable:), and clone creates placeholders where references name them\n", counts.Unreadable)
	}
	return counts, nil
}
