// Package dump writes what clone, diff and the rest read from a source into one LDIF file (ldifdir reads it back),
// so production is read once, at a time chosen for it, and the clones that follow never connect to it.
package dump

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/ldif"
	"github.com/wadahiro/ldap-cronin/internal/ldifdir"
	"github.com/wadahiro/ldap-cronin/internal/mask"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/progress"
)

// rootDSE are the attributes of the root DSE the tool reads from a source.
var rootDSE = []string{"supportedCapabilities", "namingContexts", "defaultNamingContext", "rootDomainNamingContext",
	"schemaNamingContext", "configurationNamingContext", "subschemaSubentry", "dnsHostName", "vendorName", "vendorVersion"}

// Options are what the dump is of.
type Options struct {
	BaseDN string
	// MaskValue and Masked mask attributes in the dump itself, so the file holds no value of them.
	MaskValue string
	Masked    []string
	// Server is the URL the dump is read from, Version the tool's, for the header.
	Server, Version string
	Now             func() time.Time
	Progress        *progress.Bar
}

// Counts are the entries written, per section.
type Counts struct{ RootDSE, Schema, Config, Base, Referenced int }

// Total is the number of entries.
func (c Counts) Total() int { return c.RootDSE + c.Schema + c.Config + c.Base + c.Referenced }

// Write reads from src what a clone of o.BaseDN reads, and writes it to w:
//   - the root DSE (the server type, the naming contexts);
//   - the schema (AD: the attributeSchema and classSchema entries; generic: the subschema entry);
//   - on AD the crossRef entries of the configuration partition (the NetBIOS name);
//   - the root of the naming context, every entry between it and o.BaseDN, and every entry under o.BaseDN;
//   - the entries outside o.BaseDN that a DN-valued attribute of those names, and the entries above them, without
//     what they name in turn, as clone creates them.
//
// The credentials the profile names are never written; the attributes of o.Masked are masked.
func Write(ctx context.Context, src directory.Directory, prof profile.Profile, o Options, w io.Writer) (Counts, error) {
	for _, a := range o.Masked {
		if !prof.Maskable(a) {
			return Counts{}, fmt.Errorf("%s cannot be masked: it names entries or identifies the object", a)
		}
	}
	root, err := prof.Root.Root(ctx, src, o.BaseDN)
	if err != nil {
		return Counts{}, err
	}
	if dn.Equal(o.BaseDN, root) || !dn.IsDescendant(o.BaseDN, root) {
		return Counts{}, fmt.Errorf("base DN %q must be below the root of its naming context %q", o.BaseDN, root)
	}
	rootEntry, err := src.Get(ctx, "", rootDSE)
	if err != nil {
		return Counts{}, fmt.Errorf("read the root DSE: %w", err)
	}
	if rootEntry == nil {
		rootEntry = &directory.Entry{Attrs: map[string][]string{}}
	}
	refs := map[string]bool{}
	for k := range prof.BuiltinRefs {
		refs[k] = true
	}
	if s, ok, err := prof.Refs.Discover(ctx, src); err != nil {
		return Counts{}, err
	} else if ok {
		for k := range s.Refs {
			refs[k] = true
		}
		for k := range s.BackLinks {
			delete(refs, k)
		}
	}
	for _, a := range o.Masked {
		if refs[strings.ToLower(a)] {
			return Counts{}, fmt.Errorf("%s holds DNs and cannot be masked", a)
		}
	}
	operational := append([]string(nil), prof.Operational...)
	subschema := first(rootEntry.Values("subschemaSubentry"))
	if subschema != "" {
		operational = append(operational, "attributeTypes", "objectClasses")
	}
	wr := &writer{w: ldif.Writer{W: w}, excluded: profile.Set(prof.PasswordAttrs), written: map[string]bool{}}
	masker := mask.New(o.MaskValue, o.Masked)
	read := append([]string{directory.AllAttrs}, prof.Operational...)
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}

	wr.header(o, prof, root, operational, now())
	var c Counts
	bar := o.Progress
	bar.Phases(4)

	bar.Phase("root DSE and schema", -1)
	wr.section("root-dse")
	wr.put(*rootEntry)
	c.RootDSE = 1
	wr.section("schema")
	if nc := first(rootEntry.Values("schemaNamingContext")); nc != "" {
		// Two searches, as the tool's own schema reads are (ad.ReadSchema): what it reads is then what it dumps.
		for _, class := range []string{"attributeSchema", "classSchema"} {
			if err := src.Walk(ctx, nc, "(objectClass="+class+")", []string{directory.AllAttrs}, func(e directory.Entry) error {
				if wr.put(e) {
					c.Schema++
				}
				return nil
			}); err != nil {
				return c, fmt.Errorf("read the schema: %w", err)
			}
		}
	} else if subschema != "" {
		e, err := src.Get(ctx, subschema, []string{"attributeTypes", "objectClasses"})
		if err != nil {
			return c, fmt.Errorf("read the schema: %w", err)
		}
		if e != nil && wr.put(*e) {
			c.Schema++
		}
	}
	configNC := first(rootEntry.Values("configurationNamingContext"))
	if configNC != "" {
		wr.section("configuration")
		if err := src.Walk(ctx, "CN=Partitions,"+configNC, "(objectClass=crossRef)", []string{directory.AllAttrs}, func(e directory.Entry) error {
			if wr.put(e) {
				c.Config++
			}
			return nil
		}); err != nil {
			return c, fmt.Errorf("read the partitions: %w", err)
		}
	}

	bar.Phase("the root and the parents of the base DN", -1)
	wr.section("base (" + o.BaseDN + ")")
	above := append([]string{root}, reverse(dn.Ancestors(o.BaseDN, root))...)
	for _, a := range above {
		n, err := wr.read(ctx, src, a, read, masker)
		if err != nil {
			return c, err
		}
		c.Base += n
	}

	bar.Phase("under the base DN", -1)
	outside := map[string]string{} // normalized DN -> DN of a value naming an entry outside the base
	if err := src.Walk(ctx, o.BaseDN, "(objectClass=*)", read, func(e directory.Entry) error {
		for name, values := range e.Attrs {
			base, _, _ := strings.Cut(name, ";")
			if !refs[strings.ToLower(base)] {
				continue
			}
			for _, v := range values {
				if d := dn.RefDN(v); !dn.Equal(d, o.BaseDN) && !dn.IsDescendant(d, o.BaseDN) {
					outside[dn.Normalize(d)] = d
				}
			}
		}
		if wr.put(masker.Apply(e)) {
			c.Base++
		}
		bar.Add(1)
		return nil
	}); err != nil {
		return c, fmt.Errorf("read %s: %w", o.BaseDN, err)
	}

	keys := make([]string, 0, len(outside))
	for k := range outside {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	bar.Phase("referenced outside the base DN", len(keys))
	wr.section("referenced")
	for _, k := range keys {
		v := outside[k]
		top := ""
		switch {
		case configNC != "" && (dn.Equal(v, configNC) || dn.IsDescendant(v, configNC)):
			top = configNC
		case dn.IsDescendant(v, root):
			top = root
		default:
			bar.Add(1)
			continue // another naming context, which clone does not read
		}
		for _, a := range append(reverse(dn.Ancestors(v, top)), v) {
			n, err := wr.read(ctx, src, a, read, masker)
			if err != nil {
				return c, err
			}
			c.Referenced += n
		}
		bar.Add(1)
	}
	if wr.err != nil {
		return c, wr.err // no end line: the file is not taken for a dump
	}
	fmt.Fprintf(w, "\n# end: %d entries (root-dse %d, schema %d, configuration %d, base %d, referenced %d)\n",
		c.Total(), c.RootDSE, c.Schema, c.Config, c.Base, c.Referenced)
	return c, nil
}

type writer struct {
	w        ldif.Writer
	excluded map[string]bool
	written  map[string]bool // normalized DNs
	err      error
}

func (wr *writer) header(o Options, prof profile.Profile, root string, operational []string, at time.Time) {
	w := wr.w.W
	fmt.Fprintln(w, ldifdir.Magic)
	fmt.Fprintf(w, "# version: %s\n", o.Version)
	fmt.Fprintf(w, "# dumped-at: %s\n", at.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "# server: %s\n", o.Server)
	fmt.Fprintf(w, "# profile: %s\n", prof.Name)
	fmt.Fprintf(w, "# base-dn: %s\n", o.BaseDN)
	fmt.Fprintf(w, "# root-dn: %s\n", root)
	if len(o.Masked) > 0 {
		fmt.Fprintf(w, "# masked (value: %s):\n", o.MaskValue)
		list(w, o.Masked)
	}
	fmt.Fprintln(w, "# excluded (credentials, never dumped):")
	list(w, prof.PasswordAttrs)
	if len(operational) > 0 {
		fmt.Fprintln(w, "# operational (read by name; \"*\" leaves them out):")
		list(w, operational)
	}
	fmt.Fprintln(w, "# referenced: the entries outside base-dn a reference names, and their parents, without what they name")
	fmt.Fprintln(w, "#")
}

func list(w io.Writer, names []string) {
	sorted := append([]string(nil), names...)
	sort.Slice(sorted, func(i, j int) bool { return strings.ToLower(sorted[i]) < strings.ToLower(sorted[j]) })
	for _, n := range sorted {
		fmt.Fprintf(w, "#   %s\n", n)
	}
}

func (wr *writer) section(name string) { fmt.Fprintf(wr.w.W, "\n# section: %s\n", name) }

// read writes the entry at entryDN unless it is written already or missing; it returns how many it wrote.
func (wr *writer) read(ctx context.Context, src directory.Directory, entryDN string, attrs []string, m mask.Masker) (int, error) {
	if wr.written[dn.Normalize(entryDN)] {
		return 0, nil
	}
	e, err := src.Get(ctx, entryDN, attrs)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", entryDN, err)
	}
	if e == nil {
		return 0, nil
	}
	if wr.put(m.Apply(*e)) {
		return 1, nil
	}
	return 0, nil
}

// put writes e once.
func (wr *writer) put(e directory.Entry) bool {
	key := dn.Normalize(e.DN)
	if wr.written[key] {
		return false
	}
	wr.written[key] = true
	wr.entry(e)
	return true
}

// entry writes e without the credentials, its attributes in name order, a range option dropped from a name (the
// values are all there).
func (wr *writer) entry(e directory.Entry) {
	w := wr.w.W
	fmt.Fprintln(w)
	fmt.Fprintln(w, ldif.Line("dn", e.DN))
	names := make([]string, 0, len(e.Attrs))
	for n := range e.Attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		base, _, _ := strings.Cut(n, ";")
		if wr.excluded[strings.ToLower(base)] {
			continue
		}
		for _, v := range e.Attrs[n] {
			if _, err := fmt.Fprintln(w, ldif.Line(base, v)); err != nil && wr.err == nil {
				wr.err = err
			}
		}
	}
}

func reverse(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
