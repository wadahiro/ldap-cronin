// Package ldifdir is a read-only directory over a dump (ldap-cronin dump): clone, diff and the rest read it as they
// read a server, so production is connected once, to take the dump, and never during a clone.
//
// Nothing of the entries is held in memory. A walk reads the file from the start each time, an entry at a time; a
// read of one entry goes straight to it through an index of where each starts (16 bytes an entry). A dump compressed
// with gzip is expanded to a temporary file first (readable by its owner only, removed by Close), as a compressed
// stream cannot be read from the middle. A dump without its end line, or with another count, is refused: a dump cut
// off by a broken connection or a full disk would otherwise clone some users and members and not the rest.
package ldifdir

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
)

// Magic is the first line of a dump.
const Magic = "# ldap-cronin dump"

// Meta is what the header of a dump says.
type Meta struct {
	Version, DumpedAt, Server, Profile, RootDN, MaskValue string
	// BaseDNs are the base DNs the dump was taken of (one "# base-dn:" line each).
	BaseDNs          []string
	Masked, Excluded []string
	// Operational are the attributes the dump read by name, which "*" does not return (entryUUID, ...).
	Operational []string
	Entries     int
	// Holders is whether the dump carries the groups outside its base DN that hold its entries (a dump taken
	// before they were carried does not).
	Holders bool
	// Credentials are the credentials the dump carries (dump -with-credentials).
	Credentials []string
}

// Dir is a dump opened for reading. It is safe for concurrent use: reads of single entries go through ReadAt.
type Dir struct {
	meta        Meta
	f           *os.File
	temp        string // the expanded copy of a compressed dump, removed by Close
	seed        maphash.Seed
	index       map[uint64][]int64 // hash of the normalized DN -> where its entries start (a collision lists both)
	operational map[string]bool
	// contexts are the normalized naming contexts of the root DSE, longest first: a search does not leave the one
	// its base is in, as a server's does not (a whole domain's search never returns the configuration partition).
	contexts []string
	match    *matcher
}

// Open reads the dump at path, gzip-compressed when it ends in .gz, and indexes it.
func Open(path string) (*Dir, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	d := &Dir{f: f, seed: maphash.MakeSeed(), index: map[uint64][]int64{}, operational: map[string]bool{}}
	if strings.HasSuffix(path, ".gz") {
		if err := d.expand(); err != nil {
			d.Close()
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if err := d.scan(); err != nil {
		d.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

// expand writes the uncompressed dump to a temporary file and reads that instead.
func (d *Dir) expand() error {
	z, err := gzip.NewReader(d.f)
	if err != nil {
		return err
	}
	defer z.Close()
	tmp, err := os.CreateTemp("", "ldap-cronin-dump-*.ldif")
	if err != nil {
		return err
	}
	d.temp = tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, z); err != nil {
		tmp.Close()
		return fmt.Errorf("expand to %s: %w", d.temp, err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		return err
	}
	d.f.Close()
	d.f = tmp
	return nil
}

// Close closes the file and removes the expanded copy of a compressed dump.
func (d *Dir) Close() {
	if d.f != nil {
		d.f.Close()
	}
	if d.temp != "" {
		os.Remove(d.temp)
	}
}

// scan reads the whole dump once: the header, the index, the classes' categories, the end line.
func (d *Dir) scan() error {
	end := -1
	var list *[]string
	n := 0
	categories := map[string]string{}
	err := d.records(0, func(at int64, lines []string) (bool, error) {
		e, err := parseEntry(lines)
		if err != nil {
			return false, err
		}
		h := d.key(e.DN)
		for _, prev := range d.index[h] {
			if other, err := d.readAt(prev); err == nil && dn.Equal(other.DN, e.DN) {
				return false, fmt.Errorf("%s is in the dump twice", e.DN)
			}
		}
		d.index[h] = append(d.index[h], at)
		n++
		if e.DN == "" {
			for _, nc := range e.Values("namingContexts") {
				d.contexts = append(d.contexts, dn.Normalize(nc))
			}
		}
		if hasClass(e, "classSchema") && len(e.Values("defaultObjectCategory")) > 0 {
			categories[strings.ToLower(first(e.Values("lDAPDisplayName")))] = dn.Normalize(first(e.Values("defaultObjectCategory")))
		}
		return true, nil
	}, func(line int, l string) error {
		if line == 1 && l != Magic {
			return errors.New("not a dump of ldap-cronin (its first line is not \"" + Magic + "\")")
		}
		switch {
		case strings.HasPrefix(l, "#   ") && list != nil:
			*list = append(*list, strings.TrimSpace(l[1:]))
		case strings.HasPrefix(l, "#"):
			list = d.header(strings.TrimSpace(strings.TrimPrefix(l, "#")), &end)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if end < 0 {
		return errors.New("the dump has no end line: it was cut off; dump again")
	}
	if end != n {
		return fmt.Errorf("the dump says %d entries and holds %d: dump again", end, n)
	}
	d.meta.Entries = end
	for _, a := range d.meta.Operational {
		d.operational[strings.ToLower(a)] = true
	}
	d.match = &matcher{categories: categories}
	sort.Slice(d.contexts, func(i, j int) bool { return len(d.contexts[i]) > len(d.contexts[j]) })
	return nil
}

// records reads the records from offset on, calling fn with where each starts and its lines (folded lines joined)
// until it returns false, and comment with each comment line and its number.
func (d *Dir) records(offset int64, fn func(at int64, lines []string) (bool, error), comment func(line int, l string) error) error {
	r := bufio.NewReaderSize(io.NewSectionReader(d.f, offset, 1<<62), 1<<16)
	pos := offset
	start := int64(-1)
	var lines []string
	line := 0
	flush := func() (bool, error) {
		if len(lines) == 0 {
			return true, nil
		}
		more, err := fn(start, lines)
		lines, start = lines[:0], -1
		return more, err
	}
	for {
		raw, err := r.ReadString('\n')
		if raw == "" && err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			_, ferr := flush()
			return ferr
		}
		at := pos
		pos += int64(len(raw))
		line++
		l := strings.TrimRight(raw, "\r\n")
		switch {
		case strings.HasPrefix(l, "#"):
			if comment != nil {
				if err := comment(line, l); err != nil {
					return err
				}
			}
		case l == "":
			if more, err := flush(); err != nil || !more {
				return err
			}
		case strings.HasPrefix(l, " ") && len(lines) > 0:
			lines[len(lines)-1] += l[1:]
		default:
			if comment != nil && line == 1 {
				if err := comment(line, l); err != nil {
					return err
				}
			}
			if start < 0 {
				start = at
			}
			lines = append(lines, l)
		}
	}
}

func (d *Dir) key(entryDN string) uint64 { return maphash.String(d.seed, dn.Normalize(entryDN)) }

// readAt parses the entry that starts at offset.
func (d *Dir) readAt(offset int64) (*directory.Entry, error) {
	var e *directory.Entry
	err := d.records(offset, func(_ int64, lines []string) (bool, error) {
		var err error
		e, err = parseEntry(lines)
		return false, err
	}, nil)
	return e, err
}

// header reads one header line; it returns the list the indented lines below it go to.
func (d *Dir) header(l string, end *int) *[]string {
	if rest, ok := strings.CutPrefix(l, "masked (value: "); ok {
		d.meta.MaskValue, _, _ = strings.Cut(rest, "):")
		return &d.meta.Masked
	}
	key, value, _ := strings.Cut(l, ":")
	value = strings.TrimSpace(value)
	switch {
	case key == "version":
		d.meta.Version = value
	case key == "dumped-at":
		d.meta.DumpedAt = value
	case key == "server":
		d.meta.Server = value
	case key == "profile":
		d.meta.Profile = value
	case key == "base-dn":
		d.meta.BaseDNs = append(d.meta.BaseDNs, value)
	case key == "root-dn":
		d.meta.RootDN = value
	case key == "holders":
		d.meta.Holders = true
	case strings.HasPrefix(key, "excluded"):
		return &d.meta.Excluded
	case strings.HasPrefix(key, "credentials"):
		return &d.meta.Credentials
	case strings.HasPrefix(key, "operational"):
		return &d.meta.Operational
	case key == "end":
		count, _, _ := strings.Cut(value, " ")
		if n, err := strconv.Atoi(count); err == nil {
			*end = n
		}
	}
	return nil
}

func parseEntry(lines []string) (*directory.Entry, error) {
	e := &directory.Entry{Attrs: map[string][]string{}}
	for i, l := range lines {
		name, value, err := field(l)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			if !strings.EqualFold(name, "dn") {
				return nil, fmt.Errorf("an entry starts with %q, not dn", l)
			}
			e.DN = value
			continue
		}
		e.Attrs[name] = append(e.Attrs[name], value)
	}
	return e, nil
}

func field(l string) (string, string, error) {
	name, v, ok := strings.Cut(l, ":")
	if !ok {
		return "", "", fmt.Errorf("not an LDIF line: %q", l)
	}
	if strings.HasPrefix(v, ":") {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[1:]))
		if err != nil {
			return "", "", fmt.Errorf("%s: %w", name, err)
		}
		return name, string(b), nil
	}
	return name, strings.TrimPrefix(v, " "), nil
}

// Meta returns what the header says.
func (d *Dir) Meta() Meta { return d.meta }

func (d *Dir) Get(ctx context.Context, entryDN string, attrs []string) (*directory.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, at := range d.index[d.key(entryDN)] {
		e, err := d.readAt(at)
		if err != nil {
			return nil, err
		}
		if dn.Equal(e.DN, entryDN) {
			p := d.project(e, attrs)
			return &p, nil
		}
	}
	return nil, nil
}

// Walk streams the entries at base and below that match filter, in the dump's order, reading the file through. The
// root DSE is not under any base but its own.
func (d *Dir) Walk(ctx context.Context, base, filter string, attrs []string, fn func(directory.Entry) error) error {
	f, err := d.match.compile(filter)
	if err != nil {
		return err
	}
	baseKey := dn.Normalize(base)
	baseNC := d.contextOf(baseKey)
	return d.records(0, func(_ int64, lines []string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		e, err := parseEntry(lines)
		if err != nil {
			return false, err
		}
		key := dn.Normalize(e.DN)
		if (key == "" && baseKey != "") || (key != baseKey && baseKey != "" && !strings.HasSuffix(key, ","+baseKey)) {
			return true, nil
		}
		if baseNC != "" && d.contextOf(key) != baseNC {
			return true, nil // in another naming context below the base (CN=Configuration under the domain)
		}
		if !d.match.match(f, e) {
			return true, nil
		}
		return true, fn(d.project(e, attrs))
	}, nil)
}

// contextOf is the naming context key (normalized) is in, "" for none the dump knows.
func (d *Dir) contextOf(key string) string {
	for _, nc := range d.contexts {
		if key == nc || strings.HasSuffix(key, ","+nc) {
			return nc
		}
	}
	return ""
}

// project returns the attributes asked for as a server does: "*" every one but the operational ones the dump read
// by name, which come only when named; "1.1" none. A named attribute is keyed by the name as asked.
func (d *Dir) project(e *directory.Entry, attrs []string) directory.Entry {
	out := directory.Entry{DN: e.DN, Attrs: map[string][]string{}}
	all := false
	for _, a := range attrs {
		if a == directory.AllAttrs {
			all = true
		}
	}
	if all {
		for n, v := range e.Attrs {
			if !d.operational[strings.ToLower(n)] {
				out.Attrs[n] = v
			}
		}
	}
	for _, a := range attrs {
		if a == directory.AllAttrs || a == directory.NoAttrs {
			continue
		}
		for n, v := range e.Attrs {
			if strings.EqualFold(n, a) {
				if all && !d.operational[strings.ToLower(n)] {
					delete(out.Attrs, n)
				}
				out.Attrs[a] = v
			}
		}
	}
	return out
}

func (d *Dir) Add(context.Context, directory.Entry, ...directory.Control) error {
	return fmt.Errorf("a dump: %w", directory.ErrReadOnly)
}

func (d *Dir) Replace(context.Context, string, map[string][]string) error {
	return fmt.Errorf("a dump: %w", directory.ErrReadOnly)
}

func (d *Dir) AddValues(context.Context, string, string, []string) error {
	return fmt.Errorf("a dump: %w", directory.ErrReadOnly)
}

// View returns d: a dump holds every value of an attribute, so no range is ever asked for.
func (d *Dir) View([]string) directory.Directory { return d }

func hasClass(e *directory.Entry, class string) bool {
	for _, c := range e.Values("objectClass") {
		if strings.EqualFold(c, class) {
			return true
		}
	}
	return false
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

var _ directory.Directory = (*Dir)(nil)
