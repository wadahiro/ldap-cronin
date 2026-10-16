// Package fakedir is an in-memory Directory for tests. Like a real LDAP server, it rejects an Add whose parent is missing.
package fakedir

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
)

type Dir struct {
	mu      sync.Mutex
	Entries map[string]*directory.Entry // key: dn.Normalize
	Ops     []string                    // log of write operations ("add <dn>", etc.)
	roots   []string
	// Attributes in StrictRefs make Add/Replace/AddValues fail unless the referenced DN exists (like link attributes on real AD/Samba).
	StrictRefs []string
	// RequireAttr maps a lowercase objectClass to an attribute that Add must carry (e.g. groupofnames -> member),
	// like a real server enforcing the schema's MUST list. Add then returns directory.ErrSchemaViolation.
	RequireAttr map[string]string
	nextGUID    uint64
}

// assignGUID gives an entry without an objectGUID a unique GUID (16 raw bytes), as a real server does.
func (d *Dir) assignGUID(attrs map[string][]string) {
	for n := range attrs {
		if strings.EqualFold(n, "objectGUID") {
			return
		}
	}
	d.nextGUID++
	b := make([]byte, 16)
	for i := 0; i < 8; i++ {
		b[15-i] = byte(d.nextGUID >> (8 * i))
	}
	attrs["objectGUID"] = []string{string(b)}
}

// New returns an empty directory holding roots (DNs that already exist as parents, such as the domain root).
func New(roots ...string) *Dir { return &Dir{Entries: map[string]*directory.Entry{}, roots: roots} }

func (d *Dir) Put(dnStr string, attrs map[string][]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e := &directory.Entry{DN: dnStr, Attrs: clone(attrs)}
	d.assignGUID(e.Attrs)
	d.Entries[dn.Normalize(dnStr)] = e
}

func (d *Dir) Delete(dnStr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.Entries, dn.Normalize(dnStr))
}

func (d *Dir) Lookup(dnStr string) *directory.Entry {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Entries[dn.Normalize(dnStr)]
}

// Walk collects the matching DNs first and hands them to fn one at a time, so a large data set is never copied wholesale.
func (d *Dir) Walk(base, filter string, attrs []string, fn func(directory.Entry) error) error {
	d.mu.Lock()
	var keys []string
	for k, e := range d.Entries {
		if (dn.Equal(e.DN, base) || dn.IsDescendant(e.DN, base)) && matches(*e, filter) {
			keys = append(keys, k)
		}
	}
	d.mu.Unlock()
	for _, k := range keys {
		d.mu.Lock()
		e, ok := d.Entries[k]
		var p directory.Entry
		if ok {
			p = project(*e, attrs)
		}
		d.mu.Unlock()
		if !ok {
			continue
		}
		if err := fn(p); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dir) Get(dnStr string, attrs []string) (*directory.Entry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.Entries[dn.Normalize(dnStr)]
	if !ok {
		return nil, nil
	}
	p := project(*e, attrs)
	return &p, nil
}

func (d *Dir) Add(e directory.Entry) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := dn.Normalize(e.DN)
	if _, ok := d.Entries[key]; ok {
		return directory.ErrExists
	}
	parent := dn.Parent(e.DN)
	if _, ok := d.Entries[dn.Normalize(parent)]; !ok && !d.isRoot(parent) {
		return fmt.Errorf("add %s: parent %s does not exist", e.DN, parent)
	}
	if err := d.checkRefs(e.DN, e.Attrs); err != nil {
		return err
	}
	if err := d.checkRequired(e); err != nil {
		return err
	}
	added := &directory.Entry{DN: e.DN, Attrs: clone(e.Attrs)}
	d.assignGUID(added.Attrs)
	d.Entries[key] = added
	d.Ops = append(d.Ops, "add "+e.DN)
	return nil
}

func (d *Dir) Replace(dnStr string, attrs map[string][]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.Entries[dn.Normalize(dnStr)]
	if !ok {
		return fmt.Errorf("modify %s: no such object", dnStr)
	}
	if err := d.checkRefs(dnStr, attrs); err != nil {
		return err
	}
	for n, v := range attrs {
		e.Attrs[n] = append([]string(nil), v...)
		d.Ops = append(d.Ops, "replace "+n+" "+dnStr)
	}
	return nil
}

func (d *Dir) AddValues(dnStr, attr string, values []string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.Entries[dn.Normalize(dnStr)]
	if !ok {
		return fmt.Errorf("modify %s: no such object", dnStr)
	}
	if err := d.checkRefs(dnStr, map[string][]string{attr: values}); err != nil {
		return err
	}
	e.Attrs[attr] = append(e.Attrs[attr], values...)
	d.Ops = append(d.Ops, "addvalues "+attr+" "+dnStr)
	return nil
}

func (d *Dir) checkRefs(entryDN string, attrs map[string][]string) error {
	for n, values := range attrs {
		strict := false
		for _, s := range d.StrictRefs {
			strict = strict || strings.EqualFold(s, n)
		}
		if !strict {
			continue
		}
		for _, v := range values {
			if _, ok := d.Entries[dn.Normalize(v)]; !ok {
				return fmt.Errorf("%s: %s=%s: referenced object not found", entryDN, n, v)
			}
		}
	}
	return nil
}

func (d *Dir) checkRequired(e directory.Entry) error {
	for _, class := range e.Values("objectClass") {
		if must, ok := d.RequireAttr[strings.ToLower(class)]; ok && len(e.Values(must)) == 0 {
			return fmt.Errorf("add %s: %w (%s requires %s)", e.DN, directory.ErrSchemaViolation, class, must)
		}
	}
	return nil
}

func (d *Dir) isRoot(s string) bool {
	for _, r := range d.roots {
		if dn.Equal(r, s) {
			return true
		}
	}
	return false
}

func project(e directory.Entry, attrs []string) directory.Entry {
	out := directory.Entry{DN: e.DN, Attrs: map[string][]string{}}
	for _, a := range attrs {
		if v := e.Values(a); len(v) > 0 {
			out.Attrs[a] = append([]string(nil), v...)
		}
	}
	return out
}

// matches interprets only the filters clone uses (objectClass and objectCategory=person).
func matches(e directory.Entry, filter string) bool {
	classes := strings.ToLower(strings.Join(e.Values("objectClass"), ","))
	switch {
	case strings.HasPrefix(filter, "(objectGUID="):
		return guidFilterMatches(e, filter)
	case strings.Contains(filter, "attributeSchema"):
		return strings.Contains(classes, "attributeschema")
	case strings.Contains(filter, "groupOfNames"):
		return strings.Contains(classes, "groupofnames") || strings.Contains(classes, "groupofuniquenames") || strings.Contains(classes, "posixgroup")
	case strings.Contains(filter, "inetOrgPerson"):
		return strings.Contains(classes, "inetorgperson")
	case strings.Contains(filter, "organizationalUnit"):
		return strings.Contains(classes, "organizationalunit")
	case strings.Contains(filter, "objectCategory=person"):
		return strings.Contains(classes, "user") && !strings.Contains(classes, "computer")
	case strings.Contains(filter, "objectClass=group"):
		return strings.Contains(classes, "group")
	}
	return true
}

func clone(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = append([]string(nil), v...)
	}
	return out
}

var _ directory.Directory = (*Dir)(nil)

// guidFilterMatches interprets a filter of the form "(objectGUID=\\ab\\cd...)".
func guidFilterMatches(e directory.Entry, filter string) bool {
	hexed := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(filter, "(objectGUID="), ")"), `\`, "")
	raw, err := hex.DecodeString(hexed)
	if err != nil {
		return false
	}
	v := e.Values("objectGUID")
	return len(v) == 1 && v[0] == string(raw)
}
