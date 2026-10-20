// Package fakedir is an in-memory Directory for tests. Like a real LDAP server, it rejects an Add whose parent is missing.
package fakedir

import (
	"context"
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
	// Relax is the OID of a control that lets an Add set Operational attributes, like OpenLDAP's relax control.
	// Empty: such a control, sent as critical, is refused as unsupported. An Add that sets an Operational attribute
	// without it is refused, as a real server does.
	Relax string
	// RelaxDenied refuses the Relax control for lack of rights (OpenLDAP without manage access).
	RelaxDenied bool
	// IDPrefix is the first byte of the identifiers this fake assigns, so two fakes standing for two servers never
	// hand out the same one (real identifiers are globally unique).
	IDPrefix byte
	nextGUID uint64
}

// Operational are the attributes an Add may set only with the Relax control.
var Operational = []string{"entryUUID", "createTimestamp", "modifyTimestamp", "creatorsName", "modifiersName"}

// assignGUID gives an entry the identifiers a real server assigns: objectGUID (16 raw bytes, as AD) and entryUUID
// (the same 16 bytes as text, as RFC 4530 servers). One fake serves both profiles; each reads only its own attribute.
// An entry that brings its own objectGUID (a native import) or entryUUID (an Add with relax) keeps it, and gets the
// other one from the same bytes.
func (d *Dir) assignGUID(attrs map[string][]string) {
	var b []byte
	e := directory.Entry{Attrs: attrs}
	if v := e.Values("objectGUID"); len(v) > 0 { // objectGUID wins: a test that replaces it means a new object
		b = []byte(v[0])
	} else if v := e.Values("entryUUID"); len(v) > 0 {
		if raw, err := hex.DecodeString(strings.ReplaceAll(v[0], "-", "")); err == nil && len(raw) == 16 {
			b = raw
		}
	}
	if b == nil {
		d.nextGUID++
		b = make([]byte, 16)
		for i := 0; i < 8; i++ {
			b[15-i] = byte(d.nextGUID >> (8 * i))
		}
		b[0] = d.IDPrefix
	}
	for n := range attrs {
		if strings.EqualFold(n, "objectGUID") || strings.EqualFold(n, "entryUUID") {
			delete(attrs, n)
		}
	}
	h := hex.EncodeToString(b)
	attrs["objectGUID"] = []string{string(b)}
	attrs["entryUUID"] = []string{h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]}
}

// checkControls applies the rules of the Relax control to an Add.
func (d *Dir) checkControls(e directory.Entry, controls []directory.Control) error {
	relax := false
	for _, c := range controls {
		switch {
		case d.Relax != "" && c.OID == d.Relax:
			if d.RelaxDenied {
				return fmt.Errorf("add %s: %w (no write access to entry)", e.DN, directory.ErrInsufficientAccess)
			}
			relax = true
		case c.Critical:
			return fmt.Errorf("add %s: %w (%s)", e.DN, directory.ErrControlUnsupported, c.OID)
		}
	}
	if relax {
		return nil
	}
	for _, a := range Operational {
		if len(e.Values(a)) > 0 {
			return fmt.Errorf("add %s: %s: no user modification allowed", e.DN, a)
		}
	}
	return nil
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

// Snapshot copies the entries, like a lab snapshot.
func (d *Dir) Snapshot() map[string]*directory.Entry {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]*directory.Entry, len(d.Entries))
	for k, e := range d.Entries {
		out[k] = &directory.Entry{DN: e.DN, Attrs: clone(e.Attrs)}
	}
	return out
}

// Restore puts back the entries of a Snapshot. Identifiers assigned since are never handed out again, as on a real
// server, whose identifiers are unique whatever its data was rewound to.
func (d *Dir) Restore(entries map[string]*directory.Entry) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Entries = make(map[string]*directory.Entry, len(entries))
	for k, e := range entries {
		d.Entries[k] = &directory.Entry{DN: e.DN, Attrs: clone(e.Attrs)}
	}
}

func (d *Dir) Lookup(dnStr string) *directory.Entry {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Entries[dn.Normalize(dnStr)]
}

// Walk collects the matching DNs first and hands them to fn one at a time, so a large data set is never copied wholesale.
func (d *Dir) Walk(ctx context.Context, base, filter string, attrs []string, fn func(directory.Entry) error) error {
	d.mu.Lock()
	var keys []string
	for k, e := range d.Entries {
		if (dn.Equal(e.DN, base) || dn.IsDescendant(e.DN, base)) && matches(*e, filter) {
			keys = append(keys, k)
		}
	}
	d.mu.Unlock()
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
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

func (d *Dir) Get(ctx context.Context, dnStr string, attrs []string) (*directory.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.Entries[dn.Normalize(dnStr)]
	if !ok {
		return nil, nil
	}
	p := project(*e, attrs)
	return &p, nil
}

func (d *Dir) Add(ctx context.Context, e directory.Entry, controls ...directory.Control) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	if err := d.checkControls(e, controls); err != nil {
		return err
	}
	added := &directory.Entry{DN: e.DN, Attrs: clone(e.Attrs)}
	d.assignGUID(added.Attrs)
	if isADUser(*added) {
		// AD creates a user without a password with pwdLastSet=0; setting unicodePwd makes it nonzero.
		added.Attrs["pwdLastSet"] = []string{"0"}
	}
	d.Entries[key] = added
	d.Ops = append(d.Ops, "add "+e.DN)
	return nil
}

// principals turns <SID=...> values into the DN of a foreign security principal, creating it, as a DC does when a
// member is added by SID.
func (d *Dir) principals(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		sid, ok := strings.CutPrefix(v, "<SID=")
		if !ok || len(d.roots) == 0 {
			out = append(out, v)
			continue
		}
		sid = strings.TrimSuffix(sid, ">")
		parent := "CN=ForeignSecurityPrincipals," + d.roots[0]
		if _, ok := d.Entries[dn.Normalize(parent)]; !ok {
			d.Entries[dn.Normalize(parent)] = &directory.Entry{DN: parent, Attrs: map[string][]string{"objectClass": {"top", "container"}}}
		}
		p := "CN=" + sid + "," + parent
		if _, ok := d.Entries[dn.Normalize(p)]; !ok {
			attrs := map[string][]string{"objectClass": {"top", "foreignSecurityPrincipal"}, "cn": {sid}}
			d.assignGUID(attrs)
			d.Entries[dn.Normalize(p)] = &directory.Entry{DN: p, Attrs: attrs}
		}
		out = append(out, p)
	}
	return out
}

func (d *Dir) Replace(ctx context.Context, dnStr string, attrs map[string][]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
		e.Attrs[n] = d.principals(v)
		d.Ops = append(d.Ops, "replace "+n+" "+dnStr)
		if strings.EqualFold(n, "unicodePwd") && isADUser(*e) {
			e.Attrs["pwdLastSet"] = []string{"133000000000000000"}
		}
	}
	return nil
}

// isADUser reports whether e is an AD user account (objectClass user), whose password state the fake keeps as AD does.
func isADUser(e directory.Entry) bool {
	for _, c := range e.Values("objectClass") {
		if strings.EqualFold(c, "user") {
			return true
		}
	}
	return false
}

func (d *Dir) AddValues(ctx context.Context, dnStr, attr string, values []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if dnStr == "" && strings.EqualFold(attr, "schemaUpdateNow") {
		// AD's request to reload the schema cache: an operation, not a value the root DSE keeps.
		d.Ops = append(d.Ops, "schemaUpdateNow")
		return nil
	}
	e, ok := d.Entries[dn.Normalize(dnStr)]
	if !ok {
		return fmt.Errorf("modify %s: no such object", dnStr)
	}
	values = d.principals(values)
	if err := d.checkRefs(dnStr, map[string][]string{attr: values}); err != nil {
		return err
	}
	// A real server refuses to add a value that is already there (attributeOrValueExists).
	have := map[string]bool{}
	for _, v := range e.Values(attr) {
		have[dn.Normalize(v)] = true
	}
	for _, v := range values {
		if have[dn.Normalize(v)] {
			return fmt.Errorf("modify %s: %s value %s already exists", dnStr, attr, v)
		}
		have[dn.Normalize(v)] = true
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
		if a == directory.AllAttrs {
			for n, v := range e.Attrs {
				out.Attrs[n] = append([]string(nil), v...)
			}
			continue
		}
		if v := e.Values(a); len(v) > 0 {
			out.Attrs[a] = append([]string(nil), v...)
		}
	}
	return out
}

// matches interprets only the filters clone uses (objectClass and objectCategory=person), and a single equality
// on any other attribute (identifiers, markers).
func matches(e directory.Entry, filter string) bool {
	classes := strings.ToLower(strings.Join(e.Values("objectClass"), ","))
	lower := strings.ToLower(filter)
	switch {
	case strings.HasPrefix(filter, "(!(|") && strings.HasSuffix(filter, ")"):
		// The negation of the kinds' filters (plan.Unselected).
		return !matches(e, filter[2:len(filter)-1])
	case strings.HasPrefix(filter, "(|(&"):
		for _, f := range terms(filter[2 : len(filter)-1]) {
			if matches(e, f) {
				return true
			}
		}
		return false
	case strings.HasPrefix(filter, "(|(") && !strings.Contains(lower, "objectclass=") && !strings.Contains(lower, "objectcategory="):
		// An OR of equality filters, as a mapping file builds for an object cloned more than once.
		for _, f := range strings.SplitAfter(strings.TrimSuffix(strings.TrimPrefix(filter, "(|"), ")"), ")") {
			if f != "" && equalityMatches(e, f) {
				return true
			}
		}
		return false
	case strings.Count(filter, "(") == 1 && !strings.HasPrefix(lower, "(objectclass=") && !strings.HasPrefix(lower, "(objectcategory="):
		return equalityMatches(e, filter)
	case strings.Contains(filter, "attributeSchema"):
		return strings.Contains(classes, "attributeschema")
	case strings.Contains(filter, "classSchema"):
		return strings.Contains(classes, "classschema")
	case strings.Contains(filter, "groupOfNames"):
		return strings.Contains(classes, "groupofnames") || strings.Contains(classes, "groupofuniquenames") || strings.Contains(classes, "posixgroup")
	case strings.Contains(filter, "inetOrgPerson"):
		return strings.Contains(classes, "inetorgperson")
	case strings.Contains(filter, "organizationalUnit"):
		return strings.Contains(classes, "organizationalunit")
	case strings.Contains(filter, "objectCategory=computer"):
		return strings.Contains(classes, "computer")
	case strings.Contains(filter, "objectClass=contact"):
		return strings.Contains(classes, "contact")
	case strings.Contains(filter, "objectCategory=person"):
		return strings.Contains(classes, "user") && !strings.Contains(classes, "computer")
	case strings.Contains(filter, "objectClass=group"):
		return strings.Contains(classes, "group")
	}
	return true
}

// terms splits a run of parenthesized filters into its top-level terms.
func terms(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, c := range s {
		switch c {
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				out = append(out, s[start:i+1])
			}
		}
	}
	return out
}

func clone(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = append([]string(nil), v...)
	}
	return out
}

var _ directory.Directory = (*Dir)(nil)

// equalityMatches interprets a single equality filter "(attr=value)" with RFC 4515 escapes (\ab), the form the
// identifier schemes build: escaped raw bytes for objectGUID, plain text for entryUUID. Escaped values are compared
// byte for byte (folding case would make two different GUIDs equal); plain text ignores case, as entryUUID matching does.
func equalityMatches(e directory.Entry, filter string) bool {
	name, value, ok := strings.Cut(strings.TrimSuffix(strings.TrimPrefix(filter, "("), ")"), "=")
	if !ok {
		return false
	}
	var raw []byte
	escaped := false
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+2 < len(value) {
			b, err := hex.DecodeString(value[i+1 : i+3])
			if err != nil {
				return false
			}
			raw, escaped = append(raw, b...), true
			i += 2
			continue
		}
		raw = append(raw, value[i])
	}
	for _, v := range e.Values(name) {
		if v == string(raw) || (!escaped && strings.EqualFold(v, string(raw))) {
			return true
		}
	}
	return false
}
