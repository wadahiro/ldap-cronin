// Package clone adds and updates the target objects of the clone source on the target.
//
// The order is "parent OUs -> groups and users -> DN reference attributes (member/manager/managedBy)".
// References must be applied only after every referenced object exists; otherwise they fail depending on creation order.
package clone

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"

	"github.com/wadahiro/ldap-cronin/internal/attrs"
	"github.com/wadahiro/ldap-cronin/internal/compare"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/guidmap"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/workpool"
)

const (
	attrUAC          = "userAccountControl"
	attrPwd          = "unicodePwd"
	attrUserPassword = "userPassword"
	attrPwdLastSet   = "pwdLastSet"
	// Number of members added per modify. Chosen so one AD operation stays within its limit.
	memberChunk = 500
)

type Options struct {
	Plan         plan.Options
	UserPassword string
	Workers      int // sequential if 1 or less
	// If GUIDMap is set, the GUID mapping between source and target is recorded (so diff can detect renames and moves).
	GUIDMap *guidmap.Map
}

// maxWarnings caps the warnings kept and shown, so that a flood of out-of-scope reference targets does not exhaust memory with warnings.
const maxWarnings = 1000

type Report struct {
	Added, Updated, Unchanged int
	WarningCount              int
	Warnings                  []string // first maxWarnings only
}

type runner struct {
	dst  directory.Directory
	opt  Options
	out  io.Writer
	plan *plan.Plan

	mu     sync.Mutex // guards report and out
	report Report
}

func Run(src, dst directory.Directory, opt Options, out io.Writer) (*Report, error) {
	p, err := plan.Build(src, opt.Plan)
	if err != nil {
		return nil, err
	}
	r := &runner{dst: dst, opt: opt, out: out}
	if err := r.run(p); err != nil {
		return &r.report, err
	}
	return &r.report, nil
}

func (r *runner) run(p *plan.Plan) error {
	r.plan = p
	if err := r.structure(p); err != nil {
		return err
	}
	// Groups and users do not depend on each other (references come later), so they can be applied in parallel while reading.
	for _, kind := range r.opt.Plan.P().LeafOrder {
		if !r.opt.Plan.Enabled(kind) {
			continue
		}
		if err := r.leaves(p, kind); err != nil {
			return err
		}
	}
	return r.references(p)
}

// leaves reads entries of kind from the source page by page and applies them with workers as the upper bound.
// A slow write makes the reader wait, so no more than workers unprocessed entries are held in memory.
func (r *runner) leaves(p *plan.Plan, kind string) error {
	return workpool.Feed(r.opt.Workers, func(emit func(directory.Entry) error) error {
		return p.Walk(kind, r.opt.Plan.Attrs[kind], emit)
	}, func(e directory.Entry) error {
		if kind != attrs.KindUser {
			created, cur, err := r.upsert(e, r.guidAttr()...)
			if err != nil {
				return err
			}
			return r.track(e, created, cur)
		}
		// A new creation needs no read of the target. Only for an existing entry, UAC and pwdLastSet piggyback on the read used for diffing.
		created, cur, err := r.upsert(e, append([]string{attrUAC, attrPwdLastSet}, r.guidAttr()...)...)
		if err != nil {
			return err
		}
		if err := r.track(e, created, cur); err != nil {
			return err
		}
		return r.finishUser(e, created, cur)
	})
}

type structItem struct {
	entry      directory.Entry
	createOnly bool // parent container; left untouched if it already exists on the target
}

// structure creates parents (including non-OU CN= containers) and OUs, shallowest first.
// A parent can hang under an OU, so both are processed together ordered by depth.
// Entries at the same depth are independent and run in parallel, waiting at each depth boundary.
func (r *runner) structure(p *plan.Plan) error {
	var items []structItem
	for _, a := range p.Ancestors {
		items = append(items, structItem{a, true})
	}
	for _, o := range p.OUs {
		items = append(items, structItem{o, false})
	}
	sort.SliceStable(items, func(i, j int) bool { return dn.Depth(items[i].entry.DN) < dn.Depth(items[j].entry.DN) })
	for len(items) > 0 {
		depth := dn.Depth(items[0].entry.DN)
		n := 0
		for n < len(items) && dn.Depth(items[n].entry.DN) == depth {
			n++
		}
		if err := workpool.Each(r.opt.Workers, items[:n], r.ensure); err != nil {
			return err
		}
		items = items[n:]
	}
	return nil
}

func (r *runner) ensure(it structItem) error {
	if !it.createOnly {
		created, cur, err := r.upsert(it.entry, r.guidAttr()...)
		if err != nil {
			return err
		}
		return r.track(it.entry, created, cur)
	}
	// Existing containers on the target (CN=Users, etc.) are left untouched.
	cur, err := r.dst.Get(it.entry.DN, append([]string{"objectClass"}, r.guidAttr()...))
	if err != nil {
		return err
	}
	if cur != nil {
		return r.track(it.entry, false, cur)
	}
	if err := r.dst.Add(r.withoutDeferred(it.entry)); err != nil {
		return fmt.Errorf("add parent %s: %w", it.entry.DN, err)
	}
	r.count(func(rep *Report) { rep.Added++ })
	r.logf("add    %s\n", it.entry.DN)
	return r.track(it.entry, true, nil)
}

// upsert performs an add (created=true) or an update of only the attributes that differ.
// For an existing entry it returns the current target values (read for diffing) in cur.
// extra lists attributes to include in the same read, so the caller needs no additional Get.
func (r *runner) upsert(e directory.Entry, extra ...string) (created bool, cur *directory.Entry, err error) {
	desired := r.withoutDeferred(e)
	delete(desired.Attrs, attrUAC) // finalized after the password is set
	err = r.dst.Add(desired)
	if errors.Is(err, directory.ErrSchemaViolation) {
		// A group class such as groupOfNames requires a member at creation, which the deferred reference pass cannot give.
		// Retrying with the in-scope references keeps the common case (AD, where nothing is required) on the cheaper path.
		if withRefs := r.withScopedRefs(e, desired); len(withRefs.Attrs) > len(desired.Attrs) {
			err = r.dst.Add(withRefs)
		}
	}
	if err == nil {
		r.count(func(rep *Report) { rep.Added++ })
		r.logf("add    %s\n", e.DN)
		return true, nil, nil
	}
	if !errors.Is(err, directory.ErrExists) {
		return false, nil, fmt.Errorf("add %s: %w", e.DN, err)
	}
	names := make([]string, 0, len(desired.Attrs))
	for n := range desired.Attrs {
		names = append(names, n)
	}
	cur, err = r.dst.Get(e.DN, append(names, extra...))
	if err != nil {
		return false, nil, err
	}
	if r.opt.Plan.KeepIdentity {
		if err := checkIdentity(e.DN, desired, cur); err != nil {
			return false, nil, err
		}
	}
	changes := map[string][]string{}
	for n, want := range desired.Attrs {
		// objectClass and the RDN attribute cannot be changed (or changing them is pointless).
		if strings.EqualFold(n, "objectClass") || isRDNAttr(e.DN, n) {
			continue
		}
		// objectGUID and objectSid can be specified only at creation. The check above has confirmed they are the same values.
		if isIdentityAttr(n) {
			continue
		}
		if cur != nil && r.plan.Equal(n, want, cur.Values(n)) {
			continue
		}
		changes[n] = want
	}
	if len(changes) == 0 {
		r.count(func(rep *Report) { rep.Unchanged++ })
		return false, cur, nil
	}
	if err := r.dst.Replace(e.DN, changes); err != nil {
		return false, nil, err
	}
	r.count(func(rep *Report) { rep.Updated++ })
	r.logf("update %s\n", e.DN)
	return false, cur, nil
}

// withScopedRefs returns desired plus the DN reference values of e that point into the plan's scope.
func (r *runner) withScopedRefs(e, desired directory.Entry) directory.Entry {
	out := directory.Entry{DN: desired.DN, Attrs: make(map[string][]string, len(desired.Attrs)+1)}
	for n, v := range desired.Attrs {
		out.Attrs[n] = v
	}
	for n, values := range e.Attrs {
		if !r.plan.IsRef(n) {
			continue
		}
		var inScope []string
		for _, v := range values {
			if r.plan.Scope.Has(v) {
				inScope = append(inScope, v)
			}
		}
		if len(inScope) > 0 {
			out.Attrs[n] = inScope
		}
	}
	return out
}

// guidAttr is the attribute to include in the target read when recording the mapping or preserving objectGUID.
func (r *runner) guidAttr() []string {
	if r.opt.GUIDMap == nil && !r.opt.Plan.KeepIdentity {
		return nil
	}
	return []string{r.opt.Plan.IDAttr()}
}

// track records the GUID mapping between source and target. The target GUID is the value read for diffing if the entry exists,
// or is read right after the add for a new one (the add response does not include the GUID).
func (r *runner) track(e directory.Entry, created bool, cur *directory.Entry) error {
	if r.opt.GUIDMap == nil {
		return nil
	}
	idAttr := r.opt.Plan.IDAttr()
	source := guidmap.Hex(first(e.Values(idAttr)))
	if source == "" {
		return nil
	}
	if cur == nil {
		var err error
		if cur, err = r.dst.Get(e.DN, []string{idAttr}); err != nil {
			return err
		}
	}
	if cur == nil {
		return nil
	}
	return r.opt.GUIDMap.Record(source, guidmap.Hex(first(cur.Values(idAttr))))
}

func isIdentityAttr(name string) bool {
	return strings.EqualFold(name, plan.GUIDAttr) || strings.EqualFold(name, plan.SIDAttr)
}

// checkIdentity verifies that an existing target object has the same objectGUID as the source.
// If it differs, it is a different object, so fail instead of falling back to an update (that would overwrite someone else at the same DN).
func checkIdentity(entryDN string, desired directory.Entry, cur *directory.Entry) error {
	if cur == nil {
		return nil
	}
	want, got := first(desired.Values(plan.GUIDAttr)), first(cur.Values(plan.GUIDAttr))
	if want != "" && got != want {
		return fmt.Errorf("%s already exists on the target but its objectGUID differs from the source (a different object); objectGUID cannot be changed later, so rebuild the target", entryDN)
	}
	return nil
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// finishUser finalizes the password first, then userAccountControl.
// Applying disabled or never-expires first changes the preconditions of setting the password,
// and a real AD refuses to create a user with UAC=512 and no password.
//
// Sending unicodePwd and UAC together in the add to do it in one step was rejected. Samba accepts it, but
// Microsoft specifies that unicodePwd "can only be modified, not added at object creation"
// (KB 269190 / MS-ADTS unicodePwd). An implementation that works only on Samba would fail on a real AD.
// Measurements also showed no speed difference on Samba from combining them (still about 105 s for 1600 users).
//
// So that a re-run does not roll back the password of an existing user, the password is set only on creation,
// or when creation was interrupted before the password was set (pwdLastSet=0).
func (r *runner) finishUser(e directory.Entry, created bool, cur *directory.Entry) error {
	if r.opt.UserPassword != "" && (created || (cur != nil && isUnset(cur.Values(attrPwdLastSet)))) {
		if err := r.setPassword(e.DN); err != nil {
			return err
		}
	}
	want := e.Values(attrUAC)
	if len(want) == 0 {
		return nil
	}
	uac := compare.SanitizeUAC(want[0])
	if !created && cur != nil && compare.Equal(attrUAC, cur.Values(attrUAC), []string{uac}) {
		return nil
	}
	if err := r.dst.Replace(e.DN, map[string][]string{attrUAC: {uac}}); err != nil {
		return err
	}
	if !created {
		r.count(func(rep *Report) { rep.Updated++ })
		r.logf("update %s (userAccountControl)\n", e.DN)
	}
	return nil
}

// setPassword sets the fixed password the way the profile's server expects it.
func (r *runner) setPassword(entryDN string) error {
	if r.opt.Plan.P().Password == profile.PasswordUserPassword {
		// The plain value is sent and the server hashes it with its configured scheme. The password modify extended
		// operation (RFC 3062) was rejected: not every server enables it, and a modify works everywhere.
		if err := r.dst.Replace(entryDN, map[string][]string{attrUserPassword: {r.opt.UserPassword}}); err != nil {
			return fmt.Errorf("set password (the password must satisfy the target's password policy): %w", err)
		}
		return nil
	}
	if err := r.dst.Replace(entryDN, map[string][]string{attrPwd: {EncodePassword(r.opt.UserPassword)}}); err != nil {
		return fmt.Errorf("set password (LDAPS is required; the password must also satisfy the target's password policy): %w", err)
	}
	return nil
}

func isUnset(values []string) bool { return len(values) == 1 && values[0] == "0" }

// Upper bound of the existence-check cache that avoids querying out-of-scope reference targets every time. Beyond it, nothing more is recorded.
const existsCacheLimit = 100_000

// references re-reads only the DN reference attributes from the source and applies them once all objects exist.
// Reads increase by the amount re-fetched, but memory does not, because creation does not keep and carry every entry.
func (r *runner) references(p *plan.Plan) error {
	var (
		cacheMu sync.Mutex
		exists  = map[string]bool{}
	)
	resolvable := func(v string) (bool, error) {
		if p.Scope.Has(v) {
			return true, nil
		}
		key := dn.Normalize(v)
		cacheMu.Lock()
		ok, seen := exists[key]
		cacheMu.Unlock()
		if seen {
			return ok, nil
		}
		cur, err := r.dst.Get(v, []string{"objectClass"})
		if err != nil {
			return false, err
		}
		cacheMu.Lock()
		if len(exists) < existsCacheLimit {
			exists[key] = cur != nil
		}
		cacheMu.Unlock()
		return cur != nil, nil
	}

	for _, kind := range attrs.Kinds {
		if !r.opt.Plan.Enabled(kind) {
			continue
		}
		names := p.RefNames(kind)
		if len(names) == 0 {
			continue
		}
		err := workpool.Feed(r.opt.Workers, func(emit func(directory.Entry) error) error {
			return p.WalkRefs(kind, names, emit)
		}, func(e directory.Entry) error {
			for _, name := range names {
				values := e.Values(name)
				if len(values) == 0 {
					continue
				}
				var usable []string
				for _, v := range values {
					ok, err := resolvable(v)
					if err != nil {
						return err
					}
					if !ok {
						r.warn("skip %s of %s: %s does not exist on target", name, e.DN, v)
						continue
					}
					usable = append(usable, v)
				}
				if err := r.applyReference(e.DN, name, usable); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// applyReference applies a DN reference attribute. A single value is replaced if it differs; a multi-value attribute only gets the missing values added.
// Multi-valued attributes are add-only and values present only on the target are not removed (the target is assumed empty, so nothing is deleted).
func (r *runner) applyReference(target, name string, values []string) error {
	if len(values) == 0 {
		return nil
	}
	cur, err := r.dst.Get(target, []string{name})
	if err != nil {
		return err
	}
	var have []string
	if cur != nil {
		have = cur.Values(name)
	}
	if r.plan.RefSingle(name) {
		if r.plan.Equal(name, have, values) {
			return nil
		}
		return r.dst.Replace(target, map[string][]string{name: values})
	}
	haveSet := map[string]bool{}
	for _, v := range have {
		haveSet[dn.Normalize(v)] = true
	}
	var missing []string
	for _, v := range values {
		if !haveSet[dn.Normalize(v)] {
			missing = append(missing, v)
		}
	}
	for len(missing) > 0 {
		n := min(memberChunk, len(missing))
		if err := r.dst.AddValues(target, name, missing[:n]); err != nil {
			return err
		}
		missing = missing[n:]
	}
	return nil
}

func (r *runner) count(f func(*Report)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(&r.report)
}

func (r *runner) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(r.out, format, args...)
}

func (r *runner) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.report.WarningCount++
	switch {
	case len(r.report.Warnings) < maxWarnings:
		r.report.Warnings = append(r.report.Warnings, msg)
		fmt.Fprintf(r.out, "warn   %s\n", msg)
	case len(r.report.Warnings) == maxWarnings:
		r.report.Warnings = append(r.report.Warnings, "(further warnings suppressed)")
		fmt.Fprintf(r.out, "warn   further warnings suppressed (see the count in the summary)\n")
	}
}

// withoutDeferred returns a copy with the DN reference attributes removed that are applied later.
func (r *runner) withoutDeferred(e directory.Entry) directory.Entry {
	out := directory.Entry{DN: e.DN, Attrs: map[string][]string{}}
	for n, v := range e.Attrs {
		// objectGUID is assigned by the target, so it is not copied (it is read only for the mapping).
		// A native import, however, passes objectGUID and objectSid through unchanged so the target is created with the same values as the source.
		if r.plan.IsRef(n) || len(v) == 0 || (!r.opt.Plan.KeepIdentity && strings.EqualFold(n, r.opt.Plan.IDAttr())) {
			continue
		}
		out.Attrs[n] = v
	}
	return out
}

func isRDNAttr(entryDN, attr string) bool {
	rdn := dn.Split(entryDN)[0]
	return strings.HasPrefix(strings.ToLower(rdn), strings.ToLower(attr)+"=")
}

// EncodePassword converts to the AD unicodePwd format (UTF-16LE enclosed in quotes).
func EncodePassword(pw string) string {
	units := utf16.Encode([]rune(`"` + pw + `"`))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u), byte(u>>8))
	}
	return string(b)
}
