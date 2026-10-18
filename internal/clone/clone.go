// Package clone adds and updates the target objects of the clone source on the target.
//
// The order is "parent OUs -> groups and users -> DN reference attributes (member/manager/managedBy)".
// References must be applied only after every referenced object exists; otherwise they fail depending on creation order.
package clone

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/workpool"
)

const (
	// Number of members added per modify. Chosen so one AD operation stays within its limit.
	memberChunk = 500
)

// Options are the run-time settings of a clone.
type Options struct {
	UserPassword string
	Workers      int // sequential if 1 or less
	// Marker, when set, writes the source key into every object clone creates or updates, so diff can tell where
	// it went when the program under test renames or moves it.
	Marker *identity.Marker
	// Preserve creates every object with the source identifier through the profile's Preserver (entryUUID with the
	// relax control on OpenLDAP); Operational also copies the Preserver's operational attributes at creation.
	Preserve, Operational bool
	// Mapping, when set, records the source and target identifiers of every object in a local file, for targets
	// that allow neither of the above.
	Mapping *identity.Map
	// Native passes the source identifiers through (objectGUID, objectSid), for an import into the lab Samba that
	// keeps them. An existing object with another identifier is then an error instead of an update.
	Native bool
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
	prof profile.Profile

	mu      sync.Mutex // guards report, out and skipped
	report  Report
	skipped map[string]bool // normalized DNs not created (see upsert); the reference pass leaves them alone
}

// errSkipped means an entry was not created and a warning says why; the run goes on.
var errSkipped = errors.New("skipped")

func Run(ctx context.Context, src, dst directory.Directory, job plan.Job, opt Options, out io.Writer) (*Report, error) {
	read := plan.Read{Identity: opt.Marker != nil || opt.Preserve || opt.Mapping != nil || opt.Native, CarryOver: opt.Native}
	if opt.Preserve {
		if job.Profile.Preserve == nil {
			return nil, fmt.Errorf("the %s profile cannot preserve identifiers over LDAP", job.Profile.Name)
		}
		if opt.Operational {
			read.Extra = job.Profile.Preserve.Operational
		}
	}
	p, err := plan.Build(ctx, src, job, read)
	if err != nil {
		return nil, err
	}
	r := &runner{dst: dst, opt: opt, out: out, prof: job.Profile, skipped: map[string]bool{}}
	if err := r.run(ctx, p); err != nil {
		return &r.report, err
	}
	return &r.report, nil
}

func (r *runner) run(ctx context.Context, p *plan.Plan) error {
	r.plan = p
	if err := p.EachLevel(ctx, r.opt.Workers, r.ensure); err != nil {
		return err
	}
	if err := p.EachLeaf(ctx, r.opt.Workers, r.leaf); err != nil {
		return err
	}
	return r.references(ctx, p)
}

func (r *runner) leaf(ctx context.Context, k *plan.Kind, e directory.Entry) error {
	var account profile.Account
	if k.Account {
		account = r.prof.Account
	}
	created, cur, err := r.upsert(ctx, e, account)
	if errors.Is(err, errSkipped) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := r.track(ctx, e, created, cur); err != nil {
		return err
	}
	if account == nil {
		return nil
	}
	if created {
		cur = nil
	}
	changed, err := account.Finish(ctx, r.dst, e, r.opt.UserPassword, cur)
	if err != nil {
		return fmt.Errorf("%s: %w", e.DN, err)
	}
	if len(changed) > 0 {
		r.count(func(rep *Report) { rep.Updated++ })
		r.logf("update %s (%s)\n", e.DN, strings.Join(changed, ", "))
	}
	return nil
}

// ensure creates or updates one container. A create-only ancestor that already exists on the target (CN=Users, ...)
// is left untouched.
func (r *runner) ensure(ctx context.Context, n plan.Node) error {
	if !n.CreateOnly {
		created, cur, err := r.upsert(ctx, n.Entry, nil)
		if err != nil {
			return err
		}
		return r.track(ctx, n.Entry, created, cur)
	}
	cur, err := r.dst.Get(ctx, n.Entry.DN, append([]string{"objectClass"}, r.guidAttr()...))
	if err != nil {
		return err
	}
	if cur != nil {
		return r.track(ctx, n.Entry, false, cur)
	}
	desired, err := r.desired(n.Entry)
	if err != nil {
		return err
	}
	if err := r.add(ctx, desired); err != nil {
		return fmt.Errorf("add parent %s: %w", n.Entry.DN, err)
	}
	r.count(func(rep *Report) { rep.Added++ })
	r.logf("add    %s\n", n.Entry.DN)
	return r.track(ctx, n.Entry, true, nil)
}

// upsert performs an add (created=true) or an update of only the attributes that differ.
// For an existing entry it returns the current target values (read for diffing) in cur; that read also carries the
// identifier (for the mapping) and what account needs, so the caller needs no additional Get.
// account is nil for entries that are not accounts.
func (r *runner) upsert(ctx context.Context, e directory.Entry, account profile.Account) (created bool, cur *directory.Entry, err error) {
	desired, err := r.desired(e)
	if err != nil {
		return false, nil, err
	}
	extra := r.guidAttr()
	add := desired
	if account != nil {
		for _, a := range account.Owned() {
			delete(desired.Attrs, a)
		}
		extra = append(extra, account.ReadExtra()...)
		add = account.AddEntry(desired, r.opt.UserPassword)
	}
	err = r.add(ctx, add)
	if errors.Is(err, directory.ErrSchemaViolation) {
		// A group class such as groupOfNames requires a member at creation, which the deferred reference pass cannot give.
		// Retrying with the in-scope references keeps the common case (AD, where nothing is required) on the cheaper path.
		withRefs := r.withScopedRefs(e, add)
		if len(withRefs.Attrs) == len(add.Attrs) && r.hasRefs(e) {
			// None of its references is cloned, so the schema's required member cannot be given: like a reference
			// to an object outside the scope, it is skipped with a warning instead of stopping the run.
			r.warn("skip %s: the target requires a reference to create it, and none of its references is cloned (%v)", e.DN, err)
			r.mu.Lock()
			r.skipped[dn.Normalize(e.DN)] = true
			r.mu.Unlock()
			return false, nil, errSkipped
		}
		if len(withRefs.Attrs) > len(add.Attrs) {
			err = r.add(ctx, withRefs)
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
	cur, err = r.dst.Get(ctx, e.DN, append(names, extra...))
	if err != nil {
		return false, nil, err
	}
	if r.opt.Native || r.opt.Preserve {
		if err := r.checkIdentity(e.DN, desired, cur); err != nil {
			return false, nil, err
		}
	}
	// objectClass and the RDN attribute cannot be changed (or changing them is pointless). objectGUID and objectSid
	// can be specified only at creation; the check above has confirmed they are the same values.
	var got directory.Entry // an entry deleted since the Add attempt reads as nil: every attribute is a change
	if cur != nil {
		got = *cur
	}
	plain, _ := r.plan.Changes(desired, got, names, func(n string) bool {
		return strings.EqualFold(n, "objectClass") || plan.IsRDNAttr(e.DN, n) || r.creationOnly(n)
	})
	changes := make(map[string][]string, len(plain))
	for _, c := range plain {
		changes[c.Name] = c.Want
	}
	if len(changes) == 0 {
		r.count(func(rep *Report) { rep.Unchanged++ })
		return false, cur, nil
	}
	if err := r.dst.Replace(ctx, e.DN, changes); err != nil {
		return false, nil, err
	}
	r.count(func(rep *Report) { rep.Updated++ })
	r.logf("update %s\n", e.DN)
	return false, cur, nil
}

// hasRefs reports whether e holds any DN reference value. A schema violation of an entry without one is not about
// its references, so it is an error, not a skip.
func (r *runner) hasRefs(e directory.Entry) bool {
	for n, v := range e.Attrs {
		if r.plan.IsRef(n) && len(v) > 0 {
			return true
		}
	}
	return false
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
		if inScope := r.plan.InScope(values); len(inScope) > 0 {
			out.Attrs[n] = inScope
		}
	}
	return out
}

// guidAttr is the attribute to include in the target read when recording the mapping or preserving objectGUID.
func (r *runner) guidAttr() []string {
	if r.opt.Mapping == nil && !r.opt.Native {
		return nil
	}
	return []string{r.prof.Identity.Attr()}
}

// track records the GUID mapping between source and target. The target GUID is the value read for diffing if the entry exists,
// or is read right after the add for a new one (the add response does not include the GUID).
func (r *runner) track(ctx context.Context, e directory.Entry, created bool, cur *directory.Entry) error {
	if r.opt.Mapping == nil {
		return nil
	}
	scheme := r.prof.Identity
	source, err := identity.Of(scheme, e)
	if err != nil || source.IsZero() {
		return err
	}
	if cur == nil {
		if cur, err = r.dst.Get(ctx, e.DN, []string{scheme.Attr()}); err != nil {
			return err
		}
	}
	if cur == nil {
		return nil
	}
	target, err := identity.Of(scheme, *cur)
	if err != nil {
		return fmt.Errorf("%s on the target: %w", e.DN, err)
	}
	return r.opt.Mapping.Record(source, target)
}

// creationOnly reports whether name is the identifier, another attribute a native import carries over, or an
// operational attribute a preserving Add sets. They can be given only at creation, so an update never sends them.
func (r *runner) creationOnly(name string) bool {
	scheme := r.prof.Identity
	if strings.EqualFold(name, scheme.Attr()) {
		return true
	}
	list := scheme.CarryOver()
	if r.prof.Preserve != nil {
		list = append(append([]string(nil), list...), r.prof.Preserve.Operational...)
	}
	for _, a := range list {
		if strings.EqualFold(name, a) {
			return true
		}
	}
	return false
}

// add creates an entry, with the profile's control when identifiers are preserved.
func (r *runner) add(ctx context.Context, e directory.Entry) error {
	if !r.opt.Preserve {
		return r.dst.Add(ctx, e)
	}
	pr := r.prof.Preserve
	err := r.dst.Add(ctx, e, pr.Control)
	if errors.Is(err, directory.ErrInsufficientAccess) || errors.Is(err, directory.ErrControlUnsupported) {
		// Falling back to an Add without the identifier would leave a target that looks like production and is not.
		return fmt.Errorf("the target refused to keep %s: %w; %s", r.prof.Identity.Attr(), err, pr.Remedy)
	}
	return err
}

// checkIdentity verifies that an existing target object has the same identifier as the source.
// If it differs, it is a different object, so fail instead of falling back to an update (that would overwrite someone else at the same DN).
func (r *runner) checkIdentity(entryDN string, desired directory.Entry, cur *directory.Entry) error {
	if cur == nil {
		return nil
	}
	attr := r.prof.Identity.Attr()
	want, got := first(desired.Values(attr)), first(cur.Values(attr))
	if want != "" && got != want {
		return fmt.Errorf("%s already exists on the target but its %s differs from the source (a different object); it cannot be changed later, so rebuild the target (or, for a target cloned before without preserved identifiers, set [mapping] mode = \"file\" or \"off\")", entryDN, attr)
	}
	return nil
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// Upper bound of the existence-check cache that avoids querying out-of-scope reference targets every time. Beyond it, nothing more is recorded.
const existsCacheLimit = 100_000

// references re-reads only the DN reference attributes from the source and applies them once all objects exist.
// Reads increase by the amount re-fetched, but memory does not, because creation does not keep and carry every entry.
func (r *runner) references(ctx context.Context, p *plan.Plan) error {
	type check struct {
		once sync.Once
		ok   bool
		err  error
	}
	var (
		cacheMu sync.Mutex
		exists  = map[string]*check{}
	)
	resolvable := func(v string) (bool, error) {
		if p.Scope.Has(v) {
			return true, nil
		}
		key := dn.Normalize(v)
		cacheMu.Lock()
		c, seen := exists[key]
		if !seen {
			c = &check{}
			if len(exists) < existsCacheLimit {
				exists[key] = c
			}
		}
		cacheMu.Unlock()
		// Workers asking for the same DN at once wait for the one read instead of each reading it.
		c.once.Do(func() {
			var cur *directory.Entry
			cur, c.err = r.dst.Get(ctx, v, []string{"objectClass"})
			c.ok = cur != nil
		})
		return c.ok, c.err
	}

	job := p.Job()
	for i := range job.Kinds {
		k := &job.Kinds[i]
		names := p.RefNames(k)
		if len(names) == 0 {
			continue
		}
		err := workpool.Feed(ctx, r.opt.Workers, func(ctx context.Context, emit func(directory.Entry) error) error {
			return p.WalkRefs(ctx, k, names, emit)
		}, func(ctx context.Context, e directory.Entry) error {
			r.mu.Lock()
			skipped := r.skipped[dn.Normalize(e.DN)]
			r.mu.Unlock()
			if skipped {
				return nil
			}
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
				if err := r.applyReference(ctx, e.DN, name, usable); err != nil {
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
func (r *runner) applyReference(ctx context.Context, target, name string, values []string) error {
	if len(values) == 0 {
		return nil
	}
	cur, err := r.dst.Get(ctx, target, []string{name})
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
		return r.dst.Replace(ctx, target, map[string][]string{name: values})
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
		if err := r.dst.AddValues(ctx, target, name, missing[:n]); err != nil {
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

// desired returns what the target entry should hold before references are applied: e without the DN reference
// attributes (applied later), and with the marker when there is one.
func (r *runner) desired(e directory.Entry) (directory.Entry, error) {
	out := directory.Entry{DN: e.DN, Attrs: map[string][]string{}}
	keep := r.opt.Native || r.opt.Preserve
	for n, v := range e.Attrs {
		// The identifier is assigned by the target, so it is not copied (it is read for the marker or the mapping).
		// A native import and a preserving Add, however, pass it through so the target object has the source's.
		// creatorsName and modifiersName hold DNs but are written at creation, not with the references.
		if (r.plan.IsRef(n) && !r.creationOnly(n)) || len(v) == 0 || (!keep && strings.EqualFold(n, r.prof.Identity.Attr())) {
			continue
		}
		out.Attrs[n] = v
	}
	if r.opt.Marker != nil {
		k, err := identity.Of(r.prof.Identity, e)
		if err != nil {
			return out, fmt.Errorf("%s on the source: %w", e.DN, err)
		}
		if !k.IsZero() {
			out.Attrs[r.opt.Marker.Attr] = []string{r.opt.Marker.Encode(k)}
		}
	}
	return out, nil
}
