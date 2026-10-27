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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/progress"
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
	// Progress, when set, is told the phases and how far each is (nil: nothing is shown).
	Progress *progress.Bar
	// DryRun says the target is the LDIF of a dry-run, which holds only what the run wrote: a built-in group (Domain
	// Admins) is taken to be there, as every domain has it.
	DryRun bool
	// Now is the clock the phases are timed by (nil: time.Now).
	Now func() time.Time
	// Deadline, when set, stops the run before the first object it would start after it, with ErrTimeLimit: a
	// session that ends after a while (a cloud shell) runs the clone in slices.
	Deadline time.Time
	// Journal, when set, records the objects done, and those it holds are skipped: a run resumed after
	// ErrTimeLimit does not read the target again for what an earlier one finished.
	Journal Journal
}

// Journal records what a run has finished. The keys are opaque; Mark may buffer.
type Journal interface {
	Has(key string) bool
	Mark(ctx context.Context, key string) error
}

// ErrTimeLimit stops a run at Options.Deadline. What it wrote is complete object by object; running again goes on.
var ErrTimeLimit = errors.New("the time limit was reached")

// maxWarnings caps the warnings kept and shown, so that a flood of out-of-scope reference targets does not exhaust memory with warnings.
const maxWarnings = 1000

type Report struct {
	Added, Updated, Unchanged int
	// Referenced counts the entries outside the scope cloned because a reference names them (or, as parents,
	// because entries to clone are under them); ReferencedKinds splits it per kind.
	Referenced      int
	ReferencedKinds map[string]int
	// NotCloned counts the entries under base_dn of no enabled kind, per structural object class (plan.Unselected).
	NotCloned map[string]int
	// Unwritten counts the reference values clone could not write, per "attribute: why" (plan.Classifier.Why).
	Unwritten map[string]int
	// PrimaryGroups counts the accounts given their source's primary group (not their type's default).
	PrimaryGroups int
	// OutsideGroups and BuiltinGroups count the groups outside the scope given the entries of it they hold
	// (plan.Holder); Unheld counts those left as they are, per why.
	OutsideGroups, BuiltinGroups int
	Unheld                       map[string]int
	// ACLs counts the objects given the source's ACL ([attributes] acl = "copy"); ACEsLeftOut counts, per why
	// (plan.WhyNoSourcePrincipal ...), the source's ACEs left out because the target has no principal for their trustee.
	ACLs int
	// SDValues counts, per attribute, the values written with each SID the target's (plan.Job.SDValues: the
	// resource-based delegation).
	SDValues    map[string]int
	ACEsLeftOut map[string]int
	// Placeholders counts the placeholders created for entries the source did not return (plan.RefPlaceholder),
	// with the parents created for them.
	Placeholders int
	// Withheld counts, per attribute, the values not written because the target refuses them (plan.Withheld: a
	// replication-conflict leftover shares them with another object, an SPN another object's covers through Samba's
	// aliases); WithheldWhy counts them per "attribute: why".
	Withheld    map[string]int
	WithheldWhy map[string]int
	// NameTaken lists the entries not added because the target holds another entry under a name it takes as the
	// same (Windows ignores width and kana type, Samba collapses spaces), each with the target's entry: writing them
	// would have overwritten that one.
	NameTaken []NameTaken
	// Refused lists the entries not added because the target refuses them (plan.Withheld.Refused: on Windows the
	// leftover of a name conflict, whose RDN holds a line feed, and what is longer than it takes), with why.
	Refused []plan.RefusedEntry
	// Resumed counts the objects (and the reference passes of objects) an earlier run finished, which the journal
	// let this one skip.
	Resumed      int
	WarningCount int
	Warnings     []string // first maxWarnings only
	// Took is how long each phase took, in order, so a slow run says where its time went.
	Took []PhaseTime
}

// NameTaken is a source entry not added, and the target's entry that holds its name.
type NameTaken struct {
	DN, TargetDN string
	// Unknown is set when whether the target's entry is this one renamed cannot be told (no marker, no identifier).
	Unknown bool
}

// WhyNameTaken is why a reference value naming such an entry is not written: the target would take it to name the
// other entry.
const WhyNameTaken = plan.NameTakenWhy

// maxNameTakenShown caps the entries the summary lists; the count is always given.
const maxNameTakenShown = 50

// PhaseTime is how long one phase of a run took.
type PhaseTime struct {
	Name string
	Took time.Duration
}

// WriteSummary prints the counts of a run: what was written, and what was cloned from outside the scope or not
// cloned at all, so a tester knows what the target holds.
func (rep *Report) WriteSummary(w io.Writer) {
	fmt.Fprintf(w, "\nadded=%d updated=%d unchanged=%d warnings=%d\n", rep.Added, rep.Updated, rep.Unchanged, rep.WarningCount)
	if rep.Resumed > 0 {
		fmt.Fprintf(w, "skipped, done by an earlier run (the journal): %d\n", rep.Resumed)
	}
	if len(rep.Took) > 0 {
		parts := make([]string, len(rep.Took))
		for i, t := range rep.Took {
			parts[i] = fmt.Sprintf("%s %s", t.Name, t.Took.Round(time.Second))
		}
		fmt.Fprintf(w, "time: %s\n", strings.Join(parts, ", "))
	}
	if rep.Referenced > 0 {
		plan.WriteCounts(w, "referenced objects outside the scope cloned", rep.ReferencedKinds)
	}
	if rep.PrimaryGroups > 0 {
		fmt.Fprintf(w, "accounts given their primary group (not Domain Users or Domain Computers): %d\n", rep.PrimaryGroups)
	}
	if rep.OutsideGroups > 0 || rep.BuiltinGroups > 0 {
		fmt.Fprintf(w, "groups outside the scope given its entries they hold: %d (built-in: %d)\n", rep.OutsideGroups+rep.BuiltinGroups, rep.BuiltinGroups)
	}
	if len(rep.Unheld) > 0 {
		plan.WriteCounts(w, "groups outside the scope holding its entries, left as they are", rep.Unheld)
	}
	if rep.ACLs > 0 {
		fmt.Fprintf(w, "objects given the source's ACL (owner, group and explicit ACEs, each SID the target's): %d\n", rep.ACLs)
	}
	if len(rep.SDValues) > 0 {
		plan.WriteCounts(w, "values naming principals written with each SID the target's", rep.SDValues)
	}
	if len(rep.ACEsLeftOut) > 0 {
		plan.WriteCounts(w, "ACEs left out (their trustee has no principal on the target; see the warnings)", rep.ACEsLeftOut)
	}
	if len(rep.Withheld) > 0 {
		plan.WriteCounts(w, "values not written, the target refuses them (see the warnings)", rep.WithheldWhy)
	}
	if len(rep.NameTaken) > 0 {
		fmt.Fprintf(w, "not added, the target holds another entry under a name it takes as the same: %d\n", len(rep.NameTaken))
		for i, n := range rep.NameTaken {
			if i == maxNameTakenShown {
				fmt.Fprintf(w, "  ... and %d more (see the warnings)\n", len(rep.NameTaken)-i)
				break
			}
			unknown := ""
			if n.Unknown {
				unknown = "; without a marker, it may be this entry renamed"
			}
			fmt.Fprintf(w, "  %s  (the target's: %s%s)\n", n.DN, n.TargetDN, unknown)
		}
	}
	if len(rep.Refused) > 0 {
		fmt.Fprintf(w, "not added, the target refuses them: %d\n", len(rep.Refused))
		for i, e := range rep.Refused {
			if i == maxNameTakenShown {
				fmt.Fprintf(w, "  ... and %d more (see the warnings)\n", len(rep.Refused)-i)
				break
			}
			fmt.Fprintf(w, "  %s  (%s)\n", e.DN, e.Why)
		}
	}
	if rep.Placeholders > 0 {
		fmt.Fprintf(w, "placeholders created for entries the source did not return (unreadable to the account reading it; see the warnings): %d\n", rep.Placeholders)
	}
	if len(rep.NotCloned) > 0 {
		plan.WriteCounts(w, "not cloned (of no kind, or built-in)", rep.NotCloned)
	}
	if len(rep.Unwritten) > 0 {
		plan.WriteCounts(w, "reference values not written (the target lacks what they name; diff does not compare them)", rep.Unwritten)
		fmt.Fprintln(w, "  an attribute the test does not need can be left out with [attributes] exclude")
		for key := range rep.Unwritten {
			if strings.HasSuffix(key, plan.WhyConfiguration) {
				fmt.Fprintln(w, "  [scope] configuration_refs = \"clone\" creates the entries of the configuration partition they name (for a lab)")
				break
			}
		}
	}
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
	// notAdded says why an entry of the source was not added (normalized DN): the values naming it are not written.
	notAdded map[string]string
	unwrote  map[string]bool // attribute and normalized DN of each value warned about as not written
	primary  []primaryOf     // the accounts whose primary group is not their type's default (guarded by mu)
	acls     []string        // the DNs of the objects to give the source's ACL (ACLTranslated; guarded by mu)
	aclOn    bool
	leftOut  map[string]bool // the SIDs warned about as left out of the ACEs
	// sdOn are the attributes written last with the target's SIDs (plan.Job.Translated), by lowercase name; sdValues
	// the values to write (guarded by mu).
	sdOn       map[string]string
	sdValues   []sdValue
	principals *plan.Principals // see principalsFor
	withheld   *plan.Withheld   // the values the target would refuse (see Run)
	refs       *plan.Classifier
	done       map[string]*onceErr // see once
	// phase is the phase being timed since since (lap).
	phase string
	since time.Time
}

// lap ends the phase being timed, recording how long it took, and starts next ("" starts none).
func (r *runner) lap(next string) {
	now := r.opt.Now()
	if r.phase != "" {
		r.report.Took = append(r.report.Took, PhaseTime{Name: r.phase, Took: now.Sub(r.since)})
	}
	r.phase, r.since = next, now
}

// errSkipped means an entry was not created and a warning says why; the run goes on.
var errSkipped = errors.New("skipped")

func Run(ctx context.Context, src, dst directory.Directory, job plan.Job, opt Options, out io.Writer) (*Report, error) {
	read := plan.Read{Identity: opt.Marker != nil || opt.Preserve || opt.Mapping != nil || opt.Native, CarryOver: opt.Native}
	if job.Profile.Account != nil {
		read.Extra = append(read.Extra, job.Profile.Account.SourceExtra()...)
	}
	if opt.Preserve {
		if job.Profile.Preserve == nil {
			return nil, fmt.Errorf("the %s profile cannot preserve identifiers over LDAP", job.Profile.Name)
		}
		if opt.Operational {
			read.Extra = job.Profile.Preserve.Operational
		}
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	started := opt.Now()
	opt.Progress.Phase("reading the source", -1)
	if err := plan.CheckTargetSchema(ctx, src, dst, job); err != nil {
		return nil, err
	}
	p, err := plan.Build(ctx, src, job, read)
	if err != nil {
		return nil, err
	}
	// A value more than one real object holds would be refused at the second, after the run had written everything
	// before it: refused here instead, before anything is written.
	withheld, clashes, err := p.Withholding(ctx, dst)
	if err != nil {
		return nil, err
	}
	if len(clashes) > 0 {
		return nil, plan.ClashError(clashes)
	}
	r := &runner{dst: dst, opt: opt, out: out, prof: job.Profile, skipped: map[string]bool{}, done: map[string]*onceErr{},
		unwrote: map[string]bool{}, report: Report{ReferencedKinds: map[string]int{}, Unwritten: map[string]int{}, Unheld: map[string]int{}, ACEsLeftOut: map[string]int{}, SDValues: map[string]int{}},
		aclOn: job.ACL == plan.ACLTranslated && !opt.Native, leftOut: map[string]bool{}, withheld: withheld,
		phase: "reading the source", since: started}
	defer r.lap("")
	r.notAdded = map[string]string{}
	for _, e := range withheld.Refused {
		r.refuse(e.DN, e.Why)
	}
	if len(withheld.Values) > 0 {
		r.report.Withheld, r.report.WithheldWhy = map[string]int{}, map[string]int{}
	}
	if !opt.Native {
		r.sdOn = job.Translated()
	}
	opt.Progress.Stats(func() string {
		r.mu.Lock()
		defer r.mu.Unlock()
		return fmt.Sprintf("added %d · updated %d · unchanged %d · warnings %d", r.report.Added, r.report.Updated, r.report.Unchanged, r.report.WarningCount)
	})
	if err := r.run(ctx, p); err != nil {
		return &r.report, err
	}
	r.lap("counting what is not cloned")
	nc, err := p.Unselected(ctx)
	r.report.NotCloned = nc
	return &r.report, err
}

func (r *runner) run(ctx context.Context, p *plan.Plan) error {
	r.plan, r.refs = p, p.Classifier(r.dst)
	bar := r.opt.Progress
	hs, err := p.Holders(ctx)
	if err != nil {
		return err
	}
	phases := len(p.Leaves()) + 2 // the parents, each leaf kind, the references
	if len(hs) > 0 {
		phases++ // the groups outside the scope holding its entries
	}
	if r.aclOn {
		phases++
	}
	if len(r.sdOn) > 0 {
		phases++
	}
	bar.Phases(phases)
	r.lap("OUs and parents")
	bar.Phase("OUs and parents", len(p.Containers))
	if err := p.EachLevel(ctx, r.opt.Workers, func(ctx context.Context, n plan.Node) error {
		defer bar.Add(1)
		return r.ensure(ctx, n)
	}); err != nil {
		return err
	}
	for _, k := range p.Leaves() {
		r.lap(k.Name)
		bar.Phase(k.Name, p.LeafCount(k))
		if err := p.EachLeafOf(ctx, r.opt.Workers, k, func(ctx context.Context, k *plan.Kind, e directory.Entry) error {
			defer bar.Add(1)
			return r.leaf(ctx, k, e)
		}); err != nil {
			return err
		}
	}
	r.lap("references")
	if err := r.references(ctx, p); err != nil {
		return err
	}
	r.lap("primary groups, groups outside the scope, ACLs")
	// Before the holders: AD refuses a member value naming an account whose primary group the group is, so an
	// account leaves Domain Users as its primary group before it is added to Domain Users' member.
	if err := r.primaryGroups(ctx, p); err != nil {
		return err
	}
	if err := r.holders(ctx, p, hs); err != nil {
		return err
	}
	// Last: an ACE names its trustee by SID, which an object has on the target only once created, and any object
	// clone creates (a group outside the scope included) may be one.
	if err := r.descriptors(ctx, p); err != nil {
		return err
	}
	return r.writeSDValues(ctx, p)
}

// holders gives the groups outside the scope that hold entries of it (a group of another OU, Domain Admins) the
// values naming those entries: a group of a kind is created first, as a referenced entry is; a built-in group is the
// target's own. Values are only added, and nothing else of the group is written.
func (r *runner) holders(ctx context.Context, p *plan.Plan, hs []plan.Holder) error {
	if len(hs) == 0 {
		return nil
	}
	r.opt.Progress.Phase("groups outside the scope holding its entries", len(hs))
	return workpool.Each(ctx, r.opt.Workers, hs, func(ctx context.Context, h plan.Holder) error {
		defer r.opt.Progress.Add(1)
		if h.Why != "" {
			return r.unheld(h, h.Why)
		}
		if why := r.notAddedWhy(h.DN); why != "" {
			return r.unheld(h, "is not added: "+why)
		}
		switch {
		case h.Builtin && r.opt.DryRun:
		case h.Builtin || h.Existing:
			cur, err := r.dst.Get(ctx, h.DN, []string{"objectClass"})
			if err != nil {
				return err
			}
			if cur == nil {
				why := "is a group outside the scope the target lacks ([scope] outside_groups = \"existing\")"
				if r.opt.DryRun {
					why = "is a group outside the scope, which a dry-run cannot tell the target holds ([scope] outside_groups = \"existing\")"
				}
				if h.Builtin {
					why = "is a built-in group the target lacks"
				}
				return r.unheld(h, why)
			}
		default:
			if err := r.outside(ctx, h.DN, func() (*plan.Kind, error) { return h.Kind, nil }); err != nil {
				return err
			}
			// Its name may have been taken just now: the values would go to the entry holding it.
			if why := r.notAddedWhy(h.DN); why != "" {
				return r.unheld(h, "is not added: "+why)
			}
		}
		for _, name := range h.Attrs {
			values, err := p.HolderValues(ctx, h, name)
			if err != nil {
				return err
			}
			values = r.created(values)
			if err := r.applyReference(ctx, h.DN, name, values); err != nil {
				return fmt.Errorf("%s: add %s values: %w", h.DN, name, err)
			}
		}
		r.count(func(rep *Report) {
			if h.Builtin {
				rep.BuiltinGroups++
			} else {
				rep.OutsideGroups++
			}
		})
		return nil
	})
}

// created keeps the values naming an entry clone did not skip.
func (r *runner) created(values []string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, v := range values {
		if !r.skipped[dn.Normalize(dn.RefDN(v))] {
			out = append(out, v)
		}
	}
	return out
}

// primaryOf is an account whose primary group is not its type's default, by the source's RID.
type primaryOf struct{ dn, rid string }

// primaryGroups gives the accounts the primary group they have on the source, by its DN: the group is created
// first when it is outside the scope (as a holder is), its RID on the target is read, the account is added to its
// member (AD takes only a group the account belongs to), then primaryGroupID is set, after which AD drops that
// member value by itself, as the source's group lacks it.
func (r *runner) primaryGroups(ctx context.Context, p *plan.Plan) error {
	pg := r.prof.PrimaryGroup
	if pg == nil || len(r.primary) == 0 {
		return nil
	}
	attr := pg.Attr()
	var wellKnown map[string]string // the target's groups by RID, for the built-in ones
	for _, a := range r.primary {
		var gdn string
		var err error
		if pg.WellKnown(a.rid) {
			if wellKnown == nil {
				if wellKnown, err = pg.Groups(ctx, r.dst, p.Root); err != nil {
					return err
				}
			}
			if gdn = wellKnown[a.rid]; gdn == "" {
				r.notPrimary(a, "names a built-in group the target lacks")
				continue
			}
		} else if gdn, err = p.PrimaryGroupDN(ctx, a.rid); err != nil {
			return err
		}
		if gdn == "" {
			r.notPrimary(a, "names a RID no group of the source has")
			continue
		}
		if !p.Scope.Has(gdn) {
			h, err := p.Holder(ctx, gdn)
			if err != nil {
				return err
			}
			if h.Why != "" {
				r.notPrimary(a, "names a group that "+h.Why)
				continue
			}
			if !h.Builtin && !h.Existing {
				if err := r.outside(ctx, gdn, func() (*plan.Kind, error) { return h.Kind, nil }); err != nil {
					return err
				}
			}
		}
		if why := r.notAddedWhy(gdn); why != "" {
			r.notPrimary(a, "names a group not added: "+why)
			continue
		}
		rid := ""
		if g, err := r.dst.Get(ctx, gdn, []string{"objectSid"}); err != nil {
			return err
		} else if g != nil {
			rid, _ = pg.RID(*g)
		}
		if rid == "" {
			if pg.WellKnown(a.rid) {
				rid = a.rid // the same RID in every domain
			} else {
				r.notPrimary(a, "names a group whose RID on the target cannot be read (it lacks the group, or a dry-run)")
				continue
			}
		}
		cur, err := r.dst.Get(ctx, a.dn, []string{attr})
		if err != nil {
			return err
		}
		if cur != nil && strings.TrimSpace(first(cur.Values(attr))) == rid {
			continue
		}
		if err := r.applyReference(ctx, gdn, "member", []string{a.dn}); err != nil {
			return fmt.Errorf("%s: add %s to the member of its primary group %s: %w", a.dn, a.dn, gdn, err)
		}
		if err := r.dst.Replace(ctx, a.dn, map[string][]string{attr: {rid}}); err != nil {
			return fmt.Errorf("%s: primary group %s: %w", a.dn, gdn, err)
		}
		r.count(func(rep *Report) { rep.PrimaryGroups++ })
		r.logf("update %s (%s: %s)\n", a.dn, attr, gdn)
	}
	return nil
}

// notPrimary counts an account left with its type's default primary group, and warns about it.
func (r *runner) notPrimary(a primaryOf, why string) {
	attr := r.prof.PrimaryGroup.Attr()
	r.mu.Lock()
	r.report.Unwritten[attr+": "+why]++
	r.mu.Unlock()
	r.warn("%s keeps the default primary group: its %s %s %s", a.dn, attr, a.rid, why)
}

// unheld counts a holder clone does not give its values, and warns about it.
func (r *runner) unheld(h plan.Holder, why string) error {
	r.mu.Lock()
	r.report.Unheld[why]++
	r.mu.Unlock()
	r.warn("%s holds entries of the scope (%s) and is left as it is: it %s", h.DN, strings.Join(h.Attrs, ", "), why)
	return nil
}

// timeUp is ErrTimeLimit once the deadline has passed.
func (r *runner) timeUp() error {
	if !r.opt.Deadline.IsZero() && !r.opt.Now().Before(r.opt.Deadline) {
		return ErrTimeLimit
	}
	return nil
}

// skip reports whether the journal holds key, counting it as resumed.
func (r *runner) skip(key string) bool {
	if r.opt.Journal == nil || !r.opt.Journal.Has(key) {
		return false
	}
	r.count(func(rep *Report) { rep.Resumed++ })
	return true
}

// mark records key as done in the journal.
func (r *runner) mark(ctx context.Context, key string) error {
	if r.opt.Journal == nil {
		return nil
	}
	return r.opt.Journal.Mark(ctx, key)
}

// leaf writes one entry of a kind, unless the journal says an earlier run did: then only what the later passes need
// of it is noted.
func (r *runner) leaf(ctx context.Context, k *plan.Kind, e directory.Entry) error {
	if err := r.timeUp(); err != nil {
		return err
	}
	if r.refused(e) {
		return nil
	}
	key := "object " + dn.Normalize(e.DN)
	if r.skip(key) {
		r.withACL(e.DN)
		r.withSDValues(e)
		if k.Account {
			r.notePrimary(e)
		}
		return nil
	}
	if err := r.writeLeaf(ctx, k, e); err != nil {
		return err
	}
	return r.mark(ctx, key)
}

// notePrimary notes an account whose primary group is not its type's default, for primaryGroups.
func (r *runner) notePrimary(e directory.Entry) {
	pg := r.prof.PrimaryGroup
	if pg == nil {
		return
	}
	if rid := strings.TrimSpace(first(e.Values(pg.Attr()))); rid != "" && rid != pg.Default(e) {
		r.mu.Lock()
		r.primary = append(r.primary, primaryOf{dn: e.DN, rid: rid})
		r.mu.Unlock()
	}
}

func (r *runner) writeLeaf(ctx context.Context, k *plan.Kind, e directory.Entry) error {
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
	r.withACL(e.DN)
	r.withSDValues(e)
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
	r.notePrimary(e)
	if len(changed) > 0 {
		r.count(func(rep *Report) { rep.Updated++ })
		r.logf("update %s (%s)\n", e.DN, strings.Join(changed, ", "))
	}
	return nil
}

// ensure creates or updates one container, or a parent leaf as its kind. A create-only ancestor that already exists
// on the target (CN=Users, ...) is left untouched.
func (r *runner) ensure(ctx context.Context, n plan.Node) error {
	if r.refused(n.Entry) {
		return nil
	}
	if n.Leaf() {
		if err := r.leaf(ctx, n.Kind, n.Entry); err != nil || !n.Outside {
			return err
		}
		r.referencedOne(n.Kind)
		return nil
	}
	if !n.CreateOnly {
		created, cur, err := r.upsert(ctx, n.Entry, nil)
		if errors.Is(err, errSkipped) {
			return nil
		}
		if err != nil {
			return err
		}
		r.withACL(n.Entry.DN)
		r.withSDValues(n.Entry)
		return r.track(ctx, n.Entry, created, cur)
	}
	cur, err := r.dst.Get(ctx, n.Entry.DN, append(append([]string{"objectClass"}, r.guidAttr()...), plan.TargetDNAttrs(r.prof, n.Entry.DN)...))
	if err != nil {
		return err
	}
	if r.taken(n.Entry.DN, cur) {
		return nil
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
		add = account.AddEntry(desired, r.opt.UserPassword) // it sees the owned attributes (a computer's account type)
		for _, a := range account.Owned() {
			delete(desired.Attrs, a)
		}
		extra = append(extra, account.ReadExtra()...)
	}
	err = r.add(ctx, add)
	if errors.Is(err, directory.ErrSchemaViolation) && r.prof.RefsAtCreation {
		// A group class such as groupOfNames requires a member at creation, which the deferred reference pass cannot give.
		// Retrying with the references keeps the common case (AD, where nothing is required) on the cheaper path.
		withRefs, rerr := r.withRefs(ctx, e, add)
		if rerr != nil {
			return false, nil, rerr
		}
		if len(withRefs.Attrs) == len(add.Attrs) && r.hasRefs(e) {
			// None of its references can be written, so the schema's required member cannot be given: like a reference
			// to an object outside the scope, it is skipped with a warning instead of stopping the run.
			r.warn("skip %s: the target requires a reference to create it, and none of its references can be written (%v)", e.DN, err)
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
	// An attribute all of whose values are withheld is compared too, so a value an earlier run wrote (before it was
	// withheld: Samba's alias collision stopped that run) is taken off rather than left to be refused again.
	for _, v := range r.withheld.ValuesOf(e.DN) {
		if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, v.Attr) }) {
			names = append(names, v.Attr)
		}
	}
	if r.opt.Marker != nil {
		extra = append(extra, r.opt.Marker.Attr)
	}
	if r.opt.Native || r.opt.Preserve || r.opt.Mapping != nil {
		extra = append(extra, r.prof.Identity.Attr())
	}
	extra = append(extra, plan.TargetDNAttrs(r.prof, e.DN)...)
	cur, err = r.dst.Get(ctx, e.DN, append(names, extra...))
	if err != nil {
		return false, nil, err
	}
	if cur != nil {
		// The target answered for another name it takes as the same: this entry renamed (by the program under test,
		// to a name equal to it there), or another entry, which an update would overwrite.
		if actual := plan.TargetDN(r.prof, e.DN, *cur); !dn.Equal(actual, e.DN) {
			if same, known := r.sameObject(e, *cur); !same {
				r.nameTakenAt(e.DN, actual, !known)
				return false, nil, errSkipped
			}
		}
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

// sameObject tells whether cur, found on the target under another DN than e's, is the object cloned from e: by the
// identifier a native import or a preserving add keeps, by the marker, or by the mapping file. known is false when
// none tells.
func (r *runner) sameObject(e, cur directory.Entry) (same, known bool) {
	scheme := r.prof.Identity
	if r.opt.Native || r.opt.Preserve {
		if want, got := first(e.Values(scheme.Attr())), first(cur.Values(scheme.Attr())); want != "" && got != "" {
			return want == got, true
		}
	}
	k, err := identity.Of(scheme, e)
	if err != nil || k.IsZero() {
		return false, false
	}
	if m := r.opt.Marker; m != nil {
		if v := first(cur.Values(m.Attr)); v != "" {
			return strings.EqualFold(v, m.Encode(k)), true
		}
	}
	if r.opt.Mapping != nil {
		if t, err := identity.Of(scheme, cur); err == nil && !t.IsZero() {
			for _, mapped := range r.opt.Mapping.Targets(k) {
				if mapped == t {
					return true, true
				}
			}
			return false, len(r.opt.Mapping.Targets(k)) > 0
		}
	}
	return false, false
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

// withRefs returns desired plus the DN reference values of e that clone can write (see plan.RefClass).
func (r *runner) withRefs(ctx context.Context, e, desired directory.Entry) (directory.Entry, error) {
	out := directory.Entry{DN: desired.DN, Attrs: make(map[string][]string, len(desired.Attrs)+1)}
	for n, v := range desired.Attrs {
		out.Attrs[n] = v
	}
	for n, values := range e.Attrs {
		if !r.plan.IsRef(n) {
			continue
		}
		usable, _, err := r.refs.Reproducible(ctx, values)
		if err != nil {
			return out, err
		}
		if len(usable) > 0 {
			out.Attrs[n] = usable
		}
	}
	return out, nil
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

// references re-reads only the DN reference attributes from the source and applies them once all objects exist.
// Reads increase by the amount re-fetched, but memory does not, because creation does not keep and carry every entry.
func (r *runner) references(ctx context.Context, p *plan.Plan) error {
	job := p.Job()
	total := -1
	if bar := r.opt.Progress; bar != nil {
		// An extra search of DNs only, for the total; without a display it is not worth the read.
		total = 0
		for i := range job.Kinds {
			n, err := p.CountRefs(ctx, &job.Kinds[i], p.RefNames(&job.Kinds[i]))
			if err != nil {
				return err
			}
			total += n
		}
	}
	r.opt.Progress.Phase("references (member, manager, ...)", total)
	for i := range job.Kinds {
		k := &job.Kinds[i]
		names := p.RefNames(k)
		if len(names) == 0 {
			continue
		}
		err := workpool.Feed(ctx, r.opt.Workers, func(ctx context.Context, emit func(directory.Entry) error) error {
			return p.WalkRefs(ctx, k, names, emit)
		}, func(ctx context.Context, e directory.Entry) error {
			defer r.opt.Progress.Add(1)
			if err := r.timeUp(); err != nil {
				return err
			}
			r.mu.Lock()
			skipped := r.skipped[dn.Normalize(e.DN)]
			r.mu.Unlock()
			if skipped {
				return nil
			}
			key := "references " + dn.Normalize(e.DN)
			if r.skip(key) {
				return nil
			}
			for _, name := range names {
				values := e.Values(name)
				if len(values) == 0 {
					continue
				}
				var usable []string
				for _, v := range values {
					class, err := r.refs.Class(ctx, v)
					if err != nil {
						return err
					}
					switch class {
					case plan.RefUnreproducible:
						if err := r.unwritten(ctx, name, e.DN, v); err != nil {
							return err
						}
						continue
					case plan.RefReferenced:
						if err := r.referenced(ctx, dn.RefDN(v)); err != nil {
							return err
						}
					case plan.RefPlaceholder:
						if err := r.placeholder(ctx, dn.RefDN(v)); err != nil {
							return err
						}
					case plan.RefConfiguration:
						if err := r.configuration(ctx, dn.RefDN(v)); err != nil {
							if ctx.Err() != nil {
								return err
							}
							r.notCreated(name, e.DN, v, err)
							continue
						}
					}
					// After what the value names was created: it may have been left out just now (its name taken).
					if why := r.notAddedWhy(dn.RefDN(v)); why != "" {
						r.notWritten(name, e.DN, v, "names an entry not added: "+why)
						continue
					}
					usable = append(usable, v)
				}
				if err := r.applyReference(ctx, e.DN, name, usable); err != nil {
					return err
				}
			}
			return r.mark(ctx, key)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// unwritten counts a reference value clone cannot write, and warns once per value it names: thousands of users
// listed in the same address list are one warning, and the count in the summary.
func (r *runner) unwritten(ctx context.Context, name, from, v string) error {
	why, err := r.refs.Why(ctx, v)
	if err != nil {
		return err
	}
	r.notWritten(name, from, v, why)
	return nil
}

// nameTakenAt records the source entry at d as not added, the target holding actual under a name it takes as the
// same, and warns of it.
func (r *runner) nameTakenAt(d, actual string, unknown bool) {
	r.mu.Lock()
	r.report.NameTaken = append(r.report.NameTaken, NameTaken{DN: d, TargetDN: actual, Unknown: unknown})
	r.skipped[dn.Normalize(d)] = true
	r.notAdded[dn.Normalize(d)] = WhyNameTaken
	r.mu.Unlock()
	r.warn("not added: %s: the target holds %s under a name it takes as the same", d, actual)
}

// taken reports whether cur, read from the target at d by what clone only creates when it is missing (a create-only
// parent, a placeholder, an entry of the configuration partition), is another entry under a name the target takes as
// the same: then d is recorded as not added, nothing telling it is that one (none of them carries a marker), and
// what is below it and the values naming it are left out too.
func (r *runner) taken(d string, cur *directory.Entry) bool {
	if cur == nil {
		return false
	}
	actual := plan.TargetDN(r.prof, d, *cur)
	if dn.Equal(actual, d) {
		return false
	}
	r.nameTakenAt(d, actual, true)
	return true
}

// notAddedWhy says why the source entry at d was not added, "" when it was (or is yet to be).
func (r *runner) notAddedWhy(d string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.notAdded[dn.Normalize(d)]
}

// refuse records an entry the target refuses, warning of it once.
func (r *runner) refuse(d, why string) {
	key := dn.Normalize(d)
	r.mu.Lock()
	if r.notAdded[key] != "" {
		r.mu.Unlock()
		return
	}
	r.notAdded[key], r.skipped[key] = why, true
	r.report.Refused = append(r.report.Refused, plan.RefusedEntry{DN: d, Why: why})
	r.mu.Unlock()
	r.warn("not added: %s: %s", d, why)
}

// refused reports whether the target refuses an entry of that DN, recording it the first time (one no kind took,
// such as a parent, is met only when it is written).
func (r *runner) refused(e directory.Entry) bool {
	why := r.withheld.RefusedEntryWhy(e)
	if why == "" {
		why = r.underNotAdded(e.DN)
	}
	if why == "" {
		return false
	}
	r.refuse(e.DN, why)
	return true
}

// underNotAdded says why an entry below one not added is not added either, "" when none above it was left out: its
// DN names that parent, which the target would take as the entry holding its name (a parent is written first).
func (r *runner) underNotAdded(d string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for p := dn.Parent(d); p != ""; p = dn.Parent(p) {
		if why := r.notAdded[dn.Normalize(p)]; why != "" {
			return "below " + p + ", not added: " + why
		}
	}
	return ""
}

// notWritten counts a reference value not written for why, warning of the first per attribute and value.
func (r *runner) notWritten(name, from, v, why string) {
	key := strings.ToLower(name) + "\x00" + dn.NormalizeRef(v)
	r.mu.Lock()
	r.report.Unwritten[name+": "+why]++
	first := !r.unwrote[key]
	if first && len(r.unwrote) < maxWarnings {
		r.unwrote[key] = true
	}
	r.mu.Unlock()
	if first {
		// The DN alone: the binary part of a DN-Binary value may be a credential (msDS-KeyCredentialLink).
		r.warn("skip %s values naming %s (first of %s): it %s", name, dn.RefDN(v), from, why)
	}
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
		w, err := r.writeForm(ctx, values)
		if err != nil {
			return err
		}
		return r.dst.Replace(ctx, target, map[string][]string{name: w})
	}
	haveSet := map[string]bool{}
	for _, v := range have {
		haveSet[dn.NormalizeRef(v)] = true
	}
	var missing []string
	for _, v := range values {
		if !haveSet[dn.NormalizeRef(v)] {
			missing = append(missing, v)
		}
	}
	missing, err = r.writeForm(ctx, missing)
	if err != nil {
		return err
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

// writeForm returns values as clone writes them: a well-known principal by SID, so the target creates its own.
// The target then holds the principal's DN, which is the source's (the clone keeps the domain name).
func (r *runner) writeForm(ctx context.Context, values []string) ([]string, error) {
	out := make([]string, len(values))
	for i, v := range values {
		w, err := r.refs.Write(ctx, v)
		if err != nil {
			return nil, err
		}
		out[i] = w
	}
	return out, nil
}

// referenced creates, once, an entry outside the scope that a reference names (plan.RefReferenced): its missing
// ancestors (see plan.Plan.Ancestor), then the entry as its kind, without its own references (depth one: following them
// would pull the directory in through company-wide groups).
func (r *runner) referenced(ctx context.Context, v string) error {
	return r.outside(ctx, v, func() (*plan.Kind, error) { return r.refs.Referenced(ctx, v) })
}

// outside creates, once, the entry v outside the scope as the kind kind returns (nil: nothing to create), with its
// missing ancestors: a referenced entry, or a group holding entries of the scope.
func (r *runner) outside(ctx context.Context, v string, kind func() (*plan.Kind, error)) error {
	return r.once(ctx, "ref:"+dn.Normalize(v), func() error {
		k, err := kind()
		if err != nil || k == nil {
			return err
		}
		ancestors := dn.Ancestors(v, r.plan.Root)
		for i := len(ancestors) - 1; i >= 0; i-- {
			a := ancestors[i]
			if r.plan.Scope.Has(a) {
				continue
			}
			if err := r.ancestor(ctx, a); err != nil {
				return err
			}
		}
		e, err := r.plan.ReadReferenced(ctx, v, k)
		if err != nil || e == nil {
			return err
		}
		if k.Role == profile.RoleContainer {
			err = r.ensure(ctx, plan.Node{Entry: *e, Kind: k})
		} else {
			err = r.leaf(ctx, k, *e)
		}
		if err == nil {
			r.referencedOne(k)
		}
		return err
	})
}

// ancestor creates, once, an ancestor outside the scope of an entry clone creates there; one the source does not
// return is a placeholder ([scope] unreadable_refs).
func (r *runner) ancestor(ctx context.Context, a string) error {
	// The key of a referenced entry: an ancestor that a reference also names is created once.
	return r.once(ctx, "ref:"+dn.Normalize(a), func() error {
		n, err := r.plan.Ancestor(ctx, a)
		if errors.Is(err, plan.ErrMissing) && r.plan.Job().UnreadableRefs != plan.UnreadableRefsSkip {
			e, ok := plan.PlaceholderParent(a)
			if !ok {
				return err
			}
			return r.addPlaceholder(ctx, e)
		}
		if err != nil {
			return err
		}
		return r.ensure(ctx, n)
	})
}

// placeholder creates, once, the placeholder of a reference naming an entry the source does not return
// (plan.RefPlaceholder), and the parents it lacks.
func (r *runner) placeholder(ctx context.Context, v string) error {
	return r.once(ctx, "ref:"+dn.Normalize(v), func() error {
		ancestors := dn.Ancestors(v, r.plan.Root)
		for i := len(ancestors) - 1; i >= 0; i-- {
			if a := ancestors[i]; !r.plan.Scope.Has(a) {
				if err := r.ancestor(ctx, a); err != nil {
					return err
				}
			}
		}
		e, _ := plan.Placeholder(v)
		return r.addPlaceholder(ctx, e)
	})
}

// addPlaceholder adds e, a placeholder, unless the target holds its DN; it warns once per placeholder.
func (r *runner) addPlaceholder(ctx context.Context, e directory.Entry) error {
	if r.underNotAdded(e.DN) != "" {
		return nil
	}
	cur, err := r.dst.Get(ctx, e.DN, append([]string{"objectClass"}, plan.TargetDNAttrs(r.prof, e.DN)...))
	if err != nil || cur != nil {
		r.taken(e.DN, cur)
		return err
	}
	if err := r.dst.Add(ctx, e); err != nil {
		return fmt.Errorf("add placeholder %s: %w", e.DN, err)
	}
	r.logf("add    %s (placeholder)\n", e.DN)
	r.count(func(rep *Report) {
		rep.Added++
		rep.Placeholders++
	})
	oc := e.Values("objectClass")
	r.warn("a placeholder %s at %s: the source did not return it (the account reading it may not read it)", oc[len(oc)-1], e.DN)
	return nil
}

// configuration creates the entry of the configuration partition a reference names, and the parents it lacks, top
// down and each once ([scope] configuration_refs = "clone"). They count as referenced objects of the kind
// "configuration". The containers right under the partition (CN=Services, CN=Sites, ...) are taken to be there, as
// every forest has them: a dry-run, which cannot ask the target, would otherwise add them again; were one missing,
// the add below it fails with the server's reason.
func (r *runner) configuration(ctx context.Context, v string) error {
	parent := dn.Parent(v)
	if dn.Equal(parent, r.plan.ConfigurationNC()) {
		return nil
	}
	return r.once(ctx, "config:"+dn.Normalize(v), func() error {
		cur, err := r.dst.Get(ctx, v, append([]string{"objectClass"}, plan.TargetDNAttrs(r.prof, v)...))
		if err != nil || cur != nil {
			r.taken(v, cur)
			return err
		}
		if err := r.configuration(ctx, parent); err != nil {
			return err
		}
		e, err := r.plan.ReadConfiguration(ctx, v)
		if err != nil {
			return err
		}
		if e == nil {
			return fmt.Errorf("%s is missing on the source", v)
		}
		if err := r.dst.Add(ctx, *e); err != nil {
			return fmt.Errorf("add %s: %w", v, err)
		}
		r.logf("add    %s\n", v)
		r.count(func(rep *Report) {
			rep.Added++
			rep.Referenced++
			rep.ReferencedKinds[configurationKind]++
		})
		return nil
	})
}

// configurationKind is how the entries of the configuration partition clone creates are counted.
const configurationKind = "configuration"

// notCreated is unwritten for a value whose configuration entry could not be created: the server's reason (a class
// the target's schema lacks, most likely) is the warning, once per entry.
func (r *runner) notCreated(name, from, v string, err error) {
	key := strings.ToLower(name) + "\x00" + dn.NormalizeRef(v)
	r.mu.Lock()
	r.report.Unwritten[name+": names an entry of the configuration partition clone could not create"]++
	first := !r.unwrote[key]
	if first && len(r.unwrote) < maxWarnings {
		r.unwrote[key] = true
	}
	r.mu.Unlock()
	if first {
		r.warn("skip %s values naming %s (first of %s): %v; if the target's schema lacks the class, ldap-cronin schema carries it", name, v, from, err)
	}
}

func (r *runner) referencedOne(k *plan.Kind) {
	r.count(func(rep *Report) {
		rep.Referenced++
		rep.ReferencedKinds[k.Name]++
	})
}

// once runs fn for key at most once in the run; callers for the same key wait for it and get its result.
func (r *runner) once(_ context.Context, key string, fn func() error) error {
	r.mu.Lock()
	o, ok := r.done[key]
	if !ok {
		o = &onceErr{}
		r.done[key] = o
	}
	r.mu.Unlock()
	o.once.Do(func() { o.err = fn() })
	return o.err
}

type onceErr struct {
	once sync.Once
	err  error
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
// sourceExtra reports whether name is read from the source for the account's last step only (profile.Account).
func (r *runner) sourceExtra(name string) bool {
	if r.prof.Account == nil {
		return false
	}
	for _, x := range r.prof.Account.SourceExtra() {
		if strings.EqualFold(x, name) {
			return true
		}
	}
	return false
}

func (r *runner) desired(e directory.Entry) (directory.Entry, error) {
	var stripped []string
	if e, stripped = r.withheld.Strip(e); len(stripped) > 0 {
		// Said of the entries this run writes, not of those an earlier one did (a run resumed after -time-limit).
		for _, v := range r.withheld.ValuesOf(e.DN) {
			r.count(func(rep *Report) {
				rep.Withheld[v.Attr]++
				rep.WithheldWhy[v.Attr+": "+v.Why]++
			})
			r.warn("not written: %s %s of %s: %s (%s)", v.Attr, v.Value, v.DN, v.Why, strings.Join(v.Others, "; "))
		}
	}
	out := directory.Entry{DN: e.DN, Attrs: map[string][]string{}}
	keep := r.opt.Native || r.opt.Preserve
	for n, v := range e.Attrs {
		// The identifier is assigned by the target, so it is not copied (it is read for the marker or the mapping).
		// A native import and a preserving Add, however, pass it through so the target object has the source's.
		// creatorsName and modifiersName hold DNs but are written at creation, not with the references.
		// A value naming principals by SID is written last, translated (writeSDValues).
		if (r.plan.IsRef(n) && !r.creationOnly(n)) || len(v) == 0 || (!keep && strings.EqualFold(n, r.prof.Identity.Attr())) || r.sourceExtra(n) ||
			r.sdOn[strings.ToLower(n)] != "" {
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
