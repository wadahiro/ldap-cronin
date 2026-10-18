package clone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

var errInjected = errors.New("injected target failure")

// failing fails the first target operation, after skip others, that matches op (Add, Get, Replace, AddValues), DN
// and, for Get, Replace and AddValues, attribute; every other operation goes through. It stands for a target that dies, times out or refuses
// one write in the middle of a run.
type failing struct {
	directory.Directory
	op, dn, attr string
	skip         int

	mu    sync.Mutex
	fired bool
}

func (f *failing) fire(op, entryDN string, attrs ...string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fired || op != f.op || !dn.Equal(entryDN, f.dn) {
		return false
	}
	if f.attr != "" {
		found := false
		for _, a := range attrs {
			found = found || strings.EqualFold(a, f.attr)
		}
		if !found {
			return false
		}
	}
	if f.skip > 0 {
		f.skip--
		return false
	}
	f.fired = true
	return true
}

func (f *failing) Add(ctx context.Context, e directory.Entry, c ...directory.Control) error {
	if f.fire("Add", e.DN) {
		return errInjected
	}
	return f.Directory.Add(ctx, e, c...)
}

func (f *failing) Get(ctx context.Context, d string, a []string) (*directory.Entry, error) {
	if f.fire("Get", d, a...) {
		return nil, errInjected
	}
	return f.Directory.Get(ctx, d, a)
}

func (f *failing) Replace(ctx context.Context, d string, attrs map[string][]string) error {
	names := make([]string, 0, len(attrs))
	for n := range attrs {
		names = append(names, n)
	}
	if f.fire("Replace", d, names...) {
		return errInjected
	}
	return f.Directory.Replace(ctx, d, attrs)
}

func (f *failing) AddValues(ctx context.Context, d, attr string, values []string) error {
	if f.fire("AddValues", d, attr) {
		return errInjected
	}
	return f.Directory.AddValues(ctx, d, attr, values)
}

type fault struct {
	name, op, dn, attr string
	skip               int
}

// A failure at any step stops the run with that error, and a re-run continues from where it stopped: the result is
// the same as a run that never failed. This is what README promises for an interrupted clone.
func TestAFailureAtAnyStepStopsTheRunAndARerunCompletesIt(t *testing.T) {
	outside := "CN=Domain Admins,CN=Users," + domain
	faults := []fault{
		{"add an OU", "Add", "OU=Users," + base, "", 0},
		{"add a create-only container", "Add", staff, "", 0},
		{"add a user", "Add", alice, "", 0},
		{"add a group", "Add", eng, "", 0},
		{"set a password", "Replace", alice, "unicodePwd", 0},
		{"set userAccountControl", "Replace", bob, "userAccountControl", 0},
		{"check a reference outside the scope", "Get", outside, "", 0},
		{"read before applying a reference", "Get", eng, "member", 0},
		{"apply a single-valued reference", "Replace", alice, "manager", 0},
		{"add members", "AddValues", eng, "member", 0},
	}
	for _, workers := range []int{1, 4} {
		for _, f := range faults {
			t.Run(fmt.Sprintf("%s/workers=%d", f.name, workers), func(t *testing.T) {
				src, dst := seedSource(), fakedir.New(domain)
				job, opt := options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: workers}
				expectFailureThenConvergence(t, src, dst, job, opt, f, func() {
					for _, u := range []string{alice, bob} {
						if dst.Lookup(u).Values("unicodePwd") == nil {
							t.Errorf("%s has no password after the re-run", u)
						}
					}
					if got := dst.Lookup(bob).Values("userAccountControl"); len(got) != 1 || got[0] != "514" {
						t.Errorf("bob's userAccountControl: %v", got)
					}
				})
			})
		}
	}
}

func TestAFailureOnAGenericServerStopsTheRunAndARerunCompletesIt(t *testing.T) {
	faults := []fault{
		{"add a user", "Add", gAlice, "", 0},
		{"add a group", "Add", gEng, "", 0},
		{"add a group again with its members (the schema requires one)", "Add", gEng, "", 1},
		{"add a reference", "AddValues", gBob, "manager", 0},
	}
	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			src, dst := genericSource(), fakedir.New(gRoot)
			dst.RequireAttr = map[string]string{"groupofnames": "member"}
			expectFailureThenConvergence(t, src, dst, genericOptions(t), Options{UserPassword: "Fixed1!", Workers: 2}, f, func() {
				if pw := dst.Lookup(gAlice).Values("userPassword"); len(pw) != 1 || pw[0] != "Fixed1!" {
					t.Errorf("alice's password after the re-run: %v", pw)
				}
			})
		})
	}
}

func expectFailureThenConvergence(t *testing.T, src, dst *fakedir.Dir, job plan.Job, opt Options, f fault, check func()) {
	t.Helper()
	bad := &failing{Directory: dst, op: f.op, dn: f.dn, attr: f.attr, skip: f.skip}
	rep, err := Run(context.Background(), src, bad, job, opt, &bytes.Buffer{})
	if !bad.fired {
		t.Fatalf("the fault was never reached: %+v", f)
	}
	if !errors.Is(err, errInjected) {
		t.Fatalf("the run must stop with the target's error, got %v", err)
	}
	if rep == nil {
		t.Fatal("a failed run must still report what it did")
	}
	if adds := countOps(dst, "add "); rep.Added != adds {
		t.Errorf("the report says %d added, the target got %d", rep.Added, adds)
	}

	if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if diffs := runDiff(t, src, dst, job); len(diffs) != 0 {
		var got []string
		for _, d := range diffs {
			got = append(got, fmt.Sprintf("%s %s %s", d.Kind, d.DN, d.Attr))
		}
		t.Fatalf("after the re-run the target must match the source: %v", got)
	}
	check()
}

func countOps(d *fakedir.Dir, prefix string) int {
	n := 0
	for _, op := range d.Ops {
		if strings.HasPrefix(op, prefix) {
			n++
		}
	}
	return n
}
