package clone

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

// memJournal is a Journal in memory.
type memJournal map[string]bool

func (j memJournal) Has(key string) bool                      { return j[key] }
func (j memJournal) Mark(_ context.Context, key string) error { j[key] = true; return nil }

// touching counts the target's adds of each entry (normalized DN): a done object is neither added again nor, as the
// add would then find it, read and compared.
type touching struct {
	directory.Directory
	touched map[string]int
}

func (t *touching) Add(ctx context.Context, e directory.Entry, c ...directory.Control) error {
	t.touched[dn.Normalize(e.DN)]++
	return t.Directory.Add(ctx, e, c...)
}

// A run past its deadline stops before the next object with ErrTimeLimit, everything it wrote complete and in the
// journal; the run after it skips those objects without adding them again, writes the rest (the references the
// first did not reach), and ends like a run done at once.
func TestARunStopsAtItsDeadlineAndTheNextGoesOn(t *testing.T) {
	ctx := context.Background()
	src := seedSource()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	journal := memJournal{}
	dst := fakedir.New(domain)
	job := options(t, "ou", "group", "user")

	// The clock moves a minute per user added: past the deadline after the second, before the references.
	ticking := &ticker{Directory: dst, now: &now}
	_, err := Run(ctx, src, ticking, job, Options{UserPassword: "pw", Workers: 1, Now: clock, Deadline: now.Add(90 * time.Second), Journal: journal}, &bytes.Buffer{})
	if !errors.Is(err, ErrTimeLimit) {
		t.Fatalf("got %v", err)
	}
	var done []string
	for k := range journal {
		done = append(done, k)
	}
	for _, d := range []string{eng, alice, bob} {
		if !journal["object "+dn.Normalize(d)] {
			t.Fatalf("%s is not in the journal: %v", d, done)
		}
	}
	if got := dst.Lookup(eng).Values("member"); len(got) != 0 {
		t.Fatalf("the references were not reached: %v", got)
	}

	seen := &touching{Directory: dst, touched: map[string]int{}}
	var log bytes.Buffer
	rep, err := Run(ctx, src, seen, job, Options{UserPassword: "pw", Workers: 1, Now: clock, Journal: journal}, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if rep.Resumed == 0 {
		t.Fatalf("nothing resumed: %+v", rep)
	}
	for k := range journal {
		if d, ok := strings.CutPrefix(k, "object "); ok && contains(done, k) && seen.touched[d] > 0 {
			t.Errorf("%s was done, yet touched %d times", d, seen.touched[d])
		}
	}
	for _, d := range []string{alice, bob, eng} {
		if dst.Lookup(d) == nil {
			t.Fatalf("%s is missing after the second run", d)
		}
	}
	if got := dst.Lookup(eng).Values("member"); len(got) < 2 {
		t.Fatalf("the group's members: %v", got)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ticker moves the clock a minute on each user added.
type ticker struct {
	directory.Directory
	now *time.Time
}

func (t *ticker) Add(ctx context.Context, e directory.Entry, c ...directory.Control) error {
	if contains(e.Values("objectClass"), "user") {
		*t.now = t.now.Add(time.Minute)
	}
	return t.Directory.Add(ctx, e, c...)
}
