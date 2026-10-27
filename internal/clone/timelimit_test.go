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
	"github.com/wadahiro/ldap-cronin/internal/profile"
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

// A value withheld from an entry an earlier run wrote is not warned of again by a resumed run, which skips it.
func TestAResumedRunWarnsOnlyOfTheValuesItWithholds(t *testing.T) {
	ctx := context.Background()
	src := seedSource()
	leftover := `CN=Alice\0ACNF:0f0e0d0c-0b0a-0908-0706-050403020100,OU=Tokyo,OU=Users,` + base
	src.Lookup(alice).Attrs["userPrincipalName"] = []string{"alice@ad.example.com"}
	src.Put(leftover, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Alice\nCNF:0f0e0d0c-0b0a-0908-0706-050403020100"},
		"sAMAccountName": {"$DUPLICATE-1f4"}, "userPrincipalName": {"alice@ad.example.com"}, "userAccountControl": {"512"}})
	job := options(t, "ou", "group", "user")
	for name, c := range map[string]struct {
		done bool
		warn bool
	}{"first run": {false, true}, "resumed": {true, false}} {
		t.Run(name, func(t *testing.T) {
			dst := fakedir.New(domain)
			dst.Put("", map[string][]string{"vendorName": {"Samba Team (https://www.samba.org)"}})
			journal := memJournal{}
			if c.done {
				journal["object "+dn.Normalize(leftover)] = true
			}
			var log bytes.Buffer
			rep, err := Run(ctx, src, dst, job, Options{UserPassword: "pw", Workers: 1, Journal: journal}, &log)
			if err != nil {
				t.Fatalf("%v\n%s", err, log.String())
			}
			warned := strings.Contains(log.String(), "not written: userPrincipalName")
			if warned != c.warn || (rep.Withheld["userPrincipalName"] == 1) != c.warn {
				t.Fatalf("warned %v, withheld %+v\n%s", warned, rep.Withheld, log.String())
			}
		})
	}
}

// An entry the journal holds is written again when values are held back from it: an earlier version, which did not
// hold them back, may have written them, and Samba then refuses another entry (here the computer's HOST/X, given
// the user's http/X). The resumed run takes the value off the user, adds the computer, and writes it back last.
func TestAResumedRunRewritesAJournaledEntryValuesAreWithheldFrom(t *testing.T) {
	ctx := context.Background()
	src := seedSource()
	svc := "CN=Svc,OU=Users," + base
	pc := "CN=PC1,OU=Users," + base
	src.Put(svc, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Svc"}, "sAMAccountName": {"svc"},
		"servicePrincipalName": {"http/pc1.ad.example.com"}, "userAccountControl": {"512"}})
	src.Put(pc, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user", "computer"}, "cn": {"PC1"},
		"sAMAccountName": {"PC1$"}, "servicePrincipalName": {"HOST/pc1.ad.example.com"}, "userAccountControl": {"4096"}})
	job := jobFor(t, profile.AD, base, []string{"ou", "group", "user", "computer"}, profile.Override{Extra: []string{"servicePrincipalName"}})
	dst := fakedir.New(domain)
	config := "CN=Configuration," + domain
	dst.Put("", map[string][]string{"vendorName": {"Samba Team (https://www.samba.org)"}, "defaultNamingContext": {domain}, "configurationNamingContext": {config}})
	dst.Put("CN=Directory Service,CN=Windows NT,CN=Services,"+config, map[string][]string{"objectClass": {"nTDSService"}, "sPNMappings": {"host=cifs,http"}})
	// What the earlier version left: everything up to the user written, the user's http/X with it.
	journal := memJournal{}
	if _, err := Run(ctx, src, dst, job, Options{UserPassword: "pw", Workers: 1, Journal: journal}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	dst.Delete(pc)
	delete(journal, "object "+dn.Normalize(pc))
	dst.Lookup(svc).Attrs["servicePrincipalName"] = []string{"http/pc1.ad.example.com"}

	var log bytes.Buffer
	rep, err := Run(ctx, src, dst, job, Options{UserPassword: "pw", Workers: 1, Journal: journal}, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	if got := dst.Lookup(svc).Values("servicePrincipalName"); strings.Join(got, "") != "http/pc1.ad.example.com" || dst.Lookup(pc) == nil ||
		rep.Resumed == 0 || rep.Later != 1 {
		t.Fatalf("the user's SPNs %v, the computer %v, resumed %d\n%s", got, dst.Lookup(pc) != nil, rep.Resumed, log.String())
	}
}

// A value written last is not lost to a run stopped at its deadline before the end: nothing records it, the next
// run holds it back again from the same source and writes it once every entry is written.
func TestAValueWrittenLastSurvivesARunStoppedBeforeTheEnd(t *testing.T) {
	ctx := context.Background()
	src := seedSource()
	svc, pc := "CN=Svc,OU=Users,"+base, "CN=PC1,OU=Users,"+base
	src.Put(svc, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Svc"}, "sAMAccountName": {"svc"},
		"servicePrincipalName": {"http/pc1.ad.example.com"}, "userAccountControl": {"512"}})
	src.Put(pc, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user", "computer"}, "cn": {"PC1"},
		"sAMAccountName": {"PC1$"}, "servicePrincipalName": {"HOST/pc1.ad.example.com"}, "userAccountControl": {"4096"}})
	job := jobFor(t, profile.AD, base, []string{"ou", "group", "user", "computer"}, profile.Override{Extra: []string{"servicePrincipalName"}})
	dst := fakedir.New(domain)
	config := "CN=Configuration," + domain
	dst.Put("", map[string][]string{"vendorName": {"Samba Team (https://www.samba.org)"}, "defaultNamingContext": {domain}, "configurationNamingContext": {config}})
	dst.Put("CN=Directory Service,CN=Windows NT,CN=Services,"+config, map[string][]string{"objectClass": {"nTDSService"}, "sPNMappings": {"host=cifs,http"}})
	journal := memJournal{}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	// A minute per user added: past the deadline once the users are in, before the computer.
	ticking := &ticker{Directory: dst, now: &now}
	_, err := Run(ctx, src, ticking, job, Options{UserPassword: "pw", Workers: 1, Now: clock, Deadline: now.Add(150 * time.Second), Journal: journal}, &bytes.Buffer{})
	if !errors.Is(err, ErrTimeLimit) || dst.Lookup(pc) != nil || dst.Lookup(svc).Values("servicePrincipalName") != nil {
		t.Fatalf("stopped before the computer, the alias not yet written: %v, computer %v, %v", err, dst.Lookup(pc) != nil, dst.Lookup(svc).Values("servicePrincipalName"))
	}
	var log bytes.Buffer
	rep, err := Run(ctx, src, dst, job, Options{UserPassword: "pw", Workers: 1, Now: clock, Journal: journal}, &log)
	if err != nil || dst.Lookup(pc) == nil || strings.Join(dst.Lookup(svc).Values("servicePrincipalName"), "") != "http/pc1.ad.example.com" || rep.Later != 1 {
		t.Fatalf("the next run: %v, computer %v, the user's SPNs %v, later %d\n%s", err, dst.Lookup(pc) != nil, dst.Lookup(svc).Values("servicePrincipalName"), rep.Later, log.String())
	}
}
