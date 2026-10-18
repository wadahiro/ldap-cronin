package clone

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

// groupWith returns a source holding one group whose member values are n in-scope users plus the given extra DNs.
func groupWith(n int, extra ...string) *fakedir.Dir {
	src := fakedir.New(domain)
	src.Put(base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	src.Put("OU=Users,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Users"}})
	members := append([]string(nil), extra...)
	for i := 0; i < n; i++ {
		u := fmt.Sprintf("CN=u%04d,OU=Users,%s", i, base)
		userAt(src, u, fmt.Sprintf("u%04d", i))
		members = append(members, u)
	}
	src.Put(eng, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Eng"}, "sAMAccountName": {"Eng"}, "member": members})
	return src
}

// Members are added at most memberChunk values per modify, so one operation stays within AD's limits, and a
// re-run adds nothing.
func TestMembersAreAddedInChunksAndOnlyOnce(t *testing.T) {
	for _, c := range []struct{ members, modifies int }{{memberChunk, 1}, {memberChunk + 1, 2}, {2*memberChunk + 1, 3}} {
		t.Run(fmt.Sprint(c.members), func(t *testing.T) {
			src, dst := groupWith(c.members), fakedir.New(domain)
			src.Put("OU=Groups,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Groups"}})
			job, opt := options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: 4}
			if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			if got := countOps(dst, "addvalues member "+eng); got != c.modifies {
				t.Fatalf("%d members took %d modifies, want %d", c.members, got, c.modifies)
			}
			if got := len(dst.Lookup(eng).Values("member")); got != c.members {
				t.Fatalf("%d of %d members on the target", got, c.members)
			}
			if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			if got := countOps(dst, "addvalues member "+eng); got != c.modifies {
				t.Fatalf("a re-run must add no member: %d modifies in all", got)
			}
		})
	}
}

// getCounter counts the target reads of each DN.
type getCounter struct {
	directory.Directory
	mu   sync.Mutex
	gets map[string]int
}

func (g *getCounter) Get(ctx context.Context, d string, a []string) (*directory.Entry, error) {
	g.mu.Lock()
	g.gets[dn.Normalize(d)]++
	g.mu.Unlock()
	return g.Directory.Get(ctx, d, a)
}

// A reference outside the scope is checked on the target once, however many objects point at it, and each skipped
// value is a warning. Beyond maxWarnings the warnings are only counted, so a flood of them cannot exhaust memory.
func TestOutsideReferencesAreCheckedOnceAndWarningsAreCapped(t *testing.T) {
	const outside = "CN=Domain Admins,CN=Users," + domain
	var gone []string
	for i := 0; i < maxWarnings+5; i++ {
		gone = append(gone, fmt.Sprintf("CN=gone%04d,OU=Elsewhere,%s", i, domain))
	}
	src := groupWith(3, gone...)
	src.Put("OU=Groups,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Groups"}})
	for i := 0; i < 3; i++ { // every user has the same manager outside the scope
		src.Lookup(fmt.Sprintf("CN=u%04d,OU=Users,%s", i, base)).Attrs["manager"] = []string{outside}
	}
	dst := &getCounter{Directory: fakedir.New(domain), gets: map[string]int{}}
	var log bytes.Buffer
	rep, err := Run(context.Background(), src, dst, options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: 4}, &log)
	if err != nil {
		t.Fatal(err)
	}
	if got := dst.gets[dn.Normalize(outside)]; got != 1 {
		t.Errorf("a reference outside the scope was read %d times, want once", got)
	}
	if want := len(gone) + 3; rep.WarningCount != want {
		t.Errorf("WarningCount = %d, want %d", rep.WarningCount, want)
	}
	if len(rep.Warnings) != maxWarnings+1 || rep.Warnings[maxWarnings] != "(further warnings suppressed)" {
		t.Errorf("kept %d warnings, last %q", len(rep.Warnings), rep.Warnings[len(rep.Warnings)-1])
	}
	if got := strings.Count(log.String(), "warn   "); got != maxWarnings+1 {
		t.Errorf("%d warning lines logged, want %d", got, maxWarnings+1)
	}
	if got := len(dst.Directory.(*fakedir.Dir).Lookup(eng).Values("member")); got != 3 {
		t.Errorf("the in-scope members must still be added: %d", got)
	}
}
