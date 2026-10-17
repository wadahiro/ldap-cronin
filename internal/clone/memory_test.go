package clone

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// genSource generates the given number of users on the fly and streams them, holding none of them itself.
// This is so that only the memory use of the tool is measured.
type genSource struct{ n int }

func (g genSource) Walk(ctx context.Context, base, filter string, attrs []string, fn func(directory.Entry) error) error {
	switch {
	case strings.Contains(filter, "organizationalUnit"):
		return fn(directory.Entry{DN: base, Attrs: map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}}})
	case strings.Contains(filter, "person"):
		for i := 0; i < g.n; i++ {
			if err := fn(g.user(i, len(attrs) == 1 && attrs[0] == directory.NoAttrs)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g genSource) user(i int, dnOnly bool) directory.Entry {
	dnStr := fmt.Sprintf("CN=user%07d,OU=IDM,DC=ad,DC=example,DC=com", i)
	if dnOnly {
		return directory.Entry{DN: dnStr}
	}
	name := fmt.Sprintf("user%07d", i)
	return directory.Entry{DN: dnStr, Attrs: map[string][]string{
		"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {name}, "sAMAccountName": {name},
		"mail": {name + "@example.com"}, "givenName": {"Taro"}, "sn": {"Yamada"}, "displayName": {"Yamada Taro"},
		"userAccountControl": {"512"}, "telephoneNumber": {"03-1234-5678"}, "department": {"Sales"},
		"title": {"Staff"}, "description": {"generated user for the memory test"},
	}}
}

func (g genSource) Get(ctx context.Context, dn string, _ []string) (*directory.Entry, error) {
	return &directory.Entry{DN: dn, Attrs: map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}}}, nil
}
func (genSource) Add(context.Context, directory.Entry, ...directory.Control) error { return nil }
func (genSource) Replace(context.Context, string, map[string][]string) error       { return nil }
func (genSource) AddValues(context.Context, string, string, []string) error        { return nil }

// emptyTarget discards writes and behaves as a target where nothing exists.
type emptyTarget struct{}

func (emptyTarget) Walk(context.Context, string, string, []string, func(directory.Entry) error) error {
	return nil
}
func (emptyTarget) Get(context.Context, string, []string) (*directory.Entry, error)  { return nil, nil }
func (emptyTarget) Add(context.Context, directory.Entry, ...directory.Control) error { return nil }
func (emptyTarget) Replace(context.Context, string, map[string][]string) error       { return nil }
func (emptyTarget) AddValues(context.Context, string, string, []string) error        { return nil }

// peakHeapGrowthMB returns the maximum increase in heap usage (MB) while f runs.
func peakHeapGrowthMB(f func()) float64 {
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()
	f()
	close(stop)
	<-done
	if peak.Load() < base.HeapAlloc {
		return 0
	}
	return float64(peak.Load()-base.HeapAlloc) / 1e6
}

// The old implementation, which kept everything in memory, used about 660MB for 200,000 users (about 3.3KB per user).
// This guarantees memory does not grow with the entry count (so even a million entries cannot cause OOM).
const memoryLimitMB = 60

func TestCloneMemoryDoesNotGrowWithUserCount(t *testing.T) {
	const users = 200_000
	var report *Report
	var runErr error
	mb := peakHeapGrowthMB(func() {
		report, runErr = Run(context.Background(), genSource{users}, emptyTarget{}, options(t, allKinds()...), Options{UserPassword: "x", Workers: 8}, io.Discard)
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	t.Logf("clone of %d users: peak heap growth %.0f MB (added=%d)", users, mb, report.Added)
	if report.Added != users+1 {
		t.Fatalf("added=%d", report.Added)
	}
	if mb > memoryLimitMB {
		t.Fatalf("peak heap growth %.0f MB exceeds %d MB: entries are being accumulated", mb, memoryLimitMB)
	}
}

func TestDiffMemoryDoesNotGrowEvenWhenEverythingDiffers(t *testing.T) {
	const users = 200_000
	var count int
	mb := peakHeapGrowthMB(func() {
		sum, err := diff.Run(context.Background(), genSource{users}, emptyTarget{}, options(t, allKinds()...), diff.Options{Workers: 8}, func(diff.Difference) {})
		count = sum.Differences[diff.OnlySource]
		if err != nil {
			t.Error(err)
		}
	})
	t.Logf("diff of %d users against an empty target: peak heap growth %.0f MB (%d differences)", users, mb, count)
	if count != users+1 {
		t.Fatalf("differences=%d", count)
	}
	if mb > memoryLimitMB {
		t.Fatalf("peak heap growth %.0f MB exceeds %d MB: differences are being accumulated", mb, memoryLimitMB)
	}
}
