package clone

import (
	"bytes"
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

// recorder records only the kinds of operations against the target for a specific DN.
type recorder struct {
	directory.Directory
	target string
	mu     sync.Mutex
	ops    []string
}

func (r *recorder) note(op, entryDN string) {
	if dn.Equal(entryDN, r.target) {
		r.mu.Lock()
		r.ops = append(r.ops, op)
		r.mu.Unlock()
	}
}
func (r *recorder) Add(ctx context.Context, e directory.Entry, c ...directory.Control) error {
	r.note("Add", e.DN)
	return r.Directory.Add(context.Background(), e, c...)
}
func (r *recorder) Get(ctx context.Context, d string, a []string) (*directory.Entry, error) {
	r.note("Get", d)
	return r.Directory.Get(context.Background(), d, a)
}
func (r *recorder) Replace(ctx context.Context, d string, a map[string][]string) error {
	r.note("Replace", d)
	return r.Directory.Replace(context.Background(), d, a)
}
func (r *recorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	o := r.ops
	r.ops = nil
	return o
}

// The number of operations on the target translates directly into load on the target AD.
// A new user takes 3 (add, password, UAC) and does no unused reads.
// Re-running an existing, unchanged user takes 2 (the rejected add and one read) and does not repeat the same read.
func TestOperationsPerUserOnTarget(t *testing.T) {
	src := seedSource()
	rec := &recorder{Directory: fakedir.New(domain), target: bob} // bob has no manager, so no reference apply gets in the way
	job, opt := options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: 1}

	if _, err := Run(context.Background(), src, rec, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.take(), []string{"Add", "Replace", "Replace"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("new user: got %v, want %v", got, want)
	}

	if _, err := Run(context.Background(), src, rec, job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.take(), []string{"Add", "Get"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unchanged existing user: got %v, want %v", got, want)
	}
}
