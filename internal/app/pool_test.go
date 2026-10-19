package app

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

// pooled is a directory with the connection pool of ldapdir.Client: conns connections, one borrowed per operation,
// and a paged search holding its connection until the last page has been handed over. Code that reads while it
// walks needs a second connection, or waits for ever.
type pooled struct {
	*fakedir.Dir
	conns chan struct{}
}

func newPooled(d *fakedir.Dir, n int) *pooled {
	p := &pooled{Dir: d, conns: make(chan struct{}, n)}
	for range n {
		p.conns <- struct{}{}
	}
	return p
}

func (p *pooled) borrow(ctx context.Context) (func(), error) {
	select {
	case <-p.conns:
		return func() { p.conns <- struct{}{} }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *pooled) Walk(ctx context.Context, base, filter string, attrs []string, fn func(directory.Entry) error) error {
	done, err := p.borrow(ctx)
	if err != nil {
		return err
	}
	defer done()
	return p.Dir.Walk(ctx, base, filter, attrs, fn)
}

func (p *pooled) Get(ctx context.Context, d string, attrs []string) (*directory.Entry, error) {
	done, err := p.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	return p.Dir.Get(ctx, d, attrs)
}

func (p *pooled) Add(ctx context.Context, e directory.Entry, c ...directory.Control) error {
	done, err := p.borrow(ctx)
	if err != nil {
		return err
	}
	defer done()
	return p.Dir.Add(ctx, e, c...)
}

func (p *pooled) Replace(ctx context.Context, d string, attrs map[string][]string) error {
	done, err := p.borrow(ctx)
	if err != nil {
		return err
	}
	defer done()
	return p.Dir.Replace(ctx, d, attrs)
}

func (p *pooled) AddValues(ctx context.Context, d, attr string, values []string) error {
	done, err := p.borrow(ctx)
	if err != nil {
		return err
	}
	defer done()
	return p.Dir.AddValues(ctx, d, attr, values)
}

type pooledConn struct{ *pooled }

func (c pooledConn) View([]string) directory.Directory { return c.pooled }
func (c pooledConn) Close()                            {}

// A group with members outside the scope makes the reference pass read the source (what each member is) while it
// walks the groups. With the connections the session opens, that must finish, for a dry-run and a clone alike;
// with a single source connection it waited for ever. diff then reads the same way.
func TestTheReferencePassReadsTheSourceWhileWalkingIt(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		w := newWorld()
		outside := "CN=Carol,OU=Sales," + domain
		w.src.Put("OU=Sales,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Sales"}})
		w.src.Put(outside, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Carol"}, "sAMAccountName": {"carol"}})
		// More groups than the workers' queue holds, so the walk is still running when the first member is read.
		for i := range 60 {
			g := fmt.Sprintf("G%02d", i)
			w.src.Put("CN="+g+",OU=Users,"+base, map[string][]string{"objectClass": {"top", "group"}, "cn": {g}, "sAMAccountName": {g},
				"member": {alice, outside}})
		}
		s := w.open(t, ``)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := s.Clone(ctx, dryRun, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil && !dryRun {
			var code int
			code, err = s.Diff(ctx, DiffOutput{}, &bytes.Buffer{})
			if err == nil && code != ExitSame {
				t.Errorf("diff after the clone: exit %d", code)
			}
		}
		cancel()
		if err != nil {
			t.Fatalf("dry-run=%v: %v", dryRun, err)
		}
	}
}
