package plan

import (
	"context"
	"fmt"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// Usage is, for one kind, how many entries under base_dn hold each attribute.
type Usage struct {
	Kind    *Kind
	Entries int
	// Attrs counts the entries holding each attribute, by lowercase name; Names keeps the server's spelling.
	Attrs map[string]int
	Names map[string]string
}

// Survey reads every user attribute of the entries of each kind under base_dn and counts the entries holding each,
// so a deployment sees which attributes (a schema extension of its own) it would leave behind. It reads as much as a
// clone does, so it is a command of its own (list-attrs -config), never a step of clone or diff. No value is kept.
func Survey(ctx context.Context, src directory.Directory, job Job) ([]Usage, error) {
	out := make([]Usage, 0, len(job.Kinds))
	for i := range job.Kinds {
		k := &job.Kinds[i]
		u := Usage{Kind: k, Attrs: map[string]int{}, Names: map[string]string{}}
		err := src.Walk(ctx, job.BaseDN, k.Filter, []string{directory.AllAttrs}, func(e directory.Entry) error {
			u.Entries++
			seen := map[string]bool{}
			for n, v := range e.Attrs {
				if len(v) == 0 {
					continue
				}
				name, _, _ := strings.Cut(n, ";") // member;range=0-1499 is member
				key := strings.ToLower(name)
				if seen[key] {
					continue
				}
				seen[key] = true
				u.Attrs[key]++
				if _, ok := u.Names[key]; !ok {
					u.Names[key] = name
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", k.Name, err)
		}
		out = append(out, u)
	}
	return out, nil
}
