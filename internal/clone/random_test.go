package clone

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// names are RDN values a real directory holds: escaped characters, leading and trailing spaces, non-ASCII, and a
// value that looks like an RDN boundary once unescaped.
var names = []string{
	"Alice", "Doe, Bob", "a+b", `q"uote`, "#hash", " lead", "trail ", "東京 太郎", "x,OU=Users", "semi;colon",
	`back\slash`, "<angle>", "Ünïcödé", "dup", "Dup",
}

// randomTree builds a source with nested OUs, users and groups whose references point at each other, at
// themselves (a group in itself), and outside the scope.
func randomTree(rng *rand.Rand) *fakedir.Dir {
	src := fakedir.New(domain)
	src.Put(base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	ous := []string{base}
	used := map[string]bool{}
	child := func(kind, parent string) (string, string) {
		for {
			v := names[rng.Intn(len(names))]
			if rng.Intn(3) == 0 {
				v = fmt.Sprintf("%s %d", v, rng.Intn(100))
			}
			d := kind + "=" + ldap.EscapeDN(v) + "," + parent
			if key := strings.ToLower(d); !used[key] {
				used[key] = true
				return d, v
			}
		}
	}
	for i, n := 0, 1+rng.Intn(5); i < n; i++ {
		d, v := child("OU", ous[rng.Intn(len(ous))])
		src.Put(d, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {v}, "description": {"部署 " + v}})
		ous = append(ous, d)
	}
	// Outside the scope: a built-in the target lacks, a DN of nothing, and users that exist on the source
	// (referenced objects, cloned because they are referenced).
	src.Put("OU=Elsewhere,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Elsewhere"}})
	outside := []string{"CN=Domain Admins,CN=Users," + domain, "CN=gone,OU=Elsewhere," + domain}
	for i, n := 0, rng.Intn(3); i < n; i++ {
		d, v := child("CN", "OU=Elsewhere,"+domain)
		src.Put(d, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {v},
			"sAMAccountName": {fmt.Sprintf("x%03d", i)}, "userAccountControl": {"512"}})
		outside = append(outside, d)
	}
	var users, groups []string
	for i, n := 0, 3+rng.Intn(20); i < n; i++ {
		d, v := child("CN", ous[rng.Intn(len(ous))])
		attrs := map[string][]string{
			"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {v},
			"sAMAccountName": {fmt.Sprintf("u%03d", i)}, "userAccountControl": {[]string{"512", "514", "66048"}[rng.Intn(3)]},
			"mail": {fmt.Sprintf("u%03d@real.example", i)},
		}
		if rng.Intn(2) == 0 {
			attrs["title"] = []string{names[rng.Intn(len(names))]}
		}
		if rng.Intn(2) == 0 {
			attrs["telephoneNumber"] = []string{fmt.Sprintf("+81 3 %04d", rng.Intn(10000))}
		}
		src.Put(d, attrs)
		users = append(users, d)
	}
	for i, n := 0, 1+rng.Intn(4); i < n; i++ {
		parent := ous[rng.Intn(len(ous))]
		if rng.Intn(4) == 0 {
			parent = users[rng.Intn(len(users))] // a parent leaf: a user holding a child
		}
		d, v := child("CN", parent)
		src.Put(d, map[string][]string{"objectClass": {"top", "group"}, "cn": {v}, "sAMAccountName": {fmt.Sprintf("g%03d", i)}})
		groups = append(groups, d)
	}
	pick := func(from []string) string { return from[rng.Intn(len(from))] }
	for _, u := range users {
		switch rng.Intn(3) {
		case 0:
			src.Lookup(u).Attrs["manager"] = []string{pick(users)}
		case 1:
			src.Lookup(u).Attrs["manager"] = []string{pick(outside)}
		}
	}
	for _, g := range groups {
		seen := map[string]bool{}
		var members []string
		for i, n := 0, rng.Intn(len(users)+2); i < n; i++ {
			m := pick(users)
			switch rng.Intn(6) {
			case 0:
				m = pick(groups) // nested groups, possibly the group itself
			case 1:
				m = pick(outside)
			}
			if !seen[strings.ToLower(m)] {
				seen[strings.ToLower(m)] = true
				members = append(members, m)
			}
		}
		if len(members) > 0 {
			src.Lookup(g).Attrs["member"] = members
		}
	}
	return src
}

func newRand(seed int64) *rand.Rand { return rand.New(rand.NewSource(seed)) }

// For any tree: clone, then diff finds nothing, and a second clone writes nothing. Each seed is a different tree,
// worker count and order of parallel work.
func TestRandomTreesCloneToAnIdenticalTargetAndRerunsWriteNothing(t *testing.T) {
	for seed := int64(1); seed <= 60; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := newRand(seed)
			src, dst := randomTree(rng), fakedir.New(domain)
			dst.IDPrefix = 0xd1
			root, err := identity.RootKey(context.Background(), src, base, identity.ObjectGUID)
			if err != nil {
				t.Fatal(err)
			}
			m := identity.NewMarker("adminDisplayName", root)
			job := options(t, allKinds()...)
			opt := Options{UserPassword: "Fixed1!", Workers: 1 + rng.Intn(8), Marker: &m}
			if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			var diffs []string
			if _, err := diff.Run(context.Background(), src, dst, job, diff.Options{Workers: opt.Workers, Resolver: identity.ByMarker(m)},
				func(d diff.Difference) { diffs = append(diffs, fmt.Sprintf("%s %s %s", d.Kind, d.DN, d.Attr)) }); err != nil {
				t.Fatal(err)
			}
			if len(diffs) != 0 {
				t.Fatalf("a fresh clone must match the source:\n%s", strings.Join(diffs, "\n"))
			}

			writes := len(dst.Ops)
			rep, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Added != 0 || rep.Updated != 0 || len(dst.Ops) != writes {
				t.Fatalf("a re-run must write nothing: %+v, writes %v", rep, dst.Ops[writes:])
			}
		})
	}
}

// randomGenericTree is randomTree for a generic server: inetOrgPerson users, groupOfNames groups (which need a
// member), multi-valued manager and seeAlso references.
func randomGenericTree(rng *rand.Rand) *fakedir.Dir {
	src := fakedir.New(gRoot)
	src.Put(gBase, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	ous := []string{gBase}
	used := map[string]bool{}
	child := func(kind, parent string) (string, string) {
		for {
			v := names[rng.Intn(len(names))]
			if rng.Intn(3) == 0 {
				v = fmt.Sprintf("%s %d", v, rng.Intn(100))
			}
			d := kind + "=" + ldap.EscapeDN(v) + "," + parent
			if key := strings.ToLower(d); !used[key] {
				used[key] = true
				return d, v
			}
		}
	}
	for i, n := 0, 1+rng.Intn(4); i < n; i++ {
		d, v := child("ou", ous[rng.Intn(len(ous))])
		src.Put(d, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {v}})
		ous = append(ous, d)
	}
	src.Put("ou=Elsewhere,"+gRoot, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Elsewhere"}})
	outside := []string{"uid=outsider,ou=Elsewhere," + gRoot} // names nothing: written as it is
	for i, n := 0, rng.Intn(3); i < n; i++ {
		d, v := child("cn", "ou=Elsewhere,"+gRoot)
		src.Put(d, map[string][]string{"objectClass": {"top", "inetOrgPerson"}, "cn": {v}, "sn": {"X"}, "uid": {fmt.Sprintf("x%03d", i)}})
		outside = append(outside, d)
	}
	var users []string
	for i, n := 0, 2+rng.Intn(15); i < n; i++ {
		d, v := child("cn", ous[rng.Intn(len(ous))])
		attrs := map[string][]string{"objectClass": {"top", "inetOrgPerson"}, "cn": {v}, "sn": {"S"}, "uid": {fmt.Sprintf("u%03d", i)},
			"userPassword": {"{SSHA}real-hash"}}
		if rng.Intn(2) == 0 {
			attrs["title"] = []string{names[rng.Intn(len(names))]}
		}
		src.Put(d, attrs)
		users = append(users, d)
	}
	pick := func(from []string) string { return from[rng.Intn(len(from))] }
	for _, u := range users {
		if rng.Intn(2) == 0 {
			src.Lookup(u).Attrs["manager"] = []string{pick(users), pick(outside)}
		}
	}
	var groups []string
	for i, n := 0, 1+rng.Intn(4); i < n; i++ {
		parent := ous[rng.Intn(len(ous))]
		if rng.Intn(4) == 0 {
			parent = pick(users) // a parent leaf: a generic server has no structure rules
		}
		d, v := child("cn", parent)
		members := []string{pick(users)} // groupOfNames needs one
		for j, m := 0, rng.Intn(len(users)); j < m; j++ {
			c := pick(users)
			switch rng.Intn(5) {
			case 0:
				c = pick(outside)
			case 1:
				if len(groups) > 0 {
					c = pick(groups)
				}
			}
			dup := false
			for _, x := range members {
				dup = dup || strings.EqualFold(x, c)
			}
			if !dup {
				members = append(members, c)
			}
		}
		src.Put(d, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {v}, "member": members})
		groups = append(groups, d)
	}
	return src
}

// The generic counterpart: clone preserving entryUUID, then diff by identifier finds nothing, a re-run writes
// nothing, and the dry-run LDIF loads to the same target.
func TestRandomGenericTreesCloneToAnIdenticalTargetAndRerunsWriteNothing(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := newRand(seed)
			src := randomGenericTree(rng)
			target := func() *fakedir.Dir {
				d := fakedir.New(gRoot)
				d.IDPrefix, d.Relax = 0xd1, profile.RelaxOID
				d.RequireAttr = map[string]string{"groupofnames": "member", "inetorgperson": "sn"}
				return d
			}
			dst, job := target(), genericOptions(t)
			opt := Options{UserPassword: "Fixed1!", Workers: 1 + rng.Intn(8), Preserve: true, Operational: true}
			if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			var diffs []string
			if _, err := diff.Run(context.Background(), src, dst, job, diff.Options{Workers: opt.Workers, Resolver: identity.ByIdentity(identity.EntryUUID)},
				func(d diff.Difference) { diffs = append(diffs, fmt.Sprintf("%s %s %s", d.Kind, d.DN, d.Attr)) }); err != nil {
				t.Fatal(err)
			}
			if len(diffs) != 0 {
				t.Fatalf("a fresh clone must match the source:\n%s", strings.Join(diffs, "\n"))
			}
			writes := len(dst.Ops)
			rep, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			if rep.Added != 0 || rep.Updated != 0 || len(dst.Ops) != writes {
				t.Fatalf("a re-run must write nothing: %+v, writes %v", rep, dst.Ops[writes:])
			}
			dryRunEqualsClone(t, src, target(), job, true)
		})
	}
}
