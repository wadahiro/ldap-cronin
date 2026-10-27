package clone

import (
	"bytes"
	"context"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

// memberDiff runs diff and returns the member values only on the source (removed on the target) and only on the
// target (added there) for group g, and the summary.
func memberDiff(t *testing.T, src, dst *fakedir.Dir, job plan.Job, g string) (removed, added []string, sum diff.Summary) {
	t.Helper()
	sum, err := diff.Run(context.Background(), src, dst, job, diff.Options{Workers: 2}, func(d diff.Difference) {
		switch {
		case d.Kind == diff.Differ && dn.Equal(d.DN, g) && strings.EqualFold(d.Attr, "member"):
			removed, added = append(d.OnlySource, d.Source...), append(d.OnlyTarget, d.Target...)
		default:
			t.Errorf("unexpected difference: %s %s %s", d.Kind, d.DN, d.Attr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return removed, added, sum
}

func setMembers(d *fakedir.Dir, g string, keep func(string) bool, extra ...string) {
	var out []string
	for _, m := range d.Lookup(g).Values("member") {
		if keep(m) {
			out = append(out, m)
		}
	}
	d.Lookup(g).Attrs["member"] = append(out, extra...)
}

// The test this tool exists for: a program under test rewrites a group's members, and diff must show every member
// it removed or added, whatever the member is: an object of the scope, a built-in the target holds, or (on a
// generic server) a DN of nothing cloned.
func TestDiffShowsEveryMemberRemovedOrAddedOnTheTarget(t *testing.T) {
	const admins = "CN=Domain Admins,CN=Users," + domain
	const guests = "CN=Guests,CN=Builtin," + domain
	builtins := func(d *fakedir.Dir) {
		d.Put("CN=Users,"+domain, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Users"}})
		d.Put("CN=Builtin,"+domain, map[string][]string{"objectClass": {"top", "builtinDomain"}, "cn": {"Builtin"}})
		d.Put(admins, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Domain Admins"}})
		d.Put(guests, map[string][]string{"objectClass": {"top", "group"}, "cn": {"Guests"}})
	}
	adClone := func(t *testing.T) (*fakedir.Dir, *fakedir.Dir, plan.Job) {
		src, dst := seedSource(), fakedir.New(domain)
		builtins(src)
		builtins(dst) // a target of the same domain holds the built-ins
		job := options(t, allKinds()...)
		if _, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 2}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if got := dst.Lookup(eng).Values("member"); len(got) != 3 {
			t.Fatalf("every member, the built-in included, must be cloned: %v", got)
		}
		return src, dst, job
	}
	is := func(v string) func(string) bool { return func(m string) bool { return !dn.Equal(m, v) } }

	t.Run("an in-scope member removed", func(t *testing.T) {
		src, dst, job := adClone(t)
		setMembers(dst, eng, is(alice))
		if removed, added, _ := memberDiff(t, src, dst, job, eng); !slices.Equal(removed, []string{alice}) || added != nil {
			t.Fatalf("removed %v added %v", removed, added)
		}
	})
	t.Run("a built-in member removed", func(t *testing.T) {
		src, dst, job := adClone(t)
		setMembers(dst, eng, is(admins))
		if removed, added, _ := memberDiff(t, src, dst, job, eng); !slices.Equal(removed, []string{admins}) || added != nil {
			t.Fatalf("removed %v added %v", removed, added)
		}
	})
	t.Run("an object outside the scope added", func(t *testing.T) {
		src, dst, job := adClone(t)
		setMembers(dst, eng, func(string) bool { return true }, guests)
		if removed, added, _ := memberDiff(t, src, dst, job, eng); removed != nil || !slices.Equal(added, []string{guests}) {
			t.Fatalf("removed %v added %v", removed, added)
		}
	})
	t.Run("a member the target cannot hold is counted, not compared", func(t *testing.T) {
		src, dst := seedSource(), fakedir.New(domain) // no built-ins on this target
		job := options(t, allKinds()...)
		if _, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 2}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		removed, added, sum := memberDiff(t, src, dst, job, eng)
		if removed != nil || added != nil || sum.NotCompared["member"] != 1 {
			t.Fatalf("removed %v added %v not compared %v", removed, added, sum.NotCompared)
		}
		var out bytes.Buffer
		diff.WriteSummary(&out, job, sum, nil)
		if !regexp.MustCompile(`references not compared \(clone cannot write them\): 1\n  member: names \S.*  1\n`).MatchString(out.String()) {
			t.Fatalf("the summary must say what was not compared:\n%s", out.String())
		}
	})
	t.Run("generic: a member naming nothing cloned is written, and its removal shows", func(t *testing.T) {
		src, dst := genericSource(), fakedir.New(gRoot)
		job := genericOptions(t)
		if _, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 2}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		outsider := "uid=outsider,ou=Elsewhere," + gRoot
		setMembers(dst, gEng, is(outsider))
		if removed, added, _ := memberDiff(t, src, dst, job, gEng); !slices.Equal(removed, []string{outsider}) || added != nil {
			t.Fatalf("removed %v added %v", removed, added)
		}
	})
}

// Members outside the scope are reproduced: a user outside base_dn is cloned as a user (with its ancestors, the
// fixed password and a marker, without its own references), a well-known principal is written by SID so the target
// creates its own; a principal of another domain cannot be, and is counted. Then removing any of them shows.
func TestMembersOutsideTheScopeAreReproduced(t *testing.T) {
	const (
		carol    = "CN=Carol,OU=Sales," + domain
		dave     = "CN=Dave,OU=Sales," + domain
		authUser = "CN=S-1-5-11,CN=ForeignSecurityPrincipals," + domain
		trusted  = "CN=S-1-5-21-1-2-3-1104,CN=ForeignSecurityPrincipals," + domain
	)
	source := func() *fakedir.Dir {
		src := seedSource()
		src.Put("OU=Sales,"+domain, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Sales"}, "description": {"営業"}})
		userAt(src, carol, "carol")
		src.Lookup(carol).Attrs["title"] = []string{"Lead"}
		src.Lookup(carol).Attrs["manager"] = []string{dave} // her own reference: not followed
		userAt(src, dave, "dave")
		src.Put("CN=ForeignSecurityPrincipals,"+domain, map[string][]string{"objectClass": {"top", "container"}})
		src.Put(authUser, map[string][]string{"objectClass": {"top", "foreignSecurityPrincipal"}, "cn": {"S-1-5-11"}})
		src.Put(trusted, map[string][]string{"objectClass": {"top", "foreignSecurityPrincipal"}, "cn": {"S-1-5-21-1-2-3-1104"}})
		g := src.Lookup(eng)
		g.Attrs["member"] = append(g.Attrs["member"], carol, authUser, trusted)
		return src
	}
	cloneIt := func(t *testing.T, refs string) (*fakedir.Dir, *fakedir.Dir, plan.Job, *Report) {
		src, dst := source(), fakedir.New(domain)
		dst.IDPrefix = 0xd1
		job := options(t, allKinds()...)
		job.References = refs
		rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 3}, &bytes.Buffer{})
		if err != nil {
			t.Fatal(err)
		}
		return src, dst, job, rep
	}

	src, dst, job, rep := cloneIt(t, "")
	if rep.Referenced != 1 {
		t.Fatalf("carol must be cloned as a referenced object: %+v", rep)
	}
	c := dst.Lookup(carol)
	if c == nil || c.Values("unicodePwd") == nil || c.Values("title")[0] != "Lead" || c.Values("manager") != nil {
		t.Fatalf("carol must be a full user without her own references: %v", c)
	}
	if dst.Lookup("OU=Sales,"+domain) == nil || dst.Lookup(dave) != nil {
		t.Fatal("her OU must be created, her manager not")
	}
	members := dst.Lookup(eng).Values("member")
	for _, want := range []string{alice, bob, carol, authUser} {
		if !slices.ContainsFunc(members, func(m string) bool { return dn.Equal(m, want) }) {
			t.Errorf("member %s is missing: %v", want, members)
		}
	}
	removed, added, sum := memberDiff(t, src, dst, job, eng)
	if removed != nil || added != nil || sum.Referenced != 1 || sum.NotCompared["member"] != 2 {
		// Domain Admins (the target has none) and the trusted domain's principal
		t.Fatalf("a fresh clone: removed %v added %v referenced %d not compared %v", removed, added, sum.Referenced, sum.NotCompared)
	}

	for _, gone := range []string{carol, authUser} {
		t.Run("removing "+gone, func(t *testing.T) {
			src, dst, job, _ := cloneIt(t, "")
			setMembers(dst, eng, func(m string) bool { return !dn.Equal(m, gone) })
			if removed, _, _ := memberDiff(t, src, dst, job, eng); len(removed) != 1 || !dn.Equal(removed[0], gone) {
				t.Fatalf("removed %v", removed)
			}
		})
	}
	t.Run("a referenced object changed on the target", func(t *testing.T) {
		src, dst, job, _ := cloneIt(t, "")
		dst.Lookup(carol).Attrs["title"] = []string{"Intern"}
		var got []string
		if _, err := diff.Run(context.Background(), src, dst, job, diff.Options{Workers: 2}, func(d diff.Difference) {
			got = append(got, string(d.Kind)+" "+d.DN+" "+d.Attr)
		}); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, []string{"DIFF " + carol + " title"}) {
			t.Fatalf("%v", got)
		}
	})
	t.Run("a re-run writes nothing", func(t *testing.T) {
		src, dst, job, _ := cloneIt(t, "")
		writes := len(dst.Ops)
		rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 3}, &bytes.Buffer{})
		if err != nil || rep.Added != 0 || rep.Updated != 0 || len(dst.Ops) != writes {
			t.Fatalf("%+v %v %v", rep, err, dst.Ops[writes:])
		}
	})
	t.Run(`references = "existing"`, func(t *testing.T) {
		src, dst, job, rep := cloneIt(t, "existing")
		if rep.Referenced != 0 || dst.Lookup(carol) != nil {
			t.Fatalf("nothing outside the scope is created: %+v", rep)
		}
		if _, _, sum := memberDiff(t, src, dst, job, eng); sum.NotCompared["member"] != 3 {
			t.Fatalf("carol, Domain Admins and the trusted principal are not compared: %v", sum.NotCompared)
		}
	})
}
