package clone

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

// The entries of a source that the reading account may not read: AD returns the group's member values naming them,
// and not the entries. A fake source that lacks them is such a source.
const (
	hidden      = "CN=Hidden,OU=Secret," + domain    // under a parent unread too
	hiddenInOU  = "CN=Hidden In,OU=Users," + base    // under base_dn, so never walked
	carol       = "CN=Carol,OU=Secret2," + domain    // readable, under a parent unread
	unplaceable = "OU=Somewhere,OU=Secret," + domain // no contact takes an OU= name
	secret      = "OU=Secret," + domain
	secret2     = "OU=Secret2," + domain
)

func unreadableSource() *fakedir.Dir {
	src := seedSource()
	src.Put(carol, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"Carol"}, "sAMAccountName": {"carol"}})
	g := src.Lookup(eng)
	g.Attrs["member"] = append(g.Attrs["member"], hidden, hiddenInOU, carol, unplaceable)
	return src
}

// A member the source does not return is kept as a placeholder contact, under placeholder parents where those are
// unread too; a readable entry under an unread parent is cloned under a placeholder parent. A second run adds
// nothing, and diff finds no difference: the placeholders under base_dn are counted, not ONLY_TARGET.
func TestUnreadableReferencesBecomePlaceholders(t *testing.T) {
	src, dst := unreadableSource(), fakedir.New(domain)
	job := options(t, allKinds()...)
	var log bytes.Buffer
	rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 4}, &log)
	if err != nil {
		t.Fatal(err)
	}
	for d, class := range map[string]string{hidden: "contact", hiddenInOU: "contact", secret: "organizationalUnit", secret2: "organizationalUnit"} {
		e := dst.Lookup(d)
		if e == nil || !hasValue(e.Values("objectClass"), class) || !plan.IsPlaceholder(*e) {
			t.Errorf("%s: want a placeholder %s, got %+v", d, class, e)
		}
	}
	if c := dst.Lookup(carol); c == nil || plan.IsPlaceholder(*c) {
		t.Errorf("carol is readable, so cloned: %+v", c)
	}
	members := dst.Lookup(eng).Values("member")
	for _, m := range []string{hidden, hiddenInOU, carol} {
		if !hasValue(members, m) {
			t.Errorf("member %s not written: %v", m, members)
		}
	}
	if hasValue(members, unplaceable) || rep.Unwritten["member: "+plan.WhyUnplaceable] != 1 {
		t.Errorf("an OU= name is skipped with why: %v %v", members, rep.Unwritten)
	}
	if rep.Placeholders != 4 || !strings.Contains(log.String(), "a placeholder contact at "+hidden) {
		t.Errorf("placeholders %d\n%s", rep.Placeholders, log.String())
	}
	var sum bytes.Buffer
	rep.WriteSummary(&sum)
	if !strings.Contains(sum.String(), "placeholders created for entries the source did not return") {
		t.Errorf("summary:\n%s", sum.String())
	}

	again, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 4}, &bytes.Buffer{})
	if err != nil || again.Added != 0 || again.Placeholders != 0 {
		t.Fatalf("a second run: %+v %v", again, err)
	}

	var diffs []diff.Difference
	s, err := diff.Run(context.Background(), src, dst, job, diff.Options{Workers: 4}, func(d diff.Difference) { diffs = append(diffs, d) })
	if err != nil {
		t.Fatal(err)
	}
	if len(diffs) != 0 || s.Placeholders != 1 {
		t.Errorf("diff: %+v, placeholders under base_dn %d", diffs, s.Placeholders)
	}
}

// With [scope] unreadable_refs = "skip" such values are left out, counted with why, as before.
func TestUnreadableReferencesSkipped(t *testing.T) {
	src, dst := unreadableSource(), fakedir.New(domain)
	job := options(t, allKinds()...)
	job.UnreadableRefs = plan.UnreadableRefsSkip
	rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 4}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("carol's parent is unread and no placeholder may stand for it: %+v", rep)
	}
	src.Lookup(eng).Attrs["member"] = []string{alice, hidden, hiddenInOU}
	rep, err = Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 4}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Placeholders != 0 || rep.Unwritten["member: "+plan.WhyMissing] != 2 || dst.Lookup(hidden) != nil {
		t.Errorf("%+v", rep)
	}
}

func hasValue(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(v, want) || dn.Equal(v, want) {
			return true
		}
	}
	return false
}
