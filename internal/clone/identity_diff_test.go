package clone

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/identity"
)

func TestIdentityDiffDetectsARenameWithoutAMappingFile(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	if _, err := Run(context.Background(), src, dst, identityJob(t), identityOpts, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	// On the target, Alice was moved to a different OU and renamed (the GUID does not change).
	moved := "CN=Alice Smith,OU=Staff,OU=Users," + base
	dst.Put("OU=Staff,OU=Users,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Staff"}})
	old := dst.Lookup(alice).Attrs
	dst.Delete(alice)
	dst.Put(moved, withAttr(old, "cn", "Alice Smith"))

	var got []diff.Difference
	sum, err := diff.Run(context.Background(), src, dst, identityJob(t), diff.Options{Workers: 1, Lookup: identity.Identity{}}, func(d diff.Difference) { got = append(got, d) })
	if err != nil {
		t.Fatal(err)
	}
	var renamed *diff.Difference
	for i, d := range got {
		if d.Kind == diff.Renamed && d.DN == alice {
			renamed = &got[i]
		}
		if d.Kind == diff.OnlySource || d.Kind == diff.Replaced {
			t.Errorf("unexpected %v %s", d.Kind, d.DN)
		}
	}
	if renamed == nil || renamed.TargetDN != moved {
		t.Fatalf("Alice must be RENAMED to %s: %+v", moved, got)
	}
	if !sum.Identity {
		t.Fatal("the summary must say that objectGUID is preserved")
	}
	var out strings.Builder
	diff.WriteSummary(&out, identityJob(t), sum, nil)
	if !strings.Contains(out.String(), "objectGUID preserved") {
		t.Fatalf("summary:\n%s", out.String())
	}
}

func TestIdentityDiffReportsAReplacedObjectWithTheSameDN(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	if _, err := Run(context.Background(), src, dst, identityJob(t), identityOpts, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	dst.Put(alice, withAttr(dst.Lookup(alice).Attrs, "objectGUID", strings.Repeat("\xee", 16)))
	var got []diff.Difference
	if _, err := diff.Run(context.Background(), src, dst, identityJob(t), diff.Options{Workers: 1, Lookup: identity.Identity{}}, func(d diff.Difference) { got = append(got, d) }); err != nil {
		t.Fatal(err)
	}
	for _, d := range got {
		if d.Kind == diff.Replaced && d.DN == alice {
			return
		}
	}
	t.Fatalf("a different object at the same DN must be REPLACED: %+v", got)
}
