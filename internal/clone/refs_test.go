package clone

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const schemaNC = "CN=Schema,CN=Configuration," + domain

// withSchema makes a source that has a root DSE and a schema (DN reference attributes).
func withSchema(d *fakedir.Dir) *fakedir.Dir {
	d.Put("", map[string][]string{"schemaNamingContext": {schemaNC}})
	add := func(name, syntax, linkID, single string) {
		a := map[string][]string{
			"objectClass": {"attributeSchema"}, "lDAPDisplayName": {name}, "attributeSyntax": {syntax}, "isSingleValued": {single},
		}
		if linkID != "" {
			a["linkID"] = []string{linkID}
		}
		d.Put("CN="+name+","+schemaNC, a)
	}
	add("member", "2.5.5.1", "2", "FALSE")
	add("manager", "2.5.5.1", "42", "TRUE")
	add("seeAlso", "2.5.5.1", "", "FALSE")         // not a link attribute, but holds DNs
	add("directReports", "2.5.5.1", "43", "FALSE") // back link (the other side of manager)
	add("msExchFoo", "2.5.5.7", "", "FALSE")       // DN+binary
	return d
}

func optionsWith(t *testing.T, o profile.Override, maskAttrs ...string) plan.Job {
	t.Helper()
	return jobFor(t, profile.AD, base, allKinds(), o, maskAttrs...)
}

func strictTarget() *fakedir.Dir {
	d := fakedir.New(domain)
	d.StrictRefs = []string{"member", "manager", "seeAlso"}
	return d
}

func TestSchemaDetectedReferenceIsDeferredUntilTargetExists(t *testing.T) {
	src := withSchema(seedSource())
	// alice (which may be created first) references bob and eng via seeAlso. It must be applied regardless of order.
	src.Lookup(alice).Attrs["seeAlso"] = []string{bob, eng}
	opt := optionsWith(t, profile.Override{Extra: []string{"seeAlso"}})
	dst := strictTarget()

	rep, err := Run(context.Background(), src, dst, opt, Options{Workers: 4}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("seeAlso must be applied after all objects exist: %v", err)
	}
	if got := dst.Lookup(alice).Values("seeAlso"); len(got) != 2 {
		t.Fatalf("seeAlso=%v (warnings=%v)", got, rep.Warnings)
	}
	if diffs := runDiff(t, src, dst, opt); len(diffs) != 0 {
		t.Fatalf("unexpected diff: %v", diffs)
	}
}

func TestReferenceToObjectOutsideScopeIsSkippedWithWarning(t *testing.T) {
	src := withSchema(seedSource())
	src.Lookup(alice).Attrs["seeAlso"] = []string{"CN=Ghost,OU=Nowhere," + domain}
	rep, err := Run(context.Background(), src, strictTarget(), optionsWith(t, profile.Override{Extra: []string{"seeAlso"}}), Options{Workers: 2}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.WarningCount == 0 {
		t.Fatal("expected a warning for the unresolvable reference")
	}
}

func TestSingleValuedReferenceIsReplacedWhenChanged(t *testing.T) {
	src := withSchema(seedSource())
	opt := optionsWith(t, profile.Override{})
	dst := strictTarget()
	if _, err := Run(context.Background(), src, dst, opt, Options{Workers: 1}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	src.Lookup(alice).Attrs["manager"] = []string{bob}
	if _, err := Run(context.Background(), src, dst, opt, Options{Workers: 1}, &bytes.Buffer{}); err != nil {
		t.Fatalf("a changed single-valued reference must replace, not add a 2nd value: %v", err)
	}
	if got := dst.Lookup(alice).Values("manager"); len(got) != 1 || !strings.EqualFold(got[0], bob) {
		t.Fatalf("manager=%v", got)
	}
}

func TestBackLinkAttributeIsRejected(t *testing.T) {
	_, err := Run(context.Background(), withSchema(seedSource()), fakedir.New(domain),
		optionsWith(t, profile.Override{Extra: []string{"directReports"}}), Options{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "back link") {
		t.Fatalf("got %v", err)
	}
}

// A DN-Binary attribute is a reference (dn.SplitRef): it can be named, and, holding DNs, not masked.
func TestDNBinaryAttributeIsAReference(t *testing.T) {
	if _, err := Run(context.Background(), withSchema(seedSource()), fakedir.New(domain),
		optionsWith(t, profile.Override{Extra: []string{"msExchFoo"}}), Options{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("named: %v", err)
	}
	_, err := Run(context.Background(), withSchema(seedSource()), fakedir.New(domain),
		optionsWith(t, profile.Override{Extra: []string{"msExchFoo"}}, "msExchFoo"), Options{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "cannot be masked") {
		t.Fatalf("masked: %v", err)
	}
}

func TestMaskingADNAttributeDiscoveredFromSchemaIsRejected(t *testing.T) {
	_, err := Run(context.Background(), withSchema(seedSource()), fakedir.New(domain),
		optionsWith(t, profile.Override{Extra: []string{"seeAlso"}}, "seeAlso"), Options{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "cannot be masked") {
		t.Fatalf("got %v", err)
	}
}
