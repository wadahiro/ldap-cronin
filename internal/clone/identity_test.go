package clone

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
)

func identityOptions(t *testing.T) Options {
	t.Helper()
	opt := options(t, allKinds()...)
	opt.KeepIdentity = true
	return Options{Plan: opt, UserPassword: "Fixed1!", Workers: 1}
}

func withSID(d *fakedir.Dir, dnStr, sid string) {
	e := d.Lookup(dnStr)
	d.Put(dnStr, map[string][]string{})
	attrs := map[string][]string{}
	for k, v := range e.Attrs {
		attrs[k] = v
	}
	attrs["objectSid"] = []string{sid}
	d.Put(dnStr, attrs)
}

func TestKeepIdentityCopiesObjectGUIDAndObjectSid(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	withSID(src, alice, "sid-alice")
	if _, err := Run(src, dst, identityOptions(t), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, dnStr := range []string{alice, bob, eng, tokyo} {
		want, got := src.Lookup(dnStr).Values("objectGUID"), dst.Lookup(dnStr).Values("objectGUID")
		if len(want) != 1 || len(got) != 1 || want[0] != got[0] {
			t.Errorf("%s: objectGUID source=%x target=%x", dnStr, want, got)
		}
	}
	if got := dst.Lookup(alice).Values("objectSid"); len(got) != 1 || got[0] != "sid-alice" {
		t.Fatalf("objectSid = %v", got)
	}
}

func TestWithoutKeepIdentityObjectGUIDIsStillLeftToTheTarget(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	opt := identityOptions(t)
	opt.Plan.KeepIdentity = false
	if _, err := Run(src, dst, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if string(src.Lookup(alice).Values("objectGUID")[0]) == string(dst.Lookup(alice).Values("objectGUID")[0]) {
		t.Fatal("without KeepIdentity the target must assign its own objectGUID")
	}
}

func TestKeepIdentityRerunUpdatesTheSameObjectInPlace(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	if _, err := Run(src, dst, identityOptions(t), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	src.Put(alice, withAttr(src.Lookup(alice).Attrs, "displayName", "Alice A"))
	rep, err := Run(src, dst, identityOptions(t), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Added != 0 || rep.Updated == 0 {
		t.Fatalf("a re-run must update, not add: %+v", rep)
	}
}

func TestKeepIdentityRefusesAnExistingObjectWithAnotherGUID(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	if _, err := Run(src, dst, identityOptions(t), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	// A different object was recreated at the same DN.
	dst.Put(alice, withAttr(dst.Lookup(alice).Attrs, "objectGUID", "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"))
	_, err := Run(src, dst, identityOptions(t), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "objectGUID") {
		t.Fatalf("an object with another GUID must be refused, got %v", err)
	}
}

func withAttr(in map[string][]string, name, value string) map[string][]string {
	out := map[string][]string{}
	for k, v := range in {
		out[k] = v
	}
	out[name] = []string{value}
	return out
}
