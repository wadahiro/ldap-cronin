package diff

import (
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/mask"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const (
	lDomain = "DC=ad,DC=example,DC=com"
	lBase   = "OU=IDM," + lDomain
)

func jobOf(t *testing.T, p profile.Profile, base string) plan.Job {
	t.Helper()
	job := plan.Job{Profile: p, BaseDN: base, Masker: mask.New("*", nil)}
	for _, spec := range p.Kinds {
		attrs, err := p.Attrs(spec.Name, profile.Override{})
		if err != nil {
			t.Fatal(err)
		}
		job.Kinds = append(job.Kinds, plan.NewKind(p, spec, "", attrs))
	}
	return job
}

func guid(b byte) string { return string(append(make([]byte, 15), b)) }

func baseOnly(g byte) *fakedir.Dir {
	d := fakedir.New(lDomain)
	d.Put(lBase, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}, "objectGUID": {guid(g)}})
	return d
}

func TestIdentityIsChosenOnlyWhenTheProbeHasTheSameIdentifier(t *testing.T) {
	job := jobOf(t, profile.AD, lBase)
	got, _, err := ChooseLookup(context.Background(), baseOnly(1), baseOnly(1), job, nil)
	if err != nil || got == nil || !got.Preserved() {
		t.Fatalf("same objectGUID: %v %v", got, err)
	}
	got, why, err := ChooseLookup(context.Background(), baseOnly(1), baseOnly(2), job, nil)
	if err != nil || got != nil || !strings.Contains(why, lBase) {
		t.Fatalf("a different objectGUID (an LDAP clone) must not enable identity: %v %q %v", got, why, err)
	}
}

// When base_dn is a container that already exists in the lab, such as CN=Users, its identifier naturally differs,
// so the first object below it that diff compares decides.
func TestIdentityProbeSkipsAnExistingContainerAsBaseDN(t *testing.T) {
	users := "CN=Users," + lDomain
	build := func(container, alice byte) *fakedir.Dir {
		d := fakedir.New(lDomain)
		d.Put(users, map[string][]string{"objectClass": {"top", "container"}, "objectGUID": {guid(container)}})
		d.Put("CN=Alice,"+users, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
			"objectCategory": {"person"}, "objectGUID": {guid(alice)}})
		return d
	}
	job := jobOf(t, profile.AD, users)
	if got, why, err := ChooseLookup(context.Background(), build(1, 9), build(2, 9), job, nil); err != nil || got == nil || !got.Preserved() {
		t.Fatalf("the child decides: %v %q %v", got, why, err)
	}
	if got, _, _ := ChooseLookup(context.Background(), build(1, 9), build(1, 8), job, nil); got != nil {
		t.Fatal("a different child objectGUID must not enable identity")
	}
}

// The probe is found with the job's own filters: an object diff would not compare never decides.
func TestIdentityProbeFollowsTheConfiguredFilters(t *testing.T) {
	build := func(alice byte) *fakedir.Dir {
		d := baseOnly(1)
		d.Put("CN=Alice,"+lBase, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
			"objectCategory": {"person"}, "objectGUID": {guid(alice)}})
		return d
	}
	job := jobOf(t, profile.AD, lBase)
	if got, _, _ := ChooseLookup(context.Background(), build(9), build(8), job, nil); got != nil {
		t.Fatal("with the default filters Alice is compared, and her objectGUID differs")
	}
	// Only groups are selected now (fakedir reads "objectClass=group" as group): Alice is out of scope and the base decides.
	var kinds []plan.Kind
	for _, k := range job.Kinds {
		if k.Name == profile.KindGroup {
			kinds = append(kinds, k)
		}
	}
	job.Kinds = kinds
	if got, why, err := ChooseLookup(context.Background(), build(9), build(8), job, nil); err != nil || got == nil || !got.Preserved() {
		t.Fatalf("an object outside the job must not decide: %v %q %v", got, why, err)
	}
}

// Identifiers can only be preserved by a native import, so a server type without one keeps the mapping as is.
func TestWithoutNativeSupportTheMappingIsKept(t *testing.T) {
	m := fakeLookup{}
	got, why, err := ChooseLookup(context.Background(), baseOnly(1), baseOnly(1), jobOf(t, profile.LDAP, lBase), m)
	if err != nil || got != m || why != "" {
		t.Fatalf("%v %q %v", got, why, err)
	}
}

type fakeLookup struct{}

func (fakeLookup) Target(identity.Key) (identity.Key, bool) { return identity.Key{}, false }
func (fakeLookup) Len() int                                 { return 0 }
func (fakeLookup) Preserved() bool                          { return false }
