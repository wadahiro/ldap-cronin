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

// attributeSchemas gives d a root DSE and an attributeSchema entry per name, as AD has.
func attributeSchemas(d *fakedir.Dir, names ...string) *fakedir.Dir {
	d.Put("", map[string][]string{"schemaNamingContext": {schemaNC}})
	for _, n := range names {
		d.Put("CN="+n+","+schemaNC, map[string][]string{"objectClass": {"top", "attributeSchema"}, "lDAPDisplayName": {n}})
	}
	return d
}

// An attribute of the allow lists that the source defines and the target lacks stops clone before anything is
// written, naming the attribute and the kinds that list it: found at the first object with a value, it would leave a
// target cloned half way.
func TestCloneRefusesToStartWhenTheTargetSchemaLacksAnAttribute(t *testing.T) {
	src := attributeSchemas(seedSource(), "acmeEmployeeCode", "sAMAccountName")
	src.Lookup(alice).Attrs["acmeEmployeeCode"] = []string{"E1"}
	dst := attributeSchemas(fakedir.New(domain, schemaNC), "sAMAccountName")
	job := jobFor(t, profile.AD, base, allKinds(), profile.Override{Extra: []string{"acmeEmployeeCode"}})
	_, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 2}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "acmeEmployeeCode (ou, group, user, computer, contact)") || !strings.Contains(err.Error(), "exclude") {
		t.Fatalf("got %v", err)
	}
	if len(dst.Ops) != 0 {
		t.Fatalf("nothing may be written: %v", dst.Ops)
	}
}

func TestTheTargetSchemaCheck(t *testing.T) {
	ctx := context.Background()
	job := jobFor(t, profile.AD, base, allKinds(), profile.Override{Extra: []string{"acmeEmployeeCode", "typo"}})
	src := attributeSchemas(fakedir.New(domain, schemaNC), "acmeEmployeeCode")
	if err := plan.CheckTargetSchema(ctx, src, attributeSchemas(fakedir.New(domain, schemaNC), "acmeEmployeeCode"), job); err != nil {
		t.Fatalf("the target has it: %v", err)
	}
	// typo is in neither schema: no value can be read, so it is no reason to stop.
	if err := plan.CheckTargetSchema(ctx, src, attributeSchemas(fakedir.New(domain, schemaNC)), job); err == nil || strings.Contains(err.Error(), "typo") {
		t.Fatalf("only what the source defines is required: %v", err)
	}
	// A schema that cannot be read (the dry-run, a directory without a root DSE) skips the check.
	if err := plan.CheckTargetSchema(ctx, src, fakedir.New(domain), job); err != nil {
		t.Fatal(err)
	}
	if err := plan.CheckTargetSchema(ctx, src, dryRun(&bytes.Buffer{}), job); err != nil {
		t.Fatal(err)
	}
}

// On AD no class requires a reference at creation, so an object class violation is about something else (an
// attribute or class the target lacks): it stops the run with the server's message, even for a group whose members
// cannot be written, instead of skipping the group as if it needed them.
func TestAnADSchemaViolationIsNotTakenForAMissingReference(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	src.Lookup(eng).Attrs["member"] = []string{"CN=Domain Admins,CN=Users," + domain} // not on this target
	dst.RequireAttr = map[string]string{"group": "acmeGroupCode"}
	rep, err := Run(context.Background(), src, dst, options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: 1}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "acmeGroupCode") {
		t.Fatalf("the violation must stop the run with its reason: %v %+v", err, rep)
	}
	for _, w := range rep.Warnings {
		if strings.Contains(w, "requires a reference") {
			t.Fatalf("not a missing reference: %v", rep.Warnings)
		}
	}
}
