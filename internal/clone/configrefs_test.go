package clone

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/dryrun"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const (
	configNC = "CN=Configuration," + domain
	allUsers = "CN=All Users,CN=All Address Lists,CN=Address Lists Container,CN=Acme,CN=Microsoft Exchange,CN=Services," + configNC
)

// A value naming an entry of the configuration partition cannot be written: it is skipped with one warning for the
// entry it names, however many objects hold it, and counted in the summary with the reason. seeAlso stands for
// showInAddressBook: a DN attribute that is not a link.
func TestValuesNamingTheConfigurationPartitionAreCountedWithTheReason(t *testing.T) {
	src := withSchema(seedSource())
	src.Lookup("").Attrs["configurationNamingContext"] = []string{configNC}
	src.Put(configNC, map[string][]string{"objectClass": {"top", "configuration"}, "cn": {"Configuration"}})
	src.Put(allUsers, map[string][]string{"objectClass": {"top", "addressBookContainer"}, "cn": {"All Users"}, "displayName": {"All Users"}})
	for _, u := range []string{alice, bob} {
		src.Lookup(u).Attrs["seeAlso"] = []string{allUsers}
	}
	var log bytes.Buffer
	rep, err := Run(context.Background(), src, strictTarget(), optionsWith(t, profile.Override{Extra: []string{"seeAlso"}}), Options{UserPassword: "Fixed1!", Workers: 2}, &log)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Unwritten["seeAlso: "+plan.WhyConfiguration]; got != 2 {
		t.Fatalf("both values are counted with the reason: %v", rep.Unwritten)
	}
	if got := strings.Count(log.String(), "skip seeAlso values naming "+allUsers); got != 1 {
		t.Fatalf("one warning for the entry they name, not one per value: %d\n%s", got, log.String())
	}
	var sum bytes.Buffer
	rep.WriteSummary(&sum)
	for _, want := range []string{"reference values not written", "seeAlso: " + plan.WhyConfiguration, "[attributes] exclude"} {
		if !strings.Contains(sum.String(), want) {
			t.Errorf("the summary lacks %q:\n%s", want, sum.String())
		}
	}
}

// exchangeSource is seedSource with the configuration partition of an Exchange organization: the chain of
// containers down to the All Users address list alice and bob are shown in, and the schema of their classes.
func exchangeSource() *fakedir.Dir {
	src := withSchema(seedSource())
	src.Lookup("").Attrs["configurationNamingContext"] = []string{configNC}
	for _, a := range []string{"cn", "objectClass", "displayName", "purportedSearch", "adminDisplayName"} {
		src.Put("CN="+a+","+schemaNC, map[string][]string{"objectClass": {"attributeSchema"}, "lDAPDisplayName": {a}, "attributeSyntax": {"2.5.5.12"}})
	}
	class := func(name string, must, may []string) {
		src.Put("CN="+name+","+schemaNC, map[string][]string{"objectClass": {"classSchema"}, "lDAPDisplayName": {name},
			"subClassOf": {"top"}, "systemMustContain": must, "mayContain": may})
	}
	class("top", []string{"cn", "objectClass"}, nil)
	class("container", nil, nil)
	class("msExchConfigurationContainer", nil, []string{"adminDisplayName"})
	class("msExchOrganizationContainer", nil, []string{"adminDisplayName"})
	class("msExchContainer", nil, nil)
	class("addressBookContainer", []string{"displayName"}, []string{"purportedSearch", "seeAlso"})
	src.Put(configNC, map[string][]string{"objectClass": {"top", "configuration"}, "cn": {"Configuration"}})
	services := "CN=Services," + configNC
	src.Put(services, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Services"}})
	ex := "CN=Microsoft Exchange," + services
	org := "CN=Acme," + ex
	lists := "CN=Address Lists Container," + org
	all := "CN=All Address Lists," + lists
	src.Put(ex, map[string][]string{"objectClass": {"top", "container", "msExchConfigurationContainer"}, "cn": {"Microsoft Exchange"}, "adminDisplayName": {"Microsoft Exchange"}})
	src.Put(org, map[string][]string{"objectClass": {"top", "container", "msExchOrganizationContainer"}, "cn": {"Acme"}, "systemFlags": {"1"}})
	src.Put(lists, map[string][]string{"objectClass": {"top", "container", "msExchContainer"}, "cn": {"Address Lists Container"}})
	src.Put(all, map[string][]string{"objectClass": {"top", "addressBookContainer"}, "cn": {"All Address Lists"}, "displayName": {"All Address Lists"}})
	src.Put(allUsers, map[string][]string{"objectClass": {"top", "addressBookContainer"}, "cn": {"All Users"}, "displayName": {"All Users"},
		"purportedSearch": {"(&(objectClass=user)(mail=*))"}, "seeAlso": {alice}})
	for _, u := range []string{alice, bob} {
		src.Lookup(u).Attrs["seeAlso"] = []string{allUsers}
	}
	return src
}

// With configuration_refs = "clone" the address list and the containers above it that the target lacks are created
// from the source, top down and once each, with what a client can write on their classes (not what is never cloned,
// nor their own references); the values naming it are written, and diff finds nothing.
func TestConfigurationRefsCloneCreatesWhatTheValuesName(t *testing.T) {
	src := exchangeSource()
	dst := strictTarget()
	dst.Put("", map[string][]string{"configurationNamingContext": {configNC}})
	dst.Put(configNC, map[string][]string{"objectClass": {"top", "configuration"}, "cn": {"Configuration"}})
	dst.Put("CN=Services,"+configNC, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Services"}})
	job := optionsWith(t, profile.Override{Extra: []string{"seeAlso"}})
	job.ConfigurationRefs = plan.ConfigurationRefsClone
	var log bytes.Buffer
	rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 4}, &log)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ReferencedKinds["configuration"] != 5 || rep.Unwritten["seeAlso: "+plan.WhyConfiguration] != 0 {
		t.Fatalf("the 4 containers and the list, no value naming them skipped: %+v\n%s", rep, log.String())
	}
	got := dst.Lookup(allUsers)
	if got == nil || strings.Join(got.Values("displayName"), "") != "All Users" || got.Values("purportedSearch") == nil {
		t.Fatalf("the address list with what a client writes: %v", got)
	}
	if got.Values("seeAlso") != nil {
		t.Fatalf("its own references are not followed: %v", got.Attrs)
	}
	if org := dst.Lookup("CN=Acme,CN=Microsoft Exchange,CN=Services," + configNC); org == nil || org.Values("systemFlags") != nil {
		t.Fatalf("what is never cloned stays behind: %v", org)
	}
	for _, u := range []string{alice, bob} {
		if v := dst.Lookup(u).Values("seeAlso"); len(v) != 1 || !dn.Equal(v[0], allUsers) {
			t.Fatalf("%s is shown in the list: %v", u, v)
		}
	}
	if diffs := runDiff(t, src, dst, job); len(diffs) != 0 {
		t.Fatalf("diff after the clone: %v", diffs)
	}
	again, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 4}, &bytes.Buffer{})
	if err != nil || again.Added != 0 || again.Referenced != 0 {
		t.Fatalf("a second run finds them on the target: %+v %v", again, err)
	}
}

// A value naming a schema definition or a partition is never created, even with configuration_refs = "clone": the
// schema cannot be undone, and the partitions define the lab's forest.
func TestConfigurationRefsNeverWriteTheSchemaOrThePartitions(t *testing.T) {
	src := exchangeSource()
	schemaDef := "CN=displayName," + schemaNC
	crossRef := "CN=Other,CN=Partitions," + configNC
	src.Put("CN=Partitions,"+configNC, map[string][]string{"objectClass": {"top", "crossRefContainer"}, "cn": {"Partitions"}})
	src.Put(crossRef, map[string][]string{"objectClass": {"top", "crossRef"}, "cn": {"Other"}})
	src.Lookup(alice).Attrs["seeAlso"] = []string{schemaDef, crossRef}
	dst := strictTarget()
	dst.Put("", map[string][]string{"configurationNamingContext": {configNC}})
	dst.Put(configNC, map[string][]string{"objectClass": {"top", "configuration"}, "cn": {"Configuration"}})
	job := optionsWith(t, profile.Override{Extra: []string{"seeAlso"}})
	job.ConfigurationRefs = plan.ConfigurationRefsClone
	rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 2}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Unwritten["seeAlso: "+plan.WhyFenced]; got != 2 {
		t.Fatalf("both are left out as fenced: %v", rep.Unwritten)
	}
	for d := range dst.Entries {
		if strings.Contains(d, "cn=schema,") || strings.Contains(d, "cn=partitions,") {
			t.Fatalf("clone wrote %s", d)
		}
	}
}

// In a dry-run the configuration entries are add records before the values naming them, so ldapmodify loads the
// LDIF into a lab in one go.
func TestConfigurationRefsInADryRunLoadInOrder(t *testing.T) {
	src := exchangeSource()
	dst := strictTarget()
	dst.Put(configNC, map[string][]string{"objectClass": {"top", "configuration"}, "cn": {"Configuration"}})
	dst.Put("CN=Services,"+configNC, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Services"}})
	job := optionsWith(t, profile.Override{Extra: []string{"seeAlso"}})
	job.ConfigurationRefs = plan.ConfigurationRefsClone
	var out bytes.Buffer
	if _, err := Run(context.Background(), src, dryrun.New(&out, job.Profile), job, Options{UserPassword: "Fixed1!", Workers: 4}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := ldapmodify(dst, out.String()); err != nil {
		t.Fatalf("ldapmodify refuses the LDIF: %v\n%s", err, out.String())
	}
	if dst.Lookup(allUsers) == nil || len(dst.Lookup(alice).Values("seeAlso")) != 1 {
		t.Fatalf("the list and the value are loaded:\n%s", out.String())
	}
}
