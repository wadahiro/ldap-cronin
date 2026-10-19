package clone

import (
	"bytes"
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const (
	pc01    = "CN=PC01,OU=Computers," + base
	pc99    = "CN=PC99,CN=Computers," + domain // outside base_dn: a referenced object
	partner = "CN=Partner,OU=Contacts," + base
)

// computerSource is seedSource with a computer and a contact in the scope and a computer outside it, all members of
// eng. The computers carry what must never be copied: a LAPS password and shadow credentials.
func computerSource() *fakedir.Dir {
	src := seedSource()
	computer := func(d, name string) {
		src.Put(d, map[string][]string{
			"objectClass": {"top", "person", "organizationalPerson", "user", "computer"}, "cn": {name},
			"sAMAccountName": {name + "$"}, "userAccountControl": {"4096"}, "dNSHostName": {strings.ToLower(name) + ".ad.example.com"},
			"operatingSystem": {"Windows 11 Enterprise"}, "servicePrincipalName": {"HOST/" + name},
			"ms-Mcs-AdmPwd": {"production-laps-secret"}, "msDS-KeyCredentialLink": {"B:828:0002..."},
		})
	}
	src.Put("OU=Computers,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Computers"}})
	src.Put("OU=Contacts,"+base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Contacts"}})
	src.Put("CN=Computers,"+domain, map[string][]string{"objectClass": {"top", "container"}, "cn": {"Computers"}})
	computer(pc01, "PC01")
	computer(pc99, "PC99")
	src.Put(partner, map[string][]string{
		"objectClass": {"top", "person", "organizationalPerson", "contact"}, "cn": {"Partner"},
		"sn": {"Partner"}, "mail": {"partner@other.example"}, "company": {"Other"},
	})
	g := src.Lookup(eng)
	g.Attrs["member"] = append(g.Attrs["member"], pc01, pc99, partner)
	return src
}

// Computers and contacts are what groups hold besides users. They are cloned by default, every member is on the
// target, and removing any of them shows in diff.
func TestComputersAndContactsAreClonedAndTheirRemovalShows(t *testing.T) {
	cloneIt := func(t *testing.T) (*fakedir.Dir, *fakedir.Dir, *Report, *bytes.Buffer) {
		src, dst := computerSource(), fakedir.New(domain)
		var out bytes.Buffer
		rep, err := Run(context.Background(), src, dst, options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: 3}, &out)
		if err != nil {
			t.Fatal(err)
		}
		return src, dst, rep, &out
	}
	src, dst, rep, _ := cloneIt(t)
	c := dst.Lookup(pc01)
	if c == nil || strings.Join(c.Values("userAccountControl"), "") != "4096" || c.Values("unicodePwd") == nil ||
		c.Values("dNSHostName") == nil || c.Values("servicePrincipalName") == nil {
		t.Fatalf("the computer must be cloned as an account with its attributes: %+v", c)
	}
	for _, d := range []string{pc01, pc99} {
		if e := dst.Lookup(d); e.Values("ms-Mcs-AdmPwd") != nil || e.Values("msDS-KeyCredentialLink") != nil {
			t.Fatalf("credentials of a computer must never be copied: %+v", e.Attrs)
		}
	}
	if p := dst.Lookup(partner); p == nil || p.Values("mail") == nil || p.Values("unicodePwd") != nil {
		t.Fatalf("the contact must be cloned, and is not an account: %+v", p)
	}
	if rep.Referenced != 1 || dst.Lookup(pc99) == nil {
		t.Fatalf("the computer outside base_dn is a referenced object: %+v", rep)
	}
	members := dst.Lookup(eng).Values("member")
	for _, want := range []string{pc01, pc99, partner} {
		if !slices.ContainsFunc(members, func(m string) bool { return dn.Equal(m, want) }) {
			t.Errorf("member %s is missing: %v", want, members)
		}
	}
	job := options(t, allKinds()...)
	removed, added, sum := memberDiff(t, src, dst, job, eng)
	if removed != nil || added != nil || sum.Compared[profile.KindComputer] != 1 || sum.Compared[profile.KindContact] != 1 {
		t.Fatalf("a fresh clone: removed %v added %v compared %v", removed, added, sum.Compared)
	}

	for _, gone := range []string{pc01, pc99, partner} {
		t.Run("removing "+gone, func(t *testing.T) {
			src, dst, _, _ := cloneIt(t)
			setMembers(dst, eng, func(m string) bool { return !dn.Equal(m, gone) })
			if removed, _, _ := memberDiff(t, src, dst, job, eng); len(removed) != 1 || !dn.Equal(removed[0], gone) {
				t.Fatalf("removed %v", removed)
			}
		})
	}
	t.Run("a re-run writes nothing", func(t *testing.T) {
		src, dst, _, _ := cloneIt(t)
		writes := len(dst.Ops)
		rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 3}, &bytes.Buffer{})
		if err != nil || rep.Added != 0 || rep.Updated != 0 || len(dst.Ops) != writes {
			t.Fatalf("%+v %v %v", rep, err, dst.Ops[writes:])
		}
	})
}

// A computer is added as a disabled workstation trust that needs no password, so the last step changes only those
// flags and never the account type (a DC makes an account added without userAccountControl a normal user account).
func TestAComputerKeepsItsAccountTypeFromTheAdd(t *testing.T) {
	src := computerSource()
	var out bytes.Buffer
	if _, err := Run(context.Background(), src, dryRun(&out), options(t, allKinds()...), Options{UserPassword: "Fixed1!", Workers: 1}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	ldif := out.String()
	i := strings.Index(ldif, "dn: "+pc01+"\nchangetype: add")
	if i < 0 {
		t.Fatalf("no add of the computer:\n%s", ldif)
	}
	record := ldif[i:]
	record = record[:strings.Index(record, "\n\n")]
	if !strings.Contains(record, "userAccountControl: 4130") {
		t.Fatalf("the add must carry WORKSTATION_TRUST_ACCOUNT | ACCOUNTDISABLE | PASSWD_NOTREQD:\n%s", record)
	}
	for _, secret := range []string{"production-laps-secret", "ms-Mcs-AdmPwd", "msDS-KeyCredentialLink"} {
		if strings.Contains(ldif, secret) {
			t.Fatalf("the LDIF carries %s", secret)
		}
	}
}

func TestComputerCredentialsCannotBeAllowListed(t *testing.T) {
	for _, a := range []string{"ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword", "msDS-KeyCredentialLink",
		"msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-ManagedPassword"} {
		if _, err := profile.AD.Attrs(profile.KindComputer, profile.Override{Extra: []string{a}}); err == nil {
			t.Errorf("%s must be refused in an allow list", a)
		}
	}
}

// The summaries say what the target holds beyond the scope and what it lacks: the referenced objects per kind, and
// the entries under base_dn of no kind (BitLocker recovery information under a computer), which neither clone
// copies nor diff compares. A create-only parent (CN=Staff) is created, so it is not counted; a kind left out of
// [scope] objects is.
func TestSummariesCountWhatWasClonedFromOutsideAndWhatWasNot(t *testing.T) {
	src := computerSource()
	src.Put("CN=2026-01-01T00:00:00-09:00{1},"+pc01, map[string][]string{"objectClass": {"top", "msFVE-RecoveryInformation"},
		"msFVE-RecoveryPassword": {"production-recovery-key"}})
	// AD and Samba give structuralObjectClass as the chain down to the structural class, in any objectClass order.
	src.Put("CN=Agent,"+pc01, map[string][]string{"objectClass": {"serviceConnectionPoint", "top", "connectionPoint", "leaf"},
		"structuralObjectClass": {"top", "leaf", "connectionPoint", "serviceConnectionPoint"}})
	dst := fakedir.New(domain)
	job := options(t, allKinds()...)
	rep, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 2}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(rep.ReferencedKinds, map[string]int{profile.KindComputer: 1}) || !maps.Equal(rep.NotCloned, map[string]int{"msFVE-RecoveryInformation": 1, "serviceConnectionPoint": 1}) {
		t.Fatalf("referenced %v not cloned %v", rep.ReferencedKinds, rep.NotCloned)
	}
	var out bytes.Buffer
	rep.WriteSummary(&out)
	for _, want := range []string{
		"referenced objects outside the scope cloned: 1\n  computer  1\n",
		"not cloned (matches no kind): 2\n  msFVE-RecoveryInformation  1\n  serviceConnectionPoint     1\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in\n%s", want, out.String())
		}
	}

	sum, err := diff.Run(context.Background(), src, dst, job, diff.Options{Workers: 2}, func(d diff.Difference) { t.Errorf("unexpected %+v", d) })
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	diff.WriteSummary(&out, job, sum, nil)
	if !strings.Contains(out.String(), "not compared (matches no kind, so clone does not copy it): 2\n  msFVE-RecoveryInformation  1\n  serviceConnectionPoint     1\n") {
		t.Fatalf("diff must say what it did not compare:\n%s", out.String())
	}

	noContacts := options(t, profile.KindOU, profile.KindGroup, profile.KindUser, profile.KindComputer)
	rep, err = Run(context.Background(), src, fakedir.New(domain), noContacts, Options{UserPassword: "Fixed1!", Workers: 2}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.NotCloned["contact"] != 1 {
		t.Fatalf("a kind left out is counted: %v", rep.NotCloned)
	}
}
