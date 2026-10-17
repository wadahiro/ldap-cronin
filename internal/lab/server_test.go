package lab

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ldapImage = "ldap-cronin/openldap:test"

// ldapLab is a fixture whose lab is an OpenLDAP one, with the image already loaded.
func ldapLab(t *testing.T) *labFixture {
	t.Helper()
	fx := newLabFixture(t)
	fx.d.images[ldapImage] = true
	must(t, fx.l.ChooseServer(context.Background(), ProfileLDAP))
	return fx
}

func (fx *labFixture) upLDAP(o UpOptions) {
	fx.t.Helper()
	o.Image = ldapImage
	if o.Flags.Domain == "" {
		o.Flags.Domain = "dc=example,dc=org"
	}
	o.Flags.AdminPassword = "Secret-Passw0rd!"
	must(fx.t, fx.l.Up(context.Background(), o))
}

func TestOpenLDAPUpRunsItsOwnImageWithoutSambaSettings(t *testing.T) {
	fx := ldapLab(t)
	fx.upLDAP(UpOptions{})
	run := fx.d.callsMatching("run -d --name t-ldap ")
	if len(run) != 1 {
		t.Fatalf("%v", fx.d.calls)
	}
	for _, want := range []string{
		"--hostname ldap1", "LDAP_SUFFIX=dc=example,dc=org", "-e LDAP_ADMIN_PASSWORD", "-p 13389:389", "-p 13636:636",
		"-v t-ldap-data:/var/lib/ldap", "-v t-ldap-config:/etc/ldap/slapd.d", "--health-cmd test -f /tmp/ldap-ready",
		"--label ldap-cronin.profile=ldap", ldapImage,
	} {
		if !strings.Contains(run[0], want) {
			t.Errorf("run args lack %q:\n%s", want, run[0])
		}
	}
	for _, unwanted := range []string{"SYS_ADMIN", "AD_REALM", "SAMBA_"} {
		if strings.Contains(run[0], unwanted) {
			t.Errorf("an OpenLDAP lab needs no %s:\n%s", unwanted, run[0])
		}
	}
	smoke := fx.d.callsMatching("exec -e LDAPTLS_REQCERT")
	if len(smoke) != 1 || !strings.Contains(smoke[0], `-D "cn=admin,dc=example,dc=org"`) {
		t.Fatalf("the smoke test binds as the rootdn: %v", smoke)
	}
	env, _ := ReadEnvFile(fx.l.envPath())
	if env.Profile != ProfileLDAP || env.Domain != "dc=example,dc=org" || env.LDAPSPort != 13636 {
		t.Fatalf("%+v", env)
	}
	raw, _ := os.ReadFile(fx.l.envPath())
	if !strings.Contains(string(raw), "LDAP_SUFFIX=dc=example,dc=org") || strings.Contains(string(raw), "AD_REALM") {
		t.Fatalf(".env must use the OpenLDAP names:\n%s", raw)
	}
	if !strings.Contains(fx.out.String(), "cn=admin,dc=example,dc=org") {
		t.Fatal(fx.out.String())
	}
}

func TestOpenLDAPRefusesSambaOnlySettingsAndBadSuffixes(t *testing.T) {
	for _, s := range []Settings{
		{Domain: "dc=example,dc=org", NetBIOS: "X"},
		{Domain: "dc=example,dc=org", DomainSID: "S-1-5-21-1-2-3"},
		{Domain: "cn=example,dc=org"},
		{Domain: "example.org"},
	} {
		fx := ldapLab(t)
		s.AdminPassword = "x"
		if err := fx.l.Up(context.Background(), UpOptions{Image: ldapImage, Flags: s}); err == nil {
			t.Errorf("%+v must be refused", s)
		}
	}
}

// --schema-dir is copied in before the first start, so the directory is created with it.
func TestOpenLDAPSchemaDirIsCopiedBeforeTheFirstStart(t *testing.T) {
	fx := ldapLab(t)
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "10-acme.ldif"), []byte("dn: cn=acme,cn=schema,cn=config\n"), 0o644))
	fx.upLDAP(UpOptions{SchemaDir: dir})
	var seq []string
	for _, c := range fx.d.calls {
		for _, verb := range []string{"create ", "cp ", "start "} {
			if strings.HasPrefix(c, verb) {
				seq = append(seq, verb+strings.Fields(c)[len(strings.Fields(c))-1])
			}
		}
	}
	want := []string{"create " + ldapImage, "cp t-ldap:/schema.d/", "start t-ldap"}
	if strings.Join(seq, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v", seq)
	}
	if len(fx.d.callsMatching("run -d")) != 0 {
		t.Fatal("with --schema-dir the container is created, filled and started, not run")
	}
}

func TestSchemaDirIsRefusedForSamba(t *testing.T) {
	fx := newLabFixture(t)
	fx.withBundle()
	err := fx.l.Up(context.Background(), UpOptions{SchemaDir: t.TempDir(), Flags: Settings{Domain: "lab.test", AdminPassword: "x"}})
	if err == nil || !strings.Contains(err.Error(), "--profile ldap") {
		t.Fatalf("got %v", err)
	}
}

// .env holds one lab's settings: starting the other kind in the same state directory is refused.
func TestUpRefusesAStateDirOfTheOtherKind(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("corp.example.local")
	must(t, fx.l.ChooseServer(context.Background(), ProfileLDAP))
	fx.d.images[ldapImage] = true
	err := fx.l.Up(context.Background(), UpOptions{Image: ldapImage, Flags: Settings{Domain: "dc=example,dc=org", AdminPassword: "x"}})
	if err == nil || !strings.Contains(err.Error(), "--state-dir") {
		t.Fatalf("got %v", err)
	}
}

func TestChooseServerFollowsTheFlagThenEnvThenTheContainer(t *testing.T) {
	ctx := context.Background()
	fx := ldapLab(t)
	fx.upLDAP(UpOptions{})

	// The default lab: .env says ldap.
	l := *fx.l
	l.Server, l.serverFixed = nil, false
	must(t, l.ChooseServer(ctx, ""))
	if l.srv() != OpenLDAP || !l.serverFixed {
		t.Fatalf("got %s", l.srv().Profile)
	}
	// Another instance: its container decides, whatever .env says.
	fx.d.containers["t-ldap-dev2"] = &fakeContainer{labels: map[string]string{labelProfile: ProfileLDAP}}
	must(t, os.Remove(fx.l.envPath()))
	other := *fx.l
	other.Server, other.serverFixed, other.Instance = nil, false, "dev2"
	must(t, other.ChooseServer(ctx, ""))
	if other.srv() != OpenLDAP {
		t.Fatalf("got %s", other.srv().Profile)
	}
	// Nothing at all: Samba, but not fixed (a restore may take the snapshot's kind).
	none := *fx.l
	none.Server, none.serverFixed, none.Instance = nil, false, "dev3"
	must(t, none.ChooseServer(ctx, ""))
	if none.srv() != Samba || none.serverFixed {
		t.Fatal("the default is an unfixed Samba")
	}
	if err := none.ChooseServer(ctx, "389ds"); err == nil {
		t.Fatal("an unknown profile must be refused")
	}
}

func TestOpenLDAPSnapshotsRecordTheKindAndRestoreIntoTheSameKindOnly(t *testing.T) {
	ctx := context.Background()
	fx := ldapLab(t)
	fx.upLDAP(UpOptions{})
	fx.d.volumeData["t-ldap-data"], fx.d.volumeData["t-ldap-config"] = "D", "C"
	meta, err := fx.l.Snapshot(ctx, SnapshotOptions{Name: "base"})
	must(t, err)
	if meta.Profile != ProfileLDAP || meta.Domain != "dc=example,dc=org" || len(meta.Files) != 2 ||
		meta.Files[0].File != "data.tar" || meta.Files[1].File != "config.tar" || meta.Hostname != "ldap1" {
		t.Fatalf("%+v", meta)
	}
	if !strings.Contains(fx.out.String(), "Stopping OpenLDAP") {
		t.Fatal(fx.out.String())
	}

	// A new instance with no kind given takes the snapshot's.
	dev2 := *fx.l
	dev2.Server, dev2.serverFixed, dev2.Instance = nil, false, "dev2"
	must(t, dev2.ChooseServer(ctx, ""))
	_, err = dev2.RestoreWith(ctx, "base", RestoreOptions{AdminPassword: "Secret-Passw0rd!"})
	must(t, err)
	if ct := fx.d.containers["t-ldap-dev2"]; ct == nil || ct.labels[labelProfile] != ProfileLDAP {
		t.Fatalf("containers: %v", fx.d.containers)
	}
	if fx.d.extracted["t-ldap-dev2-data"] != "D" || fx.d.extracted["t-ldap-dev2-config"] != "C" {
		t.Fatalf("%v", fx.d.extracted)
	}

	// A Samba lab refuses it before touching anything.
	sambaLab := newLabFixture(t)
	sambaLab.up("corp.example.local")
	sambaLab.l.Dirs.Snapshots = fx.l.Dirs.Snapshots
	must(t, sambaLab.l.ChooseServer(ctx, ""))
	sambaLab.d.calls = nil
	if _, err := sambaLab.l.RestoreWith(ctx, "base", RestoreOptions{}); err == nil || !strings.Contains(err.Error(), "OpenLDAP") {
		t.Fatalf("got %v", err)
	}
	if len(sambaLab.d.callsMatching("stop ")) != 0 {
		t.Fatal("a refused restore must not stop the lab")
	}
}

func TestBundleImageReadsOneLinePerServerAndTheOldSingleLine(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "IMAGE"), []byte("ad=ldap-cronin/samba-ad:1\nldap=ldap-cronin/openldap:1\n"), 0o644))
	if got, err := bundleImage(dir, ProfileLDAP); err != nil || got != "ldap-cronin/openldap:1" {
		t.Fatalf("%q %v", got, err)
	}
	must(t, os.WriteFile(filepath.Join(dir, "IMAGE"), []byte("ldap-cronin/samba-ad:0\n"), 0o644))
	if got, err := bundleImage(dir, ProfileAD); err != nil || got != "ldap-cronin/samba-ad:0" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := bundleImage(dir, ProfileLDAP); err == nil {
		t.Fatal("an old bundle has no OpenLDAP image")
	}
}

func TestValidateSuffix(t *testing.T) {
	for _, ok := range []string{"dc=example,dc=org", "o=acme", "ou=lab,o=acme", "DC=Example,DC=Org"} {
		if err := ValidateSuffix(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "example.org", "cn=x,dc=example", "uid=a"} {
		if err := ValidateSuffix(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}
