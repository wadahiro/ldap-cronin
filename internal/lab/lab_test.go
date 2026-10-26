package lab

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// ---- Settings ----

func TestValidateRealm(t *testing.T) {
	for _, ok := range []string{"corp.example.local", "ad.example.com", "a-b.c1.test", "lab.test"} {
		if err := ValidateRealm(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "singlelabel", "bad name!.test", "-lead.test", "trail-.test", "a..b", ".a.b"} {
		if ValidateRealm(bad) == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestBaseDNAndNetBIOS(t *testing.T) {
	if got := BaseDN("Corp.Example.LOCAL"); got != "DC=corp,DC=example,DC=local" {
		t.Fatal(got)
	}
	if NetBIOSOf("corp.example.local") != "CORP" {
		t.Fatal("netbios")
	}
	if _, err := (Settings{Domain: "averyveryverylonglabelname.test"}).EffectiveNetBIOS(); err == nil {
		t.Fatal("a NetBIOS name over 15 chars must be rejected")
	}
	if nb, err := (Settings{Domain: "averyveryverylonglabelname.test", NetBIOS: "LONGDOM"}).EffectiveNetBIOS(); err != nil || nb != "LONGDOM" {
		t.Fatal(nb, err)
	}
}

func TestGeneratedPasswordMeetsTheComplexityPolicy(t *testing.T) {
	a, err := GeneratePassword()
	must(t, err)
	b, _ := GeneratePassword()
	if a == b {
		t.Fatal("passwords must differ")
	}
	var upper, lower, digit, symbol bool
	for _, r := range a {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	if !upper || !lower || !digit || !symbol || len(a) < 20 {
		t.Fatalf("%q", a)
	}
}

func TestEnvFileIsPrivateAndOptionsBeatEnvBeatFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	must(t, WriteEnvFile(path, Settings{Domain: "file.test", AdminPassword: "from-file", LDAPPort: 1, LDAPSPort: 2}))
	st, err := os.Stat(path)
	must(t, err)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	file, err := ReadEnvFile(path)
	must(t, err)
	env := map[string]string{"AD_REALM": "env.test", "AD_LDAPS_PORT": "9"}
	got := Resolve(Samba, Settings{Domain: "flag.test"}, file, func(k string) string { return env[k] })
	// Domain: option > environment variable > .env. LDAPS: environment variable > .env. Password and LDAP: .env.
	if got.Domain != "flag.test" || got.LDAPSPort != 9 || got.AdminPassword != "from-file" || got.LDAPPort != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestMissingEnvFileIsEmptySettings(t *testing.T) {
	s, err := ReadEnvFile(filepath.Join(t.TempDir(), "none"))
	if err != nil || s != (Settings{}) {
		t.Fatal(s, err)
	}
}

// ---- Bundle ----

func TestVerifyChecksums(t *testing.T) {
	fx := newLabFixture(t)
	dir := fx.withBundle()
	must(t, VerifyChecksums(dir))
	must(t, os.WriteFile(filepath.Join(dir, "images", "samba-ad.tar"), []byte("corrupted"), 0o644))
	if err := VerifyChecksums(dir); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("got %v", err)
	}
}

func TestFindBundleDirChecksExplicitThenCwdThenExeDirThenItsParent(t *testing.T) {
	bundle := t.TempDir()
	must(t, os.WriteFile(filepath.Join(bundle, "IMAGE"), []byte("x"), 0o644))
	bin := filepath.Join(bundle, "bin")
	must(t, os.MkdirAll(bin, 0o755))
	other := t.TempDir()

	if got, ok := FindBundleDir("", other, bin); !ok || got != bundle { // looks in the parent even if the executable is in bin/
		t.Fatalf("%q %v", got, ok)
	}
	if got, ok := FindBundleDir("", bundle, other); !ok || got != bundle {
		t.Fatalf("%q %v", got, ok)
	}
	if _, ok := FindBundleDir("", other, other); ok {
		t.Fatal("no bundle there")
	}
	if _, ok := FindBundleDir(other, bundle, bundle); ok {
		t.Fatal("an explicit directory without IMAGE must not fall back to another one")
	}
}

// ---- load ----

// load verifies the bundle and loads its images once, starts nothing, and loads again when one of the bundle's
// images is missing or --reload asks for it.
func TestLoadLoadsTheImagesAndStartsNothing(t *testing.T) {
	ctx := context.Background()
	fx := newLabFixture(t)
	dir := fx.withBundle()
	must(t, fx.l.Load(ctx, LoadOptions{}))
	if len(fx.d.callsMatching("load -i")) != 1 || !strings.Contains(fx.out.String(), "Verifying file integrity") {
		t.Fatalf("%v\n%s", fx.d.calls, fx.out.String())
	}
	for _, c := range fx.d.calls {
		if strings.HasPrefix(c, "run ") || strings.HasPrefix(c, "create ") || strings.HasPrefix(c, "start ") {
			t.Fatalf("load must start nothing: %s", c)
		}
	}
	if _, err := os.Stat(fx.l.envPath()); err == nil {
		t.Fatal("load must not write .env: the domain is decided by up")
	}
	must(t, fx.l.Load(ctx, LoadOptions{}))
	if len(fx.d.callsMatching("load -i")) != 1 || !strings.Contains(fx.out.String(), "Images already present: ldap-cronin/samba-ad:test") {
		t.Fatalf("an image already there is not loaded again: %v\n%s", fx.d.calls, fx.out.String())
	}
	must(t, fx.l.Load(ctx, LoadOptions{Reload: true}))
	if len(fx.d.callsMatching("load -i")) != 2 {
		t.Fatalf("--reload loads again: %v", fx.d.calls)
	}

	// A bundle of both images loads its tar while the OpenLDAP one is missing, though the Samba one is there.
	must(t, os.WriteFile(filepath.Join(dir, "IMAGE"), []byte("ad=ldap-cronin/samba-ad:test\nldap=ldap-cronin/openldap:test\n"), 0o644))
	must(t, fx.l.Load(ctx, LoadOptions{SkipVerify: true}))
	if len(fx.d.callsMatching("load -i")) != 3 {
		t.Fatalf("a missing image of the bundle is loaded: %v", fx.d.calls)
	}
}

func TestLoadRefusesWithoutABundleOrWithACorruptOne(t *testing.T) {
	ctx := context.Background()
	fx := newLabFixture(t)
	if err := fx.l.Load(ctx, LoadOptions{}); err == nil || !strings.Contains(err.Error(), "bundle") {
		t.Fatalf("without a bundle: %v", err)
	}
	dir := fx.withBundle()
	must(t, os.WriteFile(filepath.Join(dir, "images", "samba-ad.tar"), []byte("corrupted"), 0o644))
	if err := fx.l.Load(ctx, LoadOptions{}); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("a corrupt bundle: %v", err)
	}
	if len(fx.d.callsMatching("load -i")) != 0 {
		t.Fatalf("nothing is loaded: %v", fx.d.calls)
	}
}

// ---- up ----

func TestUpLoadsTheImageStartsTheContainerAndHidesThePassword(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("corp.example.local")
	d := fx.d

	if len(d.callsMatching("load -i")) != 1 {
		t.Fatalf("image must be loaded once: %v", d.calls)
	}
	run := d.callsMatching("run -d --name t-ad ")
	if len(run) != 1 {
		t.Fatalf("%v", d.calls)
	}
	for _, want := range []string{
		"--hostname dc1", "AD_REALM=corp.example.local", "SAMBA_DOMAIN=CORP", "-p 12389:389", "-p 12636:636",
		"-v t-ad-private:/var/lib/samba", "-v t-ad-etc:/etc/samba", "--health-cmd test -f /tmp/ad-ready",
		"--label ldap-cronin.realm=corp.example.local", "ldap-cronin/samba-ad:test",
	} {
		if !strings.Contains(run[0], want) {
			t.Errorf("run args lack %q:\n%s", want, run[0])
		}
	}
	for _, c := range d.calls {
		if strings.Contains(c, "Secret-Passw0rd!") {
			t.Fatalf("the password must not appear in docker arguments: %s", c)
		}
	}
	if !strings.Contains(strings.Join(d.secretSeen, " "), "Secret-Passw0rd!") {
		t.Fatal("the password must be passed through the environment")
	}
	if len(d.callsMatching("exec -e LDAPTLS_REQCERT")) != 1 {
		t.Fatalf("a smoke test must run: %v", d.calls)
	}
	if env, _ := ReadEnvFile(fx.l.envPath()); env.Domain != "corp.example.local" || env.AdminPassword != "Secret-Passw0rd!" {
		t.Fatalf("%+v", env)
	}
}

func TestUpSkipsLoadWhenTheImageIsAlreadyThere(t *testing.T) {
	fx := newLabFixture(t)
	fx.withBundle()
	fx.d.images["ldap-cronin/samba-ad:test"] = true
	must(t, fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "lab.test", AdminPassword: "x-Passw0rd!"}}))
	if len(fx.d.callsMatching("load -i")) != 0 {
		t.Fatal("must not reload")
	}
	fx.d.containers = map[string]*fakeContainer{}
	must(t, fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "lab.test"}, Reload: true}))
	if len(fx.d.callsMatching("load -i")) != 1 {
		t.Fatal("--reload must load again")
	}
}

func TestUpRejectsInvalidInputBeforeTouchingDocker(t *testing.T) {
	fx := newLabFixture(t)
	fx.withBundle()
	if err := fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "bad name!", AdminPassword: "x"}}); err == nil {
		t.Fatal("invalid realm")
	}
	if err := fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "averyveryverylonglabelname.test", AdminPassword: "x"}}); err == nil {
		t.Fatal("netbios too long")
	}
	if len(fx.d.callsMatching("run -d")) != 0 {
		t.Fatal("no container may be started")
	}
}

func TestUpGeneratesAPasswordWhenNoneIsGiven(t *testing.T) {
	fx := newLabFixture(t)
	fx.withBundle()
	must(t, fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "gen.test"}}))
	env, _ := ReadEnvFile(fx.l.envPath())
	if len(env.AdminPassword) < 20 || !strings.Contains(fx.out.String(), "auto-generated") {
		t.Fatalf("%+v\n%s", env, fx.out.String())
	}
}

func TestUpAsksForTheRealmWhenOmitted(t *testing.T) {
	fx := newLabFixture(t)
	fx.withBundle()
	fx.prompt.realm = "asked.test"
	fx.prompt.password = "Asked-Passw0rd!"
	must(t, fx.l.Up(context.Background(), UpOptions{}))
	if env, _ := ReadEnvFile(fx.l.envPath()); env.Domain != "asked.test" {
		t.Fatalf("%+v", env)
	}
}

func TestUpFallsBackToTheDefaultRealmWithoutATerminal(t *testing.T) {
	fx := newLabFixture(t)
	fx.withBundle()
	must(t, fx.l.Up(context.Background(), UpOptions{Flags: Settings{AdminPassword: "x-Passw0rd!"}}))
	if env, _ := ReadEnvFile(fx.l.envPath()); env.Domain != DefaultRealm {
		t.Fatalf("%+v", env)
	}
}

func TestUpReusesAnExistingContainerWithTheSameSettings(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("corp.example.local")
	before := len(fx.d.callsMatching("run -d"))
	must(t, fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "corp.example.local"}})) // the password comes from .env
	if len(fx.d.callsMatching("run -d")) != before {
		t.Fatal("an existing container must be reused")
	}
}

func TestUpRestartsAStoppedContainer(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("corp.example.local")
	must(t, fx.l.Down(context.Background()))
	must(t, fx.l.Up(context.Background(), UpOptions{}))
	if len(fx.d.callsMatching("start t-ad")) != 1 || !fx.d.containers["t-ad"].running {
		t.Fatalf("%v", fx.d.calls)
	}
}

func TestUpRefusesAnExistingContainerWithDifferentSettingsWithoutDestroyingIt(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("corp.example.local")
	n := len(fx.d.calls)
	err := fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "other.test"}})
	if err == nil || !strings.Contains(err.Error(), "reset") {
		t.Fatalf("got %v", err)
	}
	for _, c := range fx.d.calls[n:] {
		if strings.HasPrefix(c, "rm ") || strings.HasPrefix(c, "stop ") || strings.HasPrefix(c, "volume rm") || strings.HasPrefix(c, "run ") {
			t.Fatalf("a mismatch must not destroy or recreate anything: %s", c)
		}
	}
	if err := fx.l.Up(context.Background(), UpOptions{Flags: Settings{LDAPSPort: 9999}}); err == nil {
		t.Fatal("a different port must be refused too")
	}
}

func TestUpWithSampleSourceStartsAnEphemeralContainerWithoutVolumes(t *testing.T) {
	fx := newLabFixture(t)
	fx.withBundle()
	must(t, fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "corp.example.local", AdminPassword: "x-Passw0rd!"}, WithSource: true}))
	run := fx.d.callsMatching("run -d --name t-ad-src")
	if len(run) != 1 || !strings.Contains(run[0], "SEED_SAMPLE_DATA=true") || strings.Contains(run[0], " -v ") ||
		!strings.Contains(run[0], "-p 11636:636") || !strings.Contains(run[0], "--hostname dc2") {
		t.Fatalf("%v", run)
	}
}

func TestUpFailsWithoutAnImageAndExplainsHow(t *testing.T) {
	fx := newLabFixture(t) // no bundle and no image
	err := fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "a.test", AdminPassword: "x"}})
	if err == nil || !strings.Contains(err.Error(), "--image") {
		t.Fatalf("got %v", err)
	}
	fx.d.images["my/image:1"] = true
	must(t, fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "a.test", AdminPassword: "x-Passw0rd!"}, Image: "my/image:1"}))
	if len(fx.d.callsMatching("my/image:1")) == 0 {
		t.Fatal("the explicit image must be used")
	}
}

func TestUpRefusesACorruptedBundle(t *testing.T) {
	fx := newLabFixture(t)
	dir := fx.withBundle()
	must(t, os.WriteFile(filepath.Join(dir, "images", "samba-ad.tar"), []byte("bad"), 0o644))
	if err := fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "a.test", AdminPassword: "x"}}); err == nil {
		t.Fatal("must fail")
	}
	if len(fx.d.callsMatching("load -i")) != 0 {
		t.Fatal("a corrupted image must not be loaded")
	}
	fx.d.calls = nil
	must(t, fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "a.test", AdminPassword: "x-Passw0rd!"}, SkipVerify: true}))
}

func TestUpWarnsWhenTheImageArchitectureDiffersFromTheHost(t *testing.T) {
	fx := newLabFixture(t)
	fx.withBundle()
	fx.d.arch = "arm64"
	must(t, fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "a.test", AdminPassword: "x-Passw0rd!"}}))
	if !strings.Contains(fx.errw.String(), "architecture") {
		t.Fatal(fx.errw.String())
	}
}

// ---- down / reset ----

func TestDownStopsButKeepsTheContainerAndData(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("corp.example.local")
	must(t, fx.l.Down(context.Background()))
	if _, ok := fx.d.containers["t-ad"]; !ok || fx.d.containers["t-ad"].running {
		t.Fatal("the container must be stopped, not removed")
	}
	if len(fx.d.callsMatching("volume rm")) != 0 {
		t.Fatal("data must stay")
	}
}

func TestResetRemovesDataAndEnvButKeepsSnapshotsByDefault(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("corp.example.local")
	fx.d.volumeData["t-ad-private"] = "data"
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "keep"})
	must(t, err)

	if err := fx.l.Reset(context.Background(), ResetOptions{}); err == nil {
		t.Fatal("reset must ask for confirmation")
	}
	must(t, fx.l.Reset(context.Background(), ResetOptions{Yes: true}))
	if _, ok := fx.d.containers["t-ad"]; ok {
		t.Fatal("container must be removed")
	}
	if len(fx.d.callsMatching("volume rm -f t-ad-private")) != 1 || len(fx.d.callsMatching("volume rm -f t-ad-etc")) != 1 {
		t.Fatal(fx.d.calls)
	}
	if _, err := os.Stat(fx.l.envPath()); !os.IsNotExist(err) {
		t.Fatal(".env must be removed")
	}
	if list, _ := fx.l.Snapshots(); len(list) != 1 {
		t.Fatal("snapshots must survive a reset by default")
	}
	must(t, fx.l.Reset(context.Background(), ResetOptions{Yes: true, Snapshots: true}))
	if list, _ := fx.l.Snapshots(); len(list) != 0 {
		t.Fatal("--snapshots must remove them")
	}
}

func TestResetAcceptsAConfirmation(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("corp.example.local")
	must(t, fx.l.Reset(context.Background(), ResetOptions{Confirm: func(string) bool { return true }}))
}
