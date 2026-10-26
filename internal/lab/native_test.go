package lab

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

func TestNativeStopsTheLabWhileImportingAndRestartsItAfterwards(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("ad.example.com")
	n, err := fx.l.OpenNative(context.Background(), NativeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !fx.d.helper.sawStop {
		t.Fatal("the lab container must be stopped before the helper opens the same sam.ldb")
	}
	if n.Info.DomainSID != "S-1-5-21-1-2-3" || n.Info.Base == "" {
		t.Fatalf("hello info = %+v", n.Info)
	}
	if err := n.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fx.d.containers["t-ad"].running {
		t.Fatal("the lab must be running again after Close")
	}
}

// An interrupted import stops between requests, and Close still resumes the lab with the cancelled context.
func TestInterruptedNativeImportStopsBetweenRequestsAndResumesTheLab(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("ad.example.com")
	ctx, cancel := context.WithCancel(context.Background())
	n, err := fx.l.OpenNative(ctx, NativeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	err = n.Add(ctx, directory.Entry{DN: "CN=a,DC=ad", Attrs: map[string][]string{"cn": {"a"}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a request after the cancellation must not be sent: %v", err)
	}
	if err := n.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if !fx.d.containers["t-ad"].running {
		t.Fatal("the lab must be running again after an interrupted import")
	}
}

func TestNativeHelperMountsTheLabVolumesAndKeepsPasswordsOutOfArguments(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("ad.example.com")
	n, err := fx.l.OpenNative(context.Background(), NativeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close(context.Background())
	run := fx.d.callsMatching("--entrypoint python3")
	if len(run) != 1 {
		t.Fatalf("helper start = %v", run)
	}
	for _, want := range []string{"-v t-ad-private:/var/lib/samba", "-v t-ad-etc:/etc/samba", "--name t-ad-native", "run -i --rm"} {
		if !strings.Contains(run[0], want) {
			t.Errorf("%q missing in %s", want, run[0])
		}
	}
}

func TestNativeFastPasswordReachesTheSelfCheckAndTheSummary(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("ad.example.com")
	n, err := fx.l.OpenNative(context.Background(), NativeOptions{FastPassword: true})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close(context.Background())
	if fx.d.helper.hello["fast_password"] != true {
		t.Fatalf("the helper must be told before its self-check: %v", fx.d.helper.hello)
	}
	f := NativeFinish{DBCheck: "Checked 3 objects (0 errors)", FastPasswords: 41}
	if !strings.Contains(f.Summary(), "41 users got the NT hash directly (no Kerberos AES keys)") {
		t.Fatal(f.Summary())
	}
	if strings.Contains(NativeFinish{DBCheck: "ok"}.Summary(), "fast_password") {
		t.Fatal("a normal import says nothing of it")
	}
}

func TestNativeAddMapsExistingEntryToErrExists(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("ad.example.com")
	n, err := fx.l.OpenNative(context.Background(), NativeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close(context.Background())
	e := directory.Entry{DN: "CN=a,DC=ad", Attrs: map[string][]string{"objectGUID": {"\x01\xff\x00"}, "cn": {"あ"}}}
	if err := n.Add(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := n.Add(context.Background(), e); !errors.Is(err, directory.ErrExists) {
		t.Fatalf("a second add must be ErrExists, got %v", err)
	}
	got, err := n.Get(context.Background(), "CN=a,DC=ad", []string{"objectGUID", "cn"})
	if err != nil || got == nil {
		t.Fatalf("%v %v", got, err)
	}
	if got.Values("objectGUID")[0] != "\x01\xff\x00" || got.Values("cn")[0] != "あ" {
		t.Fatalf("binary and multibyte values must survive the protocol: %+v", got.Attrs)
	}
	if missing, err := n.Get(context.Background(), "CN=none,DC=ad", nil); err != nil || missing != nil {
		t.Fatalf("a missing entry is nil, nil: %v %v", missing, err)
	}
}

func TestNativeFinishRunsBeforeTheLabIsRestarted(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("ad.example.com")
	n, err := fx.l.OpenNative(context.Background(), NativeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := n.Finish(context.Background())
	if err != nil || res.MaxRID != 1234 || res.RIDNext != 1235 || !strings.Contains(res.DBCheck, "0 errors") {
		t.Fatalf("%+v %v", res, err)
	}
	if err := n.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The journal of an import done in slices outlives the helper (it is in the lab's volume) for the same
// fingerprint, is dropped for another, and the end of a slice advances the RIDs without dbcheck.
func TestNativeJournalOutlivesASliceAndOnlyForItsFingerprint(t *testing.T) {
	ctx := context.Background()
	fx := newLabFixture(t)
	fx.up("ad.example.com")
	n, err := fx.l.OpenNative(ctx, NativeOptions{})
	must(t, err)
	j, err := n.Journal(ctx, "fp-1")
	must(t, err)
	must(t, j.Mark(ctx, "object cn=a"))
	if fx.d.helper.journalKeys != nil {
		t.Fatal("a mark is buffered until a flush")
	}
	must(t, j.Flush(ctx))
	res, err := n.FinishSlice(ctx)
	if err != nil || res.MaxRID != 1234 || res.DBCheck != "" {
		t.Fatalf("%+v %v", res, err)
	}
	must(t, n.Close(ctx))

	n, err = fx.l.OpenNative(ctx, NativeOptions{})
	must(t, err)
	if j, err = n.Journal(ctx, "fp-1"); err != nil || !j.Has("object cn=a") || j.Stale {
		t.Fatalf("the same fingerprint: %v %+v", err, j)
	}
	if j, err = n.Journal(ctx, "fp-2"); err != nil || j.Has("object cn=a") || !j.Stale {
		t.Fatalf("another fingerprint: %v %+v", err, j)
	}
	must(t, j.Clear(ctx))
	if _, err := n.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	must(t, n.Close(ctx))
}

func TestNativeRestartsTheLabWhenTheSelfCheckFails(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("ad.example.com")
	fx.d.helper = newFakeHelper()
	fx.d.helper.failOp = "hello"
	if _, err := fx.l.OpenNative(context.Background(), NativeOptions{}); err == nil {
		t.Fatal("a failing self-check must fail")
	}
	if !fx.d.containers["t-ad"].running {
		t.Fatal("the lab must be running again even when the helper failed to start")
	}
}

func TestNativeWithoutALabFails(t *testing.T) {
	fx := newLabFixture(t)
	if _, err := fx.l.OpenNative(context.Background(), NativeOptions{}); err == nil || !strings.Contains(err.Error(), "lab") {
		t.Fatalf("got %v", err)
	}
}

func TestUpPassesTheSourceDomainIdentityToTheFirstBoot(t *testing.T) {
	fx := newLabFixture(t)
	fx.withBundle()
	sid, guid := "S-1-5-21-1111111111-2222222222-3333333333", "12345678-1234-4234-8234-1234567890ab"
	err := fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: "ad.example.com", AdminPassword: "Secret-Passw0rd!", DomainSID: sid, DomainGUID: guid}})
	if err != nil {
		t.Fatal(err)
	}
	run := fx.d.callsMatching("run -d")
	if len(run) != 1 || !strings.Contains(run[0], "-e SAMBA_DOMAIN_SID="+sid) || !strings.Contains(run[0], "-e SAMBA_DOMAIN_GUID="+guid) {
		t.Fatalf("the identity must reach the container as environment variables: %v", run)
	}
	if strings.Contains(run[0], "Secret-Passw0rd!") {
		t.Fatal("the password must not appear in arguments")
	}
	env, err := ReadEnvFile(fx.l.envPath())
	if err != nil || env.DomainSID != sid || env.DomainGUID != guid {
		t.Fatalf("the identity must be kept in .env: %+v %v", env, err)
	}
}

func TestUpRejectsAMalformedDomainIdentity(t *testing.T) {
	fx := newLabFixture(t)
	fx.withBundle()
	for _, s := range []Settings{
		{Domain: "ad.example.com", AdminPassword: "x", DomainSID: "S-1-5-21-1"},
		{Domain: "ad.example.com", AdminPassword: "x", DomainGUID: "nope"},
	} {
		if err := fx.l.Up(context.Background(), UpOptions{Flags: s}); err == nil {
			t.Errorf("%+v must be rejected", s)
		}
	}
	if len(fx.d.callsMatching("run -d")) != 0 {
		t.Fatal("nothing must be started")
	}
}

// A lab target's url must be the lab's: its port is the lab's LDAPS (or LDAP) port, so what clone writes directly
// is what check, diff and schema read.
func TestCheckTargetURLComparesTheLabsPorts(t *testing.T) {
	fx := newLabFixture(t)
	if st, err := fx.l.State(context.Background()); err != nil || st != Missing {
		t.Fatalf("before up: %s %v", st, err)
	}
	if err := fx.l.CheckTargetURL(context.Background(), "ldaps://localhost:12636"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("no lab: %v", err)
	}
	fx.up("ad.example.com")
	if st, err := fx.l.State(context.Background()); err != nil || st != Running {
		t.Fatalf("after up: %s %v", st, err)
	}
	ctx := context.Background()
	for _, ok := range []string{"ldaps://localhost:" + strconv.Itoa(DefaultLDAPSPort), "ldap://localhost:" + strconv.Itoa(DefaultLDAPPort)} {
		if err := fx.l.CheckTargetURL(ctx, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	err := fx.l.CheckTargetURL(ctx, "ldaps://localhost:22636")
	if err == nil || !strings.Contains(err.Error(), "LDAPS port is "+strconv.Itoa(DefaultLDAPSPort)) {
		t.Fatalf("another port: %v", err)
	}
	if err := fx.l.Down(ctx); err != nil {
		t.Fatal(err)
	}
	if st, err := fx.l.State(ctx); err != nil || st != Stopped {
		t.Fatalf("after down: %s %v", st, err)
	}
}
