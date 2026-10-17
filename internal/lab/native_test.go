package lab

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

func TestNativeStopsTheLabWhileImportingAndRestartsItAfterwards(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("ad.example.com")
	n, err := fx.l.OpenNative(context.Background())
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
	n, err := fx.l.OpenNative(ctx)
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
	n, err := fx.l.OpenNative(context.Background())
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

func TestNativeAddMapsExistingEntryToErrExists(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("ad.example.com")
	n, err := fx.l.OpenNative(context.Background())
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
	n, err := fx.l.OpenNative(context.Background())
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

func TestNativeRestartsTheLabWhenTheSelfCheckFails(t *testing.T) {
	fx := newLabFixture(t)
	fx.up("ad.example.com")
	fx.d.helper = newFakeHelper()
	fx.d.helper.failOp = "hello"
	if _, err := fx.l.OpenNative(context.Background()); err == nil {
		t.Fatal("a failing self-check must fail")
	}
	if !fx.d.containers["t-ad"].running {
		t.Fatal("the lab must be running again even when the helper failed to start")
	}
}

func TestNativeWithoutALabFails(t *testing.T) {
	fx := newLabFixture(t)
	if _, err := fx.l.OpenNative(context.Background()); err == nil || !strings.Contains(err.Error(), "lab") {
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
