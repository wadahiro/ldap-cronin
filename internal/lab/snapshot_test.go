package lab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seededLab(t *testing.T) *labFixture {
	t.Helper()
	fx := newLabFixture(t)
	fx.up("corp.example.local")
	fx.d.volumeData["t-ad-private"] = "private-data-v1"
	fx.d.volumeData["t-ad-etc"] = "etc-data-v1"
	return fx
}

func indexOf(calls []string, sub string, from int) int {
	for i := from; i < len(calls); i++ {
		if strings.Contains(calls[i], sub) {
			return i
		}
	}
	return -1
}

func TestSnapshotStopsDumpsBothVolumesThenRestartsAndRecordsMetadata(t *testing.T) {
	fx := seededLab(t)
	fx.d.calls = nil
	meta, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline", Note: "right after clone"})
	must(t, err)

	// Order: stop -> private tar -> etc tar -> start -> wait for healthy
	c := fx.d.calls
	stop := indexOf(c, "stop -t 60 t-ad", 0)
	priv := indexOf(c, "-v t-ad-private:/var/lib/samba:ro", stop)
	etc := indexOf(c, "-v t-ad-etc:/etc/samba:ro", priv)
	start := indexOf(c, "start t-ad", etc)
	if stop < 0 || priv < 0 || etc < 0 || start < 0 {
		t.Fatalf("expected stop -> private -> etc -> start, got:\n%s", strings.Join(c, "\n"))
	}
	if !fx.d.containers["t-ad"].running {
		t.Fatal("the lab must be running again")
	}

	if meta.Realm != "corp.example.local" || meta.NetBIOS != "CORP" || meta.Hostname != "dc1" ||
		meta.Image != "ldap-cronin/samba-ad:test" || meta.Note != "right after clone" || meta.ToolVersion != "test" {
		t.Fatalf("%+v", meta)
	}
	for _, f := range meta.Files {
		raw, err := os.ReadFile(filepath.Join(fx.l.Dirs.Snapshots, "baseline", f.File))
		must(t, err)
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != f.SHA256 || int64(len(raw)) != f.Size {
			t.Fatalf("%s: metadata does not match the file", f.File)
		}
		st, _ := os.Stat(filepath.Join(fx.l.Dirs.Snapshots, "baseline", f.File))
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("snapshot files hold password hashes: mode %v", st.Mode().Perm())
		}
	}
	if got, _ := os.ReadFile(filepath.Join(fx.l.Dirs.Snapshots, "baseline", "private.tar")); string(got) != "private-data-v1" {
		t.Fatalf("%q", got)
	}
}

func TestSnapshotOfAStoppedLabDoesNotStartIt(t *testing.T) {
	fx := seededLab(t)
	must(t, fx.l.Down(context.Background()))
	fx.d.calls = nil
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "cold"})
	must(t, err)
	if len(fx.d.callsMatching("stop ")) != 0 || len(fx.d.callsMatching("start ")) != 0 {
		t.Fatalf("a stopped lab must stay stopped: %v", fx.d.calls)
	}
}

func TestSnapshotFailureRestartsTheLabAndLeavesNoPartialSnapshot(t *testing.T) {
	fx := seededLab(t)
	fx.d.failTarCreate = "t-ad-etc"
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "broken"})
	if err == nil || !strings.Contains(err.Error(), "returned to its previous state") {
		t.Fatalf("got %v", err)
	}
	if !fx.d.containers["t-ad"].running {
		t.Fatal("the lab must be running again even though the snapshot failed")
	}
	entries, _ := os.ReadDir(fx.l.Dirs.Snapshots)
	if len(entries) != 0 {
		t.Fatalf("no partial snapshot may remain: %v", entries)
	}
	if list, _ := fx.l.Snapshots(); len(list) != 0 {
		t.Fatal("a failed snapshot must not be listed")
	}
}

func TestSnapshotNameValidationAndOverwrite(t *testing.T) {
	fx := seededLab(t)
	for _, bad := range []string{"../escape", "has space", "-lead", ".hidden", "a/b", strings.Repeat("x", 65)} {
		if _, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: bad}); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "a"})
	must(t, err)
	if _, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "a"}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("overwriting needs --force: %v", err)
	}
	fx.d.volumeData["t-ad-private"] = "private-data-v2"
	_, err = fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "a", Force: true})
	must(t, err)
	if got, _ := os.ReadFile(filepath.Join(fx.l.Dirs.Snapshots, "a", "private.tar")); string(got) != "private-data-v2" {
		t.Fatalf("%q", got)
	}
}

func TestSnapshotWithoutALabExplainsWhatToDo(t *testing.T) {
	fx := newLabFixture(t)
	if _, err := fx.l.Snapshot(context.Background(), SnapshotOptions{}); err == nil || !strings.Contains(err.Error(), "up") {
		t.Fatalf("got %v", err)
	}
}

func TestSnapshotWithoutANameGetsATimestampNameAndNeverOverwrites(t *testing.T) {
	fx := seededLab(t)
	a, err := fx.l.Snapshot(context.Background(), SnapshotOptions{})
	must(t, err)
	b, err := fx.l.Snapshot(context.Background(), SnapshotOptions{}) // time advances, so the name differs
	must(t, err)
	if !strings.HasPrefix(a.Name, "snapshot-2026") || a.Name == b.Name {
		t.Fatalf("%q %q", a.Name, b.Name)
	}
}

func TestMultipleSnapshotsAreListedOldestFirstAndBrokenOnesAreSkipped(t *testing.T) {
	fx := seededLab(t)
	for _, n := range []string{"first", "second", "third"} {
		_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: n})
		must(t, err)
	}
	must(t, os.MkdirAll(filepath.Join(fx.l.Dirs.Snapshots, "not-a-snapshot"), 0o755))
	must(t, os.MkdirAll(filepath.Join(fx.l.Dirs.Snapshots, "corrupt"), 0o755))
	must(t, os.WriteFile(filepath.Join(fx.l.Dirs.Snapshots, "corrupt", "snapshot.json"), []byte("{"), 0o600))

	list, err := fx.l.Snapshots()
	must(t, err)
	var names []string
	for _, m := range list {
		names = append(names, m.Name)
	}
	if strings.Join(names, ",") != "first,second,third" {
		t.Fatal(names)
	}
	out := FormatSnapshots(list)
	if !strings.Contains(out, "second") || !strings.Contains(out, "corp.example.local") {
		t.Fatal(out)
	}
	// The list starts with a column header that shows which column is the domain. The "DOMAIN" column lines up between the header and each row.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if !strings.HasPrefix(lines[0], "NAME") || !strings.Contains(lines[0], "DOMAIN") {
		t.Fatalf("header missing: %q", lines[0])
	}
	if strings.Index(lines[0], "DOMAIN") != strings.Index(lines[1], "corp.example.local") {
		t.Fatalf("the DOMAIN column must line up with the values:\n%s", out)
	}
}

func TestSnapshotRemove(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "x"})
	must(t, err)
	must(t, fx.l.SnapshotRemove("x"))
	if list, _ := fx.l.Snapshots(); len(list) != 0 {
		t.Fatal("not removed")
	}
	if err := fx.l.SnapshotRemove("x"); err == nil {
		t.Fatal("removing a missing snapshot must fail")
	}
	if err := fx.l.SnapshotRemove("../etc"); err == nil {
		t.Fatal("path traversal must be rejected")
	}
}

// ---- restore ----

func TestRestoreWritesTheSnapshotBackAndStartsTheLab(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	// After the snapshot, another program changed the data.
	fx.d.volumeData["t-ad-private"] = "mutated-by-another-program"
	fx.d.volumeData["t-ad-etc"] = "mutated-etc"

	fx.d.calls = nil
	meta, err := fx.l.Restore(context.Background(), "baseline")
	must(t, err)
	if meta.Name != "baseline" {
		t.Fatal(meta.Name)
	}
	if fx.d.volumeData["t-ad-private"] != "private-data-v1" || fx.d.volumeData["t-ad-etc"] != "etc-data-v1" {
		t.Fatalf("data not restored: %v", fx.d.volumeData)
	}
	// Order: stop -> empty private -> extract -> empty etc -> extract -> start
	c := fx.d.calls
	stop := indexOf(c, "stop -t 60 t-ad", 0)
	wipePriv := indexOf(c, "find /var/lib/samba -mindepth 1 -delete", stop)
	extractPriv := indexOf(c, "-xf", wipePriv)
	wipeEtc := indexOf(c, "find /etc/samba -mindepth 1 -delete", extractPriv)
	extractEtc := indexOf(c, "-xf", wipeEtc)
	start := indexOf(c, "start t-ad", extractEtc)
	if stop < 0 || wipePriv < 0 || extractPriv < 0 || wipeEtc < 0 || extractEtc < 0 || start < 0 {
		t.Fatalf("unexpected order:\n%s", strings.Join(c, "\n"))
	}
	if !fx.d.containers["t-ad"].running {
		t.Fatal("must be running")
	}
	if len(fx.d.callsMatching("exec -e LDAPTLS_REQCERT")) == 0 {
		t.Fatal("a smoke test must confirm the restored AD answers")
	}
}

// Ctrl-C after Samba was stopped must not leave half-written volumes or a stopped lab: the restore runs to the start.
func TestInterruptedRestoreStillWritesBackAndStartsTheLab(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	fx.d.volumeData["t-ad-private"] = "mutated-by-another-program"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fx.d.onCall = func(line string) {
		if strings.HasPrefix(line, "stop ") {
			cancel()
		}
	}
	_, err = fx.l.Restore(ctx, "baseline")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want the cancellation reported after the critical section, got %v", err)
	}
	if fx.d.volumeData["t-ad-private"] != "private-data-v1" || !fx.d.containers["t-ad"].running {
		t.Fatalf("the restore must finish: data=%q running=%v", fx.d.volumeData["t-ad-private"], fx.d.containers["t-ad"].running)
	}
}

// Ctrl-C while the volumes are being written out abandons the snapshot but still restarts the lab.
func TestInterruptedSnapshotRestartsTheLab(t *testing.T) {
	fx := seededLab(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fx.d.onCall = func(line string) {
		if strings.HasPrefix(line, "stop ") {
			cancel()
		}
	}
	if _, err := fx.l.Snapshot(ctx, SnapshotOptions{Name: "baseline"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("want the cancellation, got %v", err)
	}
	if !fx.d.containers["t-ad"].running {
		t.Fatal("the lab must be running again")
	}
	if _, err := os.Stat(fx.l.snapshotDir("baseline")); err == nil {
		t.Fatal("an interrupted snapshot must not be kept")
	}
}

func TestRestoreVerifiesTheSnapshotBeforeTouchingTheLiveData(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	must(t, os.WriteFile(filepath.Join(fx.l.Dirs.Snapshots, "baseline", "private.tar"), []byte("tampered"), 0o600))

	fx.d.calls = nil
	fx.d.volumeData["t-ad-private"] = "live-data"
	if _, err := fx.l.Restore(context.Background(), "baseline"); err == nil || !strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("got %v", err)
	}
	for _, c := range fx.d.calls {
		if strings.HasPrefix(c, "stop ") || strings.Contains(c, "-delete") || strings.Contains(c, "-xf") {
			t.Fatalf("a corrupted snapshot must not touch the live data: %s", c)
		}
	}
	if fx.d.volumeData["t-ad-private"] != "live-data" || !fx.d.containers["t-ad"].running {
		t.Fatal("live data and the running lab must be untouched")
	}
}

func TestRestoreRefusesADifferentRealmAndAMissingSnapshot(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)

	fx.d.containers["t-ad"].labels["ldap-cronin.realm"] = "other.test"
	if _, err := fx.l.Restore(context.Background(), "baseline"); err == nil || !strings.Contains(err.Error(), "domain") {
		t.Fatalf("got %v", err)
	}
	if _, err := fx.l.Restore(context.Background(), "missing"); err == nil {
		t.Fatal("a missing snapshot must fail")
	}
}

func TestRestoreFromAnInteractiveListNewestFirst(t *testing.T) {
	fx := seededLab(t)
	for i, n := range []string{"old", "middle", "new"} {
		fx.d.volumeData["t-ad-private"] = "state-" + n
		_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: n, Note: "note " + n})
		must(t, err)
		_ = i
	}
	fx.prompt.interactive = true
	fx.prompt.choose = 1 // second newest = middle
	meta, err := fx.l.Restore(context.Background(), "")
	must(t, err)
	if meta.Name != "middle" || fx.d.volumeData["t-ad-private"] != "state-middle" {
		t.Fatalf("%q %q", meta.Name, fx.d.volumeData["t-ad-private"])
	}
	if !strings.Contains(fx.prompt.chosePrompt, "DOMAIN") {
		t.Fatalf("the interactive list must show a column header: %q", fx.prompt.chosePrompt)
	}
	items := fx.prompt.chooseItems
	if len(items) != 3 || !strings.HasPrefix(items[0], "new") || !strings.HasPrefix(items[2], "old") {
		t.Fatalf("the list must be newest first: %v", items)
	}
	if !strings.Contains(items[0], "corp.example.local") || !strings.Contains(items[0], "note new") {
		t.Fatalf("each line must show the domain and the note: %q", items[0])
	}
}

func TestRestoreWithoutANameAndWithoutATerminalListsTheCandidates(t *testing.T) {
	fx := seededLab(t)
	for _, n := range []string{"a", "b"} {
		_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: n})
		must(t, err)
	}
	_, err := fx.l.Restore(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "Candidates") || !strings.Contains(err.Error(), "a ") || !strings.Contains(err.Error(), "b ") {
		t.Fatalf("got %v", err)
	}
	fx2 := seededLab(t)
	if _, err := fx2.l.Restore(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "no snapshots exist") {
		t.Fatalf("got %v", err)
	}
}

func TestRestoredStateIsReusableAndRepeatable(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	for i := 0; i < 3; i++ { // can repeat: restore -> get modified -> restore again
		fx.d.volumeData["t-ad-private"] = "mutated"
		_, err := fx.l.Restore(context.Background(), "baseline")
		must(t, err)
		if fx.d.volumeData["t-ad-private"] != "private-data-v1" {
			t.Fatalf("round %d: %q", i, fx.d.volumeData["t-ad-private"])
		}
	}
}

// ---- Start a second lab from a snapshot, on different ports ----

func (fx *labFixture) instanceLab(name string) *Lab {
	other := *fx.l
	other.Instance = name
	return &other
}

func TestRestoreAsANewInstanceStartsAnotherContainerBesideTheRunningLab(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	fx.d.volumeData["t-ad-private"] = "main-has-moved-on" // the original lab keeps changing afterwards

	dev := fx.instanceLab("dev2")
	fx.d.calls = nil
	meta, err := dev.RestoreWith(context.Background(), "baseline", RestoreOptions{LDAPPort: 22389, LDAPSPort: 22636})
	must(t, err)
	if meta.Name != "baseline" {
		t.Fatal(meta.Name)
	}

	// The snapshot contents go into a separate container and separate volumes.
	c, ok := fx.d.containers["t-ad-dev2"]
	if !ok || !c.running {
		t.Fatalf("the new instance must be running: %v", fx.d.containers)
	}
	if fx.d.volumeData["t-ad-dev2-private"] != "private-data-v1" || fx.d.volumeData["t-ad-dev2-etc"] != "etc-data-v1" {
		t.Fatalf("snapshot not loaded into the new volumes: %v", fx.d.volumeData)
	}
	run := fx.d.callsMatching("run -d --name t-ad-dev2 ")
	if len(run) != 1 {
		t.Fatalf("%v", fx.d.calls)
	}
	for _, want := range []string{"-p 22389:389", "-p 22636:636", "-v t-ad-dev2-private:/var/lib/samba", "--hostname dc1",
		"--label ldap-cronin.instance=dev2", "AD_REALM=corp.example.local"} {
		if !strings.Contains(run[0], want) {
			t.Errorf("run args lack %q:\\n%s", want, run[0])
		}
	}
	for _, call := range fx.d.calls {
		if strings.Contains(call, "Secret-Passw0rd!") {
			t.Fatalf("the password must not appear in docker arguments: %s", call)
		}
	}

	// The original lab keeps running and its data is untouched.
	if !fx.d.containers["t-ad"].running || fx.d.volumeData["t-ad-private"] != "main-has-moved-on" {
		t.Fatal("the original lab must be untouched")
	}
	for _, call := range fx.d.calls {
		if strings.HasPrefix(call, "stop ") || strings.HasPrefix(call, "rm ") || strings.Contains(call, "t-ad-private") && !strings.Contains(call, "dev2") {
			t.Fatalf("the original lab must not be touched: %s", call)
		}
	}
	// The default lab's .env is not rewritten.
	if env, _ := ReadEnvFile(fx.l.envPath()); env.LDAPSPort != 12636 {
		t.Fatalf("the main lab's .env must stay: %+v", env)
	}
}

func TestNewInstancePicksFreePortsWhenNoneAreGiven(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	_, err = fx.instanceLab("dev2").RestoreWith(context.Background(), "baseline", RestoreOptions{})
	must(t, err)
	l := fx.d.containers["t-ad-dev2"].labels
	if l["ldap-cronin.ldap-port"] != "40001" || l["ldap-cronin.ldaps-port"] != "40002" {
		t.Fatalf("%v", l)
	}
}

func TestNewInstanceRefusesPortsUsedByAnotherInstance(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	_, err = fx.instanceLab("dev2").RestoreWith(context.Background(), "baseline", RestoreOptions{LDAPPort: 12389, LDAPSPort: 22636}) // 12389 is main's LDAP
	if err == nil || !strings.Contains(err.Error(), "12389") {
		t.Fatalf("got %v", err)
	}
	if _, ok := fx.d.containers["t-ad-dev2"]; ok {
		t.Fatal("nothing may be created")
	}
	if _, err := fx.instanceLab("dev2").RestoreWith(context.Background(), "baseline", RestoreOptions{LDAPPort: 5000, LDAPSPort: 5000}); err == nil {
		t.Fatal("the same port for LDAP and LDAPS must be refused")
	}
}

func TestRestoreIntoAnExistingInstanceOverwritesThatInstanceOnly(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	dev := fx.instanceLab("dev2")
	_, err = dev.RestoreWith(context.Background(), "baseline", RestoreOptions{LDAPPort: 22389, LDAPSPort: 22636})
	must(t, err)

	fx.d.volumeData["t-ad-dev2-private"] = "dev2-mutated"
	fx.d.volumeData["t-ad-private"] = "main-state"
	_, err = dev.RestoreWith(context.Background(), "baseline", RestoreOptions{})
	must(t, err)
	if fx.d.volumeData["t-ad-dev2-private"] != "private-data-v1" {
		t.Fatalf("dev2 must be restored: %q", fx.d.volumeData["t-ad-dev2-private"])
	}
	if fx.d.volumeData["t-ad-private"] != "main-state" {
		t.Fatal("the main lab must not be touched")
	}
}

func TestInstancesAreListedMainFirstAndStatusShowsThem(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	for _, n := range []string{"zeta", "alpha"} {
		_, err = fx.instanceLab(n).RestoreWith(context.Background(), "baseline", RestoreOptions{})
		must(t, err)
	}
	list, err := fx.l.Instances(context.Background())
	must(t, err)
	var order []string
	for _, in := range list {
		order = append(order, in.Instance)
	}
	if strings.Join(order, ",") != "main,alpha,zeta" {
		t.Fatal(order)
	}
	fx.out.Reset()
	must(t, fx.l.Status(context.Background()))
	if !strings.Contains(fx.out.String(), "t-ad-alpha") || !strings.Contains(fx.out.String(), "LDAPS=12636") {
		t.Fatal(fx.out.String())
	}
}

func TestDownAndResetOfAnInstanceLeaveTheMainLabAlone(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	dev := fx.instanceLab("dev2")
	_, err = dev.RestoreWith(context.Background(), "baseline", RestoreOptions{})
	must(t, err)

	must(t, dev.Down(context.Background()))
	if fx.d.containers["t-ad-dev2"].running || !fx.d.containers["t-ad"].running {
		t.Fatal("only dev2 must be stopped")
	}
	must(t, dev.Reset(context.Background(), ResetOptions{Yes: true}))
	if _, ok := fx.d.containers["t-ad-dev2"]; ok {
		t.Fatal("dev2 must be removed")
	}
	if len(fx.d.callsMatching("volume rm -f t-ad-dev2-private")) != 1 || len(fx.d.callsMatching("volume rm -f t-ad-private")) != 0 {
		t.Fatalf("only dev2's volumes may be removed: %v", fx.d.callsMatching("volume rm"))
	}
	if _, err := os.Stat(fx.l.envPath()); err != nil {
		t.Fatal("the main lab's .env must stay")
	}
	if list, _ := fx.l.Snapshots(); len(list) != 1 {
		t.Fatal("snapshots must stay")
	}
}

func TestSnapshotOfAnInstanceUsesItsOwnVolumes(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	dev := fx.instanceLab("dev2")
	_, err = dev.RestoreWith(context.Background(), "baseline", RestoreOptions{})
	must(t, err)
	fx.d.volumeData["t-ad-dev2-private"] = "dev2-own-state"
	_, err = dev.Snapshot(context.Background(), SnapshotOptions{Name: "from-dev2"})
	must(t, err)
	if got, _ := os.ReadFile(filepath.Join(fx.l.Dirs.Snapshots, "from-dev2", "private.tar")); string(got) != "dev2-own-state" {
		t.Fatalf("%q", got)
	}
}

func TestInstanceNameValidationAndUpIsMainOnly(t *testing.T) {
	for _, bad := range []string{"main", "Dev", "has space", "-x", "", strings.Repeat("a", 32), "a_b"} {
		if ValidateInstanceName(bad) == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	for _, ok := range []string{"dev2", "a", "test-1"} {
		if err := ValidateInstanceName(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	fx := newLabFixture(t)
	fx.withBundle()
	if err := fx.instanceLab("dev2").Up(context.Background(), UpOptions{Flags: Settings{Realm: "a.test", AdminPassword: "x"}}); err == nil ||
		!strings.Contains(err.Error(), "restore --instance dev2") {
		t.Fatalf("got %v", err)
	}
}

func TestRestoreRecreatesTheMainLabAfterAResetFromASnapshot(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline"})
	must(t, err)
	must(t, fx.l.Reset(context.Background(), ResetOptions{Yes: true})) // deletes container, volumes and .env (snapshots remain)

	if _, err := fx.l.Restore(context.Background(), "baseline"); err == nil || !strings.Contains(err.Error(), "admin password") {
		t.Fatalf("without the password it must ask for it: %v", err)
	}
	_, err = fx.l.RestoreWith(context.Background(), "baseline", RestoreOptions{AdminPassword: "Secret-Passw0rd!"})
	must(t, err)
	if !fx.d.containers["t-ad"].running || fx.d.volumeData["t-ad-private"] != "private-data-v1" {
		t.Fatal("the main lab must be recreated from the snapshot")
	}
	if env, _ := ReadEnvFile(fx.l.envPath()); env.Realm != "corp.example.local" || env.LDAPSPort != 12636 {
		t.Fatalf(".env must be written for the main lab: %+v", env)
	}
}

// ---- Include the mapping in the snapshot ----

func writeMap(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guid-map.tsv")
	must(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestSnapshotIncludesTheMappingAndRestoreWritesItBackKeepingABackup(t *testing.T) {
	fx := seededLab(t)
	mapPath := writeMap(t, "map-at-snapshot-time")

	meta, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline", Mapping: mapPath})
	must(t, err)
	if meta.Mapping == nil || meta.Mapping.Size != int64(len("map-at-snapshot-time")) || meta.Mapping.File != "mapping" {
		t.Fatalf("%+v", meta.Mapping)
	}
	copied := filepath.Join(fx.l.Dirs.Snapshots, "baseline", "mapping")
	if got, _ := os.ReadFile(copied); string(got) != "map-at-snapshot-time" {
		t.Fatalf("%q", got)
	}
	if st, _ := os.Stat(copied); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if !strings.Contains(fx.out.String(), "with mapping") {
		t.Fatal(fx.out.String())
	}

	// After the snapshot, the mapping was updated by another clone. Restoring brings back the table as of the snapshot.
	must(t, os.WriteFile(mapPath, []byte("map-after-another-clone"), 0o600))
	_, err = fx.l.RestoreWith(context.Background(), "baseline", RestoreOptions{Mapping: mapPath})
	must(t, err)
	if got, _ := os.ReadFile(mapPath); string(got) != "map-at-snapshot-time" {
		t.Fatalf("the map must be written back: %q", got)
	}
	if got, _ := os.ReadFile(mapPath + ".bak"); string(got) != "map-after-another-clone" {
		t.Fatalf("the previous map must be kept as .bak: %q", got)
	}
}

func TestRestoreWithoutAMappingDestinationLeavesTheMapAloneAndSaysWhere(t *testing.T) {
	fx := seededLab(t)
	mapPath := writeMap(t, "included")
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline", Mapping: mapPath})
	must(t, err)
	must(t, os.WriteFile(mapPath, []byte("current"), 0o600))

	fx.out.Reset()
	_, err = fx.l.Restore(context.Background(), "baseline")
	must(t, err)
	if got, _ := os.ReadFile(mapPath); string(got) != "current" {
		t.Fatal("without a destination the current map must be untouched")
	}
	if !strings.Contains(fx.out.String(), "includes a mapping") || !strings.Contains(fx.out.String(), "--mapping") {
		t.Fatalf("it must say the snapshot holds a map and how to write it back:\n%s", fx.out.String())
	}
}

func TestSnapshotWithAMissingMappingFailsBeforeStoppingTheLab(t *testing.T) {
	fx := seededLab(t)
	fx.d.calls = nil
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "x", Mapping: filepath.Join(t.TempDir(), "none.tsv")})
	if err == nil || !strings.Contains(err.Error(), "mapping") {
		t.Fatalf("got %v", err)
	}
	if len(fx.d.callsMatching("stop ")) != 0 || !fx.d.containers["t-ad"].running {
		t.Fatal("the lab must not be stopped for a snapshot that cannot be taken")
	}
}

func TestRestoreVerifiesTheMappingInTheSnapshotToo(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline", Mapping: writeMap(t, "good")})
	must(t, err)
	must(t, os.WriteFile(filepath.Join(fx.l.Dirs.Snapshots, "baseline", "mapping"), []byte("tampered"), 0o600))
	fx.d.calls = nil
	if _, err := fx.l.Restore(context.Background(), "baseline"); err == nil || !strings.Contains(err.Error(), "mapping of snapshot") {
		t.Fatalf("got %v", err)
	}
	for _, c := range fx.d.calls {
		if strings.HasPrefix(c, "stop ") || strings.Contains(c, "-delete") {
			t.Fatalf("a corrupted map must not touch the live data: %s", c)
		}
	}
}

func TestRestoreIntoASnapshotWithoutAMapWarnsAndLeavesTheDestination(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "nomap"})
	must(t, err)
	dest := writeMap(t, "keep-me")
	_, err = fx.l.RestoreWith(context.Background(), "nomap", RestoreOptions{Mapping: dest})
	must(t, err)
	if got, _ := os.ReadFile(dest); string(got) != "keep-me" || !strings.Contains(fx.errw.String(), "does not include") {
		t.Fatalf("%q / %s", got, fx.errw.String())
	}
}

func TestANewInstanceGetsItsOwnCopyOfTheMapAndTheMainMapIsUntouched(t *testing.T) {
	fx := seededLab(t)
	mainMap := writeMap(t, "main-map-now")
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "baseline", Mapping: writeMap(t, "baseline-map")})
	must(t, err)

	dev2Map := filepath.Join(t.TempDir(), "sub", "guid-map-dev2.tsv") // created even if the parent directory does not exist
	_, err = fx.instanceLab("dev2").RestoreWith(context.Background(), "baseline", RestoreOptions{Mapping: dev2Map})
	must(t, err)
	if got, _ := os.ReadFile(dev2Map); string(got) != "baseline-map" {
		t.Fatalf("%q", got)
	}
	if got, _ := os.ReadFile(mainMap); string(got) != "main-map-now" {
		t.Fatal("the main lab's map must not be touched")
	}
}

func TestSnapshotListShowsWhetherAMapIsIncluded(t *testing.T) {
	fx := seededLab(t)
	_, err := fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "with", Mapping: writeMap(t, "m")})
	must(t, err)
	_, err = fx.l.Snapshot(context.Background(), SnapshotOptions{Name: "without"})
	must(t, err)
	list, _ := fx.l.Snapshots()
	out := FormatSnapshots(list)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var withLine, withoutLine string
	for _, l := range lines {
		if strings.HasPrefix(l, "with ") {
			withLine = l
		}
		if strings.HasPrefix(l, "without ") {
			withoutLine = l
		}
	}
	if !strings.Contains(withLine, "  yes") || strings.Contains(withoutLine, "yes") || !strings.Contains(withoutLine, "  -") || !strings.Contains(lines[0], "MAP") {
		t.Fatalf("\n%s", out)
	}
}
