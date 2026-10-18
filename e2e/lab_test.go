//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/lab"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/workpool"
)

type noPrompt struct{}

func (noPrompt) Domain(string, string) (string, error)     { return "", nil }
func (noPrompt) NewPassword() (string, error)              { return "", nil }
func (noPrompt) Choose(string, []string, int) (int, error) { return 0, lab.ErrNotInteractive }

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// With real docker and Samba, runs lab up -> create data -> snapshots (several) -> modify -> restore.
// It does not use docker compose. The prefix and ports are chosen per test so they do not collide with other labs or compose environments.
// The image is passed via E2E_LAB_IMAGE (tests/e2e.sh builds it with docker build).
func TestLabSnapshotAndRestoreWithRealDocker(t *testing.T) {
	image := os.Getenv("E2E_LAB_IMAGE")
	if image == "" {
		t.Skip("E2E_LAB_IMAGE is not set (tests/e2e.sh sets it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	host := env("E2E_LAB_HOST", "localhost") // in CI docker-in-docker, connect via the service name docker

	const realm, password = "lab-e2e.test", "Adm1n-Passw0rd!"
	base := lab.BaseDN(realm)
	dir := t.TempDir()
	prefix := fmt.Sprintf("labe2e%d", time.Now().UnixNano()%1_000_000)
	ldaps := freePort(t)
	var out, errw bytes.Buffer
	l := &lab.Lab{
		D: lab.ExecDocker{}, Out: &out, Err: &errw, Prompt: noPrompt{}, Prefix: prefix, Version: "e2e",
		Dirs: lab.Dirs{State: dir, Snapshots: dir + "/snapshots"}, Sleep: time.Sleep, Now: time.Now, HostArch: "",
		// Do not read environment variables, so that AD_REALM and the like in the environment running the test do not leak into the lab settings.
		Getenv: func(string) string { return "" },
	}
	t.Cleanup(func() {
		if err := l.Reset(context.Background(), lab.ResetOptions{Yes: true, Snapshots: true}); err != nil {
			t.Logf("cleanup failed: %v", err)
		}
	})
	if testing.Verbose() {
		t.Cleanup(func() { t.Logf("lab output:\n%s%s", out.String(), errw.String()) })
	}

	started := time.Now()
	if err := l.Up(context.Background(), lab.UpOptions{Image: image, Flags: lab.Settings{Domain: realm, AdminPassword: password, LDAPPort: freePort(t), LDAPSPort: ldaps}}); err != nil {
		t.Fatalf("up: %v\n%s", err, errw.String())
	}
	t.Logf("up: %.1fs", time.Since(started).Seconds())

	ad, err := ldapdir.Dial(ldapdir.ConnConfig{
		URL: fmt.Sprintf("ldaps://%s:%d", host, ldaps), BindDN: "CN=Administrator,CN=Users," + base, Password: password, InsecureSkipVerify: true,
	}, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer ad.Close()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// Taking and restoring snapshots stops and starts Samba, which drops open connections. Reopen each time.
	reconnect := func() {
		ad.Close()
		ad, err = ldapdir.Dial(ldapdir.ConnConfig{
			URL: fmt.Sprintf("ldaps://%s:%d", host, ldaps), BindDN: "CN=Administrator,CN=Users," + base, Password: password, InsecureSkipVerify: true,
		}, 4)
		must(err)
	}
	root := "OU=Snap," + base
	userDN := func(i int) string { return fmt.Sprintf("CN=su%03d,%s", i, root) }
	count := func() int {
		entries, err := directory.Collect(context.Background(), ad, root, "(objectClass=user)", []string{directory.NoAttrs})
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	must(ad.Add(context.Background(), directory.Entry{DN: root, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"Snap"}}}))
	addUsers := func(from, to int) {
		idx := make([]int, 0, to-from)
		for i := from; i < to; i++ {
			idx = append(idx, i)
		}
		must(workpool.Each(context.Background(), 4, idx, func(ctx context.Context, i int) error {
			return ad.Add(context.Background(), directory.Entry{DN: userDN(i), Attrs: map[string][]string{
				"objectClass": {"user"}, "cn": {fmt.Sprintf("su%03d", i)}, "sAMAccountName": {fmt.Sprintf("su%03d", i)},
			}})
		}))
	}

	addUsers(0, 30)
	if got := count(); got != 30 {
		t.Fatalf("seed: %d", got)
	}
	if _, err := l.Snapshot(context.Background(), lab.SnapshotOptions{Name: "thirty", Note: "30 users"}); err != nil {
		t.Fatalf("snapshot: %v\n%s", err, errw.String())
	}
	reconnect()

	// After the snapshot, another program changed the data (added 20 users).
	addUsers(30, 50)
	if got := count(); got != 50 {
		t.Fatalf("after mutation: %d", got)
	}
	if _, err := l.Snapshot(context.Background(), lab.SnapshotOptions{Name: "fifty", Note: "50 users"}); err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	reconnect()
	list, err := l.Snapshots()
	must(err)
	if len(list) != 2 || list[0].Name != "thirty" || list[1].Name != "fifty" {
		t.Fatalf("snapshots: %+v", list)
	}
	if list[0].Domain != realm || list[0].Hostname != "dc1" {
		t.Fatalf("metadata: %+v", list[0])
	}

	// Restore to the 30-user snapshot.
	t0 := time.Now()
	if _, err := l.Restore(context.Background(), "thirty"); err != nil {
		t.Fatalf("restore thirty: %v\n%s", err, errw.String())
	}
	t.Logf("restore (stop -> write back -> start -> smoke test): %.1fs", time.Since(t0).Seconds())
	reconnect()
	if got := count(); got != 30 {
		t.Fatalf("restored thirty: %d users, want 30", got)
	}

	// You can also return to the other (50 users) at any time. Multiple snapshots do not affect each other.
	if _, err := l.Restore(context.Background(), "fifty"); err != nil {
		t.Fatalf("restore fifty: %v", err)
	}
	reconnect()
	if got := count(); got != 50 {
		t.Fatalf("restored fifty: %d users, want 50", got)
	}

	// Each restore discards changes. Back to 30 once more.
	if _, err := l.Restore(context.Background(), "thirty"); err != nil {
		t.Fatal(err)
	}
	reconnect()
	if got := count(); got != 30 {
		t.Fatalf("restored thirty again: %d", got)
	}

	// The data survives down -> up as well.
	must(l.Down(context.Background()))
	if err := l.Up(context.Background(), lab.UpOptions{Image: image}); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	reconnect()
	if got := count(); got != 30 {
		t.Fatalf("after down/up: %d", got)
	}

	// Start a lab in the snapshot's state on a different port while keeping the current lab running.
	addUsers(30, 35) // the original lab keeps changing afterwards (35 users)
	if got := count(); got != 35 {
		t.Fatalf("main: %d", got)
	}
	l2 := *l
	l2.Instance = "dev2"
	l2.FreePort = func() (int, error) { return freePort(t), nil }
	t1 := time.Now()
	if _, err := l2.RestoreWith(context.Background(), "fifty", lab.RestoreOptions{}); err != nil { // a free port is chosen automatically
		t.Fatalf("restore as a new instance: %v\n%s", err, errw.String())
	}
	t.Logf("started a separate instance from the snapshot: %.1fs", time.Since(t1).Seconds())
	t.Cleanup(func() { _ = l2.Reset(context.Background(), lab.ResetOptions{Yes: true}) })
	instances, err := l.Instances(context.Background())
	must(err)
	var dev2Port int
	for _, in := range instances {
		if in.Instance == "dev2" {
			dev2Port = in.LDAPS
		}
	}
	if len(instances) != 2 || dev2Port == 0 || dev2Port == ldaps {
		t.Fatalf("instances: %+v", instances)
	}
	ad2, err := ldapdir.Dial(ldapdir.ConnConfig{
		URL: fmt.Sprintf("ldaps://%s:%d", host, dev2Port), BindDN: "CN=Administrator,CN=Users," + base, Password: password, InsecureSkipVerify: true,
	}, 4)
	must(err)
	defer ad2.Close()
	count2 := func() int {
		entries, err := directory.Collect(context.Background(), ad2, root, "(objectClass=user)", []string{directory.NoAttrs})
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	if got := count2(); got != 50 { // the two hold different data: the neighboring instance is in the fifty state
		t.Fatalf("dev2: %d users, want 50", got)
	}
	if got := count(); got != 35 { // the original lab is untouched (its connection is not dropped either)
		t.Fatalf("main must be untouched: %d users, want 35", got)
	}
	// Changing dev2 does not affect the original lab. Deleting only dev2 leaves the original lab running.
	del := exec.Command("docker", "exec", "-e", "LDAPTLS_REQCERT=never", prefix+"-ad-dev2", "ldapdelete", "-x", "-H", "ldaps://127.0.0.1",
		"-D", "CN=Administrator,CN=Users,"+base, "-w", password, userDN(0))
	if out, err := del.CombinedOutput(); err != nil {
		t.Fatalf("ldapdelete on dev2: %v\n%s", err, out)
	}
	if got := count2(); got != 49 {
		t.Fatalf("dev2 after delete: %d", got)
	}
	if got := count(); got != 35 {
		t.Fatalf("main after changing dev2: %d", got)
	}
	must(l2.Reset(context.Background(), lab.ResetOptions{Yes: true}))
	if got := count(); got != 35 {
		t.Fatalf("main after resetting dev2: %d", got)
	}

	// A domain name mismatch is refused without damaging the data.
	err = l.Up(context.Background(), lab.UpOptions{Image: image, Flags: lab.Settings{Domain: "other.test"}})
	if err == nil || !strings.Contains(err.Error(), "reset") {
		t.Fatalf("a different realm must be refused: %v", err)
	}
	reconnect()
	if got := count(); got != 35 {
		t.Fatalf("data must survive the refused up: %d", got)
	}
}

// The intended usage: clone into a lab -> snapshot -> restore into an instance on a different port -> another program
// renames there -> diff detects the rename. The markers are part of the data, so nothing travels beside the snapshot.
func TestLabSnapshotCarriesTheMarkersToAnotherInstanceOnAnotherPort(t *testing.T) {
	image := os.Getenv("E2E_LAB_IMAGE")
	if image == "" {
		t.Skip("E2E_LAB_IMAGE is not set (tests/e2e.sh sets it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	host := env("E2E_LAB_HOST", "localhost")
	const realm, password = "lab-e2e.test", "Adm1n-Passw0rd!"
	base := lab.BaseDN(realm)
	cloneBase := "OU=IDM," + base
	dir := t.TempDir()
	prefix := fmt.Sprintf("labmap%d", time.Now().UnixNano()%1_000_000)
	var out, errw bytes.Buffer
	l := &lab.Lab{
		D: lab.ExecDocker{}, Out: &out, Err: &errw, Prompt: noPrompt{}, Prefix: prefix, Version: "e2e",
		Dirs: lab.Dirs{State: dir, Snapshots: dir + "/snapshots"}, Sleep: time.Sleep, Now: time.Now,
		Getenv:   func(string) string { return "" },
		FreePort: func() (int, error) { return freePort(t), nil },
	}
	t.Cleanup(func() { _ = l.Reset(context.Background(), lab.ResetOptions{Yes: true, Snapshots: true}) })
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%v\n%s", err, errw.String())
		}
	}

	mainLDAPS, srcLDAPS := freePort(t), freePort(t)
	must(l.Up(context.Background(), lab.UpOptions{
		Image: image, WithSource: true, SourceLDAP: freePort(t), SourceLDAPS: srcLDAPS,
		Flags: lab.Settings{Domain: realm, AdminPassword: password, LDAPPort: freePort(t), LDAPSPort: mainLDAPS},
	}))
	dial := func(port int) *ldapdir.Client {
		c, err := ldapdir.Dial(ldapdir.ConnConfig{
			URL: fmt.Sprintf("ldaps://%s:%d", host, port), BindDN: "CN=Administrator,CN=Users," + base, Password: password, InsecureSkipVerify: true,
		}, 4)
		must(err)
		return c
	}
	src, target := dial(srcLDAPS), dial(mainLDAPS)
	defer src.Close()

	// clone, writing the markers
	m := markerOf(t, src, target, cloneBase)
	opt := planOptionsFor(t, cloneBase)
	if _, err := clone.Run(context.Background(), src, target, opt, clone.Options{UserPassword: "Fixed-Passw0rd!", Workers: 4, Marker: &m}, &bytes.Buffer{}); err != nil {
		t.Fatalf("clone: %v", err)
	}
	target.Close()

	// Take a snapshot and restore it into an instance on a different port.
	_, err := l.Snapshot(context.Background(), lab.SnapshotOptions{Name: "cloned"})
	must(err)
	dev2 := *l
	dev2.Instance = "dev2"
	t.Cleanup(func() { _ = dev2.Reset(context.Background(), lab.ResetOptions{Yes: true}) })
	must2 := func(_ lab.SnapshotMeta, err error) {
		t.Helper()
		must(err)
	}
	must2(dev2.RestoreWith(context.Background(), "cloned", lab.RestoreOptions{}))
	instances, err := l.Instances(context.Background())
	must(err)
	dev2Port := 0
	for _, in := range instances {
		if in.Instance == "dev2" {
			dev2Port = in.LDAPS
		}
	}
	if dev2Port == 0 || dev2Port == mainLDAPS {
		t.Fatalf("instances: %+v", instances)
	}

	// In dev2, another program renamed a user.
	conn, err := ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", host, dev2Port), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer conn.Close()
	must(conn.Bind("CN=Administrator,CN=Users,"+base, password))
	alice := "CN=Alice Admin,OU=Tokyo,OU=Users," + cloneBase
	must(conn.ModifyDN(ldap.NewModifyDNRequest(alice, "CN=Alice Smith", true, "")))

	// dev2 is on a different port from the original lab; the markers came with the data, and the index with them.
	d2 := dial(dev2Port)
	defer d2.Close()
	markerOf(t, src, d2, cloneBase)
	var diffs []diff.Difference
	sum, err := diff.Run(context.Background(), src, d2, opt, diff.Options{Workers: 4, Resolver: identity.ByMarker(m)}, func(d diff.Difference) { diffs = append(diffs, d) })
	must(err)
	if sum.Differences[diff.Renamed] != 1 || len(diffs) != 1 || diffs[0].Kind != diff.Renamed ||
		!strings.EqualFold(diffs[0].TargetDN, "CN=Alice Smith,OU=Tokyo,OU=Users,"+cloneBase) {
		var b bytes.Buffer
		for _, d := range diffs {
			diff.Format(&b, d, 10)
		}
		t.Fatalf("want exactly one RENAMED (Alice), got:\n%s", b.String())
	}
}

// [mapping] mode = "file" with a lab: clone -> snapshot -> a user deleted, clone again (recreated with a new
// objectGUID) -> restore (the earlier objectGUID is back) -> diff finds nothing, then a rename. The file is a ledger
// of every pair, so the restore needs nothing beside the snapshot.
func TestLabRestoreWithTheMappingFileAfterAnotherClone(t *testing.T) {
	image := os.Getenv("E2E_LAB_IMAGE")
	if image == "" {
		t.Skip("E2E_LAB_IMAGE is not set (tests/e2e.sh sets it)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	ctx := context.Background()
	host := env("E2E_LAB_HOST", "localhost")
	const realm, password = "lab-e2e.test", "Adm1n-Passw0rd!"
	base := lab.BaseDN(realm)
	admin := "CN=Administrator,CN=Users," + base
	cloneBase := "OU=IDM," + base
	dir := t.TempDir()
	var out, errw bytes.Buffer
	l := &lab.Lab{
		D: lab.ExecDocker{}, Out: &out, Err: &errw, Prompt: noPrompt{}, Version: "e2e",
		Prefix: fmt.Sprintf("labfile%d", time.Now().UnixNano()%1_000_000),
		Dirs:   lab.Dirs{State: dir, Snapshots: dir + "/snapshots"}, Sleep: time.Sleep, Now: time.Now,
		Getenv:   func(string) string { return "" },
		FreePort: func() (int, error) { return freePort(t), nil },
	}
	t.Cleanup(func() { _ = l.Reset(context.Background(), lab.ResetOptions{Yes: true, Snapshots: true}) })
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%v\n%s", err, errw.String())
		}
	}
	ldaps, srcLDAPS := freePort(t), freePort(t)
	must(l.Up(ctx, lab.UpOptions{
		Image: image, WithSource: true, SourceLDAP: freePort(t), SourceLDAPS: srcLDAPS,
		Flags: lab.Settings{Domain: realm, AdminPassword: password, LDAPPort: freePort(t), LDAPSPort: ldaps},
	}))
	dial := func(port int) *ldapdir.Client {
		c, err := ldapdir.Dial(ldapdir.ConnConfig{URL: fmt.Sprintf("ldaps://%s:%d", host, port), BindDN: admin, Password: password, InsecureSkipVerify: true}, 4)
		must(err)
		t.Cleanup(c.Close)
		return c
	}
	conn := func() *ldap.Conn {
		c, err := ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", host, ldaps), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
		must(err)
		t.Cleanup(func() { c.Close() })
		must(c.Bind(admin, password))
		return c
	}
	src := dial(srcLDAPS)
	opt := planOptionsFor(t, cloneBase)
	root, err := identity.RootKey(ctx, src, base, identity.ObjectGUID)
	must(err)
	header := identity.Header{Scheme: identity.ObjectGUID.Attr(), SourceRoot: root}
	path := dir + "/mapping"
	cloneWithFile := func() {
		t.Helper()
		target := dial(ldaps)
		defer target.Close()
		m, err := identity.Open(path, header)
		must(err)
		_, err = clone.Run(ctx, src, target, opt, clone.Options{UserPassword: "Fixed-Passw0rd!", Workers: 4, Mapping: m}, &bytes.Buffer{})
		if cerr := m.Close(); err == nil {
			err = cerr
		}
		must(err)
	}
	diffWithFile := func() []diff.Difference {
		t.Helper()
		target := dial(ldaps)
		defer target.Close()
		m, err := identity.Load(path, header)
		must(err)
		defer m.Close()
		var diffs []diff.Difference
		_, err = diff.Run(ctx, src, target, opt, diff.Options{Workers: 4, Resolver: identity.ByMap(m, identity.ObjectGUID)}, func(d diff.Difference) { diffs = append(diffs, d) })
		must(err)
		return diffs
	}
	show := func(diffs []diff.Difference) string {
		var b bytes.Buffer
		for _, d := range diffs {
			diff.Format(&b, d, 10)
		}
		return b.String()
	}

	alice := "CN=Alice Admin,OU=Tokyo,OU=Users," + cloneBase
	cloneWithFile()
	_, err = l.Snapshot(ctx, lab.SnapshotOptions{Name: "cloned"})
	must(err)
	must(conn().Del(ldap.NewDelRequest(alice, nil)))
	cloneWithFile() // alice is created again, with a new objectGUID
	_, err = l.Restore(ctx, "cloned")
	must(err)
	if diffs := diffWithFile(); len(diffs) != 0 {
		t.Fatalf("the restored clone must have no differences:\n%s", show(diffs))
	}

	must(conn().ModifyDN(ldap.NewModifyDNRequest(alice, "CN=Alice Smith", true, "")))
	diffs := diffWithFile()
	if len(diffs) != 1 || diffs[0].Kind != diff.Renamed || !strings.EqualFold(diffs[0].TargetDN, "CN=Alice Smith,OU=Tokyo,OU=Users,"+cloneBase) {
		t.Fatalf("want exactly one RENAMED (Alice), got:\n%s", show(diffs))
	}
}
