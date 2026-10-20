//go:build e2e

// E2E against two real Samba4 AD servers (ad-src -> ad in docker compose). Run it from tests/e2e.sh.
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/workpool"
)

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return def
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	realmDN   = env("E2E_DOMAIN_DN", "DC=ad,DC=example,DC=com")
	adminPw   = env("SAMBA_ADMIN_PASSWORD", "Admin-Passw0rd!")
	srcURL    = env("E2E_SRC_URL", "ldaps://localhost:11636")
	dstURL    = env("E2E_DST_URL", "ldaps://localhost:12636")
	adminDN   = "CN=Administrator,CN=Users," + realmDN
	fixedPw   = "Fixed-Passw0rd!"
	baseDN    = "OU=IDM," + realmDN
	aliceDN   = "CN=Alice Admin,OU=Tokyo,OU=Users,OU=IDM," + realmDN
	bobDN     = "CN=Bob Staff,OU=Tokyo,OU=Users,OU=IDM," + realmDN
	johnDN    = `CN=Doe\, John,OU=営業部,OU=Users,OU=IDM,` + realmDN
	carolDN   = "CN=Carol Disabled,CN=Staff,OU=Users,OU=IDM," + realmDN
	daveDN    = "CN=Dave NoExpire,CN=Staff,OU=Users,OU=IDM," + realmDN
	allStaff  = "CN=AllStaff,OU=Groups,OU=IDM," + realmDN
	domainAdm = "CN=Domain Admins,CN=Users," + realmDN
)

func mustGet(t *testing.T, c *ldapdir.Client, dn string, attrs ...string) *directory.Entry {
	t.Helper()
	e, err := c.Get(context.Background(), dn, attrs)
	if err != nil || e == nil {
		t.Fatalf("%s: %v", dn, err)
	}
	return e
}

func runDiff(opt plan.Job, src, dst directory.Directory) ([]diff.Difference, error) {
	var diffs []diff.Difference
	_, err := diff.Run(context.Background(), src, dst, opt, diff.Options{Workers: 8}, func(d diff.Difference) { diffs = append(diffs, d) })
	return diffs, err
}

// runDiffWith is runDiff with a resolver (nil for none).
func runDiffWith(opt plan.Job, src, dst directory.Directory, res identity.Resolver) ([]diff.Difference, error) {
	var diffs []diff.Difference
	_, err := diff.Run(context.Background(), src, dst, opt, diff.Options{Workers: 8, Resolver: res}, func(d diff.Difference) { diffs = append(diffs, d) })
	return diffs, err
}

func dial(t *testing.T, url string) *ldapdir.Client { return dialWith(t, url, 0, 8) }

func dialWith(t *testing.T, url string, rangeSize, workers int) *ldapdir.Client {
	t.Helper()
	c, err := ldapdir.Dial(ldapdir.ConnConfig{URL: url, BindDN: adminDN, Password: adminPw, InsecureSkipVerify: true, RangeSize: rangeSize}, workers)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c.With(profile.AD.Ranged)
}

func planOptions(t *testing.T) plan.Job { return planOptionsFor(t, baseDN) }

func planOptionsFor(t *testing.T, base string) plan.Job {
	t.Helper()
	raw := `
[source]
url = "` + srcURL + `"
bind_dn = "` + adminDN + `"
[target]
url = "` + dstURL + `"
bind_dn = "` + adminDN + `"
[scope]
base_dn = "` + base + `"
[attributes]
extra_include = ["carLicense", "seeAlso"]
[mask]
attributes = ["mail"]
`
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	opt, err := cfg.JobFor(profile.AD)
	if err != nil {
		t.Fatal(err)
	}
	return opt
}

// Attributes holding DNs are determined from the source schema, not from a fixed list.
func TestReferenceAttributesAreDetectedFromSambaSchema(t *testing.T) {
	p, err := plan.Build(context.Background(), dial(t, srcURL), planOptions(t), plan.Read{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"member", "manager", "managedBy", "seeAlso"} {
		if !p.IsRef(name) {
			t.Errorf("%s must be detected as a DN reference", name)
		}
	}
	for _, name := range []string{"mail", "sAMAccountName", "memberOf"} {
		if p.IsRef(name) {
			t.Errorf("%s must not be a forward DN reference", name)
		}
	}
	if !p.RefSingle("manager") || p.RefSingle("member") {
		t.Error("manager is single-valued, member is multi-valued")
	}
}

// Every attribute in the allow list must exist in the Samba schema (requesting a nonexistent attribute can make an add fail).
func TestDefaultAttributesExistInSambaSchema(t *testing.T) {
	c := dial(t, dstURL)
	entries, err := directory.Collect(context.Background(), c, "CN=Schema,CN=Configuration,"+realmDN, "(objectClass=attributeSchema)", []string{"lDAPDisplayName"})
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, e := range entries {
		known[strings.ToLower(e.Values("lDAPDisplayName")[0])] = true
	}
	for _, k := range profile.AD.Kinds {
		for _, name := range k.Default {
			if !known[strings.ToLower(name)] {
				t.Errorf("%s: %s is not in Samba schema", k.Name, name)
			}
		}
	}
}

func TestCloneThenDiffThenIdempotentThenDetectTamper(t *testing.T) {
	src, dst := dial(t, srcURL), dial(t, dstURL)
	opt := planOptions(t)
	job, copts := opt, clone.Options{UserPassword: fixedPw, Workers: 4}

	// A diff before clone (the starting OU does not exist on the target) yields a list of MISSING entries instead of failing.
	pre, err := runDiff(opt, src, dst)
	if err != nil || len(pre) == 0 {
		t.Fatalf("diff on empty target: %v (%d diffs)", err, len(pre))
	}
	for _, d := range pre {
		if d.Kind != diff.OnlySource {
			t.Fatalf("empty target must only report MISSING: %+v", d)
		}
	}

	var out bytes.Buffer
	rep, err := clone.Run(context.Background(), src, dst, job, copts, &out)
	if err != nil {
		t.Fatalf("clone: %v\n%s", err, out.String())
	}
	t.Logf("first run: %+v", *rep)

	assertNoDiff := func(when string) {
		t.Helper()
		diffs, err := runDiff(opt, src, dst)
		if err != nil {
			t.Fatal(err)
		}
		if len(diffs) != 0 {
			var b bytes.Buffer
			for _, d := range diffs {
				diff.Format(&b, d, diff.DefaultMaxValues)
			}
			t.Fatalf("%s: unexpected diff:\n%s", when, b.String())
		}
	}
	assertNoDiff("after clone")

	t.Run("fixtures", func(t *testing.T) {
		get := func(dn string, a ...string) *directoryEntry {
			e, err := dst.Get(context.Background(), dn, a)
			if err != nil || e == nil {
				t.Fatalf("%s: %v", dn, err)
			}
			return &directoryEntry{e.Values}
		}
		if v := get(carolDN, "userAccountControl").first("userAccountControl"); v != "514" {
			t.Errorf("carol uac=%s", v)
		}
		if v := get(daveDN, "userAccountControl").first("userAccountControl"); v != "66048" {
			t.Errorf("dave uac=%s", v)
		}
		if v := get(aliceDN, "mail").first("mail"); v != "********" {
			t.Errorf("mail not masked: %s", v)
		}
		if v := get(aliceDN, "carLicense").first("carLicense"); v != "ALICE-001" {
			t.Errorf("extra_include attribute: %s", v)
		}
		if v := get(bobDN, "manager").first("manager"); !strings.EqualFold(v, aliceDN) {
			t.Errorf("manager=%s", v)
		}
		if got := get(aliceDN, "seeAlso").all("seeAlso"); len(got) != 2 {
			t.Errorf("seeAlso (DN reference found via schema) = %v", got)
		}
		members := strings.ToLower(strings.Join(mustGet(t, dst, allStaff, "member").Values("member"), "|"))
		for _, want := range []string{"cn=eng,", "cn=bob staff,", "cn=carol disabled,", "cn=domain admins,"} {
			if !strings.Contains(members, want) {
				t.Errorf("AllStaff missing member %s in %s", want, members)
			}
		}
		_ = johnDN
	})

	t.Run("fixed password works over LDAPS", func(t *testing.T) {
		conn, err := ldap.DialURL(dstURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.Bind(aliceDN, fixedPw); err != nil {
			t.Fatalf("alice bind with fixed password: %v", err)
		}
	})

	t.Run("second run changes nothing", func(t *testing.T) {
		before := mustGet(t, dst, aliceDN, "pwdLastSet").Values("pwdLastSet")
		rep, err := clone.Run(context.Background(), src, dst, job, copts, &bytes.Buffer{})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Added != 0 || rep.Updated != 0 {
			t.Fatalf("not idempotent: %+v", *rep)
		}
		if after := mustGet(t, dst, aliceDN, "pwdLastSet").Values("pwdLastSet"); strings.Join(before, "") != strings.Join(after, "") || len(before) == 0 {
			t.Fatalf("password was rewritten on re-run: pwdLastSet %v -> %v", before, after)
		}
		assertNoDiff("after second run")
	})

	t.Run("ancestors are masked", func(t *testing.T) {
		// The base OU description exists on the source and description is not masked, so it must match.
		assertNoDiff("ancestors")
	})

	t.Run("diff detects a manual change", func(t *testing.T) {
		if err := dst.Replace(context.Background(), aliceDN, map[string][]string{"title": {"Hacked"}}); err != nil {
			t.Fatal(err)
		}
		diffs, err := runDiff(opt, src, dst)
		if err != nil {
			t.Fatal(err)
		}
		if len(diffs) != 1 || diffs[0].Attr != "title" || diffs[0].Kind != diff.Differ {
			t.Fatalf("%+v", diffs)
		}
		// A re-run must repair it.
		if _, err := clone.Run(context.Background(), src, dst, job, copts, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		assertNoDiff("after repair")
	})
}

type directoryEntry struct{ values func(string) []string }

func (d *directoryEntry) all(name string) []string { return d.values(name) }

func (d *directoryEntry) first(name string) string {
	if v := d.values(name); len(v) > 0 {
		return v[0]
	}
	return ""
}

// More than 1000 users (search paging) and a group with more than 1500 members (ranged retrieval of member).
// Samba does not split member into ranges on its own, so ldapdir always requests an explicit range.
// Lower the range size to 500 so one request cannot hold everything (forcing several continuation requests).
func TestBulkUsersPagingAndLargeGroupRanges(t *testing.T) {
	users := envInt("E2E_BULK_USERS", 1600)
	workers := envInt("E2E_WORKERS", 8)
	const rangeSize = 500
	// Use a different starting OU per run so measurements can be repeated in the same environment with different worker counts.
	runID := time.Now().UnixNano() % 1_000_000
	name := fmt.Sprintf("Bulk%06d", runID)
	bulkBase := "OU=" + name + "," + realmDN
	groupDN := "CN=BulkGroup," + bulkBase
	start := time.Now()
	lap := func(label string) {
		t.Logf("%-28s %6.1fs (users=%d workers=%d)", label, time.Since(start).Seconds(), users, workers)
		start = time.Now()
	}
	userName := func(i int) string { return fmt.Sprintf("b%06d_%04d", runID, i) } // sAMAccountName is unique within the domain
	userDN := func(i int) string { return fmt.Sprintf("CN=%s,%s", userName(i), bulkBase) }

	src, dst := dialWith(t, srcURL, rangeSize, workers), dialWith(t, dstURL, rangeSize, workers)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(src.Add(context.Background(), directory.Entry{DN: bulkBase, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {name}}}))
	idx := make([]int, users)
	for i := range idx {
		idx[i] = i
	}
	must(workpool.Each(context.Background(), workers, idx, func(ctx context.Context, i int) error {
		return src.Add(context.Background(), directory.Entry{DN: userDN(i), Attrs: map[string][]string{
			"objectClass": {"user"}, "cn": {userName(i)}, "sAMAccountName": {userName(i)},
		}})
	}))
	must(src.Add(context.Background(), directory.Entry{DN: groupDN, Attrs: map[string][]string{
		"objectClass": {"group"}, "cn": {"BulkGroup"}, "sAMAccountName": {name + "G"}, "groupType": {"-2147483646"},
	}}))
	for lo := 0; lo < users; lo += 500 {
		var chunk []string
		for i := lo; i < min(lo+500, users); i++ {
			chunk = append(chunk, userDN(i))
		}
		must(src.AddValues(context.Background(), groupDN, "member", chunk))
	}

	lap("seed source")
	g, err := src.Get(context.Background(), groupDN, []string{"member"})
	if err != nil || g == nil || len(g.Values("member")) != users {
		t.Fatalf("source group members: want %d, got %v (err=%v)", users, len(g.Values("member")), err)
	}

	opt := planOptionsFor(t, bulkBase)
	lap("read group (ranged)")
	rep, err := clone.Run(context.Background(), src, dst, opt, clone.Options{UserPassword: fixedPw, Workers: workers}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	lap("clone")
	if want := users + 2; rep.Added != want || rep.WarningCount != 0 {
		t.Fatalf("added=%d want %d, warnings=%d", rep.Added, want, rep.WarningCount)
	}

	got, err := dst.Get(context.Background(), groupDN, []string{"member"})
	if err != nil || got == nil || len(got.Values("member")) != users {
		t.Fatalf("target group members: want %d, got %d (err=%v)", users, len(got.Values("member")), err)
	}
	found, err := directory.Collect(context.Background(), dst, bulkBase, userFilter(t, opt), []string{"sAMAccountName"})
	if err != nil || len(found) != users {
		t.Fatalf("paged user search on target: want %d, got %d (err=%v)", users, len(found), err)
	}

	lap("verify counts")
	diffs, err := runDiff(opt, src, dst)
	lap("diff")
	if err != nil || len(diffs) != 0 {
		t.Fatalf("diff after bulk clone: %d diffs, err=%v", len(diffs), err)
	}
	rep, err = clone.Run(context.Background(), src, dst, opt, clone.Options{UserPassword: fixedPw, Workers: workers}, &bytes.Buffer{})
	lap("re-run (no-op)")
	if err != nil || rep.Added != 0 || rep.Updated != 0 {
		t.Fatalf("bulk re-run must change nothing: %+v err=%v", rep, err)
	}
}

// markerOf is the marker of objects cloned from src, as app builds it. It also checks that the target indexes the
// marker attribute: the image sets searchFlags before any data exists.
func markerOf(t *testing.T, src, dst directory.Directory, root string) identity.Marker {
	t.Helper()
	key, err := identity.RootKey(context.Background(), src, dn.DomainRoot(root), identity.ObjectGUID)
	if err != nil {
		t.Fatal(err)
	}
	warning, err := profile.AD.MarkerCheck.CheckMarker(context.Background(), dst, profile.AD.Marker, identity.MarkerLen)
	if err != nil || warning != "" {
		t.Fatalf("the lab image must index %s: %q %v", profile.AD.Marker, warning, err)
	}
	return identity.NewMarker(profile.AD.Marker, key)
}

// Scenario under test: after the test AD is built, another program renames and moves objects on the target.
// Using the markers clone wrote, diff must detect those changes.
func TestRenameAndMoveOnTargetAreDetectedWithTheMarkers(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	root := fmt.Sprintf("OU=Ren%06d,%s", runID, realmDN)
	dept := "OU=Dept," + root
	sam := func(n string) string { return fmt.Sprintf("r%06d%s", runID, n) } // sAMAccountName is unique within the domain
	user := func(name, parent string) directory.Entry {
		return directory.Entry{DN: fmt.Sprintf("CN=%s,%s", name, parent), Attrs: map[string][]string{
			"objectClass": {"user"}, "cn": {name}, "sAMAccountName": {sam(name)},
		}}
	}
	src, dst := dial(t, srcURL), dial(t, dstURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ou := func(dnStr, name string) directory.Entry {
		return directory.Entry{DN: dnStr, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {name}}}
	}
	must(src.Add(context.Background(), ou(root, fmt.Sprintf("Ren%06d", runID))))
	must(src.Add(context.Background(), ou(dept, "Dept")))
	for _, e := range []directory.Entry{user("Ann", dept), user("Bob", dept), user("Cid", root), user("Dee", dept)} {
		must(src.Add(context.Background(), e))
	}

	// Run clone writing the markers.
	m := markerOf(t, src, dst, root)
	opt := planOptionsFor(t, root)
	_, err := clone.Run(context.Background(), src, dst, opt, clone.Options{UserPassword: fixedPw, Workers: 4, Marker: &m}, &bytes.Buffer{})
	must(err)
	marked, err := directory.Collect(context.Background(), dst, root, "("+m.Attr+"=ldap-cronin:*)", []string{directory.NoAttrs})
	must(err)
	if len(marked) != 6 {
		t.Fatalf("marked=%d", len(marked))
	}

	// Reproduce the changes another program makes on the target.
	conn, err := ldap.DialURL(dstURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer conn.Close()
	must(conn.Bind(adminDN, adminPw))
	modrdn := func(old, newRDN, newParent string) {
		t.Helper()
		must(conn.ModifyDN(ldap.NewModifyDNRequest(old, newRDN, true, newParent)))
	}
	modrdn("CN=Cid,"+root, "CN=Cid Renamed", "") // rename
	mod := ldap.NewModifyRequest("CN=Cid Renamed,"+root, nil)
	mod.Replace("description", []string{"changed by another program"})
	must(conn.Modify(mod))          // attributes changed as well as the rename
	modrdn(dept, "OU=Division", "") // rename the OU (Ann and Bob under it move together)
	annMod := ldap.NewModifyRequest("CN=Ann,OU=Division,"+root, nil)
	annMod.Replace("description", []string{"Ann changed too"})
	must(conn.Modify(annMod))                                           // attribute change on Ann too, who merely moved with the parent OU
	modrdn("CN=Bob,OU=Division,"+root, "CN=Bob", "CN=Users,"+realmDN)   // only Bob moves outside the starting point
	must(conn.Del(ldap.NewDelRequest("CN=Dee,OU=Division,"+root, nil))) // Dee was deleted after the OU moved

	var diffs []diff.Difference
	sum, err := diff.Run(context.Background(), src, dst, opt, diff.Options{Workers: 8, Resolver: identity.ByMarker(m)}, func(d diff.Difference) { diffs = append(diffs, d) })
	must(err)
	for _, d := range diffs {
		var b bytes.Buffer
		diff.Format(&b, d, diff.DefaultMaxValues)
		t.Log("\n" + strings.TrimRight(b.String(), "\n"))
	}

	// The deleted Dee is reported as ONLY_SOURCE, not lost in the OU move (a GUID lookup finds nothing on the target).
	if sum.Differences[diff.OnlyTarget] != 0 || sum.Differences[diff.OnlySource] != 1 {
		t.Fatalf("renamed/moved objects must not look like removed + added; only Dee is gone: %+v", sum.Differences)
	}
	for _, d := range diffs {
		if d.Kind == diff.OnlySource && !strings.EqualFold(d.DN, "CN=Dee,"+dept) {
			t.Fatalf("unexpected ONLY_SOURCE: %s", d.DN)
		}
	}
	if sum.Differences[diff.Renamed] != 3 { // Cid (rename), Dept (rename), Bob (move)
		t.Fatalf("RENAMED=%d, want 3: %+v", sum.Differences[diff.Renamed], sum.Differences)
	}
	if sum.Implied != 1 { // Ann merely moved with the parent OU
		t.Fatalf("implied=%d, want 1", sum.Implied)
	}
	// Do not report the cn / ou change that a rename causes; report only the genuinely separate change (description), at the current DN.
	if sum.Differences[diff.Differ] != 2 {
		t.Fatalf("DIFF=%d, want the two description changes (Cid and Ann)", sum.Differences[diff.Differ])
	}
	want := map[string]bool{strings.ToLower("CN=Cid Renamed," + root): true, strings.ToLower("CN=Ann,OU=Division," + root): true}
	for _, d := range diffs {
		if d.Kind == diff.Differ {
			if d.Attr != "description" || !want[strings.ToLower(d.DN)] {
				t.Fatalf("unexpected attribute difference: %+v", d)
			}
			delete(want, strings.ToLower(d.DN))
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing attribute differences at: %v", want)
	}
}

// Deleted and recreated at the same DN, or the OU moved and an OU with the same name was recreated.
// A recreated object has no marker: it is UNMARKED when the cloned one is gone, and a different object when the
// cloned one is found elsewhere.
func TestRecreatedObjectsOnTargetAreNotMistakenForTheOriginals(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	root := fmt.Sprintf("OU=Rec%06d,%s", runID, realmDN)
	dept := "OU=Dept," + root
	sam := func(n string) string { return fmt.Sprintf("c%06d%s", runID, n) }
	user := func(name, parent string) directory.Entry {
		return directory.Entry{DN: fmt.Sprintf("CN=%s,%s", name, parent), Attrs: map[string][]string{
			"objectClass": {"user"}, "cn": {name}, "sAMAccountName": {sam(name)},
		}}
	}
	ou := func(dnStr, name string) directory.Entry {
		return directory.Entry{DN: dnStr, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {name}}}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	src, dst := dial(t, srcURL), dial(t, dstURL)
	must(src.Add(context.Background(), ou(root, fmt.Sprintf("Rec%06d", runID))))
	must(src.Add(context.Background(), ou(dept, "Dept")))
	for _, e := range []directory.Entry{user("Eve", root), user("Fay", dept)} {
		must(src.Add(context.Background(), e))
	}

	m := markerOf(t, src, dst, root)
	opt := planOptionsFor(t, root)
	_, err := clone.Run(context.Background(), src, dst, opt, clone.Options{UserPassword: fixedPw, Workers: 4, Marker: &m}, &bytes.Buffer{})
	must(err)

	conn, err := ldap.DialURL(dstURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer conn.Close()
	must(conn.Bind(adminDN, adminPw))

	// Eve: deleted and recreated at the same DN as a different user.
	must(conn.Del(ldap.NewDelRequest("CN=Eve,"+root, nil)))
	eve := user("Eve", root)
	eve.Attrs["description"] = []string{"recreated by another program"}
	must(dst.Add(context.Background(), eve))
	// Dept: after it was moved (renamed), an OU with the same name and a new user inside it were created. Fay moved together with Dept.
	must(conn.ModifyDN(ldap.NewModifyDNRequest(dept, "OU=Division", true, "")))
	must(dst.Add(context.Background(), ou(dept, "Dept")))
	must(dst.Add(context.Background(), user("Newcomer", dept)))

	var diffs []diff.Difference
	sum, err := diff.Run(context.Background(), src, dst, opt, diff.Options{Workers: 8, Resolver: identity.ByMarker(m)}, func(d diff.Difference) { diffs = append(diffs, d) })
	must(err)
	for _, d := range diffs {
		var b bytes.Buffer
		diff.Format(&b, d, diff.DefaultMaxValues)
		t.Log("\n" + strings.TrimRight(b.String(), "\n"))
	}

	if sum.Differences[diff.Unmarked] != 1 { // Eve
		t.Fatalf("UNMARKED=%d, want 1 (Eve): %+v", sum.Differences[diff.Unmarked], sum.Differences)
	}
	if sum.Differences[diff.Renamed] != 1 { // the original Dept (to Division)
		t.Fatalf("RENAMED=%d, want 1 (the original Dept): %+v", sum.Differences[diff.Renamed], sum.Differences)
	}
	if sum.Differences[diff.OnlyTarget] != 2 { // the recreated Dept and Newcomer
		t.Fatalf("ONLY_TARGET=%d, want 2 (the recreated Dept and Newcomer): %+v", sum.Differences[diff.OnlyTarget], sum.Differences)
	}
	// The recreated Eve is a different object, but if its attributes differ from the source, that difference is reported too (description).
	if sum.Differences[diff.Differ] != 1 {
		t.Fatalf("DIFF=%d, want the description of the recreated Eve: %+v", sum.Differences[diff.Differ], sum.Differences)
	}
	if sum.Differences[diff.OnlySource] != 0 || sum.Implied != 1 { // Fay merely followed her parent
		t.Fatalf("%+v implied=%d", sum.Differences, sum.Implied)
	}
}

func userFilter(t *testing.T, job plan.Job) string {
	t.Helper()
	k, ok := job.Kind(profile.KindUser)
	if !ok {
		t.Fatal("the job has no user kind")
	}
	return k.Filter
}
