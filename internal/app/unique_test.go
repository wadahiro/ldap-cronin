package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

const (
	samba = "Samba Team (https://www.samba.org)"
	// kim and her leftover: two DCs created the account, and AD renamed the loser's RDN and sAMAccountName only.
	kim         = "CN=Kim,OU=Users," + base
	kimLeftover = "CN=Kim\\0ACNF:0f0e0d0c-0b0a-0908-0706-050403020100,OU=Users," + base
	pc9         = "CN=PC9,OU=Users," + base
	pc9Leftover = "CN=PC9-old,OU=Users," + base
)

// conflictWorld is a source holding replication-conflict leftovers that share a userPrincipalName and
// servicePrincipalNames with the real objects, as AD keeps them. vendor names the target's server (nil: Windows).
func conflictWorld(vendor string) *world {
	w := newWorld()
	if vendor != "" {
		w.dst.Put("", map[string][]string{"vendorName": {vendor}})
	}
	user := []string{"top", "person", "organizationalPerson", "user"}
	w.src.Put(kim, map[string][]string{"objectClass": user, "cn": {"Kim"}, "sAMAccountName": {"kim"},
		"userPrincipalName": {"kim@ad.example.com"}, "servicePrincipalName": {"HTTP/kim.ad.example.com"}, "userAccountControl": {"512"}})
	w.src.Put(kimLeftover, map[string][]string{"objectClass": user, "cn": {"Kim\nCNF:0f0e0d0c-0b0a-0908-0706-050403020100"},
		"sAMAccountName": {"$DUPLICATE-1f4"}, "userPrincipalName": {"kim@ad.example.com"},
		"servicePrincipalName": {"HTTP/kim.ad.example.com", "HTTP/kim-old.ad.example.com"}, "userAccountControl": {"512"}})
	computer := append(user, "computer")
	// A computer whose sAMAccountName alone collided: its DN is plain, its sAMAccountName renamed.
	w.src.Put(pc9, map[string][]string{"objectClass": computer, "cn": {"PC9"}, "sAMAccountName": {"PC9$"},
		"servicePrincipalName": {"HOST/pc9.ad.example.com"}, "userAccountControl": {"4096"}})
	w.src.Put(pc9Leftover, map[string][]string{"objectClass": computer, "cn": {"PC9-old"}, "sAMAccountName": {"$DUPLICATE-2a7"},
		"servicePrincipalName": {"HOST/pc9.ad.example.com"}, "userAccountControl": {"4096"}})
	return w
}

// A leftover is cloned with its own name and sAMAccountName, but without the values it shares with the real object,
// which the target refuses to give twice: whichever comes first, the real object keeps them. clone warns of each and
// counts them, a second clone writes nothing, diff does not compare them, and check lists them first.
func TestAConflictLeftoverIsClonedWithoutTheValuesItShares(t *testing.T) {
	ctx := context.Background()
	w := conflictWorld(samba)
	s := w.openWith(t, "[mapping]\nmode = \"off\"\n[attributes]\nmode = \"allowlist\"\nextra_include = [\"servicePrincipalName\"]\n")

	var out bytes.Buffer
	if _, err := s.Check(ctx, CheckOptions{Config: "c.toml"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "values clone will not write: 3") || !strings.Contains(out.String(), "userPrincipalName kim@ad.example.com of "+kimLeftover+" (kept by "+kim+")") {
		t.Fatalf("check:\n%s", out.String())
	}

	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	left := w.dst.Lookup(kimLeftover)
	if left == nil || left.Values("userPrincipalName") != nil || strings.Join(left.Values("servicePrincipalName"), ",") != "HTTP/kim-old.ad.example.com" ||
		strings.Join(left.Values("sAMAccountName"), "") != "$DUPLICATE-1f4" {
		t.Fatalf("the leftover: %+v", left)
	}
	if real := w.dst.Lookup(kim); strings.Join(real.Values("userPrincipalName"), "") != "kim@ad.example.com" || len(real.Values("servicePrincipalName")) != 1 {
		t.Fatalf("the real object keeps them: %+v", real)
	}
	if got := w.dst.Lookup(pc9Leftover); got == nil || got.Values("servicePrincipalName") != nil {
		t.Fatalf("the computer's leftover: %+v", got)
	}
	if rep.Withheld["userPrincipalName"] != 1 || rep.Withheld["servicePrincipalName"] != 2 || !strings.Contains(log.String(), "not written: userPrincipalName kim@ad.example.com of "+kimLeftover) {
		t.Fatalf("%+v\n%s", rep.Withheld, log.String())
	}
	var sum bytes.Buffer
	rep.WriteSummary(&sum)
	if !strings.Contains(sum.String(), "values not written (a replication-conflict leftover") {
		t.Fatalf("summary:\n%s", sum.String())
	}

	log.Reset()
	if rep, err := s.Clone(ctx, false, &log, &log); err != nil || rep.Added+rep.Updated != 0 {
		t.Fatalf("a second clone writes nothing: %v %+v\n%s", err, rep, log.String())
	}
	out.Reset()
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame || !strings.Contains(out.String(), "values not compared (clone does not write them") {
		t.Fatalf("diff (%d, %v):\n%s", code, err, out.String())
	}
}

// Samba takes an account without a userPrincipalName to hold sAMAccountName@realm, Windows does not: a leftover's
// userPrincipalName equal to that of a real account without one is withheld on Samba only.
func TestAnImpliedUserPrincipalNameCountsOnSambaOnly(t *testing.T) {
	for name, c := range map[string]struct {
		vendor   string
		withheld int
	}{"Samba": {samba, 1}, "Windows": {"", 0}} {
		t.Run(name, func(t *testing.T) {
			w := conflictWorld(c.vendor)
			delete(w.src.Lookup(kim).Attrs, "userPrincipalName")
			delete(w.src.Lookup(kim).Attrs, "servicePrincipalName")
			delete(w.src.Lookup(kimLeftover).Attrs, "servicePrincipalName")
			s := w.openWith(t, "[mapping]\nmode = \"off\"\n")
			var log bytes.Buffer
			rep, err := s.Clone(context.Background(), false, &log, &log)
			if err != nil || rep.Withheld["userPrincipalName"] != c.withheld {
				t.Fatalf("%v %+v\n%s", err, rep.Withheld, log.String())
			}
		})
	}
}

// A value two real objects hold cannot be given to one of them by rule: clone refuses before writing anything,
// naming them, and check says so.
func TestAValueTwoRealObjectsHoldStopsCloneBeforeAnyWrite(t *testing.T) {
	ctx := context.Background()
	w := conflictWorld(samba)
	w.src.Lookup(alice).Attrs["userPrincipalName"] = []string{"kim@ad.example.com"}
	s := w.openWith(t, "[mapping]\nmode = \"off\"\n")
	var out bytes.Buffer
	if code, err := s.Check(ctx, CheckOptions{Config: "c.toml"}, &out); err != nil || code != CheckBlocked ||
		!strings.Contains(out.String(), "clone refuses to start: 1 values the target holds once") {
		t.Fatalf("check (%d, %v):\n%s", code, err, out.String())
	}
	var log bytes.Buffer
	_, err := s.Clone(ctx, false, &log, &log)
	if err == nil || !strings.Contains(err.Error(), "userPrincipalName kim@ad.example.com: "+alice+"; "+kim) {
		t.Fatalf("got %v", err)
	}
	if w.dst.Lookup(alice) != nil || w.dst.Lookup("OU=Users,"+base) != nil {
		t.Fatal("nothing may be written")
	}
}
