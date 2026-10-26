package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/ad"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

const rbcd = "msDS-AllowedToActOnBehalfOfOtherIdentity"

// rbcdWorld is aclWorld whose Alice may be acted as by the group Team of the scope and by a deleted principal's SID
// (a resource-based delegation), copied with credentials = "copy".
func rbcdWorld(t *testing.T) (*world, *Session) {
	w, _ := aclWorld()
	w.src.Lookup(alice).Attrs[rbcd] = []string{testSD(0, "S-1-5-32-544", "S-1-5-32-544",
		testACE(0, 0x00, 0xf01ff, srcDomainSID+"-1106"),
		testACE(0, 0x00, 0xf01ff, srcDomainSID+"-1199"))}
	s := w.openWith(t, "[mapping]\nmode = \"off\"\n[attributes]\nmode = \"allowlist\"\ncredentials = \"copy\"\nextra_include = [\""+rbcd+"\"]\n")
	if got := s.Job.Translated(); got["msds-allowedtoactonbehalfofotheridentity"] != rbcd {
		t.Fatalf("translated: %v", got)
	}
	return w, s
}

// Over LDAP an object created gets the target's own SID, so a delegation copied as it is would name nobody: clone
// writes it last with each SID the target's object's at the same DN, leaves out the ACE of a SID no object of the
// source has, and diff compares the result (a fingerprint when it differs: the delegation is a credential).
func TestADelegationIsWrittenWithTheTargetsSIDs(t *testing.T) {
	ctx := context.Background()
	w, s := rbcdWorld(t)
	var log bytes.Buffer
	rep, err := s.Clone(ctx, false, &log, &log)
	if err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	team, _ := ad.SIDText([]byte(w.dst.Lookup("CN=Team,OU=Users," + base).Values("objectSid")[0]))
	got, err := ad.ExplicitSD([]byte(w.dst.Lookup(alice).Values(rbcd)[0]))
	if err != nil {
		t.Fatal(err)
	}
	if want := "O:S-1-5-32-544 G:S-1-5-32-544 (0;0x00;0xf01ff;" + team + ")"; got != want {
		t.Fatalf("the target's delegation:\ngot  %s\nwant %s\n%s", got, want, log.String())
	}
	if rep.SDValues[rbcd] != 1 || rep.ACEsLeftOut[plan.WhyNoSourcePrincipal] != 1 ||
		!strings.Contains(log.String(), "leave the ACEs naming "+srcDomainSID+"-1199 out (first of "+rbcd) {
		t.Fatalf("%+v\n%s", rep, log.String())
	}
	var sum bytes.Buffer
	rep.WriteSummary(&sum)
	if !strings.Contains(sum.String(), "values naming principals written with each SID the target's") {
		t.Fatalf("summary:\n%s", sum.String())
	}

	var out bytes.Buffer
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitSame ||
		!strings.Contains(out.String(), "ACEs not compared") || !strings.Contains(out.String(), "values naming principals compared") {
		t.Fatalf("diff right after the clone (%d, %v):\n%s", code, err, out.String())
	}
	log.Reset()
	if rep, err := s.Clone(ctx, false, &log, &log); err != nil || len(rep.SDValues) != 0 {
		t.Fatalf("a second clone writes no delegation: %v %+v\n%s", err, rep.SDValues, log.String())
	}

	// The program under test lets Everyone act as Alice: diff names a difference by fingerprints only.
	w.dst.Lookup(alice).Attrs[rbcd] = []string{testSD(0, "S-1-5-32-544", "S-1-5-32-544",
		testACE(0, 0x00, 0xf01ff, team), testACE(0, 0x00, 0xf01ff, "S-1-1-0"))}
	out.Reset()
	if code, err := s.Diff(ctx, DiffOutput{}, &out); err != nil || code != ExitDiff ||
		!strings.Contains(out.String(), "(credential, sha256 ") || strings.Contains(out.String(), "S-1-1-0") {
		t.Fatalf("diff after the change (%d, %v):\n%s", code, err, out.String())
	}
}

// A dry-run cannot read the target's SIDs: its LDIF gives the delegation with the source's, last, and says so; its
// value only with -with-password, as every credential's.
func TestADelegationInADryRun(t *testing.T) {
	w, s := rbcdWorld(t)
	raw := base64.StdEncoding.EncodeToString([]byte(w.src.Lookup(alice).Values(rbcd)[0]))
	var hidden bytes.Buffer
	if _, err := s.Clone(context.Background(), true, &hidden, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hidden.String(), "replace: "+rbcd) || strings.Contains(hidden.String(), raw) {
		t.Fatalf("without -with-password:\n%s", hidden.String())
	}
	s.WithPassword = true
	var ldif, log bytes.Buffer
	if _, err := s.Clone(context.Background(), true, &ldif, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	add := ldif.String()[strings.Index(ldif.String(), "dn: "+alice):]
	if strings.Contains(add[:strings.Index(add, "\n\n")], rbcd) || !strings.Contains(ldif.String(), raw) ||
		!strings.Contains(ldif.String(), "dn: "+alice+"\nchangetype: modify\nreplace: "+rbcd) ||
		!strings.Contains(log.String(), "a dry-run cannot read the target's") {
		t.Fatalf("LDIF:\n%s\nlog:\n%s", ldif.String(), log.String())
	}
}
