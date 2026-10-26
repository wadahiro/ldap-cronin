package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/dump"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const prodSecret = "Prod-Secret-1"

// credentialsWorld is a source whose user Alice holds a credential AD returns to a reader with the rights
// (userPassword), on a schema that lets a client write it; the target has the same schema.
func credentialsWorld() *world {
	w := newWorld()
	may := []string{"title", "userPassword"}
	withClasses(w.src, may)
	withClasses(w.dst, may)
	for _, name := range append(may, "cn", "objectClass", "sAMAccountName", "userAccountControl", "adminDisplayName") {
		e := map[string][]string{"objectClass": {"attributeSchema"}, "cn": {name}, "lDAPDisplayName": {name}, "attributeID": {"1.9." + name},
			"attributeSyntax": {"2.5.5.12"}}
		if name == "adminDisplayName" {
			e["isSingleValued"], e["searchFlags"] = []string{"TRUE"}, []string{"1"}
		}
		w.src.Put("CN="+name+","+schemaNC, e)
		w.dst.Put("CN="+name+","+schemaNC, e)
	}
	w.src.Lookup(alice).Attrs["userPassword"] = []string{prodSecret}
	return w
}

// By default no credential is copied, and check says which setting copies the ones the source returns.
func TestCredentialsAreNotCopiedByDefaultAndCheckSaysHow(t *testing.T) {
	w := credentialsWorld()
	s := w.openWith(t, "")
	user, _ := s.Job.Kind("user")
	if strings.Contains(strings.Join(user.Attrs, ","), "userPassword") {
		t.Fatalf("user attributes: %v", user.Attrs)
	}
	var out bytes.Buffer
	if _, err := s.Check(context.Background(), CheckOptions{NoTarget: true, Attrs: true, Config: "c.toml"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `credential; [attributes] credentials = "copy" copies it`) {
		t.Fatalf("check -attrs:\n%s", out.String())
	}
	if strings.Contains(out.String(), prodSecret) {
		t.Fatal("check prints no value")
	}
}

// credentials = "copy" copies them; their values are printed nowhere: a dry-run's LDIF carries them only with
// -with-password, and diff shows a fingerprint.
func TestCredentialsCopiedAreNeverPrinted(t *testing.T) {
	ctx := context.Background()
	w := credentialsWorld()
	s := w.openWith(t, "[mapping]\nmode = \"off\"\n[attributes]\ncredentials = \"copy\"\n")
	user, _ := s.Job.Kind("user")
	if !strings.Contains(strings.Join(user.Attrs, ","), "userPassword") {
		t.Fatalf("user attributes: %v", user.Attrs)
	}

	var ldif, log bytes.Buffer
	if _, err := s.Clone(ctx, true, &ldif, &log); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ldif.String()+log.String(), prodSecret) || !strings.Contains(ldif.String(), "userPassword") {
		t.Fatalf("a dry-run names the credential and hides its value:\n%s", ldif.String())
	}
	s.WithPassword = true
	ldif.Reset()
	if _, err := s.Clone(ctx, true, &ldif, &log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ldif.String(), "userPassword: "+prodSecret) {
		t.Fatalf("with -with-password the LDIF alone gives what clone would:\n%s", ldif.String())
	}
	s.WithPassword = false

	log.Reset()
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.dst.Lookup(alice).Values("userPassword"), ""); got != prodSecret {
		t.Fatalf("the target's userPassword: %q", got)
	}
	if strings.Contains(log.String(), prodSecret) {
		t.Fatalf("clone's log prints no credential:\n%s", log.String())
	}

	w.dst.Lookup(alice).Attrs["userPassword"] = []string{"Changed-On-Target"}
	var out bytes.Buffer
	code, err := s.Diff(ctx, DiffOutput{}, &out)
	if err != nil || code != ExitDiff {
		t.Fatalf("diff: %d %v\n%s", code, err, out.String())
	}
	got := out.String()
	if strings.Contains(got, prodSecret) || strings.Contains(got, "Changed-On-Target") || !strings.Contains(got, "(credential, sha256 ") ||
		!strings.Contains(got, "credentials copied from the source") {
		t.Fatalf("diff shows a fingerprint, never the value:\n%s", got)
	}
	var lines bytes.Buffer
	if _, err := s.Diff(ctx, DiffOutput{JSON: true}, &lines); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(lines.String(), prodSecret) || strings.Contains(lines.String(), "Changed-On-Target") ||
		!strings.Contains(lines.String(), `"copied_credentials":["userPassword"`) {
		t.Fatalf("JSON lines:\n%s", lines.String())
	}
}

// A dump carries credentials only with -with-credentials; a clone that copies them refuses a dump without.
func TestCredentialsFromADump(t *testing.T) {
	ctx := context.Background()
	w := credentialsWorld()
	// The dump's filters evaluate objectCategory as AD does; the fake directory does not need it.
	w.src.Lookup(alice).Attrs["objectCategory"] = []string{"CN=Person," + schemaNC}
	for name, prof := range map[string]profile.Profile{"plain": profile.AD, "with": profile.AD.WithSecrets()} {
		var out bytes.Buffer
		if _, err := dump.Write(ctx, w.src, prof, dump.Options{BaseDNs: []string{base}, Server: "ldaps://src:636", Version: "test"}, &out); err != nil {
			t.Fatal(err)
		}
		if has := strings.Contains(out.String(), prodSecret); has != (name == "with") {
			t.Fatalf("%s: the dump holds the credential: %v", name, has)
		}
		path := filepath.Join(t.TempDir(), name+".ldif")
		if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Parse([]byte("[source]\nldif = \"" + path + "\"\n[target]\nurl = \"ldaps://dst:636\"\nbind_dn = \"CN=a\"\n" +
			"[scope]\nprofile = \"ad\"\nbase_dn = \"" + base + "\"\n[mapping]\nmode = \"off\"\n[attributes]\ncredentials = \"copy\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		s, err := Open(ctx, cfg, w.secrets(), w.dial, &bytes.Buffer{})
		if name == "plain" {
			if err == nil || !strings.Contains(err.Error(), "dump again with -with-credentials") {
				t.Fatalf("a dump without credentials: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var log bytes.Buffer
		if _, err := s.Clone(ctx, false, &log, &log); err != nil {
			t.Fatal(err)
		}
		s.Close()
		e := w.dst.Lookup(alice)
		if e == nil || strings.Join(e.Values("userPassword"), "") != prodSecret {
			t.Fatalf("from the dump: %v\n%s", e, log.String())
		}
	}
}

// An attribute the target's schema marks systemOnly is left out with the reason, though the source's lets a client
// write it, as a target would refuse it at the first object holding one. msDS-AllowedToActOnBehalfOfOtherIdentity is
// the exception: both Windows' schema and Samba's mark it systemOnly, yet Windows lets a client write it (measured on
// Windows Server 2019), so a Windows target is given it, from a source whose schema says the same; Samba holds a
// client to it and is not.
func TestWhatTheTargetsSchemaHasSystemOnlyIsLeftOut(t *testing.T) {
	const rbcd, sealed = "msDS-AllowedToActOnBehalfOfOtherIdentity", "acmeSealed"
	for name, c := range map[string]struct {
		vendor []string
		copied bool
		why    string
	}{
		"Windows": {nil, true, ""},
		"Samba":   {[]string{"Samba Team (https://www.samba.org)"}, false, rbcd + ": Samba lets only the system write it"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			w := credentialsWorld()
			may := []string{"title", "userPassword", rbcd, sealed}
			withClasses(w.src, may)
			withClasses(w.dst, may)
			for _, n := range []string{rbcd, sealed} {
				for _, d := range []*fakedir.Dir{w.src, w.dst} {
					d.Put("CN="+n+","+schemaNC, map[string][]string{"objectClass": {"attributeSchema"}, "cn": {n}, "lDAPDisplayName": {n},
						"attributeID": {"1.9." + n}, "attributeSyntax": {"2.5.5.12"}})
				}
			}
			w.src.Lookup("CN=" + rbcd + "," + schemaNC).Attrs["systemOnly"] = []string{"TRUE"}
			w.dst.Lookup("CN=" + rbcd + "," + schemaNC).Attrs["systemOnly"] = []string{"TRUE"}
			w.dst.Lookup("CN=" + sealed + "," + schemaNC).Attrs["systemOnly"] = []string{"TRUE"}
			if c.vendor != nil {
				w.dst.Lookup("").Attrs["vendorName"] = c.vendor
			}
			// The delegation is translated, which reads each domain's SID.
			w.src.Put(domain, map[string][]string{"objectClass": {"domainDNS"}, "objectSid": {fakedir.SID(srcDomainSID)}, "objectGUID": {"0123456789abcdef"}})
			w.dst.Put(domain, map[string][]string{"objectClass": {"domainDNS"}, "objectSid": {fakedir.SID(dstDomainSID)}, "objectGUID": {"fedcba9876543210"}})
			w.dst.SIDs = "7-8-9"
			// The built-in Administrators, the same SID on every domain.
			value := testSD(0, "S-1-5-32-544", "S-1-5-32-544", testACE(0, 0, 0xf01ff, "S-1-5-32-544"))
			w.src.Lookup(alice).Attrs[rbcd] = []string{value}
			w.src.Lookup(alice).Attrs[sealed] = []string{"sealed"}
			s := w.openWith(t, "[mapping]\nmode = \"off\"\n[attributes]\ncredentials = \"copy\"\n")
			var log bytes.Buffer
			if _, err := s.Clone(ctx, false, &log, &log); err != nil {
				t.Fatalf("%v\n%s", err, log.String())
			}
			got := w.dst.Lookup(alice)
			if got.Values(sealed) != nil || !strings.Contains(log.String(), sealed+": the target's schema has it systemOnly") {
				t.Fatalf("%s: %v\n%s", sealed, got.Attrs, log.String())
			}
			if (got.Values(rbcd) != nil) != c.copied || strings.Join(got.Values("userPassword"), "") != prodSecret ||
				(c.why != "" && !strings.Contains(log.String(), c.why)) {
				t.Fatalf("%s copied %v, want %v: %v\n%s", rbcd, got.Values(rbcd) != nil, c.copied, got.Attrs, log.String())
			}
			if code, err := s.Diff(ctx, DiffOutput{}, &bytes.Buffer{}); err != nil || code != ExitSame {
				t.Fatalf("diff: %d %v", code, err)
			}
		})
	}
}
