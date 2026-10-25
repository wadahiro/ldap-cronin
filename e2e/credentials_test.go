//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// [attributes] credentials = "copy" against Samba: every credential Samba returns and lets a client write is copied
// over LDAP (a user's userPKCS12, userPassword, unixUserPassword and credential roaming blobs; a computer's shadow
// credentials, TPM owner information and legacy LAPS password, its schema added to both domains as the LAPS
// installer adds it), printed nowhere, the fixed password still logs the user on, and diff finds nothing. A
// resource-based delegation, which Samba lets only the system write (systemOnly in its schema), is left alone.
func TestCredentialsCopyAgainstSamba(t *testing.T) {
	runID := time.Now().UnixNano() % 1_000_000
	ctx := context.Background()
	src, dst := dial(t, srcURL), dial(t, dstURL)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	schema := "CN=Schema,CN=Configuration," + realmDN
	for _, d := range []directory.Directory{src, dst} {
		for _, a := range []map[string][]string{
			{"cn": {"ms-Mcs-AdmPwd"}, "attributeID": {"1.2.840.113556.1.8000.2554.50051.45980.28112.18903.35903.6685103.1224907.2.1"},
				"attributeSyntax": {"2.5.5.5"}, "oMSyntax": {"19"}, "searchFlags": {"904"}},
			{"cn": {"ms-Mcs-AdmPwdExpirationTime"}, "attributeID": {"1.2.840.113556.1.8000.2554.50051.45980.28112.18903.35903.6685103.1224907.2.2"},
				"attributeSyntax": {"2.5.5.16"}, "oMSyntax": {"65"}},
		} {
			a["objectClass"], a["lDAPDisplayName"], a["isSingleValued"] = []string{"attributeSchema"}, a["cn"], []string{"TRUE"}
			// The e2e domains outlive a run: a second run finds them added.
			if err := d.Add(ctx, directory.Entry{DN: "CN=" + a["cn"][0] + "," + schema, Attrs: a}); err != nil && !errors.Is(err, directory.ErrExists) {
				t.Fatal(err)
			}
		}
		must(d.AddValues(ctx, "", "schemaUpdateNow", []string{"1"}))
		if err := d.AddValues(ctx, "CN=Computer,"+schema, "mayContain", []string{"ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"}); err != nil &&
			!ldap.IsErrorWithCode(err, ldap.LDAPResultAttributeOrValueExists) {
			t.Fatal(err)
		}
		must(d.AddValues(ctx, "", "schemaUpdateNow", []string{"1"}))
	}

	scope := fmt.Sprintf("OU=Cred%06d,%s", runID, realmDN)
	ann, pc := "CN=Ann,"+scope, "CN=PC1,"+scope
	must(src.Add(ctx, directory.Entry{DN: scope, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {fmt.Sprintf("Cred%06d", runID)}}}))
	must(src.Add(ctx, directory.Entry{DN: ann, Attrs: map[string][]string{"objectClass": {"user"}, "cn": {"Ann"},
		"sAMAccountName": {fmt.Sprintf("c%06dann", runID)}, "userPKCS12": {"\x30\x82\x01\x0a not a real key"},
		"unixUserPassword": {"unix-secret"}}}))
	// A DN-Binary value names the object it is on, so after the add.
	must(src.Replace(ctx, ann, map[string][]string{"msPKIAccountCredentials": {"B:8:01020304:" + ann}, "msPKIDPAPIMasterKeys": {"B:8:05060708:" + ann},
		"msPKI-CredentialRoamingTokens": {"B:8:090A0B0C:" + ann}}))
	// A password set and the account enabled, so the clone is neither disabled nor a must-change user and can log on.
	must(src.Replace(ctx, ann, map[string][]string{"unicodePwd": {profile.EncodePassword("Src-Passw0rd!")}}))
	must(src.Replace(ctx, ann, map[string][]string{"userAccountControl": {"512"}}))
	// Whether Samba stores and returns a userPassword depends on dSHeuristics (fUserPwdSupport); record what it does.
	if err := src.Replace(ctx, ann, map[string][]string{"userPassword": {"Prod-Secret-1"}}); err != nil {
		t.Logf("the source refuses userPassword: %v", err)
	}
	must(src.Add(ctx, directory.Entry{DN: pc, Attrs: map[string][]string{"objectClass": {"computer"}, "userAccountControl": {"4096"},
		"sAMAccountName":         {fmt.Sprintf("c%06dpc$", runID)},
		"msTPM-OwnerInformation": {"tpm-secret"}, "ms-Mcs-AdmPwd": {"laps-secret"}, "ms-Mcs-AdmPwdExpirationTime": {"133500000000000000"}}}))
	must(src.Replace(ctx, pc, map[string][]string{"msDS-KeyCredentialLink": {"B:8:0A0B0C0D:" + pc}}))
	rbcd := "import ldb\nfrom samba.samdb import SamDB\nfrom samba.auth import system_session\nfrom samba.param import LoadParm\n" +
		"from samba.ndr import ndr_pack\nfrom samba.dcerpc import security\n" +
		"lp = LoadParm(); lp.load('/etc/samba/smb.conf')\ndb = SamDB(url='/var/lib/samba/private/sam.ldb', session_info=system_session(), lp=lp)\n" +
		"sd = security.descriptor.from_sddl('O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;' + str(db.get_domain_sid()) + '-500)', security.dom_sid(db.get_domain_sid()))\n" +
		"m = ldb.Message(ldb.Dn(db, '" + pc + "'))\n" +
		"m['msDS-AllowedToActOnBehalfOfOtherIdentity'] = ldb.MessageElement([ndr_pack(sd)], ldb.FLAG_MOD_REPLACE, 'msDS-AllowedToActOnBehalfOfOtherIdentity')\n" +
		"db.modify(m)\n"
	if out, err := exec.Command("docker", "exec", env("E2E_SRC_CONTAINER", "ldap-cronin-ad-src-1"), "python3", "-c", rbcd).CombinedOutput(); err != nil {
		t.Fatalf("the delegation on the source: %v\n%s", err, out)
	}
	creds := map[string][]string{
		ann: {"userPKCS12", "userPassword", "unixUserPassword", "msPKIAccountCredentials", "msPKIDPAPIMasterKeys", "msPKI-CredentialRoamingTokens"},
		pc:  {"msDS-KeyCredentialLink", "msTPM-OwnerInformation", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "msDS-AllowedToActOnBehalfOfOtherIdentity"},
	}
	held := map[string]*directory.Entry{}
	for dn, attrs := range creds {
		e, err := src.Get(ctx, dn, attrs)
		must(err)
		held[dn] = e
		for _, a := range attrs {
			t.Logf("the source returns %s: %d values", a, len(e.Values(a)))
			if a != "userPassword" && len(e.Values(a)) != 1 {
				t.Fatalf("the source does not return %s to the Administrator: %v", a, e.Attrs)
			}
		}
	}

	cfg, err := config.Parse([]byte(fmt.Sprintf("[source]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n"+
		"[target]\nurl = %q\nbind_dn = %q\ninsecure_skip_verify = true\n[scope]\nbase_dn = %q\n[attributes]\ncredentials = \"copy\"\n",
		srcURL, adminDN, dstURL, adminDN, scope)))
	must(err)
	pw := func() (string, error) { return adminPw, nil }
	s, err := app.Open(ctx, cfg, app.Secrets{SourceBind: pw, TargetBind: pw, UserPassword: func() (string, error) { return fixedPw, nil }}, app.LDAP, &bytes.Buffer{})
	must(err)
	t.Cleanup(s.Close)
	var log bytes.Buffer
	if _, err := s.Clone(ctx, false, &log, &log); err != nil {
		t.Fatalf("%v\n%s", err, log.String())
	}
	for _, secret := range []string{"Prod-Secret-1", "not a real key", "unix-secret", "tpm-secret", "laps-secret"} {
		if strings.Contains(log.String(), secret) {
			t.Fatalf("clone's log prints a credential:\n%s", log.String())
		}
	}
	for dn, attrs := range creds {
		got, err := dst.Get(ctx, dn, attrs)
		must(err)
		for _, a := range attrs {
			want := strings.Join(held[dn].Values(a), "|")
			if a == "msDS-AllowedToActOnBehalfOfOtherIdentity" {
				want = ""
			}
			if strings.Join(got.Values(a), "|") != want {
				t.Errorf("%s on the target: %d values, the source's: %d", a, len(got.Values(a)), len(held[dn].Values(a)))
			}
		}
	}

	conn, err := ldap.DialURL(dstURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer conn.Close()
	if err := conn.Bind(ann, fixedPw); err != nil {
		t.Fatalf("Ann logs on with the fixed password, whatever userPassword holds: %v", err)
	}
	var out bytes.Buffer
	if code, err := s.Diff(ctx, app.DiffOutput{}, &out); err != nil || code != app.ExitSame {
		t.Fatalf("diff right after the clone: %d %v\n%s", code, err, out.String())
	}
}
