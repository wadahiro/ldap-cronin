package profile

import (
	"context"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// rootDSE is a Directory that only knows the root DSE.
type rootDSE struct{ attrs map[string][]string }

func (r rootDSE) Walk(context.Context, string, string, []string, func(directory.Entry) error) error {
	return nil
}
func (r rootDSE) Get(ctx context.Context, dn string, _ []string) (*directory.Entry, error) {
	if dn != "" {
		return nil, nil
	}
	return &directory.Entry{Attrs: r.attrs}, nil
}
func (r rootDSE) Add(context.Context, directory.Entry, ...directory.Control) error { return nil }
func (r rootDSE) Replace(context.Context, string, map[string][]string) error       { return nil }
func (r rootDSE) AddValues(context.Context, string, string, []string) error        { return nil }

func TestDetectRecognizesActiveDirectoryByItsCapability(t *testing.T) {
	ad := rootDSE{map[string][]string{"supportedCapabilities": {"1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670"}}}
	if p, err := Detect(context.Background(), ad); err != nil || p.Name != NameAD {
		t.Fatalf("%v %v", p.Name, err)
	}
	openldap := rootDSE{map[string][]string{"namingContexts": {"dc=example,dc=org"}}}
	if p, err := Detect(context.Background(), openldap); err != nil || p.Name != NameLDAP {
		t.Fatalf("%v %v", p.Name, err)
	}
}

func TestResolveHonorsAnExplicitNameWithoutAskingTheServer(t *testing.T) {
	if p, err := Resolve(context.Background(), "ldap", nil); err != nil || p.Name != NameLDAP {
		t.Fatalf("%v %v", p.Name, err)
	}
	if _, err := Resolve(context.Background(), "oracle", nil); err == nil {
		t.Fatal("an unknown profile must be rejected")
	}
}

func TestProfilesDoNotShareAttributeRules(t *testing.T) {
	if !Set(AD.NeverClone)["objectguid"] || Set(LDAP.NeverClone)["objectguid"] {
		t.Fatal("objectGUID is AD-only")
	}
	if !Set(LDAP.NeverClone)["entryuuid"] || !Set(LDAP.NeverClone)["userpassword"] {
		t.Fatal("entryUUID and userPassword must never be cloned from a generic server")
	}
	if AD.Identity.Attr() != "objectGUID" || LDAP.Identity.Attr() != "entryUUID" {
		t.Fatal("AD identifies objects by objectGUID, generic servers by entryUUID")
	}
}

func TestEncodePasswordIsQuotedUTF16LE(t *testing.T) {
	if got := EncodePassword("ab"); got != "\"\x00a\x00b\x00\"\x00" {
		t.Fatalf("%q", got)
	}
}
