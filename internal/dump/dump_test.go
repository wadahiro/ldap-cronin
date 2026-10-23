package dump

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/ldifdir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

const (
	domain = "DC=ad,DC=example,DC=com"
	base   = "OU=IDM," + domain
)

// -mask follows the rules of [mask]: an attribute naming entries, or identifying the object, cannot be masked, and
// nothing is written then.
func TestWhatCannotBeMaskedIsRefused(t *testing.T) {
	src := fakedir.New(domain)
	src.Put(domain, map[string][]string{"objectClass": {"domainDNS"}})
	src.Put(base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	for _, attr := range []string{"member", "sAMAccountName"} {
		var out bytes.Buffer
		_, err := Write(context.Background(), src, profile.AD, Options{BaseDNs: []string{base}, MaskValue: "x", Masked: []string{attr}}, &out)
		if err == nil || !strings.Contains(err.Error(), "cannot be masked") || out.Len() != 0 {
			t.Errorf("%s: %v, %d bytes written", attr, err, out.Len())
		}
	}
	// The whole domain is a base DN too.
	var out bytes.Buffer
	if c, err := Write(context.Background(), src, profile.AD, Options{BaseDNs: []string{domain}}, &out); err != nil || c.Base == 0 {
		t.Errorf("the domain root itself: %+v %v", c, err)
	}
}

// An entry a member names that the source does not return (one the account may not read) is not written: it is
// listed at the end, with its unread parent, and counted; the dump is still one.
func TestUnreadableEntriesAreListed(t *testing.T) {
	const hidden = "CN=Hidden,OU=Secret," + domain
	src := fakedir.New(domain)
	src.Put(domain, map[string][]string{"objectClass": {"domainDNS"}})
	src.Put(base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	src.Put("CN=G,"+base, map[string][]string{"objectClass": {"top", "group"}, "cn": {"G"}, "member": {hidden}})
	var out bytes.Buffer
	c, err := Write(context.Background(), src, profile.AD, Options{BaseDNs: []string{base}}, &out)
	if err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"# unreadable: OU=Secret," + domain + "\n", "# unreadable: " + hidden + "\n", "; unreadable 2, not written)"} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
	if c.Unreadable != 2 || c.Referenced != 0 {
		t.Errorf("%+v", c)
	}
	path := filepath.Join(t.TempDir(), "d.ldif")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := ldifdir.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
}

// -mask kind:attribute masks on the entries of that kind only, by their object classes: a computer is no user.
func TestMaskOfAKind(t *testing.T) {
	src := fakedir.New(domain)
	src.Put(domain, map[string][]string{"objectClass": {"domainDNS"}})
	src.Put(base, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"IDM"}})
	src.Put("CN=U,"+base, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "cn": {"U"}, "mail": {"u@x"}, "telephoneNumber": {"1"}})
	src.Put("CN=G,"+base, map[string][]string{"objectClass": {"top", "group"}, "cn": {"G"}, "mail": {"g@x"}, "telephoneNumber": {"2"}})
	src.Put("CN=PC,"+base, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user", "computer"}, "cn": {"PC"}, "mail": {"pc@x"}})
	var out bytes.Buffer
	if _, err := Write(context.Background(), src, profile.AD, Options{BaseDNs: []string{base}, MaskValue: "x", Masked: []string{"telephoneNumber", "user:mail"}}, &out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"#   user:mail\n", "mail: g@x\n", "mail: pc@x\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q", want)
		}
	}
	for _, not := range []string{"u@x", "telephoneNumber: 1", "telephoneNumber: 2"} {
		if strings.Contains(text, not) {
			t.Errorf("holds %q", not)
		}
	}
	for _, bad := range []string{"person:mail", "user:member"} {
		if _, err := Write(context.Background(), src, profile.AD, Options{BaseDNs: []string{base}, Masked: []string{bad}}, &bytes.Buffer{}); err == nil {
			t.Errorf("%s taken", bad)
		}
	}
}
