package dump

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/fakedir"
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
		_, err := Write(context.Background(), src, profile.AD, Options{BaseDN: base, MaskValue: "x", Masked: []string{attr}}, &out)
		if err == nil || !strings.Contains(err.Error(), "cannot be masked") || out.Len() != 0 {
			t.Errorf("%s: %v, %d bytes written", attr, err, out.Len())
		}
	}
	var out bytes.Buffer
	if _, err := Write(context.Background(), src, profile.AD, Options{BaseDN: domain}, &out); err == nil || !strings.Contains(err.Error(), "must be below") {
		t.Errorf("the domain root itself: %v", err)
	}
}
