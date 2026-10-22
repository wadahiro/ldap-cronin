package diff

import (
	"fmt"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/ad"
	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// sdAttr is the attribute of an object's security descriptor.
const sdAttr = "nTSecurityDescriptor"

// aclTexts replaces e's security descriptor with what of it the clone gives (ad.ExplicitSDParts): its owner, group
// and protected flag as one value, each explicit ACE as another, so a difference names the ACEs that differ. The
// inherited ACEs are each server's, computed from the object's parents. The order of the ACEs is not compared.
func aclTexts(e directory.Entry) directory.Entry {
	var name string
	for n := range e.Attrs {
		if strings.EqualFold(n, sdAttr) {
			name = n
		}
	}
	if name == "" || len(e.Attrs[name]) == 0 {
		return e
	}
	parts, err := ad.ExplicitSDParts([]byte(e.Attrs[name][0]))
	if err != nil {
		parts = []string{fmt.Sprintf("(unreadable: %v)", err)}
	}
	out := directory.Entry{DN: e.DN, Attrs: make(map[string][]string, len(e.Attrs))}
	for n, v := range e.Attrs {
		out.Attrs[n] = v
	}
	out.Attrs[name] = parts
	return out
}
