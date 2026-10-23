package plan

import (
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
)

// PlaceholderNote begins the description of every placeholder clone creates, so diff and a reader of the target
// know it for what it is.
const PlaceholderNote = "ldap-cronin placeholder"

// Placeholder returns the entry clone creates at entryDN for a reference the source does not let it read
// (RefPlaceholder): a contact, which every reference attribute takes and which is no account (no SID, no logon).
// Its RDN must be CN=; ok is false for any other.
func Placeholder(entryDN string) (e directory.Entry, ok bool) {
	typ, val, ok := dn.FirstRDN(entryDN)
	if !ok || !strings.EqualFold(typ, "CN") {
		return directory.Entry{}, false
	}
	return directory.Entry{DN: entryDN, Attrs: map[string][]string{
		"objectClass": {"top", "person", "organizationalPerson", "contact"},
		"cn":          {val},
		"description": {PlaceholderNote + ": a reference names this entry, which the source did not let the account reading it read"},
	}}, true
}

// PlaceholderParent returns the entry clone creates at entryDN for a parent the source does not let it read: an
// organizational unit for OU=, a container for CN=; ok is false for any other RDN.
func PlaceholderParent(entryDN string) (e directory.Entry, ok bool) {
	typ, val, ok := dn.FirstRDN(entryDN)
	if !ok {
		return directory.Entry{}, false
	}
	note := PlaceholderNote + ": the parent of a placeholder, or of a referenced entry, which the source did not let the account reading it read"
	switch strings.ToUpper(typ) {
	case "OU":
		return directory.Entry{DN: entryDN, Attrs: map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {val}, "description": {note}}}, true
	case "CN":
		return directory.Entry{DN: entryDN, Attrs: map[string][]string{"objectClass": {"top", "container"}, "cn": {val}, "description": {note}}}, true
	}
	return directory.Entry{}, false
}

// IsPlaceholder reports whether a target entry is a placeholder clone created, by its description.
func IsPlaceholder(e directory.Entry) bool {
	for _, d := range e.Values("description") {
		if strings.HasPrefix(d, PlaceholderNote) {
			return true
		}
	}
	return false
}
