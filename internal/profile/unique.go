package profile

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/ad"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
)

// adUnique: an originating write on Samba (and on Windows Server 2012 R2 and later, unless dSHeuristics turns the
// check off) refuses a userPrincipalName or servicePrincipalName another object holds. Replication does not check,
// so when two DCs created the same account AD keeps both, renaming the loser's RDN to "<name>\nCNF:<GUID>" and its
// sAMAccountName to "$DUPLICATE-<n>", and leaving the rest of it as it was.
type adUnique struct{}

const (
	duplicatePrefix = "$duplicate-"
	conflictMark    = "\ncnf:"
)

func (adUnique) Attrs() []string { return []string{"sAMAccountName"} }

func (adUnique) Leftover(e directory.Entry) bool {
	if _, val, ok := dn.FirstRDN(e.DN); ok && strings.Contains(strings.ToLower(val), conflictMark) {
		return true
	}
	return strings.HasPrefix(strings.ToLower(first(e.Values("sAMAccountName"))), duplicatePrefix)
}

func (adUnique) Rules(ctx context.Context, dst directory.Directory, root string) (UniqueRules, error) {
	r := UniqueRules{Attrs: []string{"userPrincipalName", "servicePrincipalName"},
		Why: "a replication-conflict leftover holds a value another object has, which the target refuses to give twice"}
	// Without a target (check -no-target) the strictest rules: Samba's.
	samba := dst == nil
	if dst != nil {
		var err error
		if samba, err = IsSamba(ctx, dst); err != nil {
			return r, err
		}
		if !samba {
			// Windows (a server that is not Samba; a dry-run's LDIF has no root DSE) refuses a line feed in an RDN a
			// client writes, whatever its form (measured on Windows Server 2019: NAMING_VIOLATION), which only its own
			// conflict resolution gives a name. So the leftover of a name conflict cannot be created there, nor what
			// is below it.
			if root, err := dst.Get(ctx, "", []string{"defaultNamingContext"}); err == nil && root != nil && first(root.Values("defaultNamingContext")) != "" {
				r.Refuses = windowsRefuses
			}
			return r, nil
		}
	}
	// samldb takes an account without a userPrincipalName to hold sAMAccountName@realm (measured on 4.19.5:
	// "already in use (implied by sAMAccountName)"); Windows does not.
	realm := root
	if dst != nil {
		if rootDSE, err := dst.Get(ctx, "", []string{"defaultNamingContext"}); err == nil && rootDSE != nil && first(rootDSE.Values("defaultNamingContext")) != "" {
			realm = first(rootDSE.Values("defaultNamingContext"))
		}
	}
	realm = ad.RealmOf(realm)
	r.ImpliedHow = "implied by its sAMAccountName"
	r.Implied = map[string]func(directory.Entry) string{"userprincipalname": func(e directory.Entry) string {
		if sam := first(e.Values("sAMAccountName")); sam != "" {
			return sam + "@" + realm
		}
		return ""
	}}
	return r, nil
}

// Windows' limits beyond the schema's (measured on Windows Server 2019; Samba keeps none of them, so a Samba source
// may hold a value they refuse): an RDN value of 64 characters, a user's or computer's sAMAccountName of 20 (a
// computer's $ counted), a group's taking the schema's 256.
const (
	windowsRDNMax  = 64
	windowsSAMMax  = 20
	windowsRDNWhy  = "its RDN is longer than the 64 characters Windows takes"
	windowsSAMWhy  = "its sAMAccountName is longer than the 20 characters Windows takes of a user's or computer's"
	windowsLFWhy   = "a leftover of a name conflict: Windows refuses a line feed in an RDN a client writes"
	windowsUnderLF = "below a leftover of a name conflict, whose name Windows refuses (a line feed in its RDN)"
)

// windowsRefuses is what Windows refuses of an entry a client writes: a line feed in any RDN of its DN (only its own
// conflict resolution gives such a name), an RDN longer than it takes (the entry's own or a parent's), and a user's or
// computer's sAMAccountName longer than the SAM takes.
func windowsRefuses(e directory.Entry) string {
	parsed, err := ldap.ParseDN(e.DN)
	if err != nil {
		return ""
	}
	for i, rdn := range parsed.RDNs {
		for _, a := range rdn.Attributes {
			switch {
			case strings.Contains(a.Value, "\n") && i == 0:
				return windowsLFWhy
			case strings.Contains(a.Value, "\n"):
				return windowsUnderLF
			case utf8.RuneCountInString(a.Value) > windowsRDNMax && i == 0:
				return windowsRDNWhy
			case utf8.RuneCountInString(a.Value) > windowsRDNMax:
				return "below an entry whose RDN is longer than the 64 characters Windows takes"
			}
		}
	}
	classes := Set(e.Values("objectClass"))
	if (classes["user"] || classes["computer"]) && utf8.RuneCountInString(first(e.Values("sAMAccountName"))) > windowsSAMMax {
		return windowsSAMWhy
	}
	return ""
}
