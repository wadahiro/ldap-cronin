package profile

import (
	"context"
	"strings"

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
		if samba, err = IsSamba(ctx, dst); err != nil || !samba {
			return r, err
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
