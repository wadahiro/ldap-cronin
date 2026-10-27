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
	// Both refuse a member value naming an account whose primary group the group is, which would stop the run: samldb
	// ("member ... already set via primaryGroupID", 68), Windows (68, 0x528 ERROR_MEMBER_IN_PRIMARY_GROUP; measured
	// on Windows Server 2019). The account is a member through primaryGroupID either way.
	r := UniqueRules{Attrs: []string{"userPrincipalName", "servicePrincipalName"},
		Why:            "a replication-conflict leftover holds a value another object has, which the target refuses to give twice",
		PrimaryMembers: true,
		PrimaryWhy:     "names an account whose primary group the group is, a member through primaryGroupID: the target refuses it"}
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
	if dst != nil {
		aliases, err := spnAliases(ctx, dst)
		if err != nil {
			return r, err
		}
		r.SPNAliases = aliases
		r.AliasWhy = "Samba refuses an SPN of another object's service class it maps to (sPNMappings: host/X with http/X on another)"
	}
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

// spnAliases reads the target's sPNMappings ("host=alerter,...,http,..."), resolved as samldb resolves them: the
// first mapping naming a class decides it, a class a mapping is keyed by being no alias (measured on 4.19.5:
// check_spn_alias_collision refuses host/X when another object holds http/X, and takes the reverse order from one
// who may write that object). nil when the target has none.
func spnAliases(ctx context.Context, dst directory.Directory) (map[string]string, error) {
	root, err := dst.Get(ctx, "", []string{"configurationNamingContext"})
	if err != nil || root == nil || first(root.Values("configurationNamingContext")) == "" {
		return nil, err
	}
	ds, err := dst.Get(ctx, "CN=Directory Service,CN=Windows NT,CN=Services,"+first(root.Values("configurationNamingContext")), []string{"sPNMappings"})
	if err != nil || ds == nil {
		return nil, err
	}
	decided := map[string]string{}
	for _, m := range ds.Values("sPNMappings") {
		key, list, ok := strings.Cut(m, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if _, ok := decided[key]; !ok {
			decided[key] = ""
		}
		for _, a := range strings.Split(list, ",") {
			if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
				if _, ok := decided[a]; !ok {
					decided[a] = key
				}
			}
		}
	}
	out := map[string]string{}
	for a, key := range decided {
		if key != "" {
			out[a] = key
		}
	}
	return out, nil
}
