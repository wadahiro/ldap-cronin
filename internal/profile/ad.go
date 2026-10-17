package profile

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/ad"
	"github.com/wadahiro/ldap-cronin/internal/compare"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/identity"
)

// AD is Active Directory and Samba AD.
var AD = Profile{
	Name: NameAD,
	Kinds: []KindSpec{
		{Name: KindOU, Role: RoleContainer, Filter: "(objectClass=organizationalUnit)", Default: []string{
			"description", "displayName", "street", "l", "st", "postalCode", "co", "c", "managedBy",
		}},
		{Name: KindGroup, Role: RoleLeaf, Order: 0, Filter: "(objectClass=group)", Default: []string{
			"sAMAccountName", "groupType", "description", "displayName", "info", "mail",
			"managedBy", "member", "adminDescription", "gidNumber",
		}},
		// user excludes computer, which also has objectClass=user.
		{Name: KindUser, Role: RoleLeaf, Order: 1, Account: true, Filter: "(&(objectCategory=person)(objectClass=user))", Default: []string{
			"sAMAccountName", "userPrincipalName", "userAccountControl", "accountExpires",
			"givenName", "sn", "initials", "middleName", "displayName", "description",
			"mail", "telephoneNumber", "mobile", "homePhone", "pager", "ipPhone",
			"facsimileTelephoneNumber", "title", "department", "company", "division",
			"physicalDeliveryOfficeName", "manager", "employeeID", "employeeNumber", "employeeType",
			"streetAddress", "postOfficeBox", "l", "st", "postalCode", "co", "c",
			"wWWHomePage", "url", "info", "homeDirectory", "homeDrive", "scriptPath", "profilePath",
			"uidNumber", "gidNumber", "loginShell", "unixHomeDirectory",
		}},
	},
	Required:      []string{"objectClass", "cn", "ou"},
	AncestorAttrs: []string{"objectClass", "cn", "ou", "description"},
	NeverClone: []string{
		"objectGUID", "objectSid", "sIDHistory", "whenCreated", "whenChanged", "uSNCreated", "uSNChanged",
		"distinguishedName", "name", "pwdLastSet", "badPwdCount", "badPasswordTime", "lastLogon",
		"lastLogoff", "lastLogonTimestamp", "logonCount", "lockoutTime", "memberOf", "unicodePwd",
		"dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials", "sAMAccountType",
		"objectCategory", "instanceType", "nTSecurityDescriptor", "isCriticalSystemObject",
		"systemFlags", "dSCorePropagationData", "primaryGroupID", "msDS-KeyVersionNumber",
	},
	NoMask: []string{
		"objectClass", "cn", "ou", "sAMAccountName", "userPrincipalName", "servicePrincipalName",
		"member", "manager", "managedBy", "userAccountControl", "groupType", "accountExpires",
		"countryCode", "c", "uidNumber", "gidNumber",
	},
	PasswordAttrs: []string{"unicodePwd", "dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials"},
	// A safeguard so that Administrator, krbtgt and the like are not overwritten even if base_dn is CN=Users.
	SystemFilter: "(!(isCriticalSystemObject=TRUE))",
	BuiltinRefs:  map[string]RefInfo{"member": {}, "manager": {Single: true}, "managedby": {Single: true}},
	// AD splits a large member into ranges by itself, Samba does not. Always asking for ranges puts both through the
	// same retrieval path, so the multi-fetch code runs against Samba in CI too.
	Ranged: []string{"member"},
	Values: map[string]compare.Normalizer{
		"useraccountcontrol": SanitizeUAC,
		// "never" has two representations: 0 and 2^63-1.
		"accountexpires": func(v string) string {
			if v == "0" {
				return neverExpires
			}
			return v
		},
	},
	Identity: identity.ObjectGUID,
	Refs:     adSchema{},
	Root:     adRoot{},
	Account:  adAccount{},
	Native:   adNative{},
}

const (
	uacLockout         = 0x10
	uacPasswordExpired = 0x800000
	neverExpires       = "9223372036854775807"
)

// SanitizeUAC drops the userAccountControl bits that cannot be written (the ones the server manages).
func SanitizeUAC(v string) string {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return v
	}
	return strconv.FormatInt(n&^(uacLockout|uacPasswordExpired), 10)
}

// attributeSyntax values in the AD schema.
const (
	syntaxDN       = "2.5.5.1"  // DS-DN (member, manager, managedBy, seeAlso, etc.)
	syntaxDNBinary = "2.5.5.7"  // DN+binary; not supported because the DN inside the value cannot be rewritten
	syntaxDNString = "2.5.5.14" // DN+string; same as above
)

// adSchema reads attributeSchema entries from the schema naming context. An odd linkID marks a back link.
type adSchema struct{}

func (adSchema) Discover(ctx context.Context, src directory.Directory) (Schema, bool, error) {
	root, err := src.Get(ctx, "", []string{"schemaNamingContext"})
	if err != nil {
		return Schema{}, false, fmt.Errorf("read root DSE: %w", err)
	}
	if root == nil || first(root.Values("schemaNamingContext")) == "" {
		return Schema{}, false, nil
	}
	s := Schema{Refs: map[string]RefInfo{}, BackLinks: map[string]bool{}, Unsupported: map[string]bool{}}
	filter := "(&(objectClass=attributeSchema)(|(attributeSyntax=" + syntaxDN + ")(attributeSyntax=" + syntaxDNBinary + ")(attributeSyntax=" + syntaxDNString + ")))"
	err = src.Walk(ctx, first(root.Values("schemaNamingContext")), filter,
		[]string{"lDAPDisplayName", "attributeSyntax", "linkID", "isSingleValued"}, func(e directory.Entry) error {
			name := first(e.Values("lDAPDisplayName"))
			if name == "" {
				return nil
			}
			key := strings.ToLower(name)
			switch first(e.Values("attributeSyntax")) {
			case syntaxDN:
				s.Refs[key] = RefInfo{Single: strings.EqualFold(first(e.Values("isSingleValued")), "TRUE")}
			default:
				s.Unsupported[key] = true
			}
			// The server computes a back link (memberOf, directReports, ...) and it cannot be written.
			if id, err := strconv.Atoi(first(e.Values("linkID"))); err == nil && id%2 == 1 {
				s.BackLinks[key] = true
				delete(s.Refs, key)
			}
			return nil
		})
	if err != nil {
		return Schema{}, false, fmt.Errorf("read schema: %w", err)
	}
	return s, true, nil
}

// adRoot is the run of trailing DC= components: an AD naming context is always a domain.
type adRoot struct{}

func (adRoot) Root(_ context.Context, _ directory.Directory, baseDN string) (string, error) {
	if root := dn.DomainRoot(baseDN); root != "" {
		return root, nil
	}
	return "", fmt.Errorf("base_dn %q has no DC= components, which every AD naming context has", baseDN)
}

type adNative struct{}

func (adNative) Domain(ctx context.Context, src directory.Directory, root string) (Domain, error) {
	d, err := ad.ReadDomain(ctx, src, root)
	if err != nil {
		return Domain{}, err
	}
	return Domain{Root: d.Root, Realm: d.Realm, NetBIOS: d.NetBIOS, SID: d.SID, GUID: d.GUID}, nil
}
