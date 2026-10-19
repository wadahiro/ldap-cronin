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
		{Name: KindOU, Role: RoleContainer, Filter: "(objectClass=organizationalUnit)", Is: classIs("organizationalUnit"), Default: []string{
			"description", "displayName", "street", "l", "st", "postalCode", "co", "c", "managedBy",
		}},
		{Name: KindGroup, Role: RoleLeaf, Order: 0, Filter: "(objectClass=group)", Is: classIs("group"), Default: []string{
			"sAMAccountName", "groupType", "description", "displayName", "info", "mail",
			"managedBy", "member", "adminDescription", "gidNumber",
		}},
		// user excludes computer, which also has objectClass=user.
		{Name: KindUser, Role: RoleLeaf, Order: 1, Account: true, Filter: "(&(objectCategory=person)(objectClass=user))",
			// objectCategory=person and objectClass=user: a user or inetOrgPerson, not a computer (a subclass of user).
			Is: func(c []string) bool { return hasClass(c, []string{"user"}, "computer") }, Default: []string{
				"sAMAccountName", "userPrincipalName", "userAccountControl", "accountExpires",
				"givenName", "sn", "initials", "middleName", "displayName", "description",
				"mail", "telephoneNumber", "mobile", "homePhone", "pager", "ipPhone",
				"facsimileTelephoneNumber", "title", "department", "company", "division",
				"physicalDeliveryOfficeName", "manager", "employeeID", "employeeNumber", "employeeType",
				"streetAddress", "postOfficeBox", "l", "st", "postalCode", "co", "c",
				"wWWHomePage", "url", "info", "homeDirectory", "homeDrive", "scriptPath", "profilePath",
				"uidNumber", "gidNumber", "loginShell", "unixHomeDirectory",
			}},
		// Computers are what groups hold most besides users. A computer is an account too: it gets the fixed
		// password, as a joined computer has one (a pre-staged computer without it is not what production holds).
		// Service accounts (msDS-ManagedServiceAccount) have their own objectCategory and stay out.
		{Name: KindComputer, Role: RoleLeaf, Order: 2, Account: true, Filter: "(objectCategory=computer)", Is: classIs("computer"), Default: []string{
			"sAMAccountName", "userAccountControl", "dNSHostName", "description", "displayName", "location",
			"managedBy", "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
			"servicePrincipalName", "info",
		}},
		// Contacts: the user list without the account and logon attributes.
		{Name: KindContact, Role: RoleLeaf, Order: 3, Filter: "(objectClass=contact)", Is: classIs("contact"), Default: []string{
			"givenName", "sn", "initials", "middleName", "displayName", "description",
			"mail", "telephoneNumber", "mobile", "homePhone", "pager", "ipPhone",
			"facsimileTelephoneNumber", "title", "department", "company", "division",
			"physicalDeliveryOfficeName", "manager", "employeeID", "employeeNumber", "employeeType",
			"streetAddress", "postOfficeBox", "l", "st", "postalCode", "co", "c",
			"wWWHomePage", "url", "info",
		}},
	},
	Required:      []string{"objectClass", "cn", "ou"},
	AncestorAttrs: []string{"objectClass", "cn", "ou", "description"},
	NeverClone: append([]string{
		"objectGUID", "objectSid", "sIDHistory", "whenCreated", "whenChanged", "uSNCreated", "uSNChanged",
		"distinguishedName", "name", "pwdLastSet", "badPwdCount", "badPasswordTime", "lastLogon",
		"lastLogoff", "lastLogonTimestamp", "logonCount", "lockoutTime", "memberOf", "unicodePwd",
		"dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials", "sAMAccountType",
		"objectCategory", "instanceType", "nTSecurityDescriptor", "isCriticalSystemObject",
		"systemFlags", "dSCorePropagationData", "primaryGroupID", "msDS-KeyVersionNumber",
	}, computerCredentials...),
	NoMask: []string{
		"objectClass", "cn", "ou", "sAMAccountName", "userPrincipalName", "servicePrincipalName",
		"member", "manager", "managedBy", "userAccountControl", "groupType", "accountExpires",
		"countryCode", "c", "uidNumber", "gidNumber",
	},
	PasswordAttrs: append([]string{"unicodePwd", "dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials"}, computerCredentials...),
	// A safeguard so that Administrator, krbtgt and the like are not overwritten even if base_dn is CN=Users.
	SystemFilter: "(!(isCriticalSystemObject=TRUE))",
	SystemAttr:   "isCriticalSystemObject",
	Principal:    wellKnownPrincipal,
	BuiltinRefs:  map[string]RefInfo{"member": {}, "manager": {Single: true}, "managedby": {Single: true}},
	// AD splits a large member into ranges by itself, Samba does not. Always asking for ranges puts both through the
	// same retrieval path, so the multi-fetch code runs against Samba in CI too.
	Ranged:        []string{"member"},
	RefsNeedEntry: true,
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
	// adminDisplayName is in top's systemMayContain, so every object class allows it, and no product the tool knows
	// of uses it: adminDescription is Entra Connect's default filter, mS-DS-ConsistencyGuid its sourceAnchor,
	// extensionAttributeN need the Exchange schema and are what IdM products use most, and employeeID, info and
	// description are in the allow lists.
	Marker:      "adminDisplayName",
	MarkerCheck: adSchema{},
	Refs:        adSchema{},
	Root:        adRoot{},
	Account:     adAccount{},
	Native:      adNative{},
}

// computerCredentials are never cloned, compared or printed: LAPS (legacy and Windows LAPS), Windows Hello / shadow
// credentials, resource-based delegation (who may act as the computer), the gMSA password.
var computerCredentials = []string{
	"ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-Password", "msLAPS-EncryptedPassword",
	"msLAPS-EncryptedPasswordHistory", "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory",
	"msLAPS-PasswordExpirationTime", "msDS-KeyCredentialLink", "msDS-AllowedToActOnBehalfOfOtherIdentity",
	"msDS-ManagedPassword",
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

// Unicode, case-insensitive and printable string syntaxes: the ones a marker can be stored and searched in.
var markerSyntaxes = map[string]bool{"2.5.5.12": true, "2.5.5.4": true, "2.5.5.5": true}

const searchFlagIndexed = 1

func (adSchema) CheckMarker(ctx context.Context, dst directory.Directory, attr string, minLen int) (string, error) {
	root, err := dst.Get(ctx, "", []string{"schemaNamingContext"})
	if err != nil {
		return "", fmt.Errorf("read the target's root DSE: %w", err)
	}
	if root == nil || first(root.Values("schemaNamingContext")) == "" {
		return "", nil // test directories without a schema
	}
	var found *directory.Entry
	err = dst.Walk(ctx, first(root.Values("schemaNamingContext")), "(&(objectClass=attributeSchema)(lDAPDisplayName="+attr+"))",
		[]string{"lDAPDisplayName", "attributeSyntax", "isSingleValued", "rangeUpper", "searchFlags"}, func(e directory.Entry) error {
			if strings.EqualFold(first(e.Values("lDAPDisplayName")), attr) {
				c := e
				found = &c
			}
			return nil
		})
	if err != nil {
		return "", fmt.Errorf("read the target schema: %w", err)
	}
	if found == nil {
		return "", fmt.Errorf("[mapping] attribute %q is not in the target schema", attr)
	}
	if !markerSyntaxes[first(found.Values("attributeSyntax"))] {
		return "", fmt.Errorf("[mapping] attribute %q does not hold strings (attributeSyntax %s)", attr, first(found.Values("attributeSyntax")))
	}
	if !strings.EqualFold(first(found.Values("isSingleValued")), "TRUE") {
		return "", fmt.Errorf("[mapping] attribute %q is multi-valued; a marker needs a single-valued attribute", attr)
	}
	if v := first(found.Values("rangeUpper")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n < minLen {
			return "", fmt.Errorf("[mapping] attribute %q holds at most %d characters; a marker has %d", attr, n, minLen)
		}
	}
	if flags, _ := strconv.Atoi(first(found.Values("searchFlags"))); flags&searchFlagIndexed == 0 {
		return fmt.Sprintf("[mapping] attribute %s is not indexed on the target, so finding a renamed or moved object reads the whole naming context (set searchFlags bit 1 in its attributeSchema)", attr), nil
	}
	return "", nil
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

// wellKnownSIDs are the identities every domain has, whose foreign security principals a DC creates when one is
// added as a member by SID (Everyone, Authenticated Users, Interactive, Network, ...). A SID of another domain is
// not here: a test domain does not trust it.
var wellKnownSIDs = map[string]bool{
	"S-1-1-0": true, "S-1-5-1": true, "S-1-5-2": true, "S-1-5-3": true, "S-1-5-4": true, "S-1-5-6": true,
	"S-1-5-7": true, "S-1-5-8": true, "S-1-5-9": true, "S-1-5-10": true, "S-1-5-11": true, "S-1-5-12": true,
	"S-1-5-13": true, "S-1-5-14": true, "S-1-5-15": true, "S-1-5-17": true, "S-1-5-18": true, "S-1-5-19": true,
	"S-1-5-20": true, "S-1-5-1000": true,
}

// wellKnownPrincipal recognizes CN=<well-known SID>,CN=ForeignSecurityPrincipals,<domain> and returns the
// <SID=...> form a DC turns into its own principal.
func wellKnownPrincipal(entryDN string) (string, bool) {
	rdns := dn.Split(entryDN)
	if len(rdns) < 3 || !strings.EqualFold(strings.TrimSpace(rdns[1]), "CN=ForeignSecurityPrincipals") {
		return "", false
	}
	typ, sid, ok := dn.FirstRDN(entryDN)
	if !ok || !strings.EqualFold(typ, "cn") || !wellKnownSIDs[strings.ToUpper(sid)] {
		return "", false
	}
	return "<SID=" + strings.ToUpper(sid) + ">", true
}
