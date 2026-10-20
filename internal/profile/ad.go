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
		{Name: KindOU, Class: "organizationalUnit", Role: RoleContainer, Filter: "(objectClass=organizationalUnit)", Is: classIs("organizationalUnit"), Default: []string{
			"description", "displayName", "street", "l", "st", "postalCode", "co", "c", "managedBy",
		}},
		{Name: KindGroup, Class: "group", Role: RoleLeaf, Order: 0, Filter: "(objectClass=group)", Is: classIs("group"), Default: []string{
			"sAMAccountName", "groupType", "description", "displayName", "info", "mail",
			"managedBy", "member", "adminDescription", "gidNumber",
		}},
		// user excludes computer, which also has objectClass=user.
		{Name: KindUser, Class: "user", Role: RoleLeaf, Order: 1, Account: true, Filter: "(&(objectCategory=person)(objectClass=user))",
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
		{Name: KindComputer, Class: "computer", Role: RoleLeaf, Order: 2, Account: true, Filter: "(objectCategory=computer)", Is: classIs("computer"), Default: []string{
			"sAMAccountName", "userAccountControl", "dNSHostName", "description", "displayName", "location",
			"managedBy", "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
			"servicePrincipalName", "info",
		}},
		// Contacts: the user list without the account and logon attributes.
		{Name: KindContact, Class: "contact", Role: RoleLeaf, Order: 3, Filter: "(objectClass=contact)", Is: classIs("contact"), Default: []string{
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
	}, append(accountSecrets, computerCredentials...)...),
	NoMask: []string{
		"objectClass", "cn", "ou", "sAMAccountName", "userPrincipalName", "servicePrincipalName",
		"member", "manager", "managedBy", "userAccountControl", "groupType", "accountExpires",
		"countryCode", "c", "uidNumber", "gidNumber",
	},
	PasswordAttrs: append(append([]string{"unicodePwd", "dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials"}, accountSecrets...), computerCredentials...),
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
	SchemaAttrs: adSchema{},
	SchemaCopy:  adSchema{},
	Writable:    adSchema{},
	Refusals:    sambaRefusals{},
	Root:        adRoot{},
	Account:     adAccount{},
	Native:      adNative{},
}

// accountSecrets are the other secrets an account may hold, never cloned, compared or printed: the password a
// client may write as userPassword (and the Unix one), a private key (userPKCS12), the credential roaming blobs, the
// TPM owner information of a computer. No default allow list names them; they are listed so [attributes]
// mode = "all", which takes every attribute a client can write, leaves them out too.
var accountSecrets = []string{
	"userPassword", "unixUserPassword", "userPKCS12", "msPKIAccountCredentials", "msPKIDPAPIMasterKeys", "msTPM-OwnerInformation",
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
			case syntaxDNBinary, syntaxDNString:
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

// Attributes reads the lDAPDisplayName of every attributeSchema entry.
func (adSchema) Attributes(ctx context.Context, d directory.Directory) (map[string]bool, bool, error) {
	root, err := d.Get(ctx, "", []string{"schemaNamingContext"})
	if err != nil {
		return nil, false, fmt.Errorf("read root DSE: %w", err)
	}
	if root == nil || first(root.Values("schemaNamingContext")) == "" {
		return nil, false, nil
	}
	out := map[string]bool{}
	err = d.Walk(ctx, first(root.Values("schemaNamingContext")), "(objectClass=attributeSchema)", []string{"lDAPDisplayName"}, func(e directory.Entry) error {
		if n := first(e.Values("lDAPDisplayName")); n != "" {
			out[strings.ToLower(n)] = true
		}
		return nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("read schema: %w", err)
	}
	return out, true, nil
}

// PlanSchema compares the attributeSchema and classSchema entries of the two schema naming contexts.
func (adSchema) PlanSchema(ctx context.Context, src, dst directory.Directory) (SchemaChanges, bool, error) {
	s, err := ad.ReadSchema(ctx, src)
	if err != nil || s == nil {
		return nil, false, err
	}
	d, err := ad.ReadSchema(ctx, dst)
	if err != nil || d == nil {
		return nil, false, err
	}
	return ad.PlanSchema(s, d), true, nil
}

func (adSchema) Writable(ctx context.Context, src directory.Directory, classes []string) (map[string][]string, bool, error) {
	s, err := ad.ReadSchema(ctx, src)
	if err != nil || s == nil {
		return nil, false, err
	}
	out := map[string][]string{}
	for _, c := range classes {
		names, ok := s.Writable(c)
		if !ok {
			return nil, false, fmt.Errorf("the source schema has no class %s", c)
		}
		out[c] = names
	}
	return out, true, nil
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

// sambaRefusals is what a Samba AD DC refuses over LDAP although its schema has it, told from Windows by the
// vendorName of its root DSE (Windows publishes none).
type sambaRefusals struct{}

// sambaRefused are the attributes Samba will not have written over LDAP, with the reason it gives.
var sambaRefused = map[string]string{
	// samldb: "setting userParameters is not supported over LDAP"; Windows takes it (old RAS and Terminal Services
	// settings in a binary format Samba does not parse).
	"userParameters": "Samba refuses it over LDAP (https://bugzilla.samba.org/show_bug.cgi?id=8077)",
}

func (sambaRefusals) Refused(ctx context.Context, dst directory.Directory) (map[string]string, error) {
	root, err := dst.Get(ctx, "", []string{"vendorName"})
	if err != nil {
		return nil, fmt.Errorf("read the target's root DSE: %w", err)
	}
	if root == nil {
		return nil, nil
	}
	for _, v := range root.Values("vendorName") {
		if strings.Contains(strings.ToLower(v), "samba") {
			return sambaRefused, nil
		}
	}
	return nil, nil
}
