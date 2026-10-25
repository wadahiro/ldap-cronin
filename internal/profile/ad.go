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
		// The default allow lists are what Active Directory Users and Computers shows on its property sheets, as
		// Microsoft maps them (https://learn.microsoft.com/windows/win32/ad/mappings-for-the-active-directory-users-and-computers-snap-in),
		// without what clone never writes (what the server keeps: whenCreated, uSN*, lockoutTime, pwdLastSet; the
		// back links memberOf and directReports; primaryGroupID; Terminal Services' private data) and with, after
		// "beyond the mapping:", what the mapping leaves out that production directories use, each with why.
		// Contacts have no mapping: they show the General, Address, Telephones and Organization sheets of a user.
		{Name: KindOU, Class: "organizationalUnit", Role: RoleContainer, Filter: "(objectClass=organizationalUnit)", Is: classIs("organizationalUnit"), ByClass: "organizationalUnit", Default: []string{
			"description", "street", "l", "st", "postalCode", "c", "managedBy",
			// beyond the mapping: the display name and the country's name (c's companion, as on a user)
			"displayName", "co",
		}},
		{Name: KindGroup, Class: "group", Role: RoleLeaf, Order: 0, Filter: "(objectClass=group)", Is: classIs("group"), ByClass: "group", Default: []string{
			"sAMAccountName", "description", "mail", "groupType", "info", "member", "managedBy",
			// beyond the mapping: the display name; adminDescription, Entra Connect's default filter; gidNumber, the
			// UNIX Attributes sheet of Identity Management for UNIX
			"displayName", "adminDescription", "gidNumber",
		}},
		// user excludes computer, which also has objectClass=user.
		{Name: KindUser, Class: "user", Role: RoleLeaf, Order: 1, Account: true, Filter: "(&(objectCategory=person)(objectClass=user))",
			// objectCategory=person and objectClass=user: a user or inetOrgPerson, not a computer (a subclass of user).
			Is: func(c []string) bool { return hasClass(c, []string{"user"}, "computer") }, ByClass: "user (inetOrgPerson too), not computer", Default: []string{
				// General
				"givenName", "sn", "initials", "displayName", "description", "physicalDeliveryOfficeName",
				"telephoneNumber", "otherTelephone", "mail", "wWWHomePage", "url",
				// Account
				"userPrincipalName", "sAMAccountName", "logonHours", "userWorkstations", "userAccountControl", "accountExpires",
				// Address
				"streetAddress", "postOfficeBox", "l", "st", "postalCode", "c", "co", "countryCode",
				// Organization
				"title", "department", "company", "manager",
				// Profile
				"profilePath", "scriptPath", "homeDirectory", "homeDrive",
				// Telephones
				"homePhone", "otherHomePhone", "pager", "otherPager", "mobile", "otherMobile",
				"facsimileTelephoneNumber", "otherFacsimileTelephoneNumber", "ipPhone", "otherIpPhone", "info",
				// beyond the mapping: the employee identifiers IdM products key on, the rest of the name and the
				// organization, and the UNIX Attributes sheet of Identity Management for UNIX
				"employeeID", "employeeNumber", "employeeType", "middleName", "division",
				"uidNumber", "gidNumber", "loginShell", "unixHomeDirectory",
			}},
		// Computers are what groups hold most besides users. A computer is an account too: it gets the fixed
		// password, as a joined computer has one (a pre-staged computer without it is not what production holds).
		// Service accounts (msDS-ManagedServiceAccount and its kin) have their own objectCategory and stay out; they
		// derive from computer, so Is leaves them out by name: a group holding one does not bring it in as a computer.
		{Name: KindComputer, Class: "computer", Role: RoleLeaf, Order: 2, Account: true, Filter: "(objectCategory=computer)", Is: func(c []string) bool {
			return hasClass(c, []string{"computer"}, "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount", "msDS-DelegatedManagedServiceAccount")
		}, ByClass: "computer, not a managed service account", Default: []string{
			"sAMAccountName", "dNSHostName", "userAccountControl", "description", "location",
			"operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
			// beyond the mapping: the Managed By sheet the snap-in has had since, servicePrincipalName (Kerberos
			// finds a service by it), the display name and the notes
			"managedBy", "servicePrincipalName", "displayName", "info",
		}},
		{Name: KindContact, Class: "contact", Role: RoleLeaf, Order: 3, Filter: "(objectClass=contact)", Is: classIs("contact"), ByClass: "contact", Default: []string{
			// General
			"givenName", "sn", "initials", "displayName", "description", "physicalDeliveryOfficeName",
			"telephoneNumber", "otherTelephone", "mail", "wWWHomePage", "url",
			// Address
			"streetAddress", "postOfficeBox", "l", "st", "postalCode", "c", "co", "countryCode",
			// Organization
			"title", "department", "company", "manager",
			// Telephones
			"homePhone", "otherHomePhone", "pager", "otherPager", "mobile", "otherMobile",
			"facsimileTelephoneNumber", "otherFacsimileTelephoneNumber", "ipPhone", "otherIpPhone", "info",
			// beyond the mapping, as on a user
			"employeeID", "employeeNumber", "employeeType", "middleName", "division",
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
		"countryCode", "c", "uidNumber", "gidNumber", "logonHours",
	},
	PasswordAttrs: append(append([]string{"unicodePwd", "dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials"}, accountSecrets...), computerCredentials...),
	Secrets:       readableSecrets(),
	// A safeguard so that Administrator, krbtgt and the like are not overwritten even if base_dn is CN=Users.
	SystemFilter: "(!(isCriticalSystemObject=TRUE))",
	SystemAttr:   "isCriticalSystemObject",
	Principal:    wellKnownPrincipal,
	// Measured on Windows Server 2019: adding Everyone or Authenticated Users to a global group fails with 53
	// (WILL_NOT_PERFORM), to a domain local one with 80 (0x56C, ERROR_INVALID_MEMBER), by DN or by <SID=...>.
	WellKnownRefused: func(ctx context.Context, dst directory.Directory) (bool, error) {
		root, err := dst.Get(ctx, "", []string{"vendorName", "defaultNamingContext"})
		if err != nil || root == nil || len(root.Values("defaultNamingContext")) == 0 {
			return false, err // not a server (a dry-run's LDIF): written, as before
		}
		samba, err := IsSamba(ctx, dst)
		return !samba, err
	},
	IsWellKnown: func(v string) bool {
		if _, ok := wellKnownPrincipal(v); ok {
			return true
		}
		rdns := dn.Split(v)
		return len(rdns) > 2 && strings.EqualFold(strings.TrimSpace(rdns[1]), "CN=WellKnown Security Principals")
	},
	BuiltinRefs: map[string]RefInfo{"member": {}, "manager": {Single: true}, "managedby": {Single: true}},
	// AD splits a large member into ranges by itself, Samba does not. Always asking for ranges puts both through the
	// same retrieval path, so the multi-fetch code runs against Samba in CI too.
	Ranged:        []string{"member"},
	RefsNeedEntry: true,
	Values: map[string]compare.Normalizer{
		"useraccountcontrol": SanitizeUAC,
		// diff compares the primary group by the DN of the group (its RID is each domain's own).
		"primarygroupid": compare.DN,
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
	NotAll: map[string]string{
		// gPLink is a string ("[LDAP://cn={GUID},cn=policies,...;0]"), not a DN, so it is no reference clone could
		// follow, and GPOs are no kind: copied, it links the target's OUs to policies it lacks.
		"gplink":    "it links GPOs, which clone does not copy",
		"gpoptions": "it goes with gPLink (blocks inheritance of GPOs, which clone does not copy)",
	},
	Refusals: adRefusals{},
	Root:     adRoot{},
	ConfigurationNC: func(ctx context.Context, d directory.Directory) (string, error) {
		root, err := d.Get(ctx, "", []string{"configurationNamingContext"})
		if err != nil || root == nil {
			return "", err
		}
		return first(root.Values("configurationNamingContext")), nil
	},
	// The dump reads each entry's security descriptor by name (owner, group and DACL, through the SD flags control),
	// for a native import that gives the lab the source's ACLs.
	Operational:  []string{"nTSecurityDescriptor"},
	Account:      adAccount{},
	PrimaryGroup: adPrimaryGroup{},
	Descriptors:  adDescriptors{},
	Native:       adNative{},
}

// accountSecrets are the other secrets an account may hold, never cloned, compared or printed: the password a
// client may write as userPassword (and the Unix one), a private key (userPKCS12), the credential roaming blobs, the
// TPM owner information of a computer. No default allow list names them; they are listed so [attributes]
// mode = "all", which takes every attribute a client can write, leaves them out too.
var accountSecrets = []string{
	"userPassword", "unixUserPassword", "userPKCS12", "msPKIAccountCredentials", "msPKIDPAPIMasterKeys", "msPKI-CredentialRoamingTokens",
	"msTPM-OwnerInformation",
}

// computerCredentials are never cloned, compared or printed: LAPS (legacy and Windows LAPS), Windows Hello / shadow
// credentials, resource-based delegation (who may act as the computer), the gMSA password.
var computerCredentials = []string{
	"ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-Password", "msLAPS-EncryptedPassword",
	"msLAPS-EncryptedPasswordHistory", "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory",
	"msLAPS-PasswordExpirationTime", "msDS-KeyCredentialLink", "msDS-AllowedToActOnBehalfOfOtherIdentity",
	"msDS-ManagedPassword",
}

// readableSecrets are the credentials AD may return to a reader with the rights (a confidential attribute to one
// granted control access, LAPS to its readers) and a client may write: the other secrets and the computers'
// credentials but the gMSA password, which the DC constructs for each read. They are copied for a clone that is to
// hold the structure the source has (one test domain cloned from another); a LAPS password encrypted to the source
// domain's key, or a delegation naming its SIDs, means something on the target only when it has the source's domain
// SID ([target.lab] native = true).
func readableSecrets() []string {
	var out []string
	for _, n := range append(append([]string(nil), accountSecrets...), computerCredentials...) {
		if n != "msDS-ManagedPassword" {
			out = append(out, n)
		}
	}
	return out
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
	syntaxDNBinary = "2.5.5.7"  // DN-Binary, B:<count>:<hex>:<DN>, or Object(OR-Name), the DN alone (Exchange's authOrig)
	syntaxDNString = "2.5.5.14" // DN-String: S:<count>:<string>:<DN>
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
	s := Schema{Refs: map[string]RefInfo{}, BackLinks: map[string]bool{}, Holds: map[string]string{}}
	byLink := map[int]string{} // linkID -> lDAPDisplayName
	filter := "(&(objectClass=attributeSchema)(|(attributeSyntax=" + syntaxDN + ")(attributeSyntax=" + syntaxDNBinary + ")(attributeSyntax=" + syntaxDNString + ")))"
	err = src.Walk(ctx, first(root.Values("schemaNamingContext")), filter,
		[]string{"lDAPDisplayName", "attributeSyntax", "linkID", "isSingleValued"}, func(e directory.Entry) error {
			name := first(e.Values("lDAPDisplayName"))
			if name == "" {
				return nil
			}
			key := strings.ToLower(name)
			switch first(e.Values("attributeSyntax")) {
			case syntaxDN, syntaxDNBinary, syntaxDNString:
				// A DN-Binary or DN-String value is a reference too: its DN is what clone creates and diff
				// compares, the binary or string part around it is written as it is (dn.SplitRef).
				s.Refs[key] = RefInfo{Single: strings.EqualFold(first(e.Values("isSingleValued")), "TRUE")}
			default:
				return nil // the filter asked for these syntaxes only; a server that ignores it adds nothing
			}
			// The server computes a back link (memberOf, directReports, ...) and it cannot be written.
			if id, err := strconv.Atoi(first(e.Values("linkID"))); err == nil {
				byLink[id] = name
				if id%2 == 1 {
					s.BackLinks[key] = true
					delete(s.Refs, key)
				}
			}
			return nil
		})
	if err != nil {
		return Schema{}, false, fmt.Errorf("read schema: %w", err)
	}
	// A back link's linkID is its forward link's plus one.
	for id, name := range byLink {
		if forward, ok := byLink[id-1]; ok && id%2 == 1 {
			s.Holds[name] = forward
		}
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

// adRefusals is what an AD target refuses over LDAP although its schema has it: the attributes its own schema marks
// systemOnly (the source's may not: Samba 4.19.5 marks msDS-AllowedToActOnBehalfOfOtherIdentity so, which Windows
// lets a client write, and refuses it "can only be modified as system"), and on Samba the ones it refuses by its
// code, told from Windows by the vendorName of its root DSE (Windows publishes none).
type adRefusals struct{}

// sambaRefused are the attributes Samba will not have written over LDAP, with the reason it gives.
var sambaRefused = map[string]string{
	// samldb: "setting userParameters is not supported over LDAP"; Windows takes it (old RAS and Terminal Services
	// settings in a binary format Samba does not parse).
	"userParameters": "Samba refuses it over LDAP (https://bugzilla.samba.org/show_bug.cgi?id=8077)",
}

func (adRefusals) Refused(ctx context.Context, dst directory.Directory) (map[string]string, error) {
	out := map[string]string{}
	root, err := dst.Get(ctx, "", []string{"schemaNamingContext"})
	if err != nil {
		return nil, fmt.Errorf("read root DSE: %w", err)
	}
	if root != nil && first(root.Values("schemaNamingContext")) != "" {
		err = dst.Walk(ctx, first(root.Values("schemaNamingContext")), "(objectClass=attributeSchema)", []string{"lDAPDisplayName", "systemOnly"}, func(e directory.Entry) error {
			if n := first(e.Values("lDAPDisplayName")); n != "" && strings.EqualFold(first(e.Values("systemOnly")), "TRUE") {
				out[n] = "the target's schema has it systemOnly: only the server writes it"
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("read schema: %w", err)
		}
	}
	samba, err := IsSamba(ctx, dst)
	if err != nil {
		return nil, err
	}
	if samba {
		for n, why := range sambaRefused {
			out[n] = why
		}
	}
	return out, nil
}

// IsSamba reports whether d is a Samba AD DC, by the vendorName of its root DSE (Windows publishes none).
func IsSamba(ctx context.Context, d directory.Directory) (bool, error) {
	root, err := d.Get(ctx, "", []string{"vendorName"})
	if err != nil {
		return false, fmt.Errorf("read the root DSE: %w", err)
	}
	if root == nil {
		return false, nil
	}
	for _, v := range root.Values("vendorName") {
		if strings.Contains(strings.ToLower(v), "samba") {
			return true, nil
		}
	}
	return false, nil
}
