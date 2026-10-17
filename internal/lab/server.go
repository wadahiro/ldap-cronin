package lab

import (
	"fmt"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/dn"
)

// Profiles of the lab servers, named like [scope] profile.
const (
	ProfileAD   = "ad"
	ProfileLDAP = "ldap"
)

// Volume is a docker volume of the lab: its name suffix, where it is mounted and its file in a snapshot.
type Volume struct{ Kind, Mount, File string }

// EnvKeys are the .env and environment variable names of a server's settings.
type EnvKeys struct{ Domain, Password, LDAP, LDAPS string }

// Server is everything that differs between the lab servers (Samba AD, OpenLDAP). Shared code (stop, write volumes,
// start, checksums, instances, ports, labels, the bundle) never branches on the server's name; it asks this value.
type Server struct {
	Profile string // ad / ldap; also the IMAGE key, the container name part and the profile label
	Product string // for messages

	// DomainLabel names Settings.Domain in prompts and output: the domain name of Samba, the suffix of OpenLDAP.
	DomainLabel    string
	DefaultDomain  string
	ValidateDomain func(string) error
	// BaseDN is the naming context of a domain, AdminDN its administrator.
	BaseDN, AdminDN func(domain string) string
	// DomainIdentity is true when NetBIOS, the domain SID and GUID apply (Samba).
	DomainIdentity bool

	Env            EnvKeys
	Ports          [4]int // lab LDAP, LDAPS, sample source LDAP, LDAPS
	Hostname       string // baked into Samba's data (CN=DC1), so fixed for every server
	SourceHostname string
	Volumes        []Volume
	// Ready is the file the image writes once the server answers (the health check).
	Ready string
	// ExtraArgs are docker run arguments the image needs.
	ExtraArgs []string
	// ContainerEnv are the non-secret -e arguments of the container (the password goes as Env.Password).
	ContainerEnv func(s Settings, netbios string) []string
	// SchemaDir is where the image loads deployment LDIFs from at creation; empty when not supported.
	SchemaDir string
}

// Samba is the AD-compatible Samba4 lab.
var Samba = &Server{
	Profile: ProfileAD, Product: "Samba4 AD",
	DomainLabel: "domain", DefaultDomain: DefaultRealm, ValidateDomain: ValidateRealm,
	BaseDN:         BaseDN,
	AdminDN:        func(d string) string { return "CN=Administrator,CN=Users," + BaseDN(d) },
	DomainIdentity: true,
	Env:            EnvKeys{Domain: envRealm, Password: envPassword, LDAP: envLDAP, LDAPS: envLDAPS},
	Ports:          [4]int{DefaultLDAPPort, DefaultLDAPSPort, DefaultSrcLDAP, DefaultSrcLDAPS},
	Hostname:       dcHostname, SourceHostname: srcHostname,
	Volumes: []Volume{{"private", "/var/lib/samba", "private.tar"}, {"etc", "/etc/samba", "etc.tar"}},
	Ready:   "/tmp/ad-ready",
	// Provisioning writes NT ACLs as security.* xattrs (entrypoint.sh falls back to user.NTACL where it cannot).
	ExtraArgs: []string{"--cap-add", "SYS_ADMIN"},
	ContainerEnv: func(s Settings, nb string) []string {
		return []string{"-e", "AD_REALM=" + s.Domain, "-e", "SAMBA_DOMAIN=" + nb}
	},
}

// OpenLDAP is the generic LDAP lab (docker/ldap).
var OpenLDAP = &Server{
	Profile: ProfileLDAP, Product: "OpenLDAP",
	DomainLabel: "suffix", DefaultDomain: "dc=example,dc=org", ValidateDomain: ValidateSuffix,
	BaseDN:  func(d string) string { return d },
	AdminDN: func(d string) string { return "cn=admin," + d },
	Env:     EnvKeys{Domain: "LDAP_SUFFIX", Password: "LDAP_ADMIN_PASSWORD", LDAP: "LDAP_PORT", LDAPS: "LDAPS_PORT"},
	// Different from Samba's, so both kinds (and their sample sources) can run side by side.
	Ports:    [4]int{13389, 13636, 14389, 14636},
	Hostname: "ldap1", SourceHostname: "ldap2",
	Volumes: []Volume{{"data", "/var/lib/ldap", "data.tar"}, {"config", "/etc/ldap/slapd.d", "config.tar"}},
	Ready:   "/tmp/ldap-ready",
	ContainerEnv: func(s Settings, _ string) []string {
		return []string{"-e", "LDAP_SUFFIX=" + s.Domain}
	},
	SchemaDir: "/schema.d",
}

// Servers lists the lab servers.
func Servers() []*Server { return []*Server{Samba, OpenLDAP} }

// ServerFor returns the lab server of a profile.
func ServerFor(profile string) (*Server, error) {
	for _, s := range Servers() {
		if strings.EqualFold(s.Profile, profile) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("unknown lab profile %q (available: %s, %s)", profile, ProfileAD, ProfileLDAP)
}

// ValidateSuffix checks an OpenLDAP suffix: a DN whose first RDN is dc=, o= or ou= (what the image can create).
func ValidateSuffix(suffix string) error {
	typ, _, ok := dn.FirstRDN(suffix)
	switch {
	case !ok || dn.Normalize(suffix) == "":
		return fmt.Errorf("invalid suffix: %q (example: dc=example,dc=org)", suffix)
	case !strings.EqualFold(typ, "dc") && !strings.EqualFold(typ, "o") && !strings.EqualFold(typ, "ou"):
		return fmt.Errorf("invalid suffix: %q (the first RDN must be dc=, o= or ou=)", suffix)
	}
	return nil
}
