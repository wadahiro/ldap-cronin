package lab

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	DefaultRealm      = "ad.example.com"
	DefaultLDAPPort   = 12389
	DefaultLDAPSPort  = 12636
	DefaultSrcLDAP    = 11389
	DefaultSrcLDAPS   = 11636
	DefaultPrefix     = "ldap-cronin"
	maxNetBIOSLen     = 15
	envFileName       = ".env"
	generatedPwLength = 20
)

// Settings holds the lab's domain and connection settings.
type Settings struct {
	// Profile is the server type (ad, ldap); empty means ad. Stored in .env so later commands need no flag.
	Profile string
	// Domain is the realm of a Samba lab, or the suffix of an OpenLDAP lab.
	Domain        string
	AdminPassword string
	NetBIOS       string // if empty, the uppercased first label of the domain name
	LDAPPort      int
	LDAPSPort     int
	// DomainSID and DomainGUID are the SID (S-1-5-21-a-b-c) and GUID given when the domain is created.
	// Matching the source domain lets the native import reuse the source's objectSid and objectGUID as they are.
	// They can only be specified at domain creation.
	DomainSID  string
	DomainGUID string
}

// Precedence is "option > environment variable > .env".
const (
	envRealm    = "AD_REALM"
	envPassword = "SAMBA_ADMIN_PASSWORD"
	envNetBIOS  = "SAMBA_DOMAIN"
	envLDAP     = "AD_LDAP_PORT"
	envLDAPS    = "AD_LDAPS_PORT"
	envSID      = "SAMBA_DOMAIN_SID"
	envGUID     = "SAMBA_DOMAIN_GUID"
	envProfile  = "LAB_PROFILE"
)

var (
	domainSIDPattern  = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+$`)
	domainGUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// ValidateDomainIdentity checks the format of the domain SID and GUID (empty means unspecified and passes).
func ValidateDomainIdentity(sid, guid string) error {
	if sid != "" && !domainSIDPattern.MatchString(sid) {
		return fmt.Errorf("invalid domain SID: %q (example: S-1-5-21-1111111111-2222222222-3333333333)", sid)
	}
	if guid != "" && !domainGUIDPattern.MatchString(guid) {
		return fmt.Errorf("invalid domain GUID: %q (example: 12345678-1234-1234-1234-123456789abc)", guid)
	}
	return nil
}

var realmPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// ValidateRealm checks the format of the domain name.
func ValidateRealm(realm string) error {
	if !realmPattern.MatchString(realm) {
		return fmt.Errorf("invalid domain name: %q (example: corp.example.local; labels are alphanumerics and hyphens, with two or more separated by dots)", realm)
	}
	return nil
}

// NetBIOSOf returns the uppercased first label of the domain name (the default NetBIOS domain name).
func NetBIOSOf(realm string) string {
	first, _, _ := strings.Cut(realm, ".")
	return strings.ToUpper(first)
}

// BaseDN builds the base DN (DC=a,DC=b) from the domain name.
func BaseDN(realm string) string {
	labels := strings.Split(realm, ".")
	parts := make([]string, len(labels))
	for i, l := range labels {
		parts[i] = "DC=" + strings.ToLower(l)
	}
	return strings.Join(parts, ",")
}

// EffectiveNetBIOS returns the default NetBIOS name if none is given, and fails if it is too long.
func (s Settings) EffectiveNetBIOS() (string, error) {
	nb := s.NetBIOS
	if nb == "" {
		nb = NetBIOSOf(s.Domain)
	}
	if len(nb) > maxNetBIOSLen {
		return "", fmt.Errorf("NetBIOS name %q exceeds %d characters; specify a shorter one with --netbios", nb, maxNetBIOSLen)
	}
	return nb, nil
}

// GeneratePassword creates a password that satisfies Samba's default password policy (complexity).
// It starts with one uppercase letter, one lowercase letter, one digit and one symbol, and fills the rest randomly.
func GeneratePassword() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var b strings.Builder
	b.WriteString("Aa1-")
	for range generatedPwLength {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[n.Int64()])
	}
	return b.String(), nil
}

// ReadEnvFile reads .env. It does not source it and reads only known keys. If the file is missing, it returns empty settings.
func ReadEnvFile(path string) (Settings, error) {
	var s Settings
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		applyKey(&s, k, v)
	}
	return s, sc.Err()
}

// applyKey reads one variable. A .env holds the keys of one server, so the keys of every server are known here.
func applyKey(s *Settings, k, v string) {
	for _, srv := range Servers() {
		switch k {
		case srv.Env.Domain:
			s.Domain = v
		case srv.Env.Password:
			s.AdminPassword = v
		case srv.Env.LDAP:
			s.LDAPPort, _ = strconv.Atoi(v)
		case srv.Env.LDAPS:
			s.LDAPSPort, _ = strconv.Atoi(v)
		}
	}
	switch k {
	case envProfile:
		s.Profile = v
	case envNetBIOS:
		s.NetBIOS = v
	case envSID:
		s.DomainSID = v
	case envGUID:
		s.DomainGUID = v
	}
}

// WriteEnvFile saves the settings to .env. It contains the password, so the mode is 600.
func WriteEnvFile(path string, s Settings) error {
	var b strings.Builder
	srv, err := ServerFor(s.profile())
	if err != nil {
		return err
	}
	b.WriteString("# Generated by ldap-cronin lab. Contains a password, so keep it from being read by others\n")
	fmt.Fprintf(&b, "%s=%s\n", envProfile, srv.Profile)
	fmt.Fprintf(&b, "%s=%s\n", srv.Env.Domain, s.Domain)
	fmt.Fprintf(&b, "%s=%s\n", srv.Env.Password, s.AdminPassword)
	if s.NetBIOS != "" {
		fmt.Fprintf(&b, "%s=%s\n", envNetBIOS, s.NetBIOS)
	}
	if s.DomainSID != "" {
		fmt.Fprintf(&b, "%s=%s\n", envSID, s.DomainSID)
	}
	if s.DomainGUID != "" {
		fmt.Fprintf(&b, "%s=%s\n", envGUID, s.DomainGUID)
	}
	fmt.Fprintf(&b, "%s=%d\n", srv.Env.LDAP, s.LDAPPort)
	fmt.Fprintf(&b, "%s=%d\n", srv.Env.LDAPS, s.LDAPSPort)
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600) // also tighten the mode of an existing file
}

func (s Settings) profile() string {
	if s.Profile == "" {
		return ProfileAD
	}
	return s.Profile
}

// Resolve decides settings of srv in the order "option > environment variable > .env". env is a function
// equivalent to os.Getenv; only srv's variables are read from it.
func Resolve(srv *Server, flags, file Settings, env func(string) string) Settings {
	out := file
	out.Profile = srv.Profile
	apply := func(from Settings) {
		if from.Domain != "" {
			out.Domain = from.Domain
		}
		if from.AdminPassword != "" {
			out.AdminPassword = from.AdminPassword
		}
		if from.NetBIOS != "" {
			out.NetBIOS = from.NetBIOS
		}
		if from.DomainSID != "" {
			out.DomainSID = from.DomainSID
		}
		if from.DomainGUID != "" {
			out.DomainGUID = from.DomainGUID
		}
		if from.LDAPPort != 0 {
			out.LDAPPort = from.LDAPPort
		}
		if from.LDAPSPort != 0 {
			out.LDAPSPort = from.LDAPSPort
		}
	}
	var fromEnv Settings
	keys := []string{srv.Env.Domain, srv.Env.Password, srv.Env.LDAP, srv.Env.LDAPS}
	if srv.DomainIdentity {
		keys = append(keys, envNetBIOS, envSID, envGUID)
	}
	for _, k := range keys {
		if v := env(k); v != "" {
			applyKey(&fromEnv, k, v)
		}
	}
	apply(fromEnv)
	apply(flags)
	return out
}
