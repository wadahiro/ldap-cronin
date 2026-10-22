package profile

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/wadahiro/ldap-cronin/internal/compare"
	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// Account is how a user account is created on the target with the fixed password. clone keeps the order
// (AddEntry, Add, Finish) and the read of an existing entry; what each step does is the server's business.
type Account interface {
	// AddEntry returns what to send in the Add of a new account.
	AddEntry(e directory.Entry, password string) directory.Entry
	// ReadExtra lists attributes to read along with an existing entry, for Finish.
	ReadExtra() []string
	// SourceExtra lists attributes of the source entry Finish reads (pwdLastSet: whether the user must change the
	// password at the next logon). They are read with it and never written as they are.
	SourceExtra() []string
	// PasswordAttr is the attribute the fixed password is written to (unicodePwd, userPassword).
	PasswordAttr() string
	// Owned lists allow-listed attributes that only Finish writes. clone leaves them out of its own comparison so
	// Finish is their only writer.
	Owned() []string
	// Finish completes the account after a successful Add (cur == nil) or on an existing entry (cur as read with
	// ReadExtra). It returns the attributes it changed on an existing entry, for the update log.
	Finish(ctx context.Context, dst directory.Directory, want directory.Entry, password string, cur *directory.Entry) (changed []string, err error)
}

const (
	attrUAC          = "userAccountControl"
	attrUnicodePwd   = "unicodePwd"
	attrPwdLastSet   = "pwdLastSet"
	attrUserPassword = "userPassword"
)

// adAccount creates an AD user in three steps: add (disabled), set unicodePwd with a modify, then set
// userAccountControl to the source value.
//
// Sending unicodePwd in the Add was rejected. Samba accepts it, but Microsoft specifies that unicodePwd "can only be
// modified, not added at object creation" (KB 269190 / MS-ADTS unicodePwd), so it would work only on Samba.
// It was not faster on Samba either (about 105 s for 1600 users both ways).
// userAccountControl comes last: applying disabled or never-expires first changes the preconditions of setting the
// password, and a real AD refuses to create a user with UAC=512 and no password.
//
// A computer is added with its account type (a workstation trust), disabled and without a password required, so
// the last step changes only those flags. Without it the DC makes a normal (user) account; Samba lets the last step
// change the type, but a run stopped before it would leave a computer that is a user account (sAMAccountType).
type adAccount struct{}

const (
	uacDisabled         = 0x2
	uacPasswdNotReqd    = 0x20
	uacWorkstationTrust = 0x1000
	uacServerTrust      = 0x2000
	uacInterdomainTrust = 0x800
)

func (adAccount) AddEntry(e directory.Entry, _ string) directory.Entry {
	out := directory.Entry{DN: e.DN, Attrs: make(map[string][]string, len(e.Attrs))}
	for n, v := range e.Attrs {
		if !strings.EqualFold(n, attrUAC) {
			out.Attrs[n] = v
		}
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(first(e.Values(attrUAC))), 10, 64); err == nil && n&uacWorkstationTrust != 0 {
		out.Attrs[attrUAC] = []string{strconv.Itoa(uacWorkstationTrust | uacDisabled | uacPasswdNotReqd)}
	}
	return out
}

func (adAccount) ReadExtra() []string   { return []string{attrUAC, attrPwdLastSet} }
func (adAccount) SourceExtra() []string { return []string{attrPwdLastSet} }
func (adAccount) Owned() []string       { return []string{attrUAC} }
func (adAccount) PasswordAttr() string  { return attrUnicodePwd }

// Finish sets the password only on creation, or when creation was interrupted before the password was set
// (pwdLastSet=0), so a re-run does not roll back a password changed by the program under test. A user who must
// change the password at the next logon on the source (pwdLastSet=0 there) must on the target too: pwdLastSet=0
// right after the password (a computer's 0 is a password never set, not one to change). A re-run then sets the
// same password again, which changes nothing; once the user (or the program under test) has changed it,
// pwdLastSet is no longer 0 and it is left alone.
func (adAccount) Finish(ctx context.Context, dst directory.Directory, want directory.Entry, password string, cur *directory.Entry) ([]string, error) {
	created := cur == nil
	if password != "" && (created || isUnset(cur.Values(attrPwdLastSet))) {
		if err := dst.Replace(ctx, want.DN, map[string][]string{attrUnicodePwd: {EncodePassword(password)}}); err != nil {
			return nil, fmt.Errorf("set password (LDAPS is required; the password must also satisfy the target's password policy): %w", err)
		}
		if isUnset(want.Values(attrPwdLastSet)) && !isTrust(want) {
			if err := dst.Replace(ctx, want.DN, map[string][]string{attrPwdLastSet: {"0"}}); err != nil {
				return nil, fmt.Errorf("must change the password at the next logon (pwdLastSet=0): %w", err)
			}
		}
	}
	values := want.Values(attrUAC)
	if len(values) == 0 {
		return nil, nil
	}
	uac := SanitizeUAC(values[0])
	if !created && compare.Equal(SanitizeUAC, cur.Values(attrUAC), []string{uac}) {
		return nil, nil
	}
	if err := dst.Replace(ctx, want.DN, map[string][]string{attrUAC: {uac}}); err != nil {
		return nil, err
	}
	if created {
		return nil, nil
	}
	return []string{attrUAC}, nil
}

// isTrust reports whether e is a computer (or another trust) account, which logs on with its own password: its
// pwdLastSet=0 is a password never set (a pre-staged computer), not a user to make change it.
func isTrust(e directory.Entry) bool {
	n, err := strconv.ParseInt(strings.TrimSpace(first(e.Values(attrUAC))), 10, 64)
	return err == nil && n&(uacWorkstationTrust|uacServerTrust|uacInterdomainTrust) != 0
}

func isUnset(values []string) bool { return len(values) == 1 && values[0] == "0" }

// EncodePassword converts to the AD unicodePwd format (UTF-16LE enclosed in quotes).
func EncodePassword(pw string) string {
	units := utf16.Encode([]rune(`"` + pw + `"`))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u), byte(u>>8))
	}
	return string(b)
}

// ldapAccount sends the fixed password in the Add as userPassword; the server hashes it with its configured scheme
// (389-ds always, OpenLDAP with ppolicy_hash_cleartext) or stores it as given, exactly as it would for a modify.
//
// Being part of the Add, the password cannot be missing on an account that exists, so there is nothing to detect
// on a re-run and an existing account's password is never touched. Two alternatives were rejected:
// "set it when userPassword is absent" misfires when the bind DN's ACL hides userPassword (every run would reset
// every password), and "always set it" fails under a ppolicy pwdInHistory and undoes changes made by the program
// under test. The password modify extended operation (RFC 3062) was rejected because not every server enables it.
type ldapAccount struct{}

func (ldapAccount) AddEntry(e directory.Entry, password string) directory.Entry {
	out := directory.Entry{DN: e.DN, Attrs: make(map[string][]string, len(e.Attrs)+1)}
	for n, v := range e.Attrs {
		out.Attrs[n] = v
	}
	if password != "" {
		out.Attrs[attrUserPassword] = []string{password}
	}
	return out
}

func (ldapAccount) ReadExtra() []string   { return nil }
func (ldapAccount) SourceExtra() []string { return nil }
func (ldapAccount) Owned() []string       { return nil }
func (ldapAccount) PasswordAttr() string  { return attrUserPassword }

func (ldapAccount) Finish(context.Context, directory.Directory, directory.Entry, string, *directory.Entry) ([]string, error) {
	return nil, nil
}
