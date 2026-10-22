package profile

import (
	"context"
	"strconv"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/ad"
	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// PrimaryGrouper is how an account names its primary group, a group it belongs to without being in its member: AD's
// primaryGroupID, the RID of a group of the domain. A RID is the target's own for a group created over LDAP, so clone
// and diff go through the group's DN, which the clone keeps.
type PrimaryGrouper interface {
	// Attr is the attribute (primaryGroupID).
	Attr() string
	// Default is the value a new account of e's type gets: Domain Users for a user, Domain Computers for a
	// workstation, Domain Controllers for a server trust.
	Default(e directory.Entry) string
	// Groups maps the RID of every group of the domain under root to its DN.
	Groups(ctx context.Context, d directory.Directory, root string) (map[string]string, error)
	// RID is the RID of a group entry read with "objectSid".
	RID(group directory.Entry) (string, bool)
	// WellKnown reports whether rid is the same group in every domain (Domain Users, Domain Admins, ...), so it
	// needs no DN to be the source's.
	WellKnown(rid string) bool
}

type adPrimaryGroup struct{}

const (
	ridDomainUsers       = "513"
	ridDomainComputers   = "515"
	ridDomainControllers = "516"
)

func (adPrimaryGroup) Attr() string { return "primaryGroupID" }

// WellKnown: the RIDs below 1000 are the domain's built-in groups (MS-DTYP 2.4.2.4).
func (adPrimaryGroup) WellKnown(rid string) bool {
	n, err := strconv.Atoi(rid)
	return err == nil && n < 1000
}

func (adPrimaryGroup) Default(e directory.Entry) string {
	n, _ := strconv.ParseInt(strings.TrimSpace(first(e.Values(attrUAC))), 10, 64)
	switch {
	case n&uacServerTrust != 0:
		return ridDomainControllers
	case n&uacWorkstationTrust != 0:
		return ridDomainComputers
	}
	return ridDomainUsers
}

func (g adPrimaryGroup) Groups(ctx context.Context, d directory.Directory, root string) (map[string]string, error) {
	out := map[string]string{}
	err := d.Walk(ctx, root, "(objectClass=group)", []string{"objectSid"}, func(e directory.Entry) error {
		if rid, ok := g.RID(e); ok {
			out[rid] = e.DN
		}
		return nil
	})
	return out, err
}

// RID is the last sub-authority of a domain SID (S-1-5-21-...); a group of CN=Builtin (S-1-5-32-...) is no one's
// primary group.
func (adPrimaryGroup) RID(e directory.Entry) (string, bool) {
	raw := first(e.Values("objectSid"))
	if raw == "" {
		return "", false
	}
	text, err := ad.SIDText([]byte(raw))
	if err != nil || !strings.HasPrefix(text, "S-1-5-21-") {
		return "", false
	}
	return text[strings.LastIndexByte(text, '-')+1:], true
}
