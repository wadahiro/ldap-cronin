package profile

import (
	"context"
	"fmt"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/ad"
	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// Descriptors is how an object carries its ACL and how the ACL names its principals: AD's nTSecurityDescriptor, whose
// owner, group and ACE trustees are SIDs. An object created over LDAP gets the target's own SID, so clone
// ([attributes] acl = "copy") and diff give each SID of the source's descriptor through the DN of its object, which
// the clone keeps, as they do for a primary group (PrimaryGrouper).
type Descriptors interface {
	// Attr is the attribute (nTSecurityDescriptor).
	Attr() string
	// SIDAttr is the attribute holding an object's SID (objectSid).
	SIDAttr() string
	// SID is the SID of an entry read with SIDAttr, in text form; "" when it has none.
	SID(e directory.Entry) string
	// Filter finds the object whose SID is sid (text form).
	Filter(sid string) (string, error)
	// Domain is the SID of the domain whose root is root.
	Domain(ctx context.Context, d directory.Directory, root string) (string, error)
	// WellKnown reports whether rid, of a SID of the domain, is a principal every domain has (Domain Admins, the
	// Administrator, ...): the same RID names it in the target's domain.
	WellKnown(rid string) bool
	// Rewrite is what clone writes for raw, the source's descriptor: its owner, group, protected flag and explicit
	// ACEs, each SID passed through to (ad.ExplicitOnly). cur is the target object's descriptor: its owner and group
	// stand in for those to gives "" for; an ACE whose trustee to gives "" for is left out, its SID in dropped.
	Rewrite(raw, cur string, to func(sid string) (string, error)) (out string, dropped []string, err error)
	// Parts is what of a descriptor clone gives and diff compares: owner, group and protected flag as one value,
	// each explicit ACE as another (ad.ExplicitSDParts).
	Parts(raw string) ([]string, error)
}

type adDescriptors struct{}

func (adDescriptors) Attr() string    { return "nTSecurityDescriptor" }
func (adDescriptors) SIDAttr() string { return "objectSid" }

func (adDescriptors) SID(e directory.Entry) string {
	raw := first(e.Values("objectSid"))
	if raw == "" {
		return ""
	}
	s, err := ad.SIDText([]byte(raw))
	if err != nil {
		return ""
	}
	return s
}

// Filter escapes every byte: AD and Samba match objectSid on its binary value.
func (adDescriptors) Filter(sid string) (string, error) {
	raw, err := ad.SIDRaw(sid)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("(objectSid=")
	for _, c := range raw {
		fmt.Fprintf(&b, `\%02x`, c)
	}
	b.WriteString(")")
	return b.String(), nil
}

func (adDescriptors) Domain(ctx context.Context, d directory.Directory, root string) (string, error) {
	dom, err := ad.ReadDomain(ctx, d, root)
	return dom.SID, err
}

func (adDescriptors) WellKnown(rid string) bool { return adPrimaryGroup{}.WellKnown(rid) }

func (adDescriptors) Rewrite(raw, cur string, to func(string) (string, error)) (string, []string, error) {
	out, dropped, err := ad.ExplicitOnly([]byte(raw), []byte(cur), to)
	return string(out), dropped, err
}

func (adDescriptors) Parts(raw string) ([]string, error) { return ad.ExplicitSDParts([]byte(raw)) }
