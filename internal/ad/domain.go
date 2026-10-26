package ad

import (
	"context"
	"fmt"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
)

// Domain is what identifies an AD domain, enough to provision a lab Samba as the same domain.
type Domain struct {
	Root    string // DC=ad,DC=example,DC=com
	Realm   string // ad.example.com
	NetBIOS string // empty when the crossRef cannot be read
	SID     string // S-1-5-21-...
	GUID    string // text form of the root's objectGUID
}

// ReadDomain reads the domain whose root is root.
func ReadDomain(ctx context.Context, d directory.Directory, root string) (Domain, error) {
	e, err := d.Get(ctx, root, []string{"objectSid", "objectGUID"})
	if err != nil {
		return Domain{}, fmt.Errorf("cannot read domain root %s: %w", root, err)
	}
	if e == nil {
		return Domain{}, fmt.Errorf("domain root %s not found", root)
	}
	rawSID, rawGUID := first(e.Values("objectSid")), first(e.Values("objectGUID"))
	if rawSID == "" || rawGUID == "" {
		return Domain{}, fmt.Errorf("cannot read objectSid and objectGUID from domain root %s", root)
	}
	out := Domain{Root: root, Realm: RealmOf(root), NetBIOS: netbiosOf(ctx, d, root)}
	if out.SID, err = SIDText([]byte(rawSID)); err != nil {
		return Domain{}, err
	}
	if out.GUID, err = GUIDText([]byte(rawGUID)); err != nil {
		return Domain{}, err
	}
	return out, nil
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// RealmOf builds the domain name (a.b) from the domain root DN (DC=a,DC=b).
func RealmOf(root string) string {
	var labels []string
	for _, rdn := range dn.Split(root) {
		if v, ok := strings.CutPrefix(strings.ToLower(rdn), "dc="); ok {
			labels = append(labels, v)
		}
	}
	return strings.Join(labels, ".")
}

// netbiosOf reads the domain's NetBIOS name from the partition's crossRef. Empty if it cannot be read: the lab then
// derives it from the realm, which is what a default provisioning does too.
func netbiosOf(ctx context.Context, d directory.Directory, root string) string {
	rootDSE, err := d.Get(ctx, "", []string{"configurationNamingContext"})
	if err != nil || rootDSE == nil || first(rootDSE.Values("configurationNamingContext")) == "" {
		return ""
	}
	partitions := "CN=Partitions," + first(rootDSE.Values("configurationNamingContext"))
	found := ""
	_ = d.Walk(ctx, partitions, "(&(objectClass=crossRef)(nCName="+root+"))", []string{"nETBIOSName"}, func(e directory.Entry) error {
		if found == "" {
			found = first(e.Values("nETBIOSName"))
		}
		return nil
	})
	return found
}
