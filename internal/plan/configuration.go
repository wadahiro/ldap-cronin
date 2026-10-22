package plan

import (
	"context"
	"fmt"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// ConfigurationNC is the source's configuration partition, "" where there is none.
func (p *Plan) ConfigurationNC() string { return p.configNC }

// InConfiguration reports whether entryDN is the source's configuration partition or below it.
func (p *Plan) InConfiguration(entryDN string) bool {
	return p.configNC != "" && (dn.Equal(entryDN, p.configNC) || dn.IsDescendant(entryDN, p.configNC))
}

// fenced are the containers of the configuration partition clone never writes under, even with
// configuration_refs = "clone": the schema, whose changes cannot be undone and which ldap-cronin schema alone
// changes after showing them, and the partitions (crossRef), which define the forest the lab is.
var fenced = []string{"CN=Schema", "CN=Partitions"}

// Fenced reports whether entryDN is one of the fenced containers of the configuration partition or below one.
func (p *Plan) Fenced(entryDN string) bool {
	for _, f := range fenced {
		top := f + "," + p.configNC
		if p.configNC != "" && (dn.Equal(entryDN, top) || dn.IsDescendant(entryDN, top)) {
			return true
		}
	}
	return false
}

// ReadConfiguration reads an entry of the configuration partition as clone creates it on the target: its object
// classes, its naming attribute and the attributes a client can write on its classes, masked, without what is
// never cloned and without the DN-valued ones (as for a referenced object, its own references are not followed).
// It returns nil when the source has no such entry.
func (p *Plan) ReadConfiguration(ctx context.Context, entryDN string) (*directory.Entry, error) {
	e, err := p.src.Get(ctx, entryDN, []string{directory.AllAttrs})
	if err != nil || e == nil {
		return nil, err
	}
	allowed, err := p.writableOn(ctx, e.Values("objectClass"))
	if err != nil {
		return nil, err
	}
	prof := p.job.Profile
	never := profile.Set(append(append([]string{prof.Identity.Attr()}, prof.NeverClone...), prof.PasswordAttrs...))
	rdn, _, _ := dn.FirstRDN(entryDN)
	out := directory.Entry{DN: e.DN, Attrs: map[string][]string{}}
	for name, values := range e.Attrs {
		key := strings.ToLower(name)
		keep := key == "objectclass" || strings.EqualFold(name, rdn) ||
			(allowed[key] && !never[key] && !p.IsRef(name))
		if keep && len(values) > 0 {
			out.Attrs[name] = values
		}
	}
	m := p.job.Masker.Apply(out)
	return &m, nil
}

// writableOn is the set (lowercase) of the attributes a client can write on an entry of classes.
func (p *Plan) writableOn(ctx context.Context, classes []string) (map[string]bool, error) {
	if p.job.Profile.Writable == nil {
		return nil, fmt.Errorf("the %s profile cannot tell what a client may write on an entry", p.job.Profile.Name)
	}
	p.writableMu.Lock()
	defer p.writableMu.Unlock()
	if p.writable == nil {
		p.writable = map[string][]string{}
	}
	var missing []string
	for _, c := range classes {
		if _, ok := p.writable[strings.ToLower(c)]; !ok {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		got, ok, err := p.job.Profile.Writable.Writable(ctx, p.src, missing)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("the source schema cannot be read")
		}
		for _, c := range missing {
			p.writable[strings.ToLower(c)] = got[c]
		}
	}
	out := map[string]bool{}
	for _, c := range classes {
		for _, n := range p.writable[strings.ToLower(c)] {
			out[strings.ToLower(n)] = true
		}
	}
	return out, nil
}
