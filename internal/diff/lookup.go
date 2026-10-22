package diff

import (
	"context"
	"errors"
	"slices"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/plan"
)

// ChooseResolver decides how source objects are found on the target when their DN differs: by identifier
// (identity.ByIdentity) when the target carries the source identifiers (after a native import, or a clone that
// preserved entryUUID), otherwise through fallback (a marker or a mapping file; nil when off).
// reason says why identifiers could not be shown to be preserved.
//
// Comparing the domain identifiers was rejected: a lab created like the source and then cloned over LDAP has the
// same domain GUID but new object GUIDs, so everything would be REPLACED. The probe is the first object that diff
// itself compares, found with the job's own filters, so built-in and filtered-out objects never decide.
// base_dn itself is used only when nothing below it is selected: it may be a container that already existed in
// the lab (CN=Users) and so has the lab's own identifier.
func ChooseResolver(ctx context.Context, src, dst directory.Directory, job plan.Job, fallback identity.Resolver) (identity.Resolver, string, error) {
	scheme := job.Profile.Identity
	attrs := []string{scheme.Attr()}
	probe, err := firstSelected(ctx, src, job, attrs)
	if err != nil {
		return nil, "", err
	}
	if probe == nil {
		if probe, err = src.Get(ctx, job.BaseDNs[0], attrs); err != nil {
			return nil, "", err
		}
		if probe == nil {
			return fallback, "base_dn does not exist in the source", nil
		}
	}
	want, err := identity.Of(scheme, *probe)
	if err != nil || want.IsZero() {
		return fallback, "cannot read the source's " + scheme.Attr(), nil
	}
	got, err := dst.Get(ctx, probe.DN, attrs)
	if err != nil {
		return nil, "", err
	}
	if got == nil {
		return fallback, "target has no " + probe.DN, nil
	}
	if k, err := identity.Of(scheme, *got); err != nil || k != want {
		return fallback, probe.DN + " has a different " + scheme.Attr() + " in the source and the target", nil
	}
	return identity.ByIdentity(scheme), "", nil
}

func firstSelected(ctx context.Context, src directory.Directory, job plan.Job, attrs []string) (*directory.Entry, error) {
	stop := errors.New("found")
	for _, k := range job.Kinds {
		var found *directory.Entry
		err := plan.WalkBases(ctx, src, job.BaseDNs, k.Filter, attrs, func(e directory.Entry) error {
			if slices.ContainsFunc(job.BaseDNs, func(b string) bool { return dn.Equal(e.DN, b) }) {
				return nil
			}
			c := e
			found = &c
			return stop
		})
		if err != nil && !errors.Is(err, stop) {
			return nil, err
		}
		if found != nil {
			return found, nil
		}
	}
	return nil, nil
}
