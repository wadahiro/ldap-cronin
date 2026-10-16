package main

import (
	"fmt"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// resolveOptions decides the server type (asking the source's root DSE when the config says auto), tunes the
// source connection to it and builds the plan options.
func resolveOptions(cfg *config.Config, src *ldapdir.Client) (plan.Options, error) {
	prof, err := profile.Resolve(cfg.Clone.Profile, src)
	if err != nil {
		return plan.Options{}, err
	}
	src.SetRangedAttrs(prof.RangedAttrs)
	return cfg.PlanOptionsFor(prof)
}

// prepareTarget tunes the target connection to the profile. With profile = auto it also refuses a target of another
// type: an AD source cloned into a plain LDAP server (or the reverse) would silently drop or mis-map attributes.
func prepareTarget(cfg *config.Config, opt plan.Options, dst *ldapdir.Client) error {
	dst.SetRangedAttrs(opt.P().RangedAttrs)
	if cfg.ProfileName() != profile.NameAuto {
		return nil
	}
	got, err := profile.Detect(dst)
	if err != nil {
		return err
	}
	if got.Name != opt.P().Name {
		return fmt.Errorf("the source looks like %q but the target looks like %q; cloning between different server types is not supported (set [clone] profile to override the detection)", opt.P().Name, got.Name)
	}
	return nil
}

// rootAndID returns the naming context root of base_dn and the identifier attribute, for the GUID mapping header.
func rootAndID(opt plan.Options, src directory.Directory) (root, idAttr string, err error) {
	root, err = plan.DetectRoot(src, opt)
	return root, opt.IDAttr(), err
}
