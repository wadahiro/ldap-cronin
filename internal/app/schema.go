package app

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Schema compares the source's schema with the target's and prints what the target lacks as LDIF on out, with a
// summary on log; with apply it writes the changes to the target instead. It reads both schemas only: the entries
// under base_dn are not touched, and clone never calls it, as a schema change cannot be undone in AD.
func (s *Session) Schema(ctx context.Context, apply bool, out, log io.Writer) error {
	copier := s.Job.Profile.SchemaCopy
	if copier == nil {
		return fmt.Errorf("the %s profile has no schema definitions to carry; schema is for AD (Samba AD)", s.Job.Profile.Name)
	}
	dst, closeTarget, err := s.Target(ctx)
	if err != nil {
		return err
	}
	defer closeTarget()
	plan, ok, err := copier.PlanSchema(ctx, s.Src, dst)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the schema naming context of the source or the target cannot be read")
	}
	plan.WriteSummary(log)
	if plan.Empty() {
		return nil
	}
	if !apply {
		return plan.WriteLDIF(out)
	}
	if err := s.confirmWrite(ctx, dst, "schema -apply writes the changes above to the target's schema (AD cannot undo them)"); err != nil {
		return err
	}
	if err := plan.Apply(ctx, dst, log); err != nil {
		return err
	}
	fmt.Fprintln(log, "done: the target schema has them; on a lab, the snapshots taken from now on carry them")
	return nil
}
