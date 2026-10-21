package app

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/lab"
)

// labProfile is the kind of lab for this source: Samba for AD, OpenLDAP otherwise (as LikeSource decides).
func (s *Session) labProfile() string {
	if s.Job.Profile.Native != nil {
		return lab.ProfileAD
	}
	return lab.ProfileLDAP
}

// labState chooses the lab's kind and says whether it exists and runs.
func (s *Session) labState(ctx context.Context, l *lab.Lab) (string, error) {
	if err := l.ChooseServer(ctx, s.labProfile()); err != nil {
		return "", err
	}
	return l.State(ctx)
}

// CloneLab clones into the lab [target.lab] names. It creates the lab like the source when it does not exist (the
// same domain name, and on AD the same NetBIOS name, domain SID and GUID, which a native import needs and which can
// only be chosen when the domain is created), starts it when it is stopped, gives it the source's schema
// definitions it lacks (a lab's schema can be reset, unlike an AD's), and then clones over LDAP, or with
// native = true writes its database directly. It asks once, before any of it.
func (s *Session) CloneLab(ctx context.Context, l *lab.Lab, out, log io.Writer) (*clone.Report, error) {
	lt := s.Cfg.Target.Lab
	state, err := s.labState(ctx, l)
	if err != nil {
		return nil, err
	}
	var steps []string
	var up *lab.UpOptions
	switch state {
	case lab.Missing:
		if !l.IsMain() {
			return nil, fmt.Errorf("lab %s does not exist; clone creates the default lab only (leave out [target.lab] instance), another instance comes from a snapshot (lab restore --instance)", l.Name())
		}
		settings, err := s.LikeSource(ctx)
		if err != nil {
			return nil, err
		}
		if settings.AdminPassword, err = s.secrets.TargetBind(); err != nil {
			return nil, err
		}
		if err := portsFromURL(&settings, s.Cfg.Target.URL); err != nil {
			return nil, err
		}
		up = &lab.UpOptions{Flags: settings, Image: lt.Image, Brief: true}
		identity := ""
		if settings.DomainSID != "" {
			identity = fmt.Sprintf(" (NetBIOS %s), domain SID %s, GUID %s", settings.NetBIOS, settings.DomainSID, settings.DomainGUID)
		}
		steps = append(steps, fmt.Sprintf("create it like the source: domain %s%s", settings.Domain, identity))
	case lab.Stopped:
		up = &lab.UpOptions{Image: lt.Image, Brief: true}
		steps = append(steps, "start it")
	}
	if s.Job.Profile.SchemaCopy != nil {
		steps = append(steps, "give its schema the source's definitions it lacks")
	}
	if lt.Native {
		how := "stop it, and add and update the entries under " + s.Job.BaseDN + " in its database directly, keeping objectGUID and objectSid"
		if lt.FastPassword {
			how += " (fast_password: no Kerberos AES keys)"
		}
		steps = append(steps, how)
	} else {
		steps = append(steps, "add and update the entries under "+s.Job.BaseDN+" over LDAP")
	}
	if s.Confirm != nil {
		if err := s.ask(ctx, "clone writes the lab "+l.Name()+":", "the lab "+l.Name()+" ("+s.Cfg.Target.URL+")", steps...); err != nil {
			return nil, err
		}
		// Asked once for all of it: the steps below do not ask again.
		confirm := s.Confirm
		s.Confirm = nil
		defer func() { s.Confirm = confirm }()
	}
	if up != nil {
		if err := l.Up(ctx, *up); err != nil {
			return nil, err
		}
	}
	if err := l.CheckTargetURL(ctx, s.Cfg.Target.URL); err != nil {
		return nil, err
	}
	if err := s.labSchema(ctx, log); err != nil {
		return nil, err
	}
	if lt.Native {
		return s.Native(ctx, l, lab.NativeOptions{FastPassword: lt.FastPassword}, out)
	}
	return s.Clone(ctx, false, out, log)
}

// labSchema writes to the lab's schema the source's definitions it lacks.
func (s *Session) labSchema(ctx context.Context, log io.Writer) error {
	copier := s.Job.Profile.SchemaCopy
	if copier == nil {
		return nil
	}
	dst, closeTarget, err := s.Target(ctx)
	if err != nil {
		return err
	}
	defer closeTarget()
	changes, ok, err := copier.PlanSchema(ctx, s.Src, dst)
	if err != nil || !ok || changes.Empty() {
		return err
	}
	fmt.Fprintln(log, "the lab's schema lacks definitions of the source's; adding them:")
	changes.WriteSummary(indent{log})
	return changes.Apply(ctx, dst, log)
}

// portsFromURL makes the lab listen where [target] url says: the url is what check, diff and schema read.
func portsFromURL(settings *lab.Settings, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Port() == "" {
		return nil
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return fmt.Errorf("[target] url %s: %w", raw, err)
	}
	if u.Scheme == "ldap" {
		settings.LDAPPort = port
	} else {
		settings.LDAPSPort = port
	}
	return nil
}

// indent writes each line two spaces in.
type indent struct{ w io.Writer }

func (i indent) Write(p []byte) (int, error) {
	text := strings.TrimSuffix(string(p), "\n")
	_, err := io.WriteString(i.w, "  "+strings.ReplaceAll(text, "\n", "\n  ")+"\n")
	return len(p), err
}
