package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
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

// LabUp makes the lab [target.lab] names (the defaults without it) like the source: it creates it when it does not
// exist, with the same domain name, and on AD the same NetBIOS name, domain SID and GUID (which a native import
// needs and which only the creation of a domain can choose), the port of [target] url and the target password as
// its Administrator's; it starts it when it is stopped; and it gives its schema the source's definitions it lacks (a
// lab's schema goes with the lab, unlike an AD's). It is lab up --config: run again, it brings the schema up to date.
// o carries lab up's own options (the image, --reload, --skip-verify); its image, when set, takes the place of
// [target.lab] image. The domain, the ports and the password come from the config, never from o.
func (s *Session) LabUp(ctx context.Context, l *lab.Lab, o lab.UpOptions, log io.Writer) error {
	lt := s.Cfg.Target.Lab
	if lt == nil {
		lt = &config.Lab{}
	}
	if o.Image == "" {
		o.Image = lt.Image
	}
	state, err := s.labState(ctx, l)
	if err != nil {
		return err
	}
	if state == lab.Missing && !l.IsMain() {
		return fmt.Errorf("lab %s does not exist; lab up creates the default lab only (leave out [target.lab] instance), another instance comes from a snapshot (lab restore --instance)", l.Name())
	}
	if state != lab.Running {
		// The settings of a lab like the source, also to start a stopped one: Up then checks the existing container
		// against them (another domain, other ports are refused), and asks for nothing, whatever .env the current
		// directory holds.
		settings, err := s.LikeSource(ctx)
		if err != nil {
			return err
		}
		if settings.AdminPassword, err = s.secrets.TargetBind(); err != nil {
			return err
		}
		if err := portsFromURL(&settings, s.Cfg.Target.URL); err != nil {
			return err
		}
		o.Flags, o.Brief = settings, true
		if err := l.Up(ctx, o); err != nil {
			return err
		}
	}
	if err := l.CheckTargetURL(ctx, s.Cfg.Target.URL); err != nil {
		return err
	}
	return s.labSchema(ctx, log)
}

// CloneLab clones into the lab [target.lab] names, which lab up --config made: over LDAP, or with native = true
// into its database directly. A lab that does not exist or is stopped is refused, untouched.
func (s *Session) CloneLab(ctx context.Context, l *lab.Lab, out, log io.Writer) (*clone.Report, error) {
	state, err := s.labState(ctx, l)
	if err != nil {
		return nil, err
	}
	if why := labNotReady(state, l, s.ConfigPath); why != "" {
		return nil, errors.New(why)
	}
	if err := l.CheckTargetURL(ctx, s.Cfg.Target.URL); err != nil {
		return nil, err
	}
	if lt := s.Cfg.Target.Lab; lt.Native {
		return s.Native(ctx, l, lab.NativeOptions{FastPassword: lt.FastPassword, ServerAttributes: lt.ServerAttributes != config.ServerAttributesLab,
			ACL: lt.ACL == config.ServerAttributesSource}, out)
	}
	return s.Clone(ctx, false, out, log)
}

// labNotReady says why a lab in state cannot be written yet, and the command that makes it ready; "" when it can.
func labNotReady(state string, l *lab.Lab, cfgPath string) string {
	switch state {
	case lab.Missing:
		return fmt.Sprintf("the lab %s does not exist yet: ldap-cronin lab up --config %s creates it like the source", l.Name(), cfgPath)
	case lab.Stopped:
		return fmt.Sprintf("the lab %s is stopped: ldap-cronin lab up --config %s starts it", l.Name(), cfgPath)
	}
	return ""
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

// EC2Lab is the EC2 lab [target.lab] platform = "ec2" describes, like the source: its domain name and NetBIOS name
// are the source's (Windows lets no one choose a domain SID), its LDAPS forwarded to the port of [target] url.
func (s *Session) EC2Lab(ctx context.Context) (lab.EC2Lab, error) {
	lt := s.Cfg.Target.Lab
	if !lt.OnEC2() {
		return lab.EC2Lab{}, errors.New("[target.lab] platform is not \"ec2\"")
	}
	if s.Job.Profile.Native == nil {
		return lab.EC2Lab{}, fmt.Errorf("an EC2 lab is a Windows Server domain controller, for an AD source; this source is %q", s.Job.Profile.Name)
	}
	settings, err := s.LikeSource(ctx)
	if err != nil {
		return lab.EC2Lab{}, err
	}
	netbios, err := settings.EffectiveNetBIOS()
	if err != nil {
		return lab.EC2Lab{}, err
	}
	var port lab.Settings
	if err := portsFromURL(&port, s.Cfg.Target.URL); err != nil {
		return lab.EC2Lab{}, err
	}
	prefix := lt.Prefix
	if prefix == "" {
		prefix = lab.DefaultPrefix
	}
	name := prefix + "-" + lab.ProfileAD
	if lt.Instance != "" && lt.Instance != lab.MainInstance {
		name += "-" + lt.Instance
	}
	e := lab.EC2Lab{
		Name: name, Domain: settings.Domain, NetBIOS: netbios,
		Region: lt.Region, Subnet: lt.Subnet, InstanceType: lt.InstanceType, Windows: lt.Windows, InstanceProfile: lt.InstanceProfile,
		PasswordParameter: lt.PasswordParameter, LocalPort: port.LDAPSPort, LDAPSName: lt.LDAPSName,
	}
	if e.PasswordParameter == "" {
		e.PasswordParameter = "/ldap-cronin/" + name + "/admin-password"
	}
	if mode, attr, err := s.Cfg.MappingFor(s.Job.Profile); err != nil {
		return lab.EC2Lab{}, err
	} else if mode == config.MappingMarker {
		e.MarkerAttribute = attr
	}
	return e, e.Check()
}
