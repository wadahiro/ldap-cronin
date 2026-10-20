// Package app assembles a run from the configuration: connections, the server profile, the job and the mapping
// file. cmd only parses flags, supplies passwords and turns results into exit codes, so everything here can be
// tested end to end with in-memory directories.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dn"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/ldifdir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/progress"
)

// Secrets supplies passwords when they are needed, so a dry-run never asks for the target's.
type Secrets struct {
	SourceBind, TargetBind, UserPassword func() (string, error)
}

// Conn is an open directory connection.
type Conn interface {
	directory.Directory
	// View returns the same connections tuned to a profile (the attributes fetched with the AD range option).
	// Tuning a view instead of the connection itself means a connection already shared is never reconfigured.
	View(ranged []string) directory.Directory
	Close()
}

// Dialer opens conns connections to an endpoint.
type Dialer func(ctx context.Context, ep config.Endpoint, password string, conns int) (Conn, error)

// LDAP dials real servers.
func LDAP(_ context.Context, ep config.Endpoint, password string, conns int) (Conn, error) {
	c, err := ldapdir.Dial(ldapdir.ConnConfig{
		URL: ep.URL, BindDN: ep.BindDN, Password: password,
		CAFile: ep.CAFile, InsecureSkipVerify: ep.InsecureSkipVerify, StartTLS: ep.StartTLS, Timeout: ep.Timeout(),
	}, conns)
	if err != nil {
		return nil, err
	}
	return ldapConn{c}, nil
}

type ldapConn struct{ *ldapdir.Client }

func (c ldapConn) View(ranged []string) directory.Directory { return c.Client.With(ranged) }

// readOnlyConn is how the source is opened: its writes, and those of its views, are refused before anything is sent.
type readOnlyConn struct {
	directory.ReadOnly
	conn Conn
}

func (c readOnlyConn) View(ranged []string) directory.Directory {
	return directory.ReadOnly{Directory: c.conn.View(ranged)}
}

func (c readOnlyConn) Close() { c.conn.Close() }

// Session is a run against one source.
type Session struct {
	Cfg *config.Config
	Job plan.Job
	// Src is the source, on sourceConns connections (see there).
	Src  directory.Directory
	Warn io.Writer
	// Confirm, when set, is asked before the first write to the target (clone, schema -apply), after the target and
	// the source are shown on Warn; false stops the run with nothing written. Nil writes without asking.
	Confirm func(question string) bool
	// WithPassword makes a dry-run's LDIF carry the users' fixed password (Secrets.UserPassword) and the writes that
	// follow it, instead of comments.
	WithPassword bool
	// Progress, when set, is told how far clone and diff are.
	Progress *progress.Bar

	secrets Secrets
	dial    Dialer
	src     Conn
}

// sourceConns is how many connections the source gets: one for the paged search clone or diff walks (it holds its
// connection until the last page, as the paging cookie is tied to it), and one for what the workers read meanwhile
// (what a member outside the scope is, the entry of a referenced object). With one, those reads waited for the walk
// and the walk for the workers, and the run stopped for ever once more groups than the workers' queue were left.
// More would only add load: the source is otherwise read sequentially.
const sourceConns = 2

// Open connects to the source, resolves the profile (asking the source's root DSE for auto) and builds the job.
// The target is not touched: a dry-run and a native import never connect to it over LDAP.
func Open(ctx context.Context, cfg *config.Config, secrets Secrets, dial Dialer, warn io.Writer) (*Session, error) {
	conn, err := openSource(ctx, cfg, secrets, dial, warn)
	if err != nil {
		return nil, err
	}
	// The source is only ever read: whatever a command does, a write to it fails here instead of reaching the server.
	var src Conn = readOnlyConn{ReadOnly: directory.ReadOnly{Directory: conn}, conn: conn}
	prof, err := profile.Resolve(ctx, cfg.Scope.Profile, src)
	if err != nil {
		src.Close()
		return nil, err
	}
	job, err := cfg.JobFor(prof)
	if err != nil {
		src.Close()
		return nil, err
	}
	s := &Session{Cfg: cfg, Job: job, Src: src.View(prof.Ranged), Warn: warn, secrets: secrets, dial: dial, src: src}
	if cfg.Attributes.All() {
		if err := s.writableAttrs(ctx); err != nil {
			src.Close()
			return nil, err
		}
	}
	return s, nil
}

// openSource connects to the source server, or reads the dump [source] ldif names: no password is asked then,
// and the dump's server and time are said on warn, as what diff compares with is that moment of production.
func openSource(ctx context.Context, cfg *config.Config, secrets Secrets, dial Dialer, warn io.Writer) (Conn, error) {
	if cfg.Source.LDIF == "" {
		pw, err := secrets.SourceBind()
		if err != nil {
			return nil, err
		}
		return dial(ctx, cfg.Source, pw, sourceConns)
	}
	d, err := ldifdir.Open(cfg.Source.LDIF)
	if err != nil {
		return nil, err
	}
	m := d.Meta()
	if m.BaseDN != "" && !dn.Equal(cfg.Scope.BaseDN, m.BaseDN) && !dn.IsDescendant(cfg.Scope.BaseDN, m.BaseDN) {
		return nil, fmt.Errorf("[scope] base_dn %s is not in the dump, which holds %s", cfg.Scope.BaseDN, m.BaseDN)
	}
	fmt.Fprintf(warn, "source: the dump %s of %s, taken %s (%d entries)\n", cfg.Source.LDIF, m.Server, m.DumpedAt, m.Entries)
	if len(m.Masked) > 0 {
		fmt.Fprintf(warn, "  masked in the dump: %s\n", strings.Join(m.Masked, ", "))
	}
	return d, nil
}

// writableAttrs gives each kind every attribute the source's schema lets a client write on its class
// ([attributes] mode = "all"), but what clone never copies, the marker and exclude.
func (s *Session) writableAttrs(ctx context.Context) error {
	prof := s.Job.Profile
	if prof.Writable == nil {
		return fmt.Errorf("[attributes] mode = %q needs the schema to say what a client can write; the %s profile cannot, so list the attributes (mode = %q)", config.AttributesAll, prof.Name, config.AttributesListed)
	}
	var classes []string
	for _, k := range s.Job.Kinds {
		classes = append(classes, k.Class)
	}
	byClass, ok, err := prof.Writable.Writable(ctx, s.Src, classes)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("[attributes] mode = %q: the source schema cannot be read", config.AttributesAll)
	}
	_, marker, err := s.Cfg.MappingFor(prof)
	if err != nil {
		return err
	}
	never := profile.Set(append(append([]string{prof.Identity.Attr(), marker}, prof.NeverClone...), prof.PasswordAttrs...))
	s.Job.AllWritable = true
	for i := range s.Job.Kinds {
		k := &s.Job.Kinds[i]
		var names []string
		for _, n := range byClass[k.Class] {
			if !never[strings.ToLower(n)] {
				names = append(names, n)
			}
		}
		if k.Attrs, err = prof.Attrs(k.Name, profile.Override{Include: map[string][]string{k.Name: names}, Exclude: s.Cfg.Attributes.Exclude}); err != nil {
			return fmt.Errorf("[attributes] %s: %w", k.Name, err)
		}
	}
	return nil
}

// leftOut is what targetHas takes out of the job for a target.
type leftOut struct {
	// missing are the attributes the target's schema lacks (mode = "all").
	missing []string
	// refused are the attributes the target will not have written over LDAP, as "name: why".
	refused []string
}

// targetHas narrows the attributes of every kind to those the target can be given. In mode = "all" that is those
// the target's schema defines: the source's schema may have more (an extension, a newer Windows Server), and they
// are left out instead of stopping the run, as no one named them. In any mode it is without those the target refuses
// over LDAP (Samba: userParameters), which would otherwise stop the run at the first entry holding one, after
// everything before it was written. Required attributes are always kept. It returns the job to run and what it left out.
func (s *Session) targetHas(ctx context.Context, dst directory.Directory) (plan.Job, leftOut, error) {
	job := s.Job
	var has map[string]bool
	if s.Cfg.Attributes.All() && job.Profile.SchemaAttrs != nil {
		got, ok, err := job.Profile.SchemaAttrs.Attributes(ctx, dst)
		if err != nil {
			return job, leftOut{}, err
		}
		if ok {
			has = got
		}
	}
	refused := map[string]string{}
	if job.Profile.Refusals != nil {
		got, err := job.Profile.Refusals.Refused(ctx, dst)
		if err != nil {
			return job, leftOut{}, err
		}
		for name, why := range got {
			refused[strings.ToLower(name)] = why
		}
	}
	var out leftOut
	if has == nil && len(refused) == 0 {
		return job, out, nil
	}
	job.Kinds = append([]plan.Kind(nil), job.Kinds...)
	required := profile.Set(job.Profile.Required)
	noted := map[string]bool{}
	for i := range job.Kinds {
		var keep []string
		for _, a := range job.Kinds[i].Attrs {
			key := strings.ToLower(a)
			why, isRefused := refused[key]
			missing := has != nil && !has[key]
			if required[key] || (!isRefused && !missing) {
				keep = append(keep, a)
				continue
			}
			if noted[key] {
				continue
			}
			noted[key] = true
			if isRefused {
				out.refused = append(out.refused, a+": "+why)
			} else {
				out.missing = append(out.missing, a)
			}
		}
		job.Kinds[i].Attrs = keep
	}
	for _, l := range [][]string{out.missing, out.refused} {
		sort.Slice(l, func(i, j int) bool { return strings.ToLower(l[i]) < strings.ToLower(l[j]) })
	}
	return job, out, nil
}

// noteLeftOut lists, one per line, the attributes targetHas left out and why.
func noteLeftOut(w io.Writer, l leftOut) {
	if len(l.missing) > 0 {
		fmt.Fprintf(w, "not copied or compared: the target schema lacks %d attributes of the source's (ldap-cronin schema adds those of extensions):\n", len(l.missing))
		for _, n := range l.missing {
			fmt.Fprintf(w, "  %s\n", n)
		}
	}
	if len(l.refused) > 0 {
		fmt.Fprintf(w, "not copied or compared: the target refuses %d attributes over LDAP:\n", len(l.refused))
		for _, n := range l.refused {
			fmt.Fprintf(w, "  %s\n", n)
		}
	}
}

func (s *Session) Close() { s.src.Close() }

// confirmWrite shows which server is about to be written to, and which is only read, and asks s.Confirm. A server
// name comes from its root DSE (dnsHostName, AD), so a URL that names the server another way still shows which it is.
func (s *Session) confirmWrite(ctx context.Context, dst directory.Directory, what string) error {
	if s.Confirm == nil {
		return nil
	}
	fmt.Fprintf(s.Warn, "%s\n", what)
	fmt.Fprintf(s.Warn, "  target (written): %s%s\n", s.Cfg.Target.URL, serverName(ctx, dst))
	fmt.Fprintf(s.Warn, "    bind_dn: %s\n", s.Cfg.Target.BindDN)
	fmt.Fprintf(s.Warn, "    base_dn: %s\n", s.Job.BaseDN)
	source := s.Cfg.Source.URL
	if s.Cfg.Source.LDIF != "" {
		source = "the dump " + s.Cfg.Source.LDIF
	}
	fmt.Fprintf(s.Warn, "  source (read only): %s%s\n", source, serverName(ctx, s.Src))
	if !s.Confirm("Write to this target? [y/N]: ") {
		return errors.New("aborted: nothing was written (pass -y to skip the confirmation)")
	}
	return nil
}

// serverName is " (server <dnsHostName>)" from the root DSE, or "" when the server does not publish one.
func serverName(ctx context.Context, d directory.Directory) string {
	root, err := d.Get(ctx, "", []string{"dnsHostName"})
	if err != nil || root == nil || len(root.Values("dnsHostName")) == 0 {
		return ""
	}
	return " (server " + root.Values("dnsHostName")[0] + ")"
}

// Target connects to the target with [run] workers connections. With profile = auto it also refuses a target of
// another type: an AD source cloned into a plain LDAP server (or the reverse) would silently drop or mis-map attributes.
func (s *Session) Target(ctx context.Context) (directory.Directory, func(), error) {
	pw, err := s.secrets.TargetBind()
	if err != nil {
		return nil, nil, err
	}
	dst, err := s.dial(ctx, s.Cfg.Target, pw, s.Cfg.Run.Workers)
	if err != nil {
		return nil, nil, err
	}
	if s.Cfg.ProfileName() == profile.NameAuto {
		got, err := profile.Detect(ctx, dst)
		if err != nil {
			dst.Close()
			return nil, nil, err
		}
		if got.Name != s.Job.Profile.Name {
			dst.Close()
			return nil, nil, fmt.Errorf("the source looks like %q but the target looks like %q; cloning between different server types is not supported (set [scope] profile to override the detection)", s.Job.Profile.Name, got.Name)
		}
	}
	return dst.View(s.Job.Profile.Ranged), dst.Close, nil
}
