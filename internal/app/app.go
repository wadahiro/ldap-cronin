// Package app assembles a run from the configuration: connections, the server profile, the job and the mapping
// file. cmd only parses flags, supplies passwords and turns results into exit codes, so everything here can be
// tested end to end with in-memory directories.
package app

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
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

// Session is a run against one source.
type Session struct {
	Cfg *config.Config
	Job plan.Job
	// Src is the source, on sourceConns connections (see there).
	Src  directory.Directory
	Warn io.Writer

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
	pw, err := secrets.SourceBind()
	if err != nil {
		return nil, err
	}
	src, err := dial(ctx, cfg.Source, pw, sourceConns)
	if err != nil {
		return nil, err
	}
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

// targetHas narrows the attributes of every kind to those the target's schema defines, for mode = "all": the
// source's schema may have more (an extension, a newer Windows Server), and they are left out instead of stopping
// the run, as no one named them. It returns the job to run and the names left out.
func (s *Session) targetHas(ctx context.Context, dst directory.Directory) (plan.Job, []string, error) {
	job := s.Job
	if !s.Cfg.Attributes.All() || job.Profile.SchemaAttrs == nil {
		return job, nil, nil
	}
	has, ok, err := job.Profile.SchemaAttrs.Attributes(ctx, dst)
	if err != nil || !ok {
		return job, nil, err
	}
	job.Kinds = append([]plan.Kind(nil), job.Kinds...)
	required := profile.Set(job.Profile.Required)
	left := map[string]bool{}
	var leftOut []string
	for i := range job.Kinds {
		var keep []string
		for _, a := range job.Kinds[i].Attrs {
			key := strings.ToLower(a)
			if has[key] || required[key] {
				keep = append(keep, a)
				continue
			}
			if !left[key] {
				left[key] = true
				leftOut = append(leftOut, a)
			}
		}
		job.Kinds[i].Attrs = keep
	}
	sort.Slice(leftOut, func(i, j int) bool { return strings.ToLower(leftOut[i]) < strings.ToLower(leftOut[j]) })
	return job, leftOut, nil
}

// noteLeftOut lists, one per line, the attributes mode = "all" leaves out because the target's schema lacks them.
func noteLeftOut(w io.Writer, names []string) {
	if len(names) == 0 {
		return
	}
	fmt.Fprintf(w, "not copied or compared: the target schema lacks %d attributes of the source's (ldap-cronin schema adds those of extensions):\n", len(names))
	for _, n := range names {
		fmt.Fprintf(w, "  %s\n", n)
	}
}

func (s *Session) Close() { s.src.Close() }

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
