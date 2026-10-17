// Package app assembles a run from the configuration: connections, the server profile, the job and the mapping
// file. cmd only parses flags, supplies passwords and turns results into exit codes, so everything here can be
// tested end to end with in-memory directories.
package app

import (
	"context"
	"fmt"
	"io"

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
	// Src is the source, read sequentially on a single connection: parallel reads would only add load on the
	// source, and the paging cookie is tied to the connection anyway.
	Src  directory.Directory
	Warn io.Writer

	secrets Secrets
	dial    Dialer
	src     Conn
}

// Open connects to the source, resolves the profile (asking the source's root DSE for auto) and builds the job.
// The target is not touched: a dry-run and a native import never connect to it over LDAP.
func Open(ctx context.Context, cfg *config.Config, secrets Secrets, dial Dialer, warn io.Writer) (*Session, error) {
	pw, err := secrets.SourceBind()
	if err != nil {
		return nil, err
	}
	src, err := dial(ctx, cfg.Source, pw, 1)
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
	return &Session{Cfg: cfg, Job: job, Src: src.View(prof.Ranged), Warn: warn, secrets: secrets, dial: dial, src: src}, nil
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
