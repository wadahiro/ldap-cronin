// Package ldapdir implements directory.Directory on top of go-ldap.
// Parsing the LDIF output of an external ldapsearch command was rejected because handling
// newlines, base64 and line folding is too cumbersome.
package ldapdir

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// AD limits MaxPageSize to 1000.
const pageSize = 1000

type ConnConfig struct {
	URL                string
	BindDN             string
	Password           string
	CAFile             string
	InsecureSkipVerify bool
	StartTLS           bool
	// Timeout bounds every request on a connection, so a hung server fails the run instead of blocking it forever.
	// A context cannot do this: go-ldap's Add and Modify take none. 0 means no limit.
	Timeout time.Duration
	// RangeSize is the number of values fetched per request when retrieving member in ranges (member;range=0-N). 0 means the default.
	RangeSize int
}

// Client pools workers connections and borrows one per operation, which makes parallel execution possible.
// Its settings never change after Dial: views made by With share the pool but not the settings, so a client that is
// already in use by several goroutines is never reconfigured under them.
type Client struct {
	pool      chan *ldap.Conn
	rangeSize int
	ranged    map[string]bool
}

// With returns a view of the same connections that retrieves the given attributes with the AD range option
// (member;range=0-N). A plain client requests no ranges, which is right for servers without the option (OpenLDAP
// and most others): there, a ranged request returns the attribute empty. Close either one to close the pool.
func (c *Client) With(ranged []string) *Client {
	v := *c
	v.ranged = map[string]bool{}
	for _, n := range ranged {
		v.ranged[strings.ToLower(n)] = true
	}
	return &v
}

func Dial(c ConnConfig, workers int) (*Client, error) {
	workers = max(workers, 1)
	client := &Client{pool: make(chan *ldap.Conn, workers), rangeSize: c.RangeSize}
	if client.rangeSize <= 0 {
		client.rangeSize = DefaultRangeSize
	}
	for i := 0; i < workers; i++ {
		conn, err := dialOne(c)
		if err != nil {
			client.Close()
			return nil, err
		}
		client.pool <- conn
	}
	return client, nil
}

// acquire borrows a connection, or gives up when ctx ends first (all connections busy and the run is stopping).
func (c *Client) acquire(ctx context.Context) (*ldap.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case conn := <-c.pool:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) release(l *ldap.Conn) { c.pool <- l }

func dialOne(c ConnConfig) (*ldap.Conn, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify} //nolint:gosec // enabled only when explicitly set in the config, for self-signed lab environments
	// Unlike ldaps://, StartTLS does not set ServerName from the target host name automatically.
	if u, err := url.Parse(c.URL); err == nil {
		tlsCfg.ServerName = u.Hostname()
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s contains no certificates", c.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	conn, err := ldap.DialURL(c.URL, ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", c.URL, err)
	}
	if c.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls %s: %w", c.URL, err)
		}
	}
	if c.Timeout > 0 {
		conn.SetTimeout(c.Timeout)
	}
	if err := conn.Bind(c.BindDN, c.Password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind %s as %s: %w", c.URL, c.BindDN, err)
	}
	return conn, nil
}

func (c *Client) Close() {
	for {
		select {
		case conn := <-c.pool:
			conn.Close()
		default:
			return
		}
	}
}

// Walk processes a paged search one page at a time and never accumulates all entries in memory.
// The paging cookie is tied to the connection, so the same connection is used throughout the scan.
func (c *Client) Walk(ctx context.Context, base, filter string, attrs []string, fn func(directory.Entry) error) error {
	conn, err := c.acquire(ctx)
	if err != nil {
		return err
	}
	defer c.release(conn)
	paging := ldap.NewControlPaging(pageSize)
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, rangedRequestFor(c.ranged, attrs, c.rangeSize), append([]ldap.Control{paging}, readControls(attrs)...))
	for {
		// Checked per page: moving to SearchAsync for finer cancellation would mean rewriting the paging and range loop for no visible gain.
		if err := ctx.Err(); err != nil {
			return err
		}
		res, err := conn.Search(req)
		if err != nil {
			// A target whose search base does not exist yet (e.g. diff run before clone) is treated as having zero entries.
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				return nil
			}
			return err
		}
		for _, e := range res.Entries {
			entry, err := convert(conn, e, attrs, c.rangeSize)
			if err != nil {
				return err
			}
			if err := fn(entry); err != nil {
				return err
			}
		}
		next, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok || len(next.Cookie) == 0 {
			return nil
		}
		paging.SetCookie(next.Cookie)
	}
}

// sdFlagsOwnerGroupDACL asks AD for the owner, the group and the DACL of nTSecurityDescriptor: without the control it
// returns the SACL too, which needs a privilege a reading account may lack, and the SACL is not what the clone copies.
const sdFlagsOwnerGroupDACL = 0x1 | 0x2 | 0x4

// readControls are the controls a search for attrs needs: the SD flags when nTSecurityDescriptor is asked for (not
// critical, so a server without it answers as it would). A write of it takes the same: the owner, the group and the
// DACL are written, and the SACL, which needs a privilege and clone never reads, is left as it is.
func readControls(attrs []string) []ldap.Control {
	for _, a := range attrs {
		if strings.EqualFold(a, "nTSecurityDescriptor") {
			return []ldap.Control{&ldap.ControlMicrosoftSDFlags{ControlValue: sdFlagsOwnerGroupDACL}}
		}
	}
	return nil
}

func (c *Client) Get(ctx context.Context, dn string, attrs []string) (*directory.Entry, error) {
	conn, err := c.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer c.release(conn)
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", rangedRequestFor(c.ranged, attrs, c.rangeSize), readControls(attrs))
	res, err := conn.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, nil
		}
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, nil
	}
	entry, err := convert(conn, res.Entries[0], attrs, c.rangeSize)
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func (c *Client) Add(ctx context.Context, e directory.Entry, controls ...directory.Control) error {
	conn, err := c.acquire(ctx)
	if err != nil {
		return err
	}
	defer c.release(conn)
	var ctrls []ldap.Control
	for _, ct := range controls {
		ctrls = append(ctrls, ldap.NewControlString(ct.OID, ct.Critical, ""))
	}
	req := ldap.NewAddRequest(e.DN, ctrls)
	for _, name := range sortedKeys(e.Attrs) {
		req.Attribute(name, e.Attrs[name])
	}
	if err := conn.Add(req); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return directory.ErrExists
		}
		for code, sentinel := range map[uint16]error{
			ldap.LDAPResultObjectClassViolation:         directory.ErrSchemaViolation,
			ldap.LDAPResultInsufficientAccessRights:     directory.ErrInsufficientAccess,
			ldap.LDAPResultUnavailableCriticalExtension: directory.ErrControlUnsupported,
		} {
			if ldap.IsErrorWithCode(err, code) {
				return fmt.Errorf("add %s: %w (%v)", e.DN, sentinel, err)
			}
		}
		return fmt.Errorf("add %s: %w", e.DN, err)
	}
	return nil
}

func (c *Client) Replace(ctx context.Context, dn string, attrs map[string][]string) error {
	conn, err := c.acquire(ctx)
	if err != nil {
		return err
	}
	defer c.release(conn)
	req := ldap.NewModifyRequest(dn, readControls(sortedKeys(attrs)))
	for _, name := range sortedKeys(attrs) {
		req.Replace(name, attrs[name])
	}
	if err := conn.Modify(req); err != nil {
		return fmt.Errorf("modify %s (%s): %w", dn, strings.Join(sortedKeys(attrs), ","), err)
	}
	return nil
}

func (c *Client) AddValues(ctx context.Context, dn, attr string, values []string) error {
	conn, err := c.acquire(ctx)
	if err != nil {
		return err
	}
	defer c.release(conn)
	req := ldap.NewModifyRequest(dn, nil)
	req.Add(attr, values)
	if err := conn.Modify(req); err != nil {
		return fmt.Errorf("modify %s (add %s): %w", dn, attr, err)
	}
	return nil
}

func (c *Client) DeleteValues(ctx context.Context, dn, attr string, values []string) error {
	conn, err := c.acquire(ctx)
	if err != nil {
		return err
	}
	defer c.release(conn)
	req := ldap.NewModifyRequest(dn, nil)
	req.Delete(attr, values)
	if err := conn.Modify(req); err != nil {
		return fmt.Errorf("modify %s (delete %s): %w", dn, attr, err)
	}
	return nil
}

// convert aligns attribute names with the requested spelling and, for attributes retrieved in ranges, fetches the remainder and merges it.
func convert(conn *ldap.Conn, e *ldap.Entry, requested []string, rangeSize int) (directory.Entry, error) {
	canon := make(map[string]string, len(requested))
	for _, r := range requested {
		canon[strings.ToLower(r)] = r
	}
	out := directory.Entry{DN: e.DN, Attrs: map[string][]string{}}
	pending := map[string]int{}
	for _, a := range e.Attributes {
		name, info := a.Name, RangeInfo{Last: true}
		if ri, ok := ParseRange(a.Name); ok {
			name, info = ri.Base, ri
		}
		if cn, ok := canon[strings.ToLower(name)]; ok {
			name = cn
		}
		out.Attrs[name] = append(out.Attrs[name], a.Values...)
		if !info.Last {
			pending[name] = info.High + 1
		}
	}
	for name, next := range pending {
		values, err := CollectRanges(name, next, func(spec string) ([]RangedValues, error) {
			return fetchSpec(conn, e.DN, spec)
		})
		if err != nil {
			return directory.Entry{}, fmt.Errorf("range fetch %s of %s: %w", name, e.DN, err)
		}
		out.Attrs[name] = append(out.Attrs[name], values...)
	}
	return out, nil
}

func fetchSpec(conn *ldap.Conn, dn, spec string) ([]RangedValues, error) {
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{spec}, nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, nil
	}
	out := make([]RangedValues, 0, len(res.Entries[0].Attributes))
	for _, a := range res.Entries[0].Attributes {
		out = append(out, RangedValues{Name: a.Name, Values: a.Values})
	}
	return out, nil
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var _ directory.Directory = (*Client)(nil)
