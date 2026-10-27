package lab

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

// nativeHelper is a helper program (the Samba Python API) that operates directly on the lab volume's sam.ldb.
// Over LDAP, objects cannot be created with a specified objectGUID or objectSid,
// so this uses Samba internals. It is not a supported usage and depends on the Samba version.
//
//go:embed native_helper.py
var nativeHelper string

// ldb error codes.
const (
	ldbEntryExists = 68
)

// NativeOptions are how a native import writes.
type NativeOptions struct {
	// FastPassword gives the first user the fixed password as Samba does, and every other user the NT hash it got,
	// written directly: Samba then derives no other hash, the Kerberos AES keys among them, which is what takes the
	// time of a user. Those users log on over LDAP and with Kerberos through RC4, not AES.
	FastPassword bool
	// ServerAttributes gives each object the source's values of what the server keeps (whenCreated, the logon
	// times and count, the lockout state, sIDHistory, mS-DS-CreatorSID; profile.ServerAttributes), set right after
	// its add as the system: an add takes its own, and over LDAP only the system may change them.
	ServerAttributes bool
	// ACL gives the lab's objects the source's owner, group and DACL (written by the caller after the import,
	// through Replace; the helper replaces those three parts only).
	ACL bool
}

// NativeInfo is the information about the lab's Samba and domain reported by the helper.
type NativeInfo struct {
	Samba      string
	Tested     bool // whether this is a version whose behavior has been verified (the self-check passed even if not)
	Base       string
	DomainSID  string
	DomainGUID string
}

type wireEntry struct {
	DN    string              `json:"dn"`
	Attrs map[string][]string `json:"attrs"`
}

type wireResponse struct {
	OK   bool   `json:"ok"`
	Code int    `json:"code"`
	Msg  string `json:"msg"`

	Entry   *wireEntry  `json:"entry"`
	Entries []wireEntry `json:"entries"`

	Samba      string `json:"samba"`
	Tested     bool   `json:"tested"`
	Base       string `json:"base"`
	DomainSID  string `json:"domain_sid"`
	DomainGUID string `json:"domain_guid"`

	MaxRID        int    `json:"max_rid"`
	RIDNext       int    `json:"rid_next"`
	DBCheck       string `json:"dbcheck"`
	FastPasswords int    `json:"fast_passwords"`
	ServerAttrs   int    `json:"server_attributes"`

	Keys  []string `json:"keys"`
	Stale bool     `json:"stale"`
}

// NativeFinish is the result of the post-import cleanup (RID allocation, dbcheck).
type NativeFinish struct {
	MaxRID  int
	RIDNext int
	DBCheck string
	// FastPasswords is the number of users given the NT hash directly (NativeOptions.FastPassword).
	FastPasswords int
	// ServerAttributes is the number of objects given the source's server attributes (NativeOptions.ServerAttributes).
	ServerAttributes int
}

// Native is a session that creates objects directly in the lab's Samba with a specified objectGUID and objectSid.
// The lab container is stopped during the session (to avoid opening the same sam.ldb twice). Close resumes it.
// It can be used as a directory.Directory, but use Walk only for small results (it returns everything at once).
type Native struct {
	Info NativeInfo

	l        *Lab
	proc     *Process
	rd       *bufio.Reader
	mu       sync.Mutex // one request at a time; there is a single helper process, which handles requests serially
	wasUp    bool       // whether the lab was running before the start; Close resumes it
	closed   bool
	finished bool
}

var _ directory.Directory = (*Native)(nil)

// CheckTargetURL refuses a [target] url that is not this lab's: its port must be the lab's LDAPS port (ldaps://) or
// LDAP port (ldap://). A native import writes the lab's database through docker, while check, diff and schema read
// the url: they must be the same lab.
func (l *Lab) CheckTargetURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	labels, exists, err := l.inspectLabels(ctx, l.container())
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("lab %s does not exist; create it first with lab up --config (or restore)", l.container())
	}
	label, kind := labelLDAPS, "LDAPS"
	if u.Scheme == "ldap" {
		label, kind = labelLDAP, "LDAP"
	}
	if want := labels[label]; u.Port() != want {
		return fmt.Errorf("[target] url %s is not the lab %s, whose %s port is %s: give its url, or name the lab of the url in [target.lab]", raw, l.container(), kind, want)
	}
	return nil
}

// Name is the lab's container name (ldap-cronin-ad, or ldap-cronin-ad-<instance>).
func (l *Lab) Name() string { return l.container() }

func (l *Lab) helperName() string { return l.container() + "-native" }

// OpenNative stops the lab, starts the helper and runs the self-check. On failure it restores the lab and fails.
func (l *Lab) OpenNative(ctx context.Context, opts NativeOptions) (*Native, error) {
	st, ok := l.D.(Streamer)
	if !ok {
		return nil, errors.New("this docker invocation method does not support native import")
	}
	if err := l.checkDocker(ctx); err != nil {
		return nil, err
	}
	name := l.container()
	_, exists, err := l.inspectLabels(ctx, name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("lab %s does not exist; create it first with lab up (or restore)", name)
	}
	image, err := l.docker(ctx, "container", "inspect", "--format", "{{.Config.Image}}", name)
	if err != nil {
		return nil, err
	}
	state, err := l.state(ctx, name)
	if err != nil {
		return nil, err
	}
	n := &Native{l: l, wasUp: state != "exited"}
	if n.wasUp {
		l.logf("Stopping lab %s (only for the duration of the import; it resumes afterwards)", name)
		if _, err := l.docker(ctx, "stop", "-t", stopTimeoutSec, name); err != nil {
			return nil, err
		}
	}
	// If a helper container left over from a previous forced termination exists, remove it first.
	if _, err := l.docker(ctx, "rm", "-f", l.helperName()); err != nil && !IsNotFound(err) {
		_ = n.restart(ctx)
		return nil, err
	}
	// The helper is not bound to ctx: killing it could interrupt a write to sam.ldb. call stops between requests instead.
	proc, err := st.Start(context.WithoutCancel(ctx), Cmd{
		Args: []string{"run", "-i", "--rm", "--name", l.helperName(),
			"-v", l.volume("private") + ":/var/lib/samba", "-v", l.volume("etc") + ":/etc/samba",
			"--entrypoint", "python3", image, "-u", "-c", nativeHelper},
		Stderr: l.Err,
	})
	if err != nil {
		_ = n.restart(ctx)
		return nil, err
	}
	n.proc, n.rd = proc, bufio.NewReaderSize(proc.Stdout, 1<<20)
	resp, err := n.call(ctx, map[string]any{"op": "hello", "fast_password": opts.FastPassword, "server_attributes": opts.ServerAttributes})
	if err != nil {
		_ = n.Close(ctx)
		return nil, fmt.Errorf("cannot start the native helper (it may not work with this Samba): %w", err)
	}
	n.Info = NativeInfo{Samba: resp.Samba, Tested: resp.Tested, Base: resp.Base, DomainSID: resp.DomainSID, DomainGUID: resp.DomainGUID}
	if !n.Info.Tested {
		l.warnf("Samba %s is not a version whose behavior has been verified (the self-check passed)", n.Info.Samba)
	}
	return n, nil
}

// call sends one request and reads one response. A response with ok=false is returned as a NativeError.
// ctx is checked before sending, never while the helper works: killing it mid-request could leave sam.ldb half
// written, so a cancelled import stops between requests and Close ends the helper by closing its standard input.
func (n *Native) call(ctx context.Context, req map[string]any) (*wireResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := n.proc.Stdin.Write(append(raw, '\n')); err != nil {
		return nil, fmt.Errorf("cannot send to the helper: %w", err)
	}
	line, err := n.rd.ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the helper exited without responding (see the error output)")
		}
		return nil, err
	}
	var resp wireResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("cannot read the helper's response: %w", err)
	}
	if !resp.OK {
		return nil, &NativeError{Code: resp.Code, Msg: resp.Msg}
	}
	return &resp, nil
}

// NativeError is an error returned by the helper (ldb).
type NativeError struct {
	Code int
	Msg  string
}

func (e *NativeError) Error() string { return fmt.Sprintf("%s (ldb error %d)", e.Msg, e.Code) }

func encodeAttrs(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for name, values := range in {
		enc := make([]string, len(values))
		for i, v := range values {
			enc[i] = base64.StdEncoding.EncodeToString([]byte(v))
		}
		out[name] = enc
	}
	return out
}

func decodeEntry(w wireEntry) (directory.Entry, error) {
	e := directory.Entry{DN: w.DN, Attrs: map[string][]string{}}
	for name, values := range w.Attrs {
		dec := make([]string, len(values))
		for i, v := range values {
			raw, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return e, fmt.Errorf("cannot read %s of %s: %w", name, w.DN, err)
			}
			dec[i] = string(raw)
		}
		e.Attrs[name] = dec
	}
	return e, nil
}

// searchAttrs prepares the attribute list for ldb ("1.1", used when only the DN is wanted, is not accepted by ldb).
func searchAttrs(attrs []string) []string {
	if len(attrs) == 1 && attrs[0] == directory.NoAttrs {
		return []string{"distinguishedName"}
	}
	return attrs
}

func (n *Native) Get(ctx context.Context, dn string, attrs []string) (*directory.Entry, error) {
	resp, err := n.call(ctx, map[string]any{"op": "get", "dn": dn, "attrs": searchAttrs(attrs)})
	if err != nil || resp.Entry == nil {
		return nil, err
	}
	e, err := decodeEntry(*resp.Entry)
	return &e, err
}

func (n *Native) Walk(ctx context.Context, base, filter string, attrs []string, fn func(directory.Entry) error) error {
	resp, err := n.call(ctx, map[string]any{"op": "search", "base": base, "filter": filter, "attrs": searchAttrs(attrs)})
	if err != nil {
		return err
	}
	for _, w := range resp.Entries {
		e, err := decodeEntry(w)
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// Add ignores controls: the native API writes below the LDAP layer, where no control is needed to keep identifiers.
func (n *Native) Add(ctx context.Context, e directory.Entry, _ ...directory.Control) error {
	_, err := n.call(ctx, map[string]any{"op": "add", "dn": e.DN, "attrs": encodeAttrs(e.Attrs)})
	return mapExists(err)
}

func (n *Native) Replace(ctx context.Context, dn string, attrs map[string][]string) error {
	_, err := n.call(ctx, map[string]any{"op": "replace", "dn": dn, "attrs": encodeAttrs(attrs)})
	return err
}

func (n *Native) AddValues(ctx context.Context, dn, attr string, values []string) error {
	_, err := n.call(ctx, map[string]any{"op": "add_values", "dn": dn, "attr": attr, "values": encodeAttrs(map[string][]string{attr: values})[attr]})
	return err
}

func (n *Native) DeleteValues(ctx context.Context, dn, attr string, values []string) error {
	_, err := n.call(ctx, map[string]any{"op": "delete_values", "dn": dn, "attr": attr, "values": encodeAttrs(map[string][]string{attr: values})[attr]})
	return err
}

func mapExists(err error) error {
	var ne *NativeError
	if errors.As(err, &ne) && ne.Code == ldbEntryExists {
		return directory.ErrExists
	}
	return err
}

// Finish performs the post-import cleanup. It advances the RID allocation past the largest imported RID (otherwise
// users created over LDAP after the import would collide with imported RIDs), checks consistency with dbcheck, and
// then removes the journal: the import is complete. Call it only when the import succeeded.
func (n *Native) Finish(ctx context.Context) (NativeFinish, error) {
	resp, err := n.call(ctx, map[string]any{"op": "finish"})
	if err != nil {
		return NativeFinish{}, err
	}
	n.finished = true
	return NativeFinish{MaxRID: resp.MaxRID, RIDNext: resp.RIDNext, DBCheck: resp.DBCheck, FastPasswords: resp.FastPasswords,
		ServerAttributes: resp.ServerAttrs}, nil
}

// FinishSlice is Finish at the end of a slice of an import done in slices (clone -time-limit): the RID allocation is
// advanced, so the lab can be used and snapshotted as it is, and dbcheck is left to the slice that completes it.
func (n *Native) FinishSlice(ctx context.Context) (NativeFinish, error) {
	resp, err := n.call(ctx, map[string]any{"op": "finish", "dbcheck": false})
	if err != nil {
		return NativeFinish{}, err
	}
	n.finished = true
	return NativeFinish{MaxRID: resp.MaxRID, RIDNext: resp.RIDNext, FastPasswords: resp.FastPasswords, ServerAttributes: resp.ServerAttrs}, nil
}

// NativeJournal records what an import done in slices has finished, in the lab's volume: a snapshot of the lab
// carries exactly the progress its data has, which a file beside it (in a home directory that outlives the lab)
// would not.
type NativeJournal struct {
	n       *Native
	done    map[string]bool
	pending []string
	// Stale is set when the lab held a journal of another source or config, which was dropped.
	Stale bool
}

// journalFlush is how many keys are sent at once; a key not yet sent is only compared again by the next run.
const journalFlush = 500

// Journal reads the lab's journal for fingerprint (the source and config it is valid for), or starts one.
func (n *Native) Journal(ctx context.Context, fingerprint string) (*NativeJournal, error) {
	resp, err := n.call(ctx, map[string]any{"op": "journal_load", "fingerprint": fingerprint})
	if err != nil {
		return nil, err
	}
	j := &NativeJournal{n: n, done: make(map[string]bool, len(resp.Keys)), Stale: resp.Stale}
	for _, k := range resp.Keys {
		j.done[k] = true
	}
	return j, nil
}

// Len is how many keys the lab's journal held when it was read.
func (j *NativeJournal) Len() int { return len(j.done) }

func (j *NativeJournal) Has(key string) bool { return j.done[key] }

func (j *NativeJournal) Mark(ctx context.Context, key string) error {
	j.pending = append(j.pending, key)
	if len(j.pending) < journalFlush {
		return nil
	}
	return j.Flush(ctx)
}

// Flush sends the keys not yet sent.
func (j *NativeJournal) Flush(ctx context.Context) error {
	if len(j.pending) == 0 {
		return nil
	}
	if _, err := j.n.call(ctx, map[string]any{"op": "journal_add", "keys": j.pending}); err != nil {
		return err
	}
	j.pending = j.pending[:0]
	return nil
}

// Clear removes the journal: the import is complete, and a later one compares everything again.
func (j *NativeJournal) Clear(ctx context.Context) error {
	j.pending = nil
	_, err := j.n.call(ctx, map[string]any{"op": "journal_clear"})
	return err
}

// Close ends the helper and resumes the lab that was stopped. It runs to the end even when ctx is cancelled, since
// that is exactly when it matters: an interrupted import must not leave the lab stopped.
func (n *Native) Close(ctx context.Context) error {
	ctx = context.WithoutCancel(ctx)
	if n.closed {
		return nil
	}
	n.closed = true
	var errs []error
	if n.proc != nil {
		_ = n.proc.Stdin.Close()
		if err := n.proc.Wait(); err != nil && !n.finished {
			// Do not care about the exit code when closed midway; restoring the lab comes first.
			n.l.warnf("helper exit: %v", err)
		}
	}
	errs = append(errs, n.restart(ctx))
	return errors.Join(errs...)
}

func (n *Native) restart(ctx context.Context) error {
	ctx = context.WithoutCancel(ctx) // also on the failure paths of OpenNative
	if !n.wasUp {
		return nil
	}
	name := n.l.container()
	n.l.logf("Resuming lab %s", name)
	if _, err := n.l.docker(ctx, "start", name); err != nil {
		return err
	}
	return n.l.waitHealthy(ctx, name)
}

// Summary describes the post-import result in one line.
func (f NativeFinish) Summary() string {
	parts := []string{"dbcheck: " + strings.TrimSpace(f.DBCheck)}
	if f.MaxRID > 0 {
		parts = append(parts, fmt.Sprintf("largest imported RID=%d (next allocation=%d)", f.MaxRID, f.RIDNext))
	}
	if f.FastPasswords > 0 {
		parts = append(parts, fmt.Sprintf("fast_password: %d users got the NT hash directly (no Kerberos AES keys)", f.FastPasswords))
	}
	if f.ServerAttributes > 0 {
		parts = append(parts, fmt.Sprintf("whenCreated, logons, lockout and sIDHistory: the source's on %d objects", f.ServerAttributes))
	}
	return strings.Join(parts, " / ")
}
