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

	MaxRID  int    `json:"max_rid"`
	RIDNext int    `json:"rid_next"`
	DBCheck string `json:"dbcheck"`
}

// NativeFinish is the result of the post-import cleanup (RID allocation, dbcheck).
type NativeFinish struct {
	MaxRID  int
	RIDNext int
	DBCheck string
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

func (l *Lab) helperName() string { return l.container() + "-native" }

// OpenNative stops the lab, starts the helper and runs the self-check. On failure it restores the lab and fails.
func (l *Lab) OpenNative(ctx context.Context) (*Native, error) {
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
	resp, err := n.call(ctx, map[string]any{"op": "hello"})
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

func (n *Native) Add(ctx context.Context, e directory.Entry) error {
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

func mapExists(err error) error {
	var ne *NativeError
	if errors.As(err, &ne) && ne.Code == ldbEntryExists {
		return directory.ErrExists
	}
	return err
}

// Finish performs the post-import cleanup. It advances the RID allocation past the largest imported RID (otherwise
// users created over LDAP after the import would collide with imported RIDs), and checks consistency with dbcheck.
// Call it only when the import succeeded.
func (n *Native) Finish(ctx context.Context) (NativeFinish, error) {
	resp, err := n.call(ctx, map[string]any{"op": "finish"})
	if err != nil {
		return NativeFinish{}, err
	}
	n.finished = true
	return NativeFinish{MaxRID: resp.MaxRID, RIDNext: resp.RIDNext, DBCheck: resp.DBCheck}, nil
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
	return strings.Join(parts, " / ")
}
