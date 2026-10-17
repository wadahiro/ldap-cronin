package lab

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDocker reproduces part of the docker command. It records every call so that call order can be verified.
type fakeDocker struct {
	mu         sync.Mutex
	calls      []string
	secretSeen []string // detects strings that must be hidden (the password) appearing in arguments

	images     map[string]bool
	containers map[string]*fakeContainer
	volumeData map[string]string // volume name -> string standing in for the tar contents
	extracted  map[string]string // volume name -> content received for extraction
	wiped      []string
	arch       string

	// If failTarCreate is non-empty, tar creation for that volume fails.
	failTarCreate string
	helper        *fakeHelper // the native helper program; created by Start

	// startsHealthyAfter is the number of state queries after startup before the container becomes healthy.
	startsHealthyAfter int
	// onCall, if set, sees every command line after it is recorded (e.g. to cancel the run at a chosen step).
	onCall func(line string)
}

type fakeContainer struct {
	labels  map[string]string
	image   string
	running bool
	polls   int
}

func newFake() *fakeDocker {
	return &fakeDocker{
		images: map[string]bool{}, containers: map[string]*fakeContainer{}, arch: "amd64",
		volumeData: map[string]string{}, extracted: map[string]string{}, startsHealthyAfter: 2,
	}
}

func (f *fakeDocker) record(c Cmd) string {
	line := strings.Join(c.Args, " ")
	f.calls = append(f.calls, line)
	return line
}

func (f *fakeDocker) callsMatching(sub string) []string {
	var out []string
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			out = append(out, c)
		}
	}
	return out
}

func notFound(what string) error {
	return &DockerError{Args: []string{"inspect"}, Stderr: "Error: No such " + what, Err: fmt.Errorf("exit status 1")}
}

func argAfter(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func (f *fakeDocker) Do(ctx context.Context, c Cmd) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Like exec.CommandContext: a command is not started once its context is done.
	if err := ctx.Err(); err != nil {
		return "", err
	}
	line := f.record(c)
	if f.onCall != nil {
		f.onCall(line)
	}
	a := c.Args
	switch a[0] {
	case "info":
		return "27.0", nil
	case "load":
		f.images["ldap-cronin/samba-ad:test"] = true
		return "Loaded image", nil
	case "logs":
		return "", nil
	case "exec":
		return "", nil
	case "volume":
		return "", nil
	case "image":
		name := a[len(a)-1]
		format := argAfter(a, "--format")
		if !f.images[name] {
			return "", notFound("image: " + name)
		}
		if format == "{{.Architecture}}" {
			return f.arch, nil
		}
		return "sha256:abc", nil
	case "container":
		if a[1] == "ls" {
			return f.list(c), nil
		}
		return f.inspect(c)
	case "stop":
		ct, ok := f.containers[a[len(a)-1]]
		if !ok {
			return "", notFound("container")
		}
		ct.running = false
		return "", nil
	case "start":
		ct, ok := f.containers[a[len(a)-1]]
		if !ok {
			return "", notFound("container")
		}
		ct.running, ct.polls = true, 0
		return "", nil
	case "rm":
		delete(f.containers, a[len(a)-1])
		return "", nil
	case "run":
		return f.run(c)
	case "create": // a container started later, after files are copied in
		f.addContainer(a, false)
		return "id", nil
	case "cp":
		if _, ok := f.containers[strings.SplitN(a[len(a)-1], ":", 2)[0]]; !ok {
			return "", notFound("container")
		}
		return "", nil
	}
	return "", fmt.Errorf("fake: unsupported docker command: %v", a)
}

// list reproduces `docker container ls -a --filter label=ldap-cronin.lab=<prefix> --format ...`.
func (f *fakeDocker) list(c Cmd) string {
	prefix := ""
	for i, x := range c.Args {
		if x == "--filter" && strings.HasPrefix(c.Args[i+1], "label=ldap-cronin.lab=") {
			prefix = strings.TrimPrefix(c.Args[i+1], "label=ldap-cronin.lab=")
		}
	}
	var names []string
	for n := range f.containers {
		names = append(names, n)
	}
	sort.Strings(names)
	var lines []string
	for _, n := range names {
		ct := f.containers[n]
		if ct.labels["ldap-cronin.lab"] != prefix {
			continue
		}
		state := "exited"
		if ct.running {
			state = "running"
		}
		lines = append(lines, strings.Join([]string{n, state, ct.labels["ldap-cronin.instance"], ct.labels["ldap-cronin.realm"],
			ct.labels["ldap-cronin.ldap-port"], ct.labels["ldap-cronin.ldaps-port"], ct.labels["ldap-cronin.profile"]}, "\t"))
	}
	return strings.Join(lines, "\n")
}

func (f *fakeDocker) inspect(c Cmd) (string, error) {
	a := c.Args
	name := a[len(a)-1]
	ct, ok := f.containers[name]
	if !ok {
		return "", notFound("container: " + name)
	}
	switch format := argAfter(a, "--format"); {
	case format == "{{json .Config.Labels}}":
		raw, _ := json.Marshal(ct.labels)
		return string(raw), nil
	case format == "{{.Config.Image}}":
		return ct.image, nil
	case strings.Contains(format, ".State.Running"):
		if !ct.running {
			return "exited", nil
		}
		ct.polls++
		if ct.polls > f.startsHealthyAfter {
			return "healthy", nil
		}
		return "starting", nil
	}
	return "", fmt.Errorf("fake: unsupported inspect: %v", a)
}

func (f *fakeDocker) run(c Cmd) (string, error) {
	a := c.Args
	for _, s := range c.Env {
		_, v, _ := strings.Cut(s, "=")
		f.secretSeen = append(f.secretSeen, v)
	}
	switch {
	case a[1] == "-d": // start a container
		f.addContainer(a, true)
		return "id", nil
	case contains(a, "-cf"): // create a tar
		vol := volumeOf(a)
		if vol == f.failTarCreate {
			return "", &DockerError{Args: a, Stderr: "tar: error", Err: fmt.Errorf("exit status 2")}
		}
		if c.Stdout != nil {
			_, _ = io.WriteString(c.Stdout, f.volumeData[vol])
		}
		return "", nil
	case contains(a, "-xf"): // extract a tar
		raw, _ := io.ReadAll(c.Stdin)
		f.extracted[volumeOf(a)] = string(raw)
		f.volumeData[volumeOf(a)] = string(raw)
		return "", nil
	case contains(a, "-delete") || strings.Contains(strings.Join(a, " "), "-mindepth 1 -delete"): // empty a volume
		f.wiped = append(f.wiped, volumeOf(a))
		f.volumeData[volumeOf(a)] = ""
		return "", nil
	}
	return "", fmt.Errorf("fake: unsupported run: %v", a)
}

func (f *fakeDocker) addContainer(a []string, running bool) {
	labels := map[string]string{}
	for i := 0; i+1 < len(a); i++ {
		if a[i] == "--label" {
			k, v, _ := strings.Cut(a[i+1], "=")
			labels[k] = v
		}
	}
	f.containers[argAfter(a, "--name")] = &fakeContainer{labels: labels, image: a[len(a)-1], running: running}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func volumeOf(args []string) string {
	v := argAfter(args, "-v")
	name, _, _ := strings.Cut(v, ":")
	return name
}

// ---- Lab for tests ----

type fakePrompt struct {
	realm, password string
	choose          int
	interactive     bool
	chooseItems     []string
	chosePrompt     string
}

func (p *fakePrompt) Domain(_, def string) (string, error) { return p.realm, nil }
func (p *fakePrompt) NewPassword() (string, error)         { return p.password, nil }
func (p *fakePrompt) Choose(prompt string, items []string, def int) (int, error) {
	p.chooseItems = items
	p.chosePrompt = prompt
	if !p.interactive {
		return 0, ErrNotInteractive
	}
	return p.choose, nil
}

type labFixture struct {
	t      *testing.T
	d      *fakeDocker
	l      *Lab
	out    *strings.Builder
	errw   *strings.Builder
	prompt *fakePrompt
	now    time.Time
	env    map[string]string
	// nextPort is the port FreePort returns (stands in for automatic selection of a free port).
	nextPort int
}

func newLabFixture(t *testing.T) *labFixture {
	t.Helper()
	dir := t.TempDir()
	fx := &labFixture{t: t, d: newFake(), out: &strings.Builder{}, errw: &strings.Builder{}, prompt: &fakePrompt{},
		now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), env: map[string]string{}, nextPort: 40000}
	fx.l = &Lab{
		D: fx.d, Out: fx.out, Err: fx.errw, Prompt: fx.prompt, Prefix: "t",
		Dirs:    Dirs{State: dir, Snapshots: filepath.Join(dir, "snapshots")},
		Version: "test", Getenv: func(k string) string { return fx.env[k] }, Sleep: func(time.Duration) {},
		Now: func() time.Time { fx.now = fx.now.Add(time.Second); return fx.now }, HostArch: "amd64",
		FreePort: func() (int, error) { fx.nextPort++; return fx.nextPort, nil },
	}
	return fx
}

// withBundle creates a carry-in bundle (IMAGE, images/samba-ad.tar and SHA256SUMS).
func (fx *labFixture) withBundle() string {
	fx.t.Helper()
	dir := fx.t.TempDir()
	must(fx.t, os.MkdirAll(filepath.Join(dir, "images"), 0o755))
	must(fx.t, os.WriteFile(filepath.Join(dir, "IMAGE"), []byte("ldap-cronin/samba-ad:test\n"), 0o644))
	must(fx.t, os.WriteFile(filepath.Join(dir, "images", "samba-ad.tar"), []byte("tar-bytes"), 0o644))
	sum, err := fileSHA256(filepath.Join(dir, "images", "samba-ad.tar"))
	must(fx.t, err)
	sumIMAGE, err := fileSHA256(filepath.Join(dir, "IMAGE"))
	must(fx.t, err)
	must(fx.t, os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sum+"  images/samba-ad.tar\n"+sumIMAGE+"  IMAGE\n"), 0o644))
	fx.l.Dirs.Bundle = dir
	return dir
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// up starts a lab for verification (with the bundle).
func (fx *labFixture) up(realm string) {
	fx.t.Helper()
	fx.withBundle()
	must(fx.t, fx.l.Up(context.Background(), UpOptions{Flags: Settings{Domain: realm, AdminPassword: "Secret-Passw0rd!"}}))
}

// ---- fake of the native helper program ----

// fakeHelper is an in-memory sam.ldb that speaks the JSON-lines protocol in place of the helper program (Python).
type fakeHelper struct {
	mu      sync.Mutex
	entries map[string]map[string][]string // DN -> attributes (values stay base64)
	sawStop bool                           // whether the lab container was stopped at startup
	ops     []string
	failOp  string // returns an error for this op
}

func newFakeHelper() *fakeHelper {
	return &fakeHelper{entries: map[string]map[string][]string{}}
}

// Start makes fakeDocker a Streamer. It detects the helper's launch from the arguments of run -i.
func (f *fakeDocker) Start(ctx context.Context, c Cmd) (*Process, error) {
	f.mu.Lock()
	f.record(c)
	if f.helper == nil {
		f.helper = newFakeHelper()
	}
	h := f.helper
	if ct, ok := f.containers[f.helperLabContainer(c.Args)]; ok {
		h.sawStop = !ct.running
	}
	f.mu.Unlock()

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer outW.Close()
		dec := json.NewDecoder(inR)
		for {
			var req map[string]any
			if err := dec.Decode(&req); err != nil {
				return
			}
			resp := h.handle(req)
			raw, _ := json.Marshal(resp)
			_, _ = outW.Write(append(raw, '\n'))
			if req["op"] == "finish" {
				return
			}
		}
	}()
	return &Process{Stdin: inW, Stdout: outR, Wait: func() error { <-done; return nil }}, nil
}

// helperLabContainer returns the lab container name that the helper container opens (derived from <lab>-native).
func (f *fakeDocker) helperLabContainer(args []string) string {
	return strings.TrimSuffix(argAfter(args, "--name"), "-native")
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func (h *fakeHelper) handle(req map[string]any) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	op, _ := req["op"].(string)
	h.ops = append(h.ops, op)
	if op == h.failOp {
		return map[string]any{"ok": false, "code": 1, "msg": "forced failure"}
	}
	dn, _ := req["dn"].(string)
	switch op {
	case "hello":
		return map[string]any{"ok": true, "samba": "4.19.5-Ubuntu", "tested": true, "base": "DC=ad,DC=example,DC=com",
			"domain_sid": "S-1-5-21-1-2-3", "domain_guid": "11111111-2222-3333-4444-555555555555"}
	case "get":
		e, ok := h.entries[strings.ToLower(dn)]
		if !ok {
			return map[string]any{"ok": true, "entry": nil}
		}
		return map[string]any{"ok": true, "entry": map[string]any{"dn": dn, "attrs": e}}
	case "add":
		if _, ok := h.entries[strings.ToLower(dn)]; ok {
			return map[string]any{"ok": false, "code": 68, "msg": "Entry already exists"}
		}
		attrs := map[string][]string{}
		raw, _ := json.Marshal(req["attrs"])
		_ = json.Unmarshal(raw, &attrs)
		h.entries[strings.ToLower(dn)] = attrs
		return map[string]any{"ok": true}
	case "replace":
		attrs := map[string][]string{}
		raw, _ := json.Marshal(req["attrs"])
		_ = json.Unmarshal(raw, &attrs)
		e := h.entries[strings.ToLower(dn)]
		for k, v := range attrs {
			e[k] = v
		}
		return map[string]any{"ok": true}
	case "add_values":
		name, _ := req["attr"].(string)
		var vals []string
		raw, _ := json.Marshal(req["values"])
		_ = json.Unmarshal(raw, &vals)
		e := h.entries[strings.ToLower(dn)]
		e[name] = append(e[name], vals...)
		return map[string]any{"ok": true}
	case "search":
		var entries []map[string]any
		for k, e := range h.entries {
			entries = append(entries, map[string]any{"dn": k, "attrs": e})
		}
		return map[string]any{"ok": true, "entries": entries}
	case "finish":
		return map[string]any{"ok": true, "max_rid": 1234, "rid_next": 1235, "dbcheck": "Checked 3 objects (0 errors)"}
	}
	return map[string]any{"ok": false, "code": -1, "msg": "unknown op"}
}
