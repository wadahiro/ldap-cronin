package lab

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// A snapshot is the contents of the docker volumes holding the lab server's data (Samba or OpenLDAP), written out to
// tar files on the host.
//
// The approach was chosen by measurement (1600 users, about 60MB of data; total time needed to restore):
//   - copy volume to volume: 5.5 s. But unused volumes are removed by docker volume prune
//   - docker commit: 4.0 s. But the password stays in the image's environment variables, and the number of layers is capped
//   - volume contents to a tar on the host: 6.6 s (adopted). Survives prune, can be carried out as a file, and
//     the host file is owned by the invoking user
//
// Restore time is dominated by the server's startup (Samba about 3 s, OpenLDAP under 1 s) and grows in proportion to the data size.

const (
	metaFileName    = "snapshot.json"
	snapshotPrefix  = "snapshot-"
	timestampLayout = "20060102-150405"
)

var snapshotNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// ErrNotInteractive means there is no terminal, so interactive input is not possible.
var ErrNotInteractive = errors.New("cannot prompt interactively (no terminal)")

// SnapshotFile is a file included in a snapshot.
type SnapshotFile struct {
	Volume string `json:"volume"` // private / etc
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// SnapshotMeta is the snapshot metadata (snapshot.json).
type SnapshotMeta struct {
	Name    string    `json:"name"`
	Note    string    `json:"note,omitempty"`
	Created time.Time `json:"created"`
	// Profile is the server type of the lab (ad, ldap). Snapshots written before there was a choice have none: ad.
	Profile string `json:"profile,omitempty"`
	// Domain is the realm of a Samba lab, or the suffix of an OpenLDAP lab.
	Domain string `json:"domain"`
	// LegacyRealm is where snapshots of earlier versions kept the realm; readMeta moves it to Domain.
	LegacyRealm string         `json:"realm,omitempty"`
	NetBIOS     string         `json:"netbios"`
	Hostname    string         `json:"hostname"`
	Image       string         `json:"image"`
	ToolVersion string         `json:"tool_version"`
	Files       []SnapshotFile `json:"files"`
	// Compression is how the files are compressed: "gzip", or "" for none (snapshots of earlier versions).
	Compression string `json:"compression,omitempty"`
}

// compressionGzip compresses the files of a snapshot: a Samba database shrinks several times, which decides whether
// a large lab's snapshot fits where it is kept (a cloud shell's home holds 1 GB). The fastest level, as the CPU that
// takes it may be small.
const compressionGzip = "gzip"

// Size is the total size of the snapshot's files.
func (m SnapshotMeta) Size() int64 {
	var n int64
	for _, f := range m.Files {
		n += f.Size
	}
	return n
}

// ValidateSnapshotName checks the snapshot name format (it becomes a directory name, so it is limited to alphanumerics, _, . and -).
func ValidateSnapshotName(name string) error {
	if !snapshotNamePattern.MatchString(name) {
		return fmt.Errorf("invalid snapshot name: %q (alphanumerics, _, . and -, up to 64 characters, starting with an alphanumeric)", name)
	}
	return nil
}

// SnapshotOptions are the options for snapshot.
type SnapshotOptions struct {
	Name  string // if empty, named automatically from the date and time (never overwrites)
	Note  string
	Force bool // overwrite if the same name exists
}

func (l *Lab) snapshotDir(name string) string { return filepath.Join(l.Dirs.Snapshots, name) }

func tarCreateArgs(image, volume, mount string) []string {
	return []string{"run", "--rm", "-v", volume + ":" + mount + ":ro", "--cap-add", "SYS_ADMIN", "--entrypoint", "tar", image,
		// Sockets (ldapi, winbindd pipes, etc.) are created only at runtime, so they are excluded. Their warnings are suppressed too.
		"-C", mount, "--xattrs", "--xattrs-include=*", "--numeric-owner", "--warning=no-file-ignored", "-cf", "-", "."}
}

func tarExtractArgs(image, volume, mount string) []string {
	return []string{"run", "-i", "--rm", "-v", volume + ":" + mount, "--cap-add", "SYS_ADMIN", "--entrypoint", "tar", image,
		"-C", mount, "--xattrs", "--xattrs-include=*", "--numeric-owner", "-xf", "-"}
}

func wipeArgs(image, volume, mount string) []string {
	return []string{"run", "--rm", "-v", volume + ":" + mount, "--entrypoint", "sh", image, "-c", "find " + mount + " -mindepth 1 -delete"}
}

// Snapshot stops the lab, writes the data to a tar, and returns it to its previous state (started if it was running).
// Taking one right after a clone lets you return to that state at any time. The markers clone wrote are part of the
// data, so diff's rename and move detection keeps working after a restore, in this instance or another.
func (l *Lab) Snapshot(ctx context.Context, o SnapshotOptions) (SnapshotMeta, error) {
	var meta SnapshotMeta
	if err := l.checkDocker(ctx); err != nil {
		return meta, err
	}
	name := o.Name
	if name == "" {
		name = snapshotPrefix + l.Now().Format(timestampLayout)
	}
	if err := ValidateSnapshotName(name); err != nil {
		return meta, err
	}
	final := l.snapshotDir(name)
	if _, err := os.Stat(final); err == nil && !o.Force {
		return meta, fmt.Errorf("snapshot %q already exists (use --force to overwrite)", name)
	}

	labels, exists, err := l.inspectLabels(ctx, l.container())
	if err != nil {
		return meta, err
	}
	if !exists {
		return meta, errors.New("no lab exists; create one with up first, then populate it with clone")
	}
	image, err := l.docker(ctx, "container", "inspect", "--format", "{{.Config.Image}}", l.container())
	if err != nil {
		return meta, err
	}
	state, err := l.state(ctx, l.container())
	if err != nil {
		return meta, err
	}
	wasRunning := state != "exited"

	if err := os.MkdirAll(l.Dirs.Snapshots, 0o755); err != nil {
		return meta, err
	}
	tmp, err := os.MkdirTemp(l.Dirs.Snapshots, "."+name+".tmp-")
	if err != nil {
		return meta, err
	}
	defer os.RemoveAll(tmp) // do not leave a partial write behind on failure (after success it has been renamed, so this does nothing)

	// Stop the server cleanly to capture consistent data, then write it out. Afterwards return to the previous state.
	// Writing out may be interrupted (the partial snapshot is discarded), but returning the lab to its previous state
	// may not: an interrupted run must never leave the lab stopped.
	restore := context.WithoutCancel(ctx)
	if wasRunning {
		l.logf("Stopping %s (to capture consistent data)", l.srv().Product)
		if _, err := l.docker(restore, "stop", "-t", stopTimeoutSec, l.container()); err != nil {
			return meta, err
		}
	}
	start := l.Now()
	var files []SnapshotFile
	var dumpErr error
	for _, v := range l.srv().Volumes {
		file := v.File + ".gz"
		f, err := l.dumpVolume(ctx, image, v.Kind, v.Mount, filepath.Join(tmp, file))
		if err != nil {
			dumpErr = err
			break
		}
		f.Volume, f.File = v.Kind, file
		files = append(files, f)
	}
	if wasRunning {
		l.logf("Restarting %s", l.srv().Product)
		if _, err := l.docker(restore, "start", l.container()); err != nil && dumpErr == nil {
			dumpErr = err
		} else if err == nil {
			if err := l.waitHealthy(restore, l.container()); err != nil && dumpErr == nil {
				dumpErr = err
			}
		}
	}
	if dumpErr != nil {
		return meta, fmt.Errorf("could not take the snapshot (the lab was returned to its previous state): %w", dumpErr)
	}

	meta = SnapshotMeta{
		Name: name, Note: o.Note, Created: l.Now().UTC(), Profile: l.srv().Profile, Domain: labels[labelRealm], NetBIOS: labels[labelNB],
		Hostname: l.srv().Hostname, Image: image, ToolVersion: l.Version, Files: files, Compression: compressionGzip,
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return meta, err
	}
	if err := os.WriteFile(filepath.Join(tmp, metaFileName), append(raw, '\n'), 0o600); err != nil {
		return meta, err
	}
	if o.Force {
		if err := os.RemoveAll(final); err != nil {
			return meta, err
		}
	}
	if err := os.Rename(tmp, final); err != nil {
		return meta, err
	}
	l.logf("Snapshot taken: %s (%s, %s)", name, humanSize(meta.Size()), l.Now().Sub(start).Round(100*time.Millisecond))
	return meta, nil
}

// dumpVolume writes the volume contents to a host file as a tar (streaming docker's output as is.
// It does not use docker bind mounts, so the host file is owned by the invoking user).
func (l *Lab) dumpVolume(ctx context.Context, image, kind, mount, path string) (SnapshotFile, error) {
	var sf SnapshotFile
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return sf, err
	}
	// The size and checksum are the file's as kept (compressed), which verifySnapshot reads back.
	h := sha256.New()
	cw := &countingWriter{w: io.MultiWriter(out, h)}
	z, _ := gzip.NewWriterLevel(cw, gzip.BestSpeed)
	_, derr := l.D.Do(ctx, Cmd{Args: tarCreateArgs(image, l.volume(kind), mount), Stdout: z, Stderr: l.Err})
	if zerr := z.Close(); derr == nil {
		derr = zerr
	}
	if cerr := out.Close(); derr == nil {
		derr = cerr
	}
	if derr != nil {
		return sf, derr
	}
	sf.Size, sf.SHA256 = cw.n, hex.EncodeToString(h.Sum(nil))
	return sf, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Snapshots returns the list of snapshots in the order taken (oldest first).
func (l *Lab) Snapshots() ([]SnapshotMeta, error) {
	entries, err := os.ReadDir(l.Dirs.Snapshots)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []SnapshotMeta
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		m, err := l.readMeta(e.Name())
		if err != nil {
			continue // broken entries and unrelated directories are not listed
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

func (l *Lab) readMeta(name string) (SnapshotMeta, error) {
	var m SnapshotMeta
	raw, err := os.ReadFile(filepath.Join(l.snapshotDir(name), metaFileName))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, err
	}
	if m.Domain == "" {
		m.Domain, m.LegacyRealm = m.LegacyRealm, ""
	}
	if m.Profile == "" {
		m.Profile = ProfileAD
	}
	if m.Name != name {
		return m, fmt.Errorf("name %q in snapshot.json differs from the directory name %q", m.Name, name)
	}
	return m, nil
}

// SnapshotRemove deletes a snapshot.
func (l *Lab) SnapshotRemove(name string) error {
	if err := ValidateSnapshotName(name); err != nil {
		return err
	}
	if _, err := l.readMeta(name); err != nil {
		return fmt.Errorf("snapshot %q not found: %w", name, err)
	}
	return os.RemoveAll(l.snapshotDir(name))
}

// choose lets the user pick from the list when the name is omitted (newest first, which is the default).
func (l *Lab) choose() (string, error) {
	list, err := l.Snapshots()
	if err != nil {
		return "", err
	}
	if len(list) == 0 {
		return "", errors.New("no snapshots exist; take one with lab snapshot after a clone")
	}
	// Sort newest first.
	items := make([]string, len(list))
	names := make([]string, len(list))
	for i := range list {
		m := list[len(list)-1-i]
		names[i] = m.Name
		items[i] = formatSnapshotLine(m)
	}
	// Each list line gets a 7-column prefix such as " * 1) ", so shift the header by 7 columns to align the columns.
	prompt := "Which snapshot to restore?\n       " + snapshotHeader()
	idx, err := l.Prompt.Choose(prompt, items, 0)
	if errors.Is(err, ErrNotInteractive) {
		return "", fmt.Errorf("specify a snapshot name. Candidates:\n  %s\n  %s", snapshotHeader(), strings.Join(items, "\n  "))
	}
	if err != nil {
		return "", err
	}
	return names[idx], nil
}

// snapshotHeader is the list's column header. Column widths match formatSnapshotLine (full-width characters misalign columns, so Latin letters are used).
func snapshotHeader() string {
	return fmt.Sprintf("%-24s %-19s  %-24s %8s  %s", "NAME", "CREATED", "DOMAIN", "SIZE", "NOTE")
}

func formatSnapshotLine(m SnapshotMeta) string {
	s := fmt.Sprintf("%-24s %s  %-24s %8s", m.Name, m.Created.Local().Format("2006-01-02 15:04:05"), m.Domain, humanSize(m.Size()))
	if m.Note != "" {
		s += "  " + m.Note
	}
	return s
}

// FormatSnapshots formats the list for display (oldest first).
func FormatSnapshots(list []SnapshotMeta) string {
	if len(list) == 0 {
		return "No snapshots\n"
	}
	var b strings.Builder
	b.WriteString(snapshotHeader() + "\n")
	for _, m := range list {
		b.WriteString(formatSnapshotLine(m) + "\n")
	}
	return b.String()
}

// RestoreOptions are the options for restore. Used when no lab container exists (when creating a new one from a snapshot).
type RestoreOptions struct {
	LDAPPort      int // if omitted: the default lab uses .env or the default, and other instances pick a free port
	LDAPSPort     int
	AdminPassword string // if omitted: the server's password environment variable (SAMBA_ADMIN_PASSWORD, LDAP_ADMIN_PASSWORD), then .env
}

// Restore is RestoreWith without options.
func (l *Lab) Restore(ctx context.Context, name string) (SnapshotMeta, error) {
	return l.RestoreWith(ctx, name, RestoreOptions{})
}

// RestoreWith returns the lab's data to the snapshot's state. If the name is omitted, it is chosen from a list.
// If the target container does not exist, it **creates and starts a new one** from the snapshot. By choosing another instance with --instance
// and changing the ports, you can start a second lab in the snapshot's state alongside the running one.
// Before restoring, it verifies the snapshot's checksums (if they are broken, the current data is left untouched).
func (l *Lab) RestoreWith(ctx context.Context, name string, o RestoreOptions) (SnapshotMeta, error) {
	var meta SnapshotMeta
	if err := l.checkDocker(ctx); err != nil {
		return meta, err
	}
	if name == "" {
		var err error
		if name, err = l.choose(); err != nil {
			return meta, err
		}
	}
	if err := ValidateSnapshotName(name); err != nil {
		return meta, err
	}
	meta, err := l.readMeta(name)
	if err != nil {
		return meta, fmt.Errorf("snapshot %q not found (list them with lab snapshots): %w", name, err)
	}
	if err := l.adoptServer(meta); err != nil {
		return meta, err
	}
	if err := l.verifySnapshot(meta); err != nil {
		return meta, err
	}

	labels, exists, err := l.inspectLabels(ctx, l.container())
	if err != nil {
		return meta, err
	}
	if !exists {
		return meta, l.restoreIntoNew(ctx, meta, o)
	}
	if !strings.EqualFold(labels[labelRealm], meta.Domain) {
		return meta, fmt.Errorf("the lab's %s (%s) differs from the snapshot's (%s). Recreate the lab with the same one: lab reset, then lab restore",
			l.srv().DomainLabel, labels[labelRealm], meta.Domain)
	}
	image, err := l.docker(ctx, "container", "inspect", "--format", "{{.Config.Image}}", l.container())
	if err != nil {
		return meta, err
	}

	start := l.Now()
	state, err := l.state(ctx, l.container())
	if err != nil {
		return meta, err
	}
	// From stopping to starting again the run is not interruptible: a half-written volume is worse than waiting.
	critical := context.WithoutCancel(ctx)
	if state != "exited" {
		l.logf("Stopping %s", l.srv().Product)
		if _, err := l.docker(critical, "stop", "-t", stopTimeoutSec, l.container()); err != nil {
			return meta, err
		}
	}
	l.logf("Writing back snapshot %s", name)
	if err := l.writeSnapshot(critical, image, meta); err != nil {
		return meta, err
	}
	l.logf("Starting %s", l.srv().Product)
	if _, err := l.docker(critical, "start", l.container()); err != nil {
		return meta, err
	}
	if err := l.waitHealthy(ctx, l.container()); err != nil {
		return meta, err
	}
	if file, err := ReadEnvFile(l.envPath()); err == nil && file.AdminPassword != "" && file.profile() == l.srv().Profile {
		file.Domain = meta.Domain
		if err := l.smokeTest(ctx, file); err != nil {
			return meta, err
		}
	}
	l.logf("Restored: %s (%s)", name, l.Now().Sub(start).Round(100*time.Millisecond))
	return meta, nil
}

// adoptServer makes the lab the snapshot's kind. When the kind was given or an existing container decided it, a
// snapshot of another kind is refused before anything is touched.
func (l *Lab) adoptServer(meta SnapshotMeta) error {
	srv, err := ServerFor(meta.Profile)
	if err != nil {
		return fmt.Errorf("snapshot %q: %w", meta.Name, err)
	}
	if srv == l.srv() {
		return nil
	}
	if l.serverFixed {
		return fmt.Errorf("snapshot %q is of a %s lab, but this is a %s lab; restore it into another instance (--instance)", meta.Name, srv.Product, l.srv().Product)
	}
	l.Server = srv
	return nil
}

// writeSnapshot empties the volumes and extracts the snapshot's tars into them.
func (l *Lab) writeSnapshot(ctx context.Context, image string, meta SnapshotMeta) error {
	for _, v := range l.srv().Volumes {
		file := v.File
		for _, f := range meta.Files {
			if f.Volume == v.Kind {
				file = f.File
			}
		}
		if err := l.loadVolume(ctx, image, v.Kind, v.Mount, filepath.Join(l.snapshotDir(meta.Name), file), meta.Compression); err != nil {
			return fmt.Errorf("restore failed midway. The volumes are in a partial state, so run lab restore again: %w", err)
		}
	}
	return nil
}

// restoreIntoNew creates and starts a new container from a snapshot when no lab container exists.
// A snapshot is a file on the host and independent of the original volumes, so another lab in the same state can be
// started with a different volume and host port (change the name with --instance; the original lab keeps running).
func (l *Lab) restoreIntoNew(ctx context.Context, meta SnapshotMeta, o RestoreOptions) error {
	image := meta.Image
	if !l.imageExists(ctx, image) {
		return fmt.Errorf("image %s not found; load it (lab load, or ./setup.sh of the offline package), then run again", image)
	}
	file, err := ReadEnvFile(l.envPath())
	if err != nil {
		return err
	}
	srv := l.srv()
	s := Settings{Profile: srv.Profile, Domain: meta.Domain, NetBIOS: meta.NetBIOS, AdminPassword: o.AdminPassword}
	if file.profile() != srv.Profile {
		file = Settings{} // .env of a lab of the other kind says nothing about this one
	}
	if s.AdminPassword == "" {
		s.AdminPassword = l.Getenv(srv.Env.Password)
	}
	if s.AdminPassword == "" {
		s.AdminPassword = file.AdminPassword
	}
	if s.AdminPassword == "" {
		return fmt.Errorf("the admin password is unknown. Specify it with --admin-password or the %s environment variable (the one in effect when the snapshot was taken; it is used to confirm startup completed)", srv.Env.Password)
	}
	if s.LDAPPort, s.LDAPSPort, err = l.pickPorts(o, file); err != nil {
		return err
	}
	if err := l.checkPortsFree(ctx, s); err != nil {
		return err
	}
	nb := ""
	if srv.DomainIdentity {
		if nb, err = s.EffectiveNetBIOS(); err != nil {
			return err
		}
	}

	start := l.Now()
	l.logf("Creating a new lab from snapshot %s: %s (%s %s)", meta.Name, l.container(), srv.DomainLabel, meta.Domain)
	// Not interruptible for the same reason as the in-place restore.
	critical := context.WithoutCancel(ctx)
	if err := l.writeSnapshot(critical, image, meta); err != nil {
		return err
	}
	if err := l.createContainer(critical, image, s, nb, ""); err != nil {
		return err
	}
	if err := l.waitHealthy(ctx, l.container()); err != nil {
		return err
	}
	if err := l.smokeTest(ctx, s); err != nil {
		return err
	}
	if l.isMain() {
		if err := WriteEnvFile(l.envPath(), s); err != nil {
			return fmt.Errorf("cannot write .env: %w", err)
		}
	}
	fmt.Fprintf(l.Out, "\nStarted (%s, %s).\n\n", l.container(), l.Now().Sub(start).Round(100*time.Millisecond))
	if srv.DomainIdentity {
		fmt.Fprintf(l.Out, "  Domain          : %s  (NetBIOS: %s)\n", s.Domain, nb)
	}
	fmt.Fprintf(l.Out, "  Base DN         : %s\n", srv.BaseDN(s.Domain))
	fmt.Fprintf(l.Out, "  LDAP / LDAPS    : ldap://localhost:%d / ldaps://localhost:%d\n", s.LDAPPort, s.LDAPSPort)
	fmt.Fprintf(l.Out, "  Administrator   : %s (the password is the one in effect when the snapshot was taken)\n", srv.AdminDN(s.Domain))
	if !l.isMain() {
		fmt.Fprintf(l.Out, "\nThis is a separate instance, so pass --instance %s to the following commands:\n  lab snapshot / restore / down / reset\n", l.Instance)
	}
	return nil
}

// pickPorts decides the published ports of the new container: the specified ones if given, otherwise
// the default lab uses .env or the default, and other instances pick free ports.
func (l *Lab) pickPorts(o RestoreOptions, file Settings) (int, int, error) {
	ldap, ldaps := o.LDAPPort, o.LDAPSPort
	if l.isMain() {
		if ldap == 0 {
			ldap = file.LDAPPort
		}
		if ldaps == 0 {
			ldaps = file.LDAPSPort
		}
		if ldap == 0 {
			ldap = l.srv().Ports[0]
		}
		if ldaps == 0 {
			ldaps = l.srv().Ports[1]
		}
		return ldap, ldaps, nil
	}
	pick := func(p int) (int, error) {
		if p != 0 {
			return p, nil
		}
		if l.FreePort == nil {
			return 0, errors.New("cannot pick a free port; specify it with --ldap-port / --ldaps-port")
		}
		return l.FreePort()
	}
	var err error
	if ldap, err = pick(ldap); err != nil {
		return 0, 0, err
	}
	if ldaps, err = pick(ldaps); err != nil {
		return 0, 0, err
	}
	if ldap == ldaps {
		return 0, 0, fmt.Errorf("LDAP and LDAPS cannot use the same port (%d)", ldap)
	}
	return ldap, ldaps, nil
}

// checkPortsFree verifies that no other instance with the same prefix uses the same host port.
func (l *Lab) checkPortsFree(ctx context.Context, s Settings) error {
	list, err := l.Instances(ctx)
	if err != nil {
		return err
	}
	for _, in := range list {
		if in.Container == l.container() {
			continue
		}
		for _, p := range []int{in.LDAP, in.LDAPS} {
			if p != 0 && (p == s.LDAPPort || p == s.LDAPSPort) {
				return fmt.Errorf("port %d is used by instance %s (%s); specify a different port with --ldap-port / --ldaps-port", p, in.Instance, in.Container)
			}
		}
	}
	return nil
}

// verifySnapshot verifies file sizes and checksums.
func (l *Lab) verifySnapshot(m SnapshotMeta) error {
	if len(m.Files) != len(l.srv().Volumes) {
		return fmt.Errorf("snapshot %q is missing files", m.Name)
	}
	for _, f := range m.Files {
		got, err := fileSHA256(filepath.Join(l.snapshotDir(m.Name), f.File))
		if err != nil {
			return fmt.Errorf("cannot verify %s of snapshot %q: %w", f.File, m.Name, err)
		}
		if got != f.SHA256 {
			return fmt.Errorf("%s of snapshot %q is corrupted (checksum mismatch). The current data has not been touched", f.File, m.Name)
		}
	}
	return nil
}

// loadVolume empties the volume and extracts the tar into it.
func (l *Lab) loadVolume(ctx context.Context, image, kind, mount, path, compression string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	var r io.Reader = in
	switch compression {
	case "":
	case compressionGzip:
		z, err := gzip.NewReader(in)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		defer z.Close()
		r = z
	default:
		return fmt.Errorf("%s: compressed with %q, which this version does not read", path, compression)
	}
	if _, err := l.docker(ctx, wipeArgs(image, l.volume(kind), mount)...); err != nil {
		return err
	}
	_, err = l.D.Do(ctx, Cmd{Args: tarExtractArgs(image, l.volume(kind), mount), Stdin: r, Stderr: l.Err})
	return err
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGT"[exp])
}
