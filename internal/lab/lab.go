package lab

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// The DC name is baked into the domain data (CN=DC1, DNS records), so always start with the same name.
	// This keeps the host name from drifting when a snapshot is restored.
	dcHostname     = "dc1"
	srcHostname    = "dc2"
	stopTimeoutSec = "60"

	healthWait    = 2 * time.Second
	healthRetries = 90

	labelPrefix   = "ldap-cronin."
	labelRealm    = labelPrefix + "realm"
	labelLDAP     = labelPrefix + "ldap-port"
	labelLDAPS    = labelPrefix + "ldaps-port"
	labelNB       = labelPrefix + "netbios"
	labelInstance = labelPrefix + "instance"
	labelSID      = labelPrefix + "domain-sid"
	labelGUID     = labelPrefix + "domain-guid"
	labelLab      = labelPrefix + "lab" // lab prefix; lets containers with the same prefix be listed together

	// MainInstance is the name of the default lab that up creates.
	MainInstance = "main"
)

// Prompter is interactive input. Without a terminal, defaults or auto-generated values are used.
type Prompter interface {
	Realm(def string) (string, error)
	// NewPassword asks for the admin password. An empty string means auto-generate.
	NewPassword() (string, error)
	// Choose lets the user pick one of items by number and returns the chosen index (def is the default). Without a terminal it returns ErrNotInteractive.
	Choose(prompt string, items []string, def int) (int, error)
}

// Dirs are the directories the lab uses.
type Dirs struct {
	Bundle    string // carry-in bundle (IMAGE, images/, SHA256SUMS); empty if absent
	State     string // where .env is placed
	Snapshots string // where snapshots are placed
}

type Lab struct {
	D        Docker
	Out, Err io.Writer
	Prompt   Prompter
	Dirs     Dirs
	Prefix   string // name prefix for containers and volumes
	// Instance is the instance being operated on. Empty means the default lab (main).
	// A second instance started from a snapshot on different ports is told apart by its own name.
	Instance string
	// FreePort returns a free host port (used when an instance's ports are not specified).
	FreePort func() (int, error)
	Version  string
	Getenv   func(string) string
	Sleep    func(time.Duration)
	Now      func() time.Time
	HostArch string // "amd64" / "arm64". Used to warn when it differs from the image architecture
}

func (l *Lab) instanceName() string {
	if l.Instance == "" {
		return MainInstance
	}
	return l.Instance
}

func (l *Lab) isMain() bool { return l.instanceName() == MainInstance }

// Lab container and volume names. main is <prefix>-ad; other instances are <prefix>-ad-<name>.
func (l *Lab) container() string {
	if l.isMain() {
		return l.Prefix + "-ad"
	}
	return l.Prefix + "-ad-" + l.Instance
}

func (l *Lab) sourceContainer() string { return l.Prefix + "-ad-src" }

func (l *Lab) volume(kind string) string { return l.container() + "-" + kind }

func (l *Lab) envPath() string { return filepath.Join(l.Dirs.State, envFileName) }

var instanceNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// ValidateInstanceName checks the instance name format (it becomes part of the container and volume names).
func ValidateInstanceName(name string) error {
	if name == MainInstance || !instanceNamePattern.MatchString(name) {
		return fmt.Errorf("invalid instance name: %q (lowercase alphanumerics and hyphens, up to 31 characters; %q is the name of the default lab and cannot be used)", name, MainInstance)
	}
	return nil
}

func (l *Lab) logf(format string, a ...any) { fmt.Fprintf(l.Out, "==> "+format+"\n", a...) }
func (l *Lab) warnf(format string, a ...any) {
	fmt.Fprintf(l.Err, "warning: "+format+"\n", a...)
}

func (l *Lab) docker(args ...string) (string, error) { return l.D.Do(Cmd{Args: args}) }

// UpOptions are the options for up.
type UpOptions struct {
	Flags       Settings
	WithSource  bool // also start a disposable clone source loaded with sample data
	SourceLDAP  int
	SourceLDAPS int
	Image       string // explicit image name (takes precedence over the IMAGE file)
	Reload      bool
	SkipVerify  bool
}

func (l *Lab) checkDocker() error {
	if _, err := l.docker("info", "--format", "{{.ServerVersion}}"); err != nil {
		return fmt.Errorf("cannot connect to the docker daemon (docker is missing, not running, or you lack permission): %w", err)
	}
	return nil
}

// Up loads the image, starts the Samba4 AD, and verifies that it works.
// The domain name is decided at this point (it is not baked into the image).
func (l *Lab) Up(o UpOptions) error {
	if !l.isMain() {
		return fmt.Errorf("up starts the default lab. Create other instances from a snapshot: lab restore --instance %s", l.Instance)
	}
	if err := l.checkDocker(); err != nil {
		return err
	}
	image, err := l.prepareImage(o)
	if err != nil {
		return err
	}
	s, generated, err := l.resolveSettings(o.Flags)
	if err != nil {
		return err
	}
	nb, err := s.EffectiveNetBIOS()
	if err != nil {
		return err
	}
	if err := WriteEnvFile(l.envPath(), s); err != nil {
		return fmt.Errorf("cannot write .env: %w", err)
	}

	l.logf("Starting Samba4 AD (domain: %s / NetBIOS: %s)", s.Realm, nb)
	if err := l.startLab(image, s, nb); err != nil {
		return err
	}
	if o.WithSource {
		if err := l.startSource(image, s, nb, o); err != nil {
			return err
		}
	}
	if err := l.smokeTest(s); err != nil {
		return err
	}
	l.summary(s, nb, generated, o)
	return nil
}

// prepareImage verifies the bundle's integrity and docker-loads the image if it is missing. It returns the image name.
func (l *Lab) prepareImage(o UpOptions) (string, error) {
	name := o.Image
	hasBundle := l.Dirs.Bundle != ""
	if hasBundle && !o.SkipVerify {
		if _, err := os.Stat(filepath.Join(l.Dirs.Bundle, sumsFileName)); err == nil {
			l.logf("Verifying file integrity (%s)", sumsFileName)
			if err := VerifyChecksums(l.Dirs.Bundle); err != nil {
				return "", fmt.Errorf("%w (use --skip-verify to skip)", err)
			}
		} else {
			l.warnf("%s not found; skipping verification", sumsFileName)
		}
	}
	if name == "" && hasBundle {
		b, err := os.ReadFile(filepath.Join(l.Dirs.Bundle, imageFileName))
		if err != nil {
			return "", err
		}
		name = strings.TrimSpace(string(b))
	}
	if name == "" {
		return "", errors.New("cannot determine the image: the carry-in bundle (IMAGE file) was not found. Specify the image name with --image, or run from the bundle directory")
	}

	exists := l.imageExists(name)
	if !exists || o.Reload {
		tar := ""
		if hasBundle {
			tar = filepath.Join(l.Dirs.Bundle, imageTarPath)
			if _, err := os.Stat(tar); err != nil {
				tar = ""
			}
		}
		switch {
		case tar != "":
			l.logf("Loading image: %s", imageTarPath)
			if _, err := l.docker("load", "-i", tar); err != nil {
				return "", err
			}
		case exists:
			l.warnf("%s not found, so the image cannot be reloaded; using the existing image", imageTarPath)
		default:
			return "", fmt.Errorf("image %s is missing and %s to load it from was not found (build it with make image, or run from the bundle directory)", name, imageTarPath)
		}
	} else {
		l.logf("Image already present: %s", name)
	}
	if arch, err := l.docker("image", "inspect", "--format", "{{.Architecture}}", name); err == nil && l.HostArch != "" && arch != l.HostArch {
		l.warnf("Image architecture (%s) differs from this host (%s); it may not start", arch, l.HostArch)
	}
	return name, nil
}

func (l *Lab) imageExists(name string) bool {
	_, err := l.docker("image", "inspect", "--format", "{{.Id}}", name)
	return err == nil
}

// resolveSettings decides settings from options, environment variables and .env, and asks for anything missing (defaults or auto-generation when there is no terminal).
func (l *Lab) resolveSettings(flags Settings) (Settings, bool, error) {
	file, err := ReadEnvFile(l.envPath())
	if err != nil {
		return Settings{}, false, err
	}
	s := Resolve(flags, file, l.Getenv)
	if s.LDAPPort == 0 {
		s.LDAPPort = DefaultLDAPPort
	}
	if s.LDAPSPort == 0 {
		s.LDAPSPort = DefaultLDAPSPort
	}
	if s.Realm == "" {
		r, err := l.Prompt.Realm(DefaultRealm)
		if err != nil {
			return s, false, err
		}
		if r == "" {
			r = DefaultRealm
		}
		s.Realm = r
	}
	if err := ValidateRealm(s.Realm); err != nil {
		return s, false, err
	}
	if err := ValidateDomainIdentity(s.DomainSID, s.DomainGUID); err != nil {
		return s, false, err
	}
	generated := false
	if s.AdminPassword == "" {
		pw, err := l.Prompt.NewPassword()
		if err != nil {
			return s, false, err
		}
		if pw == "" {
			if pw, err = GeneratePassword(); err != nil {
				return s, false, err
			}
			generated = true
		}
		s.AdminPassword = pw
	}
	return s, generated, nil
}

// runArgs builds the docker run arguments. The password is passed via the environment (-e NAME), not in the arguments.
func (l *Lab) runArgs(name, hostname, image string, s Settings, nb string, ldap, ldaps int, extra ...string) Cmd {
	args := []string{"run", "-d", "--name", name, "--hostname", hostname, "--cap-add", "SYS_ADMIN",
		"-e", "AD_REALM=" + s.Realm, "-e", "SAMBA_ADMIN_PASSWORD", "-e", "SAMBA_DOMAIN=" + nb,
		"-p", fmt.Sprintf("%d:389", ldap), "-p", fmt.Sprintf("%d:636", ldaps),
		"--health-cmd", "test -f /tmp/ad-ready", "--health-interval", "3s", "--health-retries", "60"}
	// The SID and GUID are not secret, so pass them with values. They are only used when the domain is created (first start).
	if s.DomainSID != "" {
		args = append(args, "-e", envSID+"="+s.DomainSID)
	}
	if s.DomainGUID != "" {
		args = append(args, "-e", envGUID+"="+s.DomainGUID)
	}
	args = append(args, extra...)
	args = append(args, image)
	return Cmd{Args: args, Env: []string{"SAMBA_ADMIN_PASSWORD=" + s.AdminPassword}}
}

// startLab starts the clone target container. If it already exists, it is reused only when the settings match.
func (l *Lab) startLab(image string, s Settings, nb string) error {
	name := l.container()
	labels, exists, err := l.inspectLabels(name)
	if err != nil {
		return err
	}
	if exists {
		if err := checkLabels(labels, s); err != nil {
			return err
		}
		state, err := l.state(name)
		if err != nil {
			return err
		}
		if state == "healthy" || state == "starting" {
			l.logf("Already running: %s (to recreate it, run ./setup.sh reset)", name)
			return nil
		}
		l.logf("Resuming stopped container: %s", name)
		if _, err := l.docker("start", name); err != nil {
			return err
		}
		return l.waitHealthy(name)
	}
	l.logf("Starting: %s", name)
	if err := l.createContainer(image, s, nb); err != nil {
		return err
	}
	return l.waitHealthy(name)
}

// createContainer creates the lab container with docker run (it does not wait for healthy).
// The domain, ports and instance name are kept in labels, to detect configuration mismatches and to list instances later.
func (l *Lab) createContainer(image string, s Settings, nb string) error {
	extra := []string{
		"-v", l.volume("private") + ":/var/lib/samba", "-v", l.volume("etc") + ":/etc/samba",
		"--label", labelRealm + "=" + s.Realm,
		"--label", labelLDAP + "=" + strconv.Itoa(s.LDAPPort),
		"--label", labelLDAPS + "=" + strconv.Itoa(s.LDAPSPort),
		"--label", labelNB + "=" + nb,
		"--label", labelInstance + "=" + l.instanceName(),
		"--label", labelLab + "=" + l.Prefix,
	}
	if s.DomainSID != "" {
		extra = append(extra, "--label", labelSID+"="+s.DomainSID)
	}
	if s.DomainGUID != "" {
		extra = append(extra, "--label", labelGUID+"="+s.DomainGUID)
	}
	if _, err := l.D.Do(l.runArgs(l.container(), dcHostname, image, s, nb, s.LDAPPort, s.LDAPSPort, extra...)); err != nil {
		return fmt.Errorf("docker run failed (the port may be in use; change it with --ldap-port / --ldaps-port): %w", err)
	}
	return nil
}

// startSource starts a clone source loaded with sample data, for checking that the tool works. Its data is not persisted.
func (l *Lab) startSource(image string, s Settings, nb string, o UpOptions) error {
	name := l.sourceContainer()
	if _, exists, err := l.inspectLabels(name); err != nil {
		return err
	} else if exists {
		if _, err := l.docker("rm", "-f", name); err != nil {
			return err
		}
	}
	ldap, ldaps := o.SourceLDAP, o.SourceLDAPS
	if ldap == 0 {
		ldap = DefaultSrcLDAP
	}
	if ldaps == 0 {
		ldaps = DefaultSrcLDAPS
	}
	l.logf("Starting: %s (clone source for testing; loaded with sample data, data is not persisted)", name)
	if _, err := l.D.Do(l.runArgs(name, srcHostname, image, s, nb, ldap, ldaps, "-e", "SEED_SAMPLE_DATA=true")); err != nil {
		return fmt.Errorf("docker run failed (the port may be in use): %w", err)
	}
	return l.waitHealthy(name)
}

// inspectLabels returns the container's labels. If the container does not exist, exists=false.
func (l *Lab) inspectLabels(name string) (labels map[string]string, exists bool, err error) {
	out, err := l.docker("container", "inspect", "--format", "{{json .Config.Labels}}", name)
	if err != nil {
		if IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	labels = map[string]string{}
	if out != "" && out != "null" {
		if err := json.Unmarshal([]byte(out), &labels); err != nil {
			return nil, true, fmt.Errorf("cannot read container labels: %w", err)
		}
	}
	return labels, true, nil
}

// checkLabels verifies that the existing container's settings match the current ones. On mismatch it fails without destroying anything.
func checkLabels(labels map[string]string, s Settings) error {
	var diffs []string
	if r := labels[labelRealm]; !strings.EqualFold(r, s.Realm) {
		diffs = append(diffs, fmt.Sprintf("domain %s (specified: %s)", r, s.Realm))
	}
	if p := labels[labelLDAP]; p != strconv.Itoa(s.LDAPPort) {
		diffs = append(diffs, fmt.Sprintf("LDAP port %s (specified: %d)", p, s.LDAPPort))
	}
	if p := labels[labelLDAPS]; p != strconv.Itoa(s.LDAPSPort) {
		diffs = append(diffs, fmt.Sprintf("LDAPS port %s (specified: %d)", p, s.LDAPSPort))
	}
	if len(diffs) > 0 {
		return fmt.Errorf("the existing container has different settings: %s. Its data has been kept. To recreate it, delete the data with ./setup.sh reset and start over", strings.Join(diffs, ", "))
	}
	return nil
}

// state returns the container state (healthy / starting / unhealthy / running / exited).
func (l *Lab) state(name string) (string, error) {
	return l.docker("container", "inspect", "--format",
		"{{if .State.Running}}{{if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}{{else}}exited{{end}}", name)
}

// waitHealthy waits until the health check reports healthy. If the container stops, it prints the logs and fails.
func (l *Lab) waitHealthy(name string) error {
	for i := 0; i < healthRetries; i++ {
		st, err := l.state(name)
		if err != nil {
			return err
		}
		switch st {
		case "healthy":
			return nil
		case "exited":
			l.dumpLogs(name)
			return errors.New("startup failed. If you specified a different domain name from the existing data, delete it with ./setup.sh reset and start over")
		}
		l.Sleep(healthWait)
	}
	l.dumpLogs(name)
	return fmt.Errorf("%s did not become healthy (waited %v)", name, healthWait*healthRetries)
}

func (l *Lab) dumpLogs(name string) {
	_, _ = l.D.Do(Cmd{Args: []string{"logs", "--tail", "40", name}, Stdout: l.Err, Stderr: l.Err})
}

// smokeTest verifies that an admin search works over LDAPS. The password is passed via the environment.
func (l *Lab) smokeTest(s Settings) error {
	base := BaseDN(s.Realm)
	l.logf("Smoke test (searching as admin over LDAPS)")
	_, err := l.D.Do(Cmd{
		Args: []string{"exec", "-e", "LDAPTLS_REQCERT=never", "-e", "LDAP_PW", l.container(), "sh", "-c",
			`ldapsearch -x -H ldaps://127.0.0.1 -D "CN=Administrator,CN=Users,` + base + `" -w "$LDAP_PW" -b "` + base + `" -s base dn`},
		Env: []string{"LDAP_PW=" + s.AdminPassword},
	})
	if err != nil {
		return fmt.Errorf("LDAPS search failed: %w", err)
	}
	return nil
}

func (l *Lab) summary(s Settings, nb string, generated bool, o UpOptions) {
	base := BaseDN(s.Realm)
	w := l.Out
	fmt.Fprintf(w, "\nStarted.\n\n")
	fmt.Fprintf(w, "  Domain          : %s  (NetBIOS: %s)\n", s.Realm, nb)
	fmt.Fprintf(w, "  Base DN         : %s\n", base)
	fmt.Fprintf(w, "  Administrator   : CN=Administrator,CN=Users,%s\n", base)
	fmt.Fprintf(w, "  LDAP / LDAPS    : ldap://localhost:%d / ldaps://localhost:%d  (self-signed certificate)\n", s.LDAPPort, s.LDAPSPort)
	if o.WithSource {
		ldaps := o.SourceLDAPS
		if ldaps == 0 {
			ldaps = DefaultSrcLDAPS
		}
		fmt.Fprintf(w, "  Clone source    : ldaps://localhost:%d  (test; loaded with sample data. Same administrator and password)\n", ldaps)
	}
	if generated {
		fmt.Fprintf(w, "  Admin password  : %s   <- auto-generated; also saved in .env\n", s.AdminPassword)
	} else {
		fmt.Fprintf(w, "  Admin password  : (the one you specified; saved in .env)\n")
	}
	fmt.Fprintf(w, "\nExample tool configuration ([target] in config.toml):\n\n")
	fmt.Fprintf(w, "  [target]\n  url = \"ldaps://localhost:%d\"\n  bind_dn = \"CN=Administrator,CN=Users,%s\"\n  insecure_skip_verify = true   # because of the self-signed certificate\n\n", s.LDAPSPort, base)
	fmt.Fprintf(w, "After cloning, you can take a snapshot so you can always roll back:\n\n")
	fmt.Fprintf(w, "  ldap-cronin clone -config config.toml\n  ldap-cronin lab snapshot            # take\n  ldap-cronin lab restore             # roll back (a few seconds)\n\n")
	fmt.Fprintf(w, "Stop: lab down    Delete everything including domain data: lab reset\n")
}

// Down stops the container. The data stays in the volume, and running up again resumes with the same settings.
func (l *Lab) Down() error {
	if err := l.checkDocker(); err != nil {
		return err
	}
	if l.isMain() {
		if _, exists, err := l.inspectLabels(l.sourceContainer()); err != nil {
			return err
		} else if exists {
			if _, err := l.docker("rm", "-f", l.sourceContainer()); err != nil {
				return err
			}
		}
	}
	_, exists, err := l.inspectLabels(l.container())
	if err != nil {
		return err
	}
	if !exists {
		l.logf("Not running: %s", l.container())
		return nil
	}
	if _, err := l.docker("stop", "-t", stopTimeoutSec, l.container()); err != nil {
		return err
	}
	if l.isMain() {
		l.logf("Stopped (the data stays in the volume; running up again resumes with the same settings)")
	} else {
		l.logf("Stopped: %s (the data stays in the volume; to resume, docker start %s)", l.container(), l.container())
	}
	return nil
}

// ResetOptions are the options for reset.
type ResetOptions struct {
	Yes       bool
	Snapshots bool // also delete snapshots
	Confirm   func(prompt string) bool
}

// Reset deletes the container, the volume (domain data) and .env. Snapshots are kept by default.
func (l *Lab) Reset(o ResetOptions) error {
	if err := l.checkDocker(); err != nil {
		return err
	}
	if !o.Yes {
		if o.Confirm == nil || !o.Confirm("This deletes the domain data (all users, groups, etc.). Continue? [y/N]: ") {
			return errors.New("aborted (pass -y if confirmation is not possible)")
		}
	}
	containers := []string{l.container()}
	if l.isMain() {
		containers = []string{l.sourceContainer(), l.container()}
	}
	for _, c := range containers {
		if _, exists, err := l.inspectLabels(c); err != nil {
			return err
		} else if exists {
			if _, err := l.docker("rm", "-f", c); err != nil {
				return err
			}
		}
	}
	for _, kind := range []string{"private", "etc"} {
		if _, err := l.docker("volume", "rm", "-f", l.volume(kind)); err != nil {
			return err
		}
	}
	if !l.isMain() {
		// Delete only the other instance. The default lab's .env and the snapshots are left untouched.
		l.logf("Deleted instance %s (container and volume)", l.Instance)
		return nil
	}
	if err := os.Remove(l.envPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	if o.Snapshots {
		list, err := l.Snapshots()
		if err != nil {
			return err
		}
		for _, sn := range list {
			if err := l.SnapshotRemove(sn.Name); err != nil {
				return err
			}
		}
	}
	l.logf("Deleted the data and settings (.env). Snapshots %s", map[bool]string{true: "deleted", false: "kept (lab restore brings them back into a lab recreated with the same domain name)"}[o.Snapshots])
	return nil
}

// InstanceInfo is a running (or stopped) lab instance.
type InstanceInfo struct {
	Instance  string
	Container string
	State     string
	Realm     string
	LDAP      int
	LDAPS     int
}

// Instances lists the lab instances with the same prefix (the default lab and those created from snapshots).
func (l *Lab) Instances() ([]InstanceInfo, error) {
	format := "{{.Names}}\t{{.State}}\t{{.Label \"" + labelInstance + "\"}}\t{{.Label \"" + labelRealm + "\"}}\t{{.Label \"" +
		labelLDAP + "\"}}\t{{.Label \"" + labelLDAPS + "\"}}"
	out, err := l.docker("container", "ls", "-a", "--filter", "label="+labelLab+"="+l.Prefix, "--format", format)
	if err != nil {
		return nil, err
	}
	var list []InstanceInfo
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 6 {
			continue
		}
		ldap, _ := strconv.Atoi(f[4])
		ldaps, _ := strconv.Atoi(f[5])
		list = append(list, InstanceInfo{Container: f[0], State: f[1], Instance: f[2], Realm: f[3], LDAP: ldap, LDAPS: ldaps})
	}
	sort.SliceStable(list, func(i, j int) bool {
		if (list[i].Instance == MainInstance) != (list[j].Instance == MainInstance) {
			return list[i].Instance == MainInstance // put the default lab first
		}
		return list[i].Instance < list[j].Instance
	})
	return list, nil
}

// Status shows the lab state (the default lab and instances created from snapshots) and the snapshot count.
func (l *Lab) Status() error {
	if err := l.checkDocker(); err != nil {
		return err
	}
	list, err := l.Instances()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(l.Out, "Lab: none (create one with up)")
	}
	for _, in := range list {
		fmt.Fprintf(l.Out, "Lab %-10s %-24s state=%-8s domain=%s  LDAP=%d LDAPS=%d\n", in.Instance, in.Container, in.State, in.Realm, in.LDAP, in.LDAPS)
	}
	snaps, err := l.Snapshots()
	if err != nil {
		return err
	}
	fmt.Fprintf(l.Out, "Snapshots: %d (%s)\n", len(snaps), l.Dirs.Snapshots)
	return nil
}
