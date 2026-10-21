package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/wadahiro/ldap-cronin/internal/lab"
)

const labUsage = `Usage: ldap-cronin lab <command> [flags]

Starts a directory server on docker for verification (an AD-compatible Samba4, or OpenLDAP with --profile ldap),
and takes and restores snapshots. Works with docker alone (docker compose is not required).

Commands:
  up                 Load the image and start the server. The domain name (OpenLDAP: the suffix) is decided at this first start
  down               Stop it (the data stays; running up again resumes with the same settings)
  reset              Delete the domain data and settings (.env). Use this to change the domain name
  status             Show the status
  snapshot [name]    Save the current data as a snapshot (named after the date and time if the name is omitted)
  snapshots          List the snapshots
  restore [name]     Return the data to a snapshot's state (choose from a list if the name is omitted).
                     If the target lab does not exist, it is created from the snapshot. By changing --instance and the ports,
                     you can start a second lab in the snapshot's state alongside the running one
  snapshot-rm name   Delete a snapshot

Flags (common):
  --profile ad|ldap      The kind of lab: ad (Samba4 AD, default) or ldap (OpenLDAP). Needed only for up and for a restore
                         that should not take the snapshot's kind; later commands take it from .env or the container
  --state-dir <dir>      Directory where .env is placed (default: .). An AD and an OpenLDAP lab need separate ones
  --snapshot-dir <dir>   Directory where snapshots are placed (default: <state-dir>/snapshots)
  --bundle-dir <dir>     Carry-in bundle (directory containing IMAGE and images/). Searched for automatically if omitted
  --instance <name>      Instance to operate on (down / reset / status / snapshot / restore).
                         Defaults to the default lab. Other instances are created by restore (lowercase alphanumerics and hyphens)

Flags (up):
  --realm <name>            Domain name (e.g. corp.example.local). Can also be set with the AD_REALM environment variable
  --suffix <dn>             OpenLDAP: the suffix (e.g. dc=example,dc=org). Can also be set with LDAP_SUFFIX
  --admin-password <pw>     Administrator password. Prompted for if omitted (auto-generated if left empty).
                            It stays in shell history, so the SAMBA_ADMIN_PASSWORD (OpenLDAP: LDAP_ADMIN_PASSWORD)
                            environment variable is recommended
  --schema-dir <dir>        OpenLDAP: LDIFs applied when the directory is created, in name order: schemas
                            (olcSchemaConfig entries) and cn=config changes (overlays, ACLs, indexes)
  --netbios <name>          NetBIOS domain name (default: the uppercased first label of the domain name; up to 15 characters)
  --ldap-port <n>           Published LDAP port (default 12389; OpenLDAP 13389)
  --ldaps-port <n>          Published LDAPS port (default 12636; OpenLDAP 13636)
  --config <file>           Make the lab of the config's [target.lab] like its source (a server or a dump): for AD the same
                            domain name, NetBIOS name, domain SID and GUID (which [target.lab] native = true needs) and the
                            source's schema extensions; for a generic server an OpenLDAP lab with the source's naming context.
                            Its ports are those of [target] url, its administrator password the target password. A stopped
                            lab is started; run again, it adds what the source's schema has gained. Then check and clone
  --domain-sid <sid>        Create the domain with this SID (S-1-5-21-a-b-c)
  --domain-guid <guid>      Create the domain with this GUID
  --with-sample-source      Also start a disposable clone source loaded with sample data, for checking that things work
  --source-ldap-port <n>    LDAP port of that source (default 11389; OpenLDAP 14389)
  --source-ldaps-port <n>   LDAPS port of that source (default 11636; OpenLDAP 14636)
  --image <name>            Image name to use (default: the bundle's IMAGE file)
  --reload                  Run docker load again even if the image already exists
  --skip-verify             Skip verifying SHA256SUMS

Flags (reset):
  -y, --yes                 Do not ask for confirmation
  --snapshots               Also delete snapshots

Flags (snapshot):
  --note <text>             Note (shown in the list)
  --force                   Overwrite if the same name exists

Flags (restore, when no target container exists and a new one is created):
  --ldap-port <n>           Published LDAP port (for other instances, a free port is chosen if omitted)
  --ldaps-port <n>          Published LDAPS port (same as above)
  --admin-password <pw>     Administrator password (the one in effect when the snapshot was taken; defaults to the environment variable, then .env)

The markers clone writes are part of the data, so diff's rename and move detection keeps working after a restore.

Example: start a second lab in the baseline state on a different port while keeping the current lab running
  ldap-cronin lab restore baseline --instance dev2 --ldaps-port 22636
  ldap-cronin lab restore --instance dev2             # choose from a list
  ldap-cronin lab status                              # show all instances
  ldap-cronin lab reset --instance dev2 -y            # delete only dev2

Settings are saved in .env; from the second run on, values not specified are taken from .env. Precedence: option > environment variable > .env
`

type labCommon struct {
	stateDir, snapshotDir, bundleDir, prefix, instance, profile string
}

func (c *labCommon) register(fs *flag.FlagSet) {
	fs.StringVar(&c.profile, "profile", "", "")
	fs.StringVar(&c.stateDir, "state-dir", ".", "")
	fs.StringVar(&c.snapshotDir, "snapshot-dir", "", "")
	fs.StringVar(&c.bundleDir, "bundle-dir", "", "")
	fs.StringVar(&c.instance, "instance", "", "")
	// For development and testing. Lets several labs, including test labs, run on the same host without colliding.
	fs.StringVar(&c.prefix, "prefix", lab.DefaultPrefix, "")
}

func runLab(ctx context.Context, args []string, out, errW io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(out, labUsage)
		if len(args) == 0 {
			return errors.New("specify a lab command")
		}
		return nil
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("lab "+sub, flag.ContinueOnError)
	fs.SetOutput(errW)
	var c labCommon
	c.register(fs)

	var (
		up        lab.UpOptions
		reset     lab.ResetOptions
		snap      lab.SnapshotOptions
		realm     string
		suffix    string
		password  string
		netbios   string
		cfgPath   string
		domSID    string
		domGUID   string
		ldapPort  int
		ldapsPort int
	)
	switch sub {
	case "up":
		fs.StringVar(&realm, "realm", "", "")
		fs.StringVar(&suffix, "suffix", "", "")
		fs.StringVar(&up.SchemaDir, "schema-dir", "", "")
		fs.StringVar(&password, "admin-password", "", "")
		fs.StringVar(&netbios, "netbios", "", "")
		fs.IntVar(&ldapPort, "ldap-port", 0, "")
		fs.IntVar(&ldapsPort, "ldaps-port", 0, "")
		fs.StringVar(&cfgPath, "config", "", "")
		fs.StringVar(&domSID, "domain-sid", "", "")
		fs.StringVar(&domGUID, "domain-guid", "", "")
		fs.BoolVar(&up.WithSource, "with-sample-source", false, "")
		fs.IntVar(&up.SourceLDAP, "source-ldap-port", 0, "")
		fs.IntVar(&up.SourceLDAPS, "source-ldaps-port", 0, "")
		fs.StringVar(&up.Image, "image", "", "")
		fs.BoolVar(&up.Reload, "reload", false, "")
		fs.BoolVar(&up.SkipVerify, "skip-verify", false, "")
	case "reset":
		fs.BoolVar(&reset.Yes, "y", false, "")
		fs.BoolVar(&reset.Yes, "yes", false, "")
		fs.BoolVar(&reset.Snapshots, "snapshots", false, "")
	case "snapshot":
		fs.StringVar(&snap.Note, "note", "", "")
		fs.BoolVar(&snap.Force, "force", false, "")
	case "restore":
		fs.StringVar(&password, "admin-password", "", "")
		fs.IntVar(&ldapPort, "ldap-port", 0, "")
		fs.IntVar(&ldapsPort, "ldaps-port", 0, "")
	case "down", "status", "snapshots", "snapshot-rm":
	default:
		fmt.Fprint(errW, labUsage)
		return fmt.Errorf("unknown lab command: %q", sub)
	}
	for _, a := range rest {
		if f := strings.SplitN(strings.TrimLeft(a, "-"), "=", 2)[0]; f == "like-source" && a != f {
			return errors.New("--like-source is now --config <file>: lab up --config makes the lab of [target.lab] like the source")
		}
	}
	positional, err := parseInterleaved(fs, rest)
	if err != nil {
		return err
	}
	if len(positional) > 1 {
		return fmt.Errorf("extra arguments: %s", strings.Join(positional[1:], " "))
	}
	name := ""
	if len(positional) == 1 {
		name = positional[0]
	}

	if sub == "up" && cfgPath != "" {
		return labUpFromConfig(ctx, fs, c, cfgPath, up, labFlagsGiven{realm, suffix, password, netbios, domSID, domGUID, ldapPort, ldapsPort}, out, errW)
	}
	l, err := newLab(c, out, errW)
	if err != nil {
		return err
	}
	// status lists every kind; the rest work on one lab, whose kind is known now.
	if sub != "status" && sub != "snapshots" && sub != "snapshot-rm" {
		if err := l.ChooseServer(ctx, c.profile); err != nil {
			return err
		}
	}
	switch sub {
	case "up":
		domain := realm
		switch {
		case realm != "" && suffix != "":
			return errors.New("give --realm (Samba) or --suffix (OpenLDAP), not both")
		case suffix != "":
			if l.Server != lab.OpenLDAP {
				return errors.New("--suffix is for an OpenLDAP lab (--profile ldap); a Samba lab takes --realm")
			}
			domain = suffix
		case realm != "" && l.Server == lab.OpenLDAP:
			return errors.New("--realm is for a Samba lab; an OpenLDAP lab takes --suffix")
		}
		up.Flags = mergeLike(up.Flags, lab.Settings{Domain: domain, AdminPassword: password, NetBIOS: netbios, LDAPPort: ldapPort, LDAPSPort: ldapsPort,
			DomainSID: domSID, DomainGUID: domGUID})
		return l.Up(ctx, up)
	case "down":
		return l.Down(ctx)
	case "reset":
		reset.Confirm = confirm
		return l.Reset(ctx, reset)
	case "status":
		return l.Status(ctx)
	case "snapshot":
		snap.Name = name
		_, err := l.Snapshot(ctx, snap)
		return err
	case "snapshots":
		list, err := l.Snapshots()
		if err != nil {
			return err
		}
		fmt.Fprint(out, lab.FormatSnapshots(list))
		return nil
	case "restore":
		_, err = l.RestoreWith(ctx, name, lab.RestoreOptions{LDAPPort: ldapPort, LDAPSPort: ldapsPort, AdminPassword: password})
		return err
	case "snapshot-rm":
		if name == "" {
			return errors.New("specify the name of the snapshot to delete")
		}
		if err := l.SnapshotRemove(name); err != nil {
			return err
		}
		fmt.Fprintf(out, "==> Deleted: %s\n", name)
		return nil
	}
	return nil
}

// mergeLike overrides the settings read from the source with explicitly given options.
func mergeLike(base, flags lab.Settings) lab.Settings {
	out := base
	for _, f := range []struct {
		dst *string
		v   string
	}{
		{&out.Domain, flags.Domain}, {&out.AdminPassword, flags.AdminPassword}, {&out.NetBIOS, flags.NetBIOS},
		{&out.DomainSID, flags.DomainSID}, {&out.DomainGUID, flags.DomainGUID},
	} {
		if f.v != "" {
			*f.dst = f.v
		}
	}
	out.LDAPPort, out.LDAPSPort = flags.LDAPPort, flags.LDAPSPort
	return out
}

// labFlagsGiven are lab up's settings of a lab, which --config takes from the config instead.
type labFlagsGiven struct {
	realm, suffix, password, netbios, sid, guid string
	ldapPort, ldapsPort                         int
}

// labUpFromConfig is lab up --config: the lab [target.lab] names (its prefix and instance, unless given as flags),
// made like the source of the config, its ports those of [target] url, its Administrator password the target's.
func labUpFromConfig(ctx context.Context, fs *flag.FlagSet, c labCommon, cfgPath string, up lab.UpOptions, given labFlagsGiven, out, errW io.Writer) error {
	if given != (labFlagsGiven{}) || up.WithSource || c.profile != "" || up.SchemaDir != "" {
		return errors.New("lab up --config takes the domain, the ports, the password and the kind of lab from the config ([source], [target] and [target.lab]): leave out --realm, --suffix, --admin-password, --netbios, --domain-sid, --domain-guid, --ldap-port, --ldaps-port, --profile, --schema-dir and --with-sample-source")
	}
	s, err := openSession(ctx, cfgPath)
	if err != nil {
		return err
	}
	defer s.Close()
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if lt := s.Cfg.Target.Lab; lt != nil {
		if lt.Prefix != "" && !set["prefix"] {
			c.prefix = lt.Prefix
		}
		if lt.Instance != "" && !set["instance"] {
			c.instance = lt.Instance
		}
	}
	l, err := newLab(c, out, errW)
	if err != nil {
		return err
	}
	if err := s.LabUp(ctx, l, up, out); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nThe lab %s is like the source of %s (%s).\nNext: ldap-cronin check -config %s, then ldap-cronin clone -config %s\n", l.Name(), cfgPath, s.Cfg.Target.URL, cfgPath, cfgPath)
	return nil
}

// parseInterleaved lets flags appear both before and after the positional argument (the snapshot name).
// The standard flag package stops parsing at the first positional argument, so `lab snapshot baseline --note x` would not work.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func newLab(c labCommon, out, errW io.Writer) (*lab.Lab, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	exeDir := ""
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		exeDir = filepath.Dir(exe)
	}
	instance := c.instance
	if instance == lab.MainInstance {
		instance = ""
	}
	if instance != "" {
		if err := lab.ValidateInstanceName(instance); err != nil {
			return nil, err
		}
	}
	bundle, _ := lab.FindBundleDir(c.bundleDir, cwd, exeDir)
	if c.bundleDir != "" && bundle == "" {
		return nil, fmt.Errorf("--bundle-dir %s has no IMAGE file", c.bundleDir)
	}
	snapshots := c.snapshotDir
	if snapshots == "" {
		snapshots = filepath.Join(c.stateDir, "snapshots")
	}
	return &lab.Lab{
		D: lab.ExecDocker{}, Out: out, Err: errW, Prompt: &terminalPrompter{in: bufio.NewReader(os.Stdin), out: errW},
		Dirs:   lab.Dirs{Bundle: bundle, State: c.stateDir, Snapshots: snapshots},
		Prefix: c.prefix, Instance: instance, FreePort: freePort,
		Version: version, Getenv: os.Getenv, Sleep: time.Sleep, Now: time.Now, HostArch: runtime.GOARCH,
	}, nil
}

// freePort picks one free host port (used when another instance's port is not specified).
func freePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func stdinIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func confirm(prompt string) bool {
	if !stdinIsTerminal() {
		return false
	}
	fmt.Fprint(os.Stderr, prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return isYes(line)
}

// isYes is the answer to a [y/N] question: only y or yes is a yes, so Enter alone (or anything else) is a no.
func isYes(line string) bool {
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

// terminalPrompter is interactive input from the terminal. Without a terminal it does not ask and leaves it to defaults and auto-generation.
type terminalPrompter struct {
	in  *bufio.Reader
	out io.Writer
}

func (p *terminalPrompter) Domain(label, def string) (string, error) {
	if !stdinIsTerminal() {
		return "", nil
	}
	fmt.Fprintf(p.out, "%s%s [%s]: ", strings.ToUpper(label[:1]), label[1:], def)
	line, err := p.in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (p *terminalPrompter) NewPassword() (string, error) {
	if !stdinIsTerminal() {
		return "", nil
	}
	fd := int(os.Stdin.Fd())
	fmt.Fprint(p.out, "Administrator password (leave empty to auto-generate): ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(p.out)
	if err != nil {
		return "", err
	}
	if len(first) == 0 {
		return "", nil
	}
	fmt.Fprint(p.out, "Once more: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(p.out)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("passwords do not match")
	}
	return string(first), nil
}

// Choose prints a numbered list and lets the user pick. Pressing Enter with no input selects def (the first).
func (p *terminalPrompter) Choose(prompt string, items []string, def int) (int, error) {
	if !stdinIsTerminal() {
		return 0, lab.ErrNotInteractive
	}
	fmt.Fprintf(p.out, "%s:\n", prompt)
	for i, it := range items {
		marker := " "
		if i == def {
			marker = "*"
		}
		fmt.Fprintf(p.out, " %s %2d) %s\n", marker, i+1, it)
	}
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(p.out, "Enter a number [%d] (q to quit): ", def+1)
		line, err := p.in.ReadString('\n')
		if err != nil && line == "" {
			return 0, err
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			return def, nil
		case strings.EqualFold(line, "q"):
			return 0, errors.New("aborted")
		}
		if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(items) {
			return n - 1, nil
		}
		fmt.Fprintf(p.out, "Enter a number from 1 to %d\n", len(items))
	}
	return 0, errors.New("could not choose a number")
}
