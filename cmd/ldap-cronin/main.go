package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/lab"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/progress"
	"github.com/wadahiro/ldap-cronin/internal/prompt"
)

const (
	envSourcePassword = "LDAP_CRONIN_SOURCE_PASSWORD"
	envTargetPassword = "LDAP_CRONIN_TARGET_PASSWORD"
	envUserPassword   = "LDAP_CRONIN_USER_PASSWORD"
	exitError         = 2
)

const usage = `Usage: ldap-cronin <command> [flags]

Commands, in the order they are used:
  dump          Read a source (read only) into one LDIF file that check, clone, diff and the rest take as [source]
                ldif, so they never connect to production. Takes no config file: -url, -bind-dn, -base-dn, -o
  lab           Start an AD-compatible Samba4 on docker for verification, and take and restore snapshots (lab help)
  check         Say what clone would do, writing nothing: the attributes it would leave behind (with the
                [attributes] line that copies them), what the target's schema lacks and refuses, the next steps.
                Exit code 1 when clone would refuse to start
  schema        Print as LDIF the attributes and classes the source's schema has and the target's lacks (AD); -apply
                writes them to the target instead
  clone         Add or update the source directory's OUs, groups, users, computers and contacts in the target (AD or generic LDAP)
  diff          Compare the source and the target (exit code 1 if there are differences)
  list-attrs    Show the default allow lists per object type (-profile ad|ldap), without reading anything
  version       Show the version

Flags (clone/diff):
  -config <file>   TOML config file (default: config.toml)
  -dry-run         (clone only) Do not connect to the target; print what would be done as LDIF
  -with-password   (clone -dry-run) The LDIF carries the users' fixed password, and on AD the userAccountControl set
                   after it, so ldapmodify alone gives users that can log on; without it they are comments
  -y, -yes         (clone only) Write without asking: clone shows the target (a lab: what it does to it) and the
                   source and asks [y/N] first
  -format <f>      (diff only) text (default), or json: JSON Lines, one object per difference, then the summary
  -max-values <n>  (diff only, text) Show at most n values per direction of a multi-valued difference (default: 0, all)
  -progress <m>    auto (default): on a terminal a status kept at the bottom of the screen (phase, count, rate, time
                   left) while the log scrolls above it, elsewhere a line every 10s; plain: the lines; off

A lab target ([target.lab] in the config): clone creates the lab like the source if it is missing (the same domain,
and on AD the same domain SID and GUID), starts it if stopped, gives its schema the source's definitions it lacks,
then clones; with native = true it writes Samba's database directly, keeping objectGUID and objectSid (lab help).

Flags (dump):
  -url <url>, -bind-dn <dn>   The source (the password: LDAP_CRONIN_SOURCE_PASSWORD, or asked)
  -base-dn <dn>    What to dump: the entries under it, the root of its naming context and the entries in between, the
                   entries outside it its references name (and their parents), the schema; credentials never.
                   Repeat it for several OUs (none below another), as [scope] base_dn lists them
  -o <file>        The dump (.gz: compressed). Written to a temporary file and renamed when complete
  -mask <a,b>      Attributes masked in the file itself (-mask-value, default ********)
  -ca-file <file>, -insecure-skip-verify, -start-tls, -timeout <d>   The connection, as in [source]

Flags (check):
  -config <file>   TOML config file (default: config.toml)
  -no-target       Read the source alone (a machine that reaches only production, a dump before the lab exists)
  -attrs           Also list every attribute of every kind, held or named, and what clone does with it
  -progress <m>    As for clone and diff: the kind being read and how many entries so far

Flags (schema):
  -config <file>   TOML config file (default: config.toml); reads the schemas of [source] and [target]
  -apply           Write the changes to the target (a schema change cannot be undone in AD); without it, the LDIF goes
                   to stdout, for ldapmodify or ldifde, and the summary to stderr
  -y, -yes         With -apply: write without asking (it shows the target and asks [y/N] first)
`

// version is embedded at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	stopOnSignal(cancel, os.Stderr)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	cancel()
	os.Exit(code)
}

// stopOnSignal turns the first Ctrl-C (or SIGTERM) into a cancellation, so the run stops at its next operation and
// its deferred cleanup still runs: the mapping is written and a lab stopped for a native import is resumed.
// The handler is then removed, so a second Ctrl-C ends the process at once for someone who does not want to wait.
func stopOnSignal(cancel context.CancelFunc, warn io.Writer) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		signal.Stop(sig)
		fmt.Fprintln(warn, "\ninterrupted: finishing the operations in progress (press Ctrl-C again to abort at once)")
		cancel()
	}()
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	var err error
	code := 0
	switch args[0] {
	case "clone":
		err = runClone(ctx, args[1:], stdout)
	case "diff":
		code, err = runDiff(ctx, args[1:], stdout)
	case "check":
		code, err = runCheck(ctx, args[1:], stdout)
	case "list-attrs":
		err = listAttrs(ctx, args[1:], stdout)
	case "schema":
		err = runSchema(ctx, args[1:], stdout, stderr)
	case "dump":
		err = runDump(ctx, args[1:], stderr)
	case "lab":
		err = runLab(ctx, args[1:], stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "ldap-cronin", version)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return exitError
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "interrupted")
		return exitError
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	return code
}

// secrets prompts for passwords without echo, or takes them from the environment for non-interactive use.
// They never come from the config file or the command line.
var secrets = app.Secrets{
	SourceBind: func() (string, error) { return prompt.Password("source bind password", envSourcePassword, false) },
	TargetBind: func() (string, error) { return prompt.Password("target bind password", envTargetPassword, false) },
	UserPassword: func() (string, error) {
		return prompt.Password("fixed password for cloned users", envUserPassword, true)
	},
}

// dial is replaced in tests by in-memory directories.
var dial app.Dialer = app.LDAP

func openSession(ctx context.Context, cfgPath string) (*app.Session, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	s, err := app.Open(ctx, cfg, secretsFor(cfg), dial, os.Stderr)
	if err != nil {
		return nil, err
	}
	s.ConfigPath = cfgPath
	return s, nil
}

// secretsFor takes the fixed password of the cloned users from [accounts] fixed_password when the environment does not
// give one, instead of asking. The bind passwords are never in the config.
func secretsFor(cfg *config.Config) app.Secrets {
	s := secrets
	if fixed := cfg.Accounts.FixedPassword; fixed != "" {
		s.UserPassword = func() (string, error) {
			if v := os.Getenv(envUserPassword); v != "" {
				return v, nil
			}
			return fixed, nil
		}
	}
	return s
}

func runClone(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("clone", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.toml", "config file")
	dryRun := fs.Bool("dry-run", false, "print LDIF instead of writing")
	withPassword := fs.Bool("with-password", false, "with -dry-run: the LDIF carries the users' fixed password and what follows it, so ldapmodify alone completes them")
	yes := yesFlag(fs)
	progressMode := progressFlag(fs)
	for _, a := range args {
		switch strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-") {
		case "native", "fast-password", "lab-prefix", "lab-instance":
			return fmt.Errorf("%s moved to the config: [target.lab] (native, fast_password, prefix, instance)", a)
		}
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *withPassword && !*dryRun {
		return errors.New("-with-password is for -dry-run: clone itself always sets the password")
	}
	mode, err := progress.ParseMode(*progressMode)
	if err != nil {
		return err
	}
	s, err := openSession(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer s.Close()
	askBeforeWriting(s, *yes)
	s.WithPassword = *withPassword
	lt := s.Cfg.Target.Lab
	if lt.OnEC2() {
		lt = nil // a Windows Server reached through its tunnel at [target] url: written as any server is
	}
	if *dryRun && s.Cfg.NativeLab() != nil {
		return errors.New("[target.lab] native = true writes the lab's database directly, which produces no LDIF: a dry-run is for a clone over LDAP")
	}

	// The dry-run stdout carries only LDIF that can be passed straight to ldapmodify; progress logs go to stderr.
	log := out
	title := "clone → " + s.Cfg.Target.URL
	switch {
	case lt != nil && !*dryRun:
		title = "clone → the lab " + s.Cfg.Target.URL
	case *dryRun:
		log, title = os.Stderr, "clone -dry-run (LDIF)"
	}
	display, bar := progress.Start(mode, os.Stderr, title)
	defer display.Stop()
	s.Progress, s.Warn = bar, display.Writer(s.Warn)
	out, log = display.Writer(out), display.Writer(log)

	var report *clone.Report
	if lt != nil && !*dryRun {
		l, lerr := labOf(lt, out, display.Writer(os.Stderr))
		if lerr != nil {
			return lerr
		}
		report, err = s.CloneLab(ctx, l, out, log)
	} else {
		report, err = s.Clone(ctx, *dryRun, out, log)
	}
	display.Stop()
	if report != nil {
		report.WriteSummary(log)
	}
	return err
}

// labOf is the lab [target.lab] names, with the lab commands' defaults (its state in the current directory).
func labOf(lt *config.Lab, out, errW io.Writer) (*lab.Lab, error) {
	if lt.OnEC2() {
		return nil, errors.New("[target.lab] platform = \"ec2\": the lab is a Windows Server reached through its tunnel at [target] url, not a docker lab")
	}
	c := labCommon{stateDir: ".", prefix: lt.Prefix, instance: lt.Instance}
	if c.prefix == "" {
		c.prefix = lab.DefaultPrefix
	}
	return newLab(c, out, errW)
}

// progressFlag is -progress: how clone and diff show how far they are.
func progressFlag(fs *flag.FlagSet) *string {
	return fs.String("progress", string(progress.Auto), "auto (a status kept at the bottom of a terminal, a line every 10s elsewhere), plain (the lines) or off")
}

// yesFlag is -y (and -yes): write to the target without asking first, for scripts.
func yesFlag(fs *flag.FlagSet) *bool {
	yes := fs.Bool("y", false, "write to the target without asking first")
	fs.BoolVar(yes, "yes", false, "same as -y")
	return yes
}

// askBeforeWriting makes the session ask on the terminal before its first write to the target, unless -y. The
// answer is No unless y or yes is typed: Enter alone, or no terminal to ask on, writes nothing.
func askBeforeWriting(s *app.Session, yes bool) {
	if !yes {
		s.Confirm = confirm
	}
}

func runDiff(ctx context.Context, args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.toml", "config file")
	maxValues := fs.Int("max-values", diff.DefaultMaxValues, "max values shown per direction for multi-valued attributes in the text output (0 = all, the default)")
	format := fs.String("format", "text", "output format: text, or json (JSON Lines: one object per difference, then the summary)")
	progressMode := progressFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if *format != "text" && *format != "json" {
		return 0, fmt.Errorf("-format %q: use text or json", *format)
	}
	mode, err := progress.ParseMode(*progressMode)
	if err != nil {
		return 0, err
	}
	s, err := openSession(ctx, *cfgPath)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	display, bar := progress.Start(mode, os.Stderr, "diff "+s.Cfg.Source.URL+" ↔ "+s.Cfg.Target.URL)
	defer display.Stop()
	s.Progress, s.Warn = bar, display.Writer(s.Warn)
	return s.Diff(ctx, app.DiffOutput{JSON: *format == "json", MaxValues: *maxValues}, display.Writer(out))
}

func runSchema(ctx context.Context, args []string, out, log io.Writer) error {
	fs := flag.NewFlagSet("schema", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.toml", "config file")
	apply := fs.Bool("apply", false, "write the changes to the target instead of printing them (cannot be undone in AD)")
	yes := yesFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := openSession(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer s.Close()
	askBeforeWriting(s, *yes)
	if *apply {
		// The progress is the output then, and stays apart from the error on stderr.
		log = out
	}
	return s.Schema(ctx, *apply, out, log)
}

func runDump(ctx context.Context, args []string, log io.Writer) error {
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	url := fs.String("url", "", "the source: ldap:// or ldaps://")
	bindDN := fs.String("bind-dn", "", "the DN to bind as (read access is enough)")
	var baseDNs listFlag
	fs.Var(&baseDNs, "base-dn", "what to dump (repeat it for several)")
	out := fs.String("o", "", "the dump file (.gz: compressed)")
	maskAttrs := fs.String("mask", "", "attributes masked in the dump, comma separated")
	maskValue := fs.String("mask-value", config.DefaultMaskValue, "the value masked attributes get")
	caFile := fs.String("ca-file", "", "CA certificate (PEM) for the server's")
	insecure := fs.Bool("insecure-skip-verify", false, "do not verify the server's certificate (tests only)")
	startTLS := fs.Bool("start-tls", false, "StartTLS on an ldap:// URL")
	timeout := fs.Duration("timeout", config.DefaultTimeout, "bound on each LDAP operation (0: none)")
	progressMode := progressFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *bindDN == "" || len(baseDNs) == 0 || *out == "" {
		return errors.New("dump needs -url, -bind-dn, -base-dn and -o")
	}
	mode, err := progress.ParseMode(*progressMode)
	if err != nil {
		return err
	}
	var masked []string
	for _, a := range strings.Split(*maskAttrs, ",") {
		if a = strings.TrimSpace(a); a != "" {
			masked = append(masked, a)
		}
	}
	display, bar := progress.Start(mode, os.Stderr, "dump ← "+*url)
	defer display.Stop()
	_, err = app.Dump(ctx, app.DumpOptions{
		Conn:    ldapdir.ConnConfig{URL: *url, BindDN: *bindDN, CAFile: *caFile, InsecureSkipVerify: *insecure, StartTLS: *startTLS, Timeout: *timeout},
		BaseDNs: baseDNs, Out: *out, MaskValue: *maskValue, Masked: masked, Version: version, Progress: bar,
	}, secrets.SourceBind, display.Writer(log))
	return err
}

func runCheck(ctx context.Context, args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.toml", "config file")
	noTarget := fs.Bool("no-target", false, "read the source alone")
	attrs := fs.Bool("attrs", false, "also list every attribute of every kind and what clone does with it")
	progressMode := progressFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	mode, err := progress.ParseMode(*progressMode)
	if err != nil {
		return 0, err
	}
	s, err := openSession(ctx, *cfgPath)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	// The report is written at the end, after the status is gone, so it reads as one block.
	source := s.Cfg.Source.URL
	if s.Cfg.Source.LDIF != "" {
		source = s.Cfg.Source.LDIF
	}
	display, bar := progress.Start(mode, os.Stderr, "check "+source)
	defer display.Stop()
	s.Progress, s.Warn = bar, display.Writer(s.Warn)
	opts := app.CheckOptions{NoTarget: *noTarget, Attrs: *attrs, Config: *cfgPath}
	if lt := s.Cfg.Target.Lab; lt != nil && !lt.OnEC2() { // an EC2 lab is read as any server is, through its tunnel
		if opts.Lab, err = labOf(lt, io.Discard, display.Writer(os.Stderr)); err != nil {
			return 0, err
		}
	}
	var report bytes.Buffer
	code, err := s.Check(ctx, opts, &report)
	display.Stop()
	if _, werr := out.Write(report.Bytes()); err == nil {
		err = werr
	}
	return code, err
}

func listAttrs(_ context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("list-attrs", flag.ContinueOnError)
	name := fs.String("profile", profile.NameAD, "server type: ad or ldap")
	cfgPath := fs.String("config", "", "moved to check")
	fs.Bool("target", false, "moved to check")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath != "" {
		return fmt.Errorf("list-attrs reads nothing now: ldap-cronin check -config %s says what the source's entries hold and clone leaves behind (-attrs: every attribute)", *cfgPath)
	}
	p, err := profile.ByName(*name)
	if err != nil {
		return err
	}
	for _, k := range p.Kinds {
		fmt.Fprintf(out, "[%s]\n", k.Name)
		for _, name := range k.Default {
			fmt.Fprintf(out, "  %s\n", name)
		}
	}
	return nil
}

// listFlag is a flag given once per value (-base-dn A -base-dn B).
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, "; ") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}
