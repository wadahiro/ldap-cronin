package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/wadahiro/ldap-cronin/internal/app"
	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/lab"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/prompt"
)

const (
	envSourcePassword = "LDAP_CRONIN_SOURCE_PASSWORD"
	envTargetPassword = "LDAP_CRONIN_TARGET_PASSWORD"
	envUserPassword   = "LDAP_CRONIN_USER_PASSWORD"
	exitError         = 2
)

const usage = `Usage: ldap-cronin <command> [flags]

Commands:
  clone         Add or update the source directory's OUs, groups, users, computers and contacts in the target (AD or generic LDAP)
  diff          Compare the source and the target (exit code 1 if there are differences)
  list-attrs    Show the default attributes (allow list) per object type (-profile ad|ldap); with -config, read the
                source and list the attributes its entries hold, copied or not (-target: and the target's schema)
  schema        Print as LDIF the attributes and classes the source's schema has and the target's lacks (AD); -apply
                writes them to the target instead
  lab           Start an AD-compatible Samba4 on docker for verification, and take and restore snapshots (lab help)
  version       Show the version

Flags (clone/diff):
  -config <file>   TOML config file (default: config.toml)
  -dry-run         (clone only) Do not connect to the target; print what would be done as LDIF
  -native          (clone only) Import into the lab's Samba keeping the source's objectGUID and objectSid (Samba only. lab help)
  -lab-prefix <p>, -lab-instance <name>   (clone -native) The lab to import into
  -format <f>      (diff only) text (default), or json: JSON Lines, one object per difference, then the summary
  -max-values <n>  (diff only, text) Show at most n values per direction of a multi-valued difference (default: 0, all)

Flags (schema):
  -config <file>   TOML config file (default: config.toml); reads the schemas of [source] and [target]
  -apply           Write the changes to the target (a schema change cannot be undone in AD); without it, the LDIF goes
                   to stdout, for ldapmodify or ldifde, and the summary to stderr
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
	case "list-attrs":
		err = listAttrs(ctx, args[1:], stdout)
	case "schema":
		err = runSchema(ctx, args[1:], stdout, stderr)
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
	return app.Open(ctx, cfg, secrets, dial, os.Stderr)
}

func runClone(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("clone", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.toml", "config file")
	dryRun := fs.Bool("dry-run", false, "print LDIF instead of writing")
	native := fs.Bool("native", false, "import into a lab Samba keeping objectGUID/objectSid (Samba only)")
	var labFlags labCommon
	fs.StringVar(&labFlags.prefix, "lab-prefix", lab.DefaultPrefix, "lab container name prefix (with -native)")
	fs.StringVar(&labFlags.instance, "lab-instance", "", "lab instance (with -native; default: the main lab)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *native && *dryRun {
		return errors.New("-native and -dry-run cannot be used together")
	}
	s, err := openSession(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer s.Close()

	var report *clone.Report
	// The dry-run stdout carries only LDIF that can be passed straight to ldapmodify; progress logs go to stderr.
	log := out
	switch {
	case *native:
		l, lerr := newLab(labFlags, out, os.Stderr)
		if lerr != nil {
			return lerr
		}
		report, err = s.Native(ctx, l, out)
	default:
		if *dryRun {
			log = os.Stderr
		}
		report, err = s.Clone(ctx, *dryRun, out, log)
	}
	if report != nil {
		report.WriteSummary(log)
	}
	return err
}

func runDiff(ctx context.Context, args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.toml", "config file")
	maxValues := fs.Int("max-values", diff.DefaultMaxValues, "max values shown per direction for multi-valued attributes in the text output (0 = all, the default)")
	format := fs.String("format", "text", "output format: text, or json (JSON Lines: one object per difference, then the summary)")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if *format != "text" && *format != "json" {
		return 0, fmt.Errorf("-format %q: use text or json", *format)
	}
	s, err := openSession(ctx, *cfgPath)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	return s.Diff(ctx, app.DiffOutput{JSON: *format == "json", MaxValues: *maxValues}, out)
}

func runSchema(ctx context.Context, args []string, out, log io.Writer) error {
	fs := flag.NewFlagSet("schema", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.toml", "config file")
	apply := fs.Bool("apply", false, "write the changes to the target instead of printing them (cannot be undone in AD)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := openSession(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer s.Close()
	if *apply {
		// The progress is the output then, and stays apart from the error on stderr.
		log = out
	}
	return s.Schema(ctx, *apply, out, log)
}

func listAttrs(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("list-attrs", flag.ContinueOnError)
	name := fs.String("profile", profile.NameAD, "server type: ad or ldap (without -config)")
	cfgPath := fs.String("config", "", "config file: read the source and list the attributes its entries hold")
	target := fs.Bool("target", false, "with -config: also read the target's schema")
	all := fs.Bool("all", false, "with -config: also list the attributes of the allow lists that no entry holds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath != "" {
		s, err := openSession(ctx, *cfgPath)
		if err != nil {
			return err
		}
		defer s.Close()
		return s.ListAttrs(ctx, *target, *all, out)
	}
	if *target {
		return errors.New("-target needs -config")
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
