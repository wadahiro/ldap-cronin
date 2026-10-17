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
  clone         Add or update the source directory's OUs, groups and users in the target (AD or generic LDAP)
  diff          Compare the source and the target (exit code 1 if there are differences)
  list-attrs    Show the default attributes (allow list) per object type (-profile ad|ldap)
  lab           Start an AD-compatible Samba4 on docker for verification, and take and restore snapshots (lab help)
  version       Show the version

Flags (clone/diff):
  -config <file>   TOML config file (default: config.toml)
  -dry-run         (clone only) Do not connect to the target; print what would be done as LDIF
  -native          (clone only) Import into the lab's Samba keeping the source's objectGUID and objectSid (Samba only. lab help)
  -lab-prefix <p>, -lab-instance <name>   (clone -native) The lab to import into
  -max-values <n>  (diff only) How many multi-valued attribute differences to show per direction (default: 10, 0 for all)
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
		err = listAttrs(args[1:], stdout)
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
		fmt.Fprintf(log, "\nadded=%d updated=%d unchanged=%d warnings=%d\n",
			report.Added, report.Updated, report.Unchanged, report.WarningCount)
	}
	return err
}

func runDiff(ctx context.Context, args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.toml", "config file")
	maxValues := fs.Int("max-values", diff.DefaultMaxValues, "max values shown per direction for multi-valued attributes (0 = all)")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	s, err := openSession(ctx, *cfgPath)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	return s.Diff(ctx, *maxValues, out)
}

func listAttrs(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("list-attrs", flag.ContinueOnError)
	name := fs.String("profile", profile.NameAD, "server type: ad or ldap")
	if err := fs.Parse(args); err != nil {
		return err
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
