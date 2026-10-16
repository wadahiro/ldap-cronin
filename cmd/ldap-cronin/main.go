package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/wadahiro/ldap-cronin/internal/attrs"
	"github.com/wadahiro/ldap-cronin/internal/clone"
	"github.com/wadahiro/ldap-cronin/internal/config"
	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/guidmap"
	"github.com/wadahiro/ldap-cronin/internal/lab"
	"github.com/wadahiro/ldap-cronin/internal/ldapdir"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
	"github.com/wadahiro/ldap-cronin/internal/prompt"
)

const (
	envSourcePassword = "LDAP_CRONIN_SOURCE_PASSWORD"
	envTargetPassword = "LDAP_CRONIN_TARGET_PASSWORD"
	envUserPassword   = "LDAP_CRONIN_USER_PASSWORD"
	exitDiff          = 1
	exitError         = 2

	// The source gets only a single read-only paged search and is not read in parallel (parallelism applies only to processing on the target).
	// Keeping idle connections open would only add login load on the source, so a single connection is used.
	// Searching the source in parallel was rejected because it would increase the load on the source.
	sourceConnections = 1
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

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	var err error
	code := 0
	switch args[0] {
	case "clone":
		err = runClone(args[1:], stdout)
	case "diff":
		code, err = runDiff(args[1:], stdout)
	case "list-attrs":
		err = listAttrs(args[1:], stdout)
	case "lab":
		err = runLab(args[1:], stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "ldap-cronin", version)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return exitError
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	return code
}

func runClone(args []string, out io.Writer) error {
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
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	srcPw, err := prompt.Password("source bind password", envSourcePassword, false)
	if err != nil {
		return err
	}
	src, err := dial(cfg.Source, srcPw, sourceConnections)
	if err != nil {
		return err
	}
	defer src.Close()
	opt, err := resolveOptions(cfg, src)
	if err != nil {
		return err
	}

	if *native {
		if !opt.P().SupportsNative {
			return fmt.Errorf("-native needs an AD (Samba) source; this source was detected as %q", opt.P().Name)
		}
		report, err := cloneNative(cfg, opt, src, labFlags, out, os.Stderr)
		if report != nil {
			fmt.Fprintf(out, "\nadded=%d updated=%d unchanged=%d warnings=%d\n",
				report.Added, report.Updated, report.Unchanged, report.WarningCount)
		}
		return err
	}

	// The dry-run stdout carries only LDIF that can be passed straight to ldapmodify; progress logs go to stderr.
	logOut := out
	var dst directory.Directory = directory.DryRun{Out: out}
	if *dryRun {
		logOut = os.Stderr
	}
	userPw := "<fixed-password>"
	if !*dryRun {
		tgtPw, err := prompt.Password("target bind password", envTargetPassword, false)
		if err != nil {
			return err
		}
		if userPw, err = prompt.Password("fixed password for cloned users", envUserPassword, true); err != nil {
			return err
		}
		client, err := dial(cfg.Target, tgtPw, cfg.Clone.Workers)
		if err != nil {
			return err
		}
		defer client.Close()
		if err := prepareTarget(cfg, opt, client); err != nil {
			return err
		}
		dst = client
	}

	var guids *guidmap.Map
	if cfg.State.File != "" && !*dryRun {
		header, err := mappingHeader(cfg, opt, src, dst)
		if err != nil {
			return err
		}
		if guids, err = guidmap.Open(cfg.State.File, header); err != nil {
			return err
		}
		opt.TrackGUID = true
	}
	report, err := clone.Run(src, dst, clone.Options{Plan: opt, UserPassword: userPw, Workers: cfg.Clone.Workers, GUIDMap: guids}, logOut)
	if guids != nil {
		if cerr := guids.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("write mapping file: %w", cerr)
		}
	}
	if report != nil {
		fmt.Fprintf(logOut, "\nadded=%d updated=%d unchanged=%d warnings=%d\n",
			report.Added, report.Updated, report.Unchanged, report.WarningCount)
	}
	return err
}

func runDiff(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.toml", "config file")
	maxValues := fs.Int("max-values", diff.DefaultMaxValues, "max values shown per direction for multi-valued attributes (0 = all)")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return 0, err
	}
	srcPw, err := prompt.Password("source bind password", envSourcePassword, false)
	if err != nil {
		return 0, err
	}
	tgtPw, err := prompt.Password("target bind password", envTargetPassword, false)
	if err != nil {
		return 0, err
	}
	src, err := dial(cfg.Source, srcPw, sourceConnections)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	opt, err := resolveOptions(cfg, src)
	if err != nil {
		return 0, err
	}
	dst, err := dial(cfg.Target, tgtPw, cfg.Clone.Workers)
	if err != nil {
		return 0, err
	}
	defer dst.Close()
	if err := prepareTarget(cfg, opt, dst); err != nil {
		return 0, err
	}

	var tracker guidmap.Lookup
	// Identical object identifiers are only possible after a native import (AD/Samba lab).
	same, why := false, ""
	if opt.P().SupportsNative {
		if same, why, err = identityPreserved(src, dst, cfg.Clone.BaseDN); err != nil {
			return 0, err
		}
	}
	if same {
		// Native import keeps objectGUID identical, so no mapping is needed.
		tracker = guidmap.Identity{}
	} else {
		if why != "" && cfg.State.File == "" {
			fmt.Fprintf(os.Stderr, "note: cannot say the objectGUIDs are identical (%s)\n", why)
		}
		guids, err := loadMapping(cfg, opt, src, dst)
		if err != nil {
			return 0, err
		}
		if guids != nil {
			defer guids.Close()
			tracker = guids
		}
	}
	sum, err := diff.RunWith(src, dst, opt, cfg.Clone.Workers, tracker, func(d diff.Difference) { diff.Format(out, d, *maxValues) })
	if err != nil {
		return 0, err
	}
	total := sum.Differences[diff.OnlySource] + sum.Differences[diff.OnlyTarget] + sum.Differences[diff.Differ]
	if total == 0 {
		fmt.Fprintln(out, "no differences")
	}
	diff.WriteSummary(out, opt, sum, cfg.Attributes.Exclude)
	if total == 0 {
		return 0, nil
	}
	return exitDiff, nil
}

// mappingHeader builds the mapping header (identifiers of the source and target domains).
func mappingHeader(cfg *config.Config, opt plan.Options, src, dst directory.Directory) (guidmap.Header, error) {
	root, idAttr, err := rootAndID(opt, src)
	if err != nil {
		return guidmap.Header{}, err
	}
	srcID, err := guidmap.RootID(src, root, idAttr)
	if err != nil {
		return guidmap.Header{}, fmt.Errorf("source: %w", err)
	}
	dstID, err := guidmap.RootID(dst, root, idAttr)
	if err != nil {
		return guidmap.Header{}, fmt.Errorf("target: %w", err)
	}
	return guidmap.Header{SourceDomain: srcID, TargetDomain: dstID, BaseDN: cfg.Clone.BaseDN}, nil
}

// loadMapping opens the mapping for diff. If it is not specified, the file is missing, or it is another domain's, it
// continues without rename and move detection (the same behavior as before). The reason goes to standard error.
func loadMapping(cfg *config.Config, opt plan.Options, src, dst directory.Directory) (*guidmap.Map, error) {
	if cfg.State.File == "" {
		return nil, nil
	}
	header, err := mappingHeader(cfg, opt, src, dst)
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: cannot identify the domain, so rename and move detection is not used: %v\n", err)
		return nil, nil
	}
	m, err := guidmap.Load(cfg.State.File, header)
	switch {
	case err == nil:
		return m, nil
	case errors.Is(err, os.ErrNotExist):
		fmt.Fprintf(os.Stderr, "note: %s not found; rename/move detection is off (run clone with [state] file to record it)\n", cfg.State.File)
		return nil, nil
	case errors.Is(err, guidmap.ErrHeaderMismatch):
		fmt.Fprintf(os.Stderr, "note: %s belongs to a different source/target domain or base_dn; rename/move detection is off\n", cfg.State.File)
		return nil, nil
	}
	return nil, err
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
	defaults := attrs.DefaultsFor(p)
	for _, kind := range attrs.Kinds {
		fmt.Fprintf(out, "[%s]\n", kind)
		for _, name := range defaults[kind] {
			fmt.Fprintf(out, "  %s\n", name)
		}
	}
	return nil
}

func dial(ep config.Endpoint, password string, workers int) (*ldapdir.Client, error) {
	return ldapdir.Dial(ldapdir.ConnConfig{
		URL: ep.URL, BindDN: ep.BindDN, Password: password,
		CAFile: ep.CAFile, InsecureSkipVerify: ep.InsecureSkipVerify, StartTLS: ep.StartTLS,
	}, workers)
}
