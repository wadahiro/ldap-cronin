package clone

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dryrun"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/identity"
	"github.com/wadahiro/ldap-cronin/internal/plan"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// ldapmodify applies LDIF change records to d as ldapmodify does without -c: in order, stopping at the first
// failure. It reads what the dry-run writes (RFC 2849): base64 values, control lines, add and modify records with
// replace (no values removes the attribute) and add, and comments.
func ldapmodify(d *fakedir.Dir, text string) error {
	ctx := context.Background()
	for i, record := range strings.Split(strings.TrimSpace(text), "\n\n") {
		var lines []string
		sc := bufio.NewScanner(strings.NewReader(record))
		for sc.Scan() {
			l := sc.Text()
			switch {
			case strings.HasPrefix(l, "#"):
			case strings.HasPrefix(l, " ") && len(lines) > 0:
				lines[len(lines)-1] += l[1:] // folded line
			default:
				lines = append(lines, l)
			}
		}
		if len(lines) == 0 {
			continue
		}
		field := func(l string) (string, string, error) {
			name, rest, ok := strings.Cut(l, ":")
			if !ok {
				return "", "", fmt.Errorf("record %d: not an LDIF line: %q", i+1, l)
			}
			if strings.HasPrefix(rest, ":") {
				b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest[1:]))
				return name, string(b), err
			}
			return name, strings.TrimPrefix(rest, " "), nil
		}
		name, entryDN, err := field(lines[0])
		if err != nil || name != "dn" {
			return fmt.Errorf("record %d: must start with dn: %q %v", i+1, lines[0], err)
		}
		var controls []directory.Control
		rest := lines[1:]
		for len(rest) > 0 && strings.HasPrefix(rest[0], "control: ") {
			f := strings.Fields(strings.TrimPrefix(rest[0], "control: "))
			controls = append(controls, directory.Control{OID: f[0], Critical: len(f) > 1 && f[1] == "true"})
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return fmt.Errorf("record %d: no changetype", i+1)
		}
		switch rest[0] {
		case "changetype: add":
			attrs := map[string][]string{}
			for _, l := range rest[1:] {
				n, v, err := field(l)
				if err != nil {
					return err
				}
				attrs[n] = append(attrs[n], v)
			}
			if err := d.Add(ctx, directory.Entry{DN: entryDN, Attrs: attrs}, controls...); err != nil {
				return fmt.Errorf("record %d: %w", i+1, err)
			}
		case "changetype: modify":
			for _, op := range strings.Split(strings.Join(rest[1:], "\n"), "\n-\n") {
				opLines := strings.Split(op, "\n")
				kind, attr, err := field(opLines[0])
				if err != nil {
					return err
				}
				var values []string
				for _, l := range opLines[1:] {
					_, v, err := field(l)
					if err != nil {
						return err
					}
					values = append(values, v)
				}
				switch kind {
				case "replace":
					if len(values) == 0 {
						// A replace without values deletes the attribute; AD refuses that for unicodePwd.
						return fmt.Errorf("record %d: replace of %s on %s has no value", i+1, attr, entryDN)
					}
					err = d.Replace(ctx, entryDN, map[string][]string{attr: values})
				case "add":
					err = d.AddValues(ctx, entryDN, attr, values)
				default:
					err = fmt.Errorf("unsupported modify operation %q", kind)
				}
				if err != nil {
					return fmt.Errorf("record %d: %w", i+1, err)
				}
			}
		default:
			return fmt.Errorf("record %d: unsupported %q", i+1, rest[0])
		}
	}
	return nil
}

// The dry-run LDIF loads with ldapmodify into an empty target. On a generic server that gives what clone gives:
// diff finds nothing, through the preserved identifiers the LDIF carries. On AD the LDIF has no password, so the
// users are disabled accounts without one; clone run against the loaded target completes them, and then diff
// finds nothing, through the markers the LDIF carries.
func TestDryRunLDIFLoadedWithLdapmodifyEqualsAClone(t *testing.T) {
	t.Run("ad", func(t *testing.T) {
		for seed := int64(1); seed <= 20; seed++ {
			src := randomTree(newRand(seed))
			dst := fakedir.New(domain)
			dryRunEqualsClone(t, src, dst, options(t, allKinds()...), false)
			for d, e := range dst.Entries {
				if strings.HasPrefix(d, "cn=") && e.Values("sAMAccountName") != nil && strings.HasPrefix(e.Values("sAMAccountName")[0], "u") && e.Values("unicodePwd") == nil {
					t.Fatalf("seed %d: %s has no password after clone", seed, e.DN)
				}
			}
		}
	})
	t.Run("ldap", func(t *testing.T) {
		dst := fakedir.New(gRoot)
		dst.Relax = profile.RelaxOID
		dst.RequireAttr = map[string]string{"groupofnames": "member", "inetorgperson": "sn"}
		dryRunEqualsClone(t, genericParentLeafSource(), dst, genericOptions(t), true)
	})
}

// dryRunEqualsClone loads the dry-run LDIF into dst, runs clone against it unless the profile preserves identifiers
// (and so writes the password in the Add), and expects diff to find nothing.
func dryRunEqualsClone(t *testing.T, src, dst *fakedir.Dir, job plan.Job, preserve bool) {
	t.Helper()
	dst.IDPrefix = 0xd1
	// Several workers, as the command runs it: the LDIF records must not interleave.
	opt := Options{UserPassword: "Fixed1!", Workers: 4, Preserve: preserve, Operational: preserve}
	var res identity.Resolver = identity.ByIdentity(job.Profile.Identity)
	if !preserve {
		root, err := identity.RootKey(context.Background(), src, job.BaseDN, job.Profile.Identity)
		if err != nil {
			t.Fatal(err)
		}
		m := identity.NewMarker(job.Profile.Marker, root)
		opt.Marker, res = &m, identity.ByMarker(m)
	}
	var out bytes.Buffer
	if _, err := Run(context.Background(), src, dryrun.New(&out, job.Profile), job, opt, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Fixed1!") {
		t.Fatal("the LDIF must not carry the password")
	}
	if err := ldapmodify(dst, out.String()); err != nil {
		t.Fatalf("ldapmodify refuses the dry-run LDIF: %v\n%s", err, out.String())
	}
	if !preserve {
		if _, err := Run(context.Background(), src, dst, job, opt, &bytes.Buffer{}); err != nil {
			t.Fatalf("clone after loading the LDIF: %v", err)
		}
	}
	var diffs []string
	if _, err := diff.Run(context.Background(), src, dst, job, diff.Options{Workers: 1, Resolver: res},
		func(d diff.Difference) { diffs = append(diffs, fmt.Sprintf("%s %s %s", d.Kind, d.DN, d.Attr)) }); err != nil {
		t.Fatal(err)
	}
	if len(diffs) != 0 {
		t.Fatalf("the loaded LDIF must give what clone gives:\n%s", strings.Join(diffs, "\n"))
	}
}

// With the password, the dry-run LDIF alone gives what clone gives: ldapmodify loads users with the fixed password
// and their source userAccountControl, and diff finds nothing without a clone run after it. Only the attribute the
// fixed password goes to is printed; the other password attributes stay redacted.
func TestDryRunLDIFWithThePasswordNeedsNoCloneAfterIt(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		src := randomTree(newRand(seed))
		dst := fakedir.New(domain)
		dst.IDPrefix = 0xd1
		job := options(t, allKinds()...)
		root, err := identity.RootKey(context.Background(), src, job.BaseDN, job.Profile.Identity)
		if err != nil {
			t.Fatal(err)
		}
		m := identity.NewMarker(job.Profile.Marker, root)
		opt := Options{UserPassword: "Fixed1!", Workers: 4, Marker: &m}
		var out bytes.Buffer
		if _, err := Run(context.Background(), src, dryrun.WithPassword(&out, job.Profile), job, opt, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), base64.StdEncoding.EncodeToString([]byte(profile.EncodePassword("Fixed1!")))) {
			t.Fatalf("seed %d: the LDIF must carry the password:\n%s", seed, out.String())
		}
		if strings.Contains(out.String(), "# changetype") {
			t.Fatalf("seed %d: nothing is left as a comment for clone:\n%s", seed, out.String())
		}
		if err := ldapmodify(dst, out.String()); err != nil {
			t.Fatalf("seed %d: ldapmodify refuses the LDIF: %v\n%s", seed, err, out.String())
		}
		users := 0
		for _, e := range dst.Entries {
			if v := e.Values("sAMAccountName"); v != nil && strings.HasPrefix(v[0], "u") {
				users++
				if got := e.Values("unicodePwd"); len(got) != 1 || got[0] != profile.EncodePassword("Fixed1!") {
					t.Fatalf("seed %d: %s has no fixed password: %q", seed, e.DN, got)
				}
			}
		}
		if users == 0 {
			t.Fatalf("seed %d: no user to check", seed)
		}
		var diffs []string
		if _, err := diff.Run(context.Background(), src, dst, job, diff.Options{Workers: 1, Resolver: identity.ByMarker(m)},
			func(d diff.Difference) { diffs = append(diffs, fmt.Sprintf("%s %s %s", d.Kind, d.DN, d.Attr)) }); err != nil {
			t.Fatal(err)
		}
		if len(diffs) != 0 {
			t.Fatalf("seed %d: the LDIF alone must give what clone gives:\n%s", seed, strings.Join(diffs, "\n"))
		}
	}
	var out bytes.Buffer
	d := dryrun.WithPassword(&out, profile.AD)
	if err := d.Add(context.Background(), directory.Entry{DN: "CN=x," + domain, Attrs: map[string][]string{"cn": {"x"}, "userPassword": {"secret"}}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "secret") {
		t.Fatalf("another password attribute must stay redacted:\n%s", out.String())
	}
}
