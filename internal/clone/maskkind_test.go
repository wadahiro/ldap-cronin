package clone

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wadahiro/ldap-cronin/internal/diff"
	"github.com/wadahiro/ldap-cronin/internal/fakedir"
	"github.com/wadahiro/ldap-cronin/internal/mask"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

// [mask.kinds] user = ["mail"]: a user's mail is masked, a group's is copied; diff compares the group's and not the
// user's, and says so.
func TestMaskOfAKindInCloneAndDiff(t *testing.T) {
	src, dst := seedSource(), fakedir.New(domain)
	src.Lookup(eng).Attrs["mail"] = []string{"eng@real.example"}
	job := jobFor(t, profile.AD, base, allKinds(), profile.Override{})
	job.Masker = mask.New("***", nil).WithKinds(map[string][]string{"user": {"mail"}})
	if _, err := Run(context.Background(), src, dst, job, Options{UserPassword: "Fixed1!", Workers: 4}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := dst.Lookup(alice).Values("mail"); len(got) != 1 || got[0] != "***" {
		t.Errorf("the user's mail: %v", got)
	}
	if got := dst.Lookup(eng).Values("mail"); len(got) != 1 || got[0] != "eng@real.example" {
		t.Errorf("the group's mail: %v", got)
	}
	if d := runDiff(t, src, dst, job); len(d) != 0 {
		t.Errorf("diff: %+v", d)
	}
	dst.Lookup(eng).Attrs["mail"] = []string{"changed@x"}
	if d := runDiff(t, src, dst, job); len(d) != 1 || d[0].DN != eng {
		t.Errorf("the group's mail is compared: %+v", d)
	}
	var sum bytes.Buffer
	diff.WriteSummary(&sum, job, diff.Summary{}, nil)
	if !strings.Contains(sum.String(), "mail (user)") {
		t.Errorf("summary:\n%s", sum.String())
	}
}
