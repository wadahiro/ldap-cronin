package lab

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func instanceJSON(state, volume string) string {
	return `[{"InstanceId":"i-0lab","State":{"Name":"` + state + `"},"InstanceType":"t3.large","LaunchTime":"2026-10-23T00:00:00+00:00",
		"PrivateIpAddress":"10.0.0.5","RootDeviceName":"/dev/sda1","BlockDeviceMappings":[{"DeviceName":"xvdf","Ebs":{"VolumeId":"vol-data"}},
		{"DeviceName":"/dev/sda1","Ebs":{"VolumeId":"` + volume + `"}}]}]`
}

const twoSnapshots = `[{"SnapshotId":"snap-2","StartTime":"2026-10-23T02:00:00.000Z","State":"pending","Progress":"40%","VolumeSize":50,
	"Tags":[{"Key":"ldap-cronin.snapshot","Value":"after-clone"}]},
	{"SnapshotId":"snap-1","StartTime":"2026-10-23T01:00:00.000Z","State":"completed","Progress":"100%","VolumeSize":50,
	"Tags":[{"Key":"ldap-cronin.snapshot","Value":"base"},{"Key":"ldap-cronin.note","Value":"before the clone"}]}]`

// verbs are the calls' first two arguments, in order.
func (f *fakeAWS) verbs() []string {
	var v []string
	for _, c := range f.calls {
		v = append(v, strings.Join(c[:2], " "))
	}
	return v
}

func (f *fakeAWS) call(verb string) []string {
	for _, c := range f.calls {
		if strings.Join(c[:2], " ") == verb {
			return c
		}
	}
	return nil
}

func ready() []fakeAnswer { return []fakeAnswer{{out: "Success\tREADY\n"}} }

// A snapshot of a running lab: the instance stopped, its root volume (not another) taken with the lab's tags, the
// account's, its name and note, then the instance started again and waited for.
func TestEC2SnapshotStopsTakesAndStartsAgain(t *testing.T) {
	f := &fakeAWS{answers: map[string][]fakeAnswer{
		"ec2 describe-snapshots":     {{out: "[]"}},
		"ec2 describe-instances":     {{out: instanceJSON("running", "vol-root")}},
		"ec2 create-snapshot":        {{out: "snap-9\n"}},
		"ssm send-command":           {{out: "cmd\n"}},
		"ssm get-command-invocation": ready(),
	}}
	e := testEC2Lab()
	e.Tags = map[string]string{"Project": "h2"}
	var log bytes.Buffer
	s, err := e.Snapshot(context.Background(), run(f, &log), EC2SnapshotOptions{Note: "after the clone", Now: func() time.Time { return time.Date(2026, 10, 23, 1, 2, 3, 0, time.UTC) }})
	if err != nil || s.ID != "snap-9" || s.Name != "snapshot-20261023-010203" {
		t.Fatalf("%+v %v\n%s", s, err, log.String())
	}
	got := strings.Join(f.verbs(), ",")
	if want := "ec2 describe-snapshots,ec2 describe-instances,ec2 stop-instances,ec2 wait,ec2 create-snapshot,ec2 start-instances,ec2 wait,ssm send-command,ssm get-command-invocation"; got != want {
		t.Fatalf("calls\n got %s\nwant %s", got, want)
	}
	create := strings.Join(f.call("ec2 create-snapshot"), " ")
	for _, want := range []string{"--volume-id vol-root", `"ResourceType":"snapshot"`, `{"Key":"ldap-cronin.lab","Value":"ldap-cronin-ad"}`,
		`{"Key":"Project","Value":"h2"}`, `{"Key":"ldap-cronin.snapshot","Value":"snapshot-20261023-010203"}`, `{"Key":"ldap-cronin.note","Value":"after the clone"}`} {
		if !strings.Contains(create, want) {
			t.Errorf("create-snapshot lacks %s: %s", want, create)
		}
	}
}

// A stopped lab is left stopped; a name taken is refused, and replaced with --force once the new one is taken.
func TestEC2SnapshotOfAStoppedLabAndAName(t *testing.T) {
	f := &fakeAWS{answers: map[string][]fakeAnswer{
		"ec2 describe-snapshots": {{out: twoSnapshots}},
		"ec2 describe-instances": {{out: instanceJSON("stopped", "vol-root")}},
		"ec2 create-snapshot":    {{out: "snap-9\n"}},
	}}
	if _, err := testEC2Lab().Snapshot(context.Background(), run(f, &bytes.Buffer{}), EC2SnapshotOptions{Name: "base"}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("a name taken: %v", err)
	}
	f.calls = nil
	if _, err := testEC2Lab().Snapshot(context.Background(), run(f, &bytes.Buffer{}), EC2SnapshotOptions{Name: "base", Force: true}); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(f.verbs(), ",")
	if want := "ec2 describe-snapshots,ec2 describe-instances,ec2 create-snapshot,ec2 delete-snapshot"; got != want {
		t.Fatalf("calls\n got %s\nwant %s", got, want)
	}
	if d := strings.Join(f.call("ec2 delete-snapshot"), " "); !strings.Contains(d, "--snapshot-id snap-1") {
		t.Errorf("the replaced one: %s", d)
	}
}

// A restore: a stopped instance started, the snapshot waited for while pending, the root volume replaced by it
// (the replaced one deleted), the new volume given the lab's tags, the domain controller waited for.
func TestEC2RestoreReplacesTheRootVolume(t *testing.T) {
	f := &fakeAWS{answers: map[string][]fakeAnswer{
		"ec2 describe-snapshots":                 {{out: twoSnapshots}},
		"ec2 describe-instances":                 {{out: instanceJSON("stopped", "vol-root")}, {out: instanceJSON("running", "vol-new")}},
		"ec2 create-replace-root-volume-task":    {{out: "replacevol-1\n"}},
		"ec2 describe-replace-root-volume-tasks": {{out: "in-progress\n"}, {out: "succeeded\n"}},
		"ssm send-command":                       {{out: "cmd\n"}},
		"ssm get-command-invocation":             ready(),
	}}
	var log bytes.Buffer
	id, err := testEC2Lab().Restore(context.Background(), run(f, &log), "after-clone")
	if err != nil || id != "i-0lab" {
		t.Fatalf("%q %v\n%s", id, err, log.String())
	}
	got := strings.Join(f.verbs(), ",")
	want := "ec2 describe-snapshots,ec2 describe-instances,ec2 start-instances,ec2 wait,ec2 wait,ec2 create-replace-root-volume-task," +
		"ec2 describe-replace-root-volume-tasks,ec2 describe-replace-root-volume-tasks,ec2 describe-instances,ec2 create-tags,ssm send-command,ssm get-command-invocation"
	if got != want {
		t.Fatalf("calls\n got %s\nwant %s", got, want)
	}
	if c := strings.Join(f.calls[4], " "); !strings.Contains(c, "snapshot-completed --snapshot-ids snap-2") {
		t.Errorf("the pending snapshot waited for: %s", c)
	}
	if c := strings.Join(f.call("ec2 create-replace-root-volume-task"), " "); !strings.Contains(c, "--instance-id i-0lab --snapshot-id snap-2 --delete-replaced-root-volume") {
		t.Errorf("the task: %s", c)
	}
	if c := strings.Join(f.call("ec2 create-tags"), " "); !strings.Contains(c, "--resources vol-new") || !strings.Contains(c, `"ldap-cronin.lab"`) {
		t.Errorf("the new volume's tags: %s", c)
	}
}

// Without a name, or with one the lab has not, nothing is done: the candidates are shown.
func TestEC2RestoreNeedsASnapshotOfTheLab(t *testing.T) {
	for _, name := range []string{"", "nope"} {
		f := &fakeAWS{answers: map[string][]fakeAnswer{"ec2 describe-snapshots": {{out: twoSnapshots}}}}
		_, err := testEC2Lab().Restore(context.Background(), run(f, &bytes.Buffer{}), name)
		if err == nil || !strings.Contains(err.Error(), "after-clone") || !strings.Contains(err.Error(), "before the clone") || len(f.calls) != 1 {
			t.Errorf("%q: %v, calls %v", name, err, f.calls)
		}
	}
}

// The list is oldest first, with the state of one still pending.
func TestEC2SnapshotsList(t *testing.T) {
	f := &fakeAWS{answers: map[string][]fakeAnswer{"ec2 describe-snapshots": {{out: twoSnapshots}}}}
	list, err := testEC2Lab().Snapshots(context.Background(), f)
	if err != nil || len(list) != 2 || list[0].Name != "base" || list[1].Name != "after-clone" {
		t.Fatalf("%+v %v", list, err)
	}
	text := FormatEC2Snapshots(list)
	if !strings.Contains(text, "pending 40%") || !strings.Contains(text, "snap-1") || !strings.Contains(text, "before the clone") {
		t.Errorf("%s", text)
	}
	if args := strings.Join(f.calls[0], " "); !strings.Contains(args, "--owner-ids self --filters Name=tag:ldap-cronin.lab,Values=ldap-cronin-ad") {
		t.Errorf("only the lab's own: %s", args)
	}
}

// down stops the instance and waits; status shows it, its addresses and the snapshots' count.
func TestEC2DownAndStatus(t *testing.T) {
	f := &fakeAWS{answers: map[string][]fakeAnswer{"ec2 describe-instances": {{out: instanceJSON("running", "vol-root")}}}}
	if err := testEC2Lab().Down(context.Background(), run(f, &bytes.Buffer{})); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.verbs(), ","); got != "ec2 describe-instances,ec2 stop-instances,ec2 wait" {
		t.Errorf("down: %s", got)
	}
	f = &fakeAWS{answers: map[string][]fakeAnswer{"ec2 describe-instances": {{out: instanceJSON("stopped", "vol-root")}}, "ec2 describe-snapshots": {{out: twoSnapshots}}}}
	var log bytes.Buffer
	if err := testEC2Lab().Status(context.Background(), run(f, &log)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"i-0lab, stopped", "root volume vol-root", "private address 10.0.0.5, public address none", "Snapshots: 2"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, log.String())
		}
	}
}

// lab reset --snapshots deletes them all once confirmed.
func TestEC2RemoveSnapshots(t *testing.T) {
	f := &fakeAWS{answers: map[string][]fakeAnswer{"ec2 describe-snapshots": {{out: twoSnapshots}}}}
	asked := ""
	if err := testEC2Lab().RemoveSnapshots(context.Background(), run(f, &bytes.Buffer{}), func(q string) bool { asked = q; return false }); err == nil {
		t.Fatal("a no must stop it")
	}
	if !strings.Contains(asked, "base (snap-1), after-clone (snap-2)") || !strings.HasSuffix(asked, "[y/N]: ") {
		t.Errorf("asked %q", asked)
	}
	f.calls = nil
	if err := testEC2Lab().RemoveSnapshots(context.Background(), run(f, &bytes.Buffer{}), nil); err != nil || f.called("ec2 delete-snapshot") != 2 {
		t.Fatalf("%v %v", err, f.calls)
	}
}
