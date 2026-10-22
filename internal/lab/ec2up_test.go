package lab

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeAWS answers the aws commands by their verb (the first two arguments), in turn, and records them.
type fakeAWS struct {
	answers  map[string][]fakeAnswer
	calls    [][]string
	userData string // the user data file's content when run-instances was called
	dataPath string
}

type fakeAnswer struct {
	out string
	err error
}

func (f *fakeAWS) Run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, args)
	verb := strings.Join(args[:2], " ")
	if verb == "ec2 run-instances" {
		for i, a := range args {
			if a == "--user-data" {
				f.dataPath = strings.TrimPrefix(args[i+1], "file://")
				b, _ := os.ReadFile(f.dataPath)
				f.userData = string(b)
			}
		}
	}
	queue := f.answers[verb]
	if len(queue) == 0 {
		return "", nil
	}
	a := queue[0]
	if len(queue) > 1 {
		f.answers[verb] = queue[1:]
	}
	return a.out, a.err
}

func (f *fakeAWS) called(verb string) int {
	n := 0
	for _, c := range f.calls {
		if strings.Join(c[:2], " ") == verb {
			n++
		}
	}
	return n
}

func run(f *fakeAWS, log *bytes.Buffer) EC2Run {
	return EC2Run{AWS: f, Log: log, Sleep: func(time.Duration) {}}
}

// A new lab: the image, the instance with the user data in a file only its owner reads (removed right after,
// never an argument), then the readiness asked until READY, through the restart where Systems Manager does not
// know the instance; the log shows the last line of the setup log, never the password.
func TestEC2UpMakesTheInstanceAndWaitsForTheDomainController(t *testing.T) {
	f := &fakeAWS{answers: map[string][]fakeAnswer{
		"ssm get-parameter": {{out: "ami-0123\n"}},
		"ec2 run-instances": {{out: "i-0abc\n"}},
		"ssm send-command": {{err: errors.New("aws ssm send-command: An error occurred (InvalidInstanceId)")},
			{out: "cmd-1\n"}, {out: "cmd-2\n"}, {err: errors.New("aws ssm send-command: An error occurred (InvalidInstanceId)")}, {out: "cmd-3\n"}},
		"ssm get-command-invocation": {{err: errors.New("An error occurred (InvocationDoesNotExist)")}, {out: "InProgress\t\n"},
			{out: "Success\tcreating the forest ad.example.com (AD)\n"}, {out: "Success\tpassword policy for the fixed password\n"}, {out: "Success\tREADY\n"}},
	}}
	var log bytes.Buffer
	id, err := testEC2Lab().Up(context.Background(), run(f, &log), "It's-a-Passw0rd")
	if err != nil || id != "i-0abc" {
		t.Fatalf("%q %v\n%s", id, err, log.String())
	}
	if !strings.Contains(f.userData, "$Password = 'It''s-a-Passw0rd'") {
		t.Fatalf("the user data file:\n%s", f.userData)
	}
	if _, err := os.Stat(f.dataPath); !os.IsNotExist(err) {
		t.Errorf("the user data file is left: %s", f.dataPath)
	}
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), "Passw0rd") {
			t.Errorf("the password in an argument: %v", c)
		}
	}
	text := log.String()
	for _, want := range []string{"creating the forest ad.example.com (AD)", "password policy for the fixed password", "i-0abc is ready",
		"Systems Manager does not know the instance yet"} {
		if !strings.Contains(text, want) {
			t.Errorf("the log lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Passw0rd") {
		t.Errorf("the password in the log:\n%s", text)
	}
}

// An instance of the lab's tag is used: a running one as it is, a stopped one started; two are refused.
func TestEC2UpUsesTheLabsInstance(t *testing.T) {
	ready := []fakeAnswer{{out: "Success\tREADY\n"}}
	for state, started := range map[string]int{"running": 0, "stopped": 1} {
		f := &fakeAWS{answers: map[string][]fakeAnswer{
			"ec2 describe-instances":     {{out: "i-0old\t" + state + "\n"}},
			"ssm send-command":           {{out: "cmd\n"}},
			"ssm get-command-invocation": ready,
		}}
		var log bytes.Buffer
		if id, err := testEC2Lab().Up(context.Background(), run(f, &log), testPassword); err != nil || id != "i-0old" {
			t.Fatalf("%s: %q %v", state, id, err)
		}
		if f.called("ec2 run-instances") != 0 || f.called("ec2 start-instances") != started {
			t.Errorf("%s: %v", state, f.calls)
		}
	}
	f := &fakeAWS{answers: map[string][]fakeAnswer{"ec2 describe-instances": {{out: "i-1\trunning\ni-2\tstopped\n"}}}}
	if _, err := testEC2Lab().Up(context.Background(), run(f, &bytes.Buffer{}), testPassword); err == nil || !strings.Contains(err.Error(), "lab reset --config") {
		t.Fatalf("two instances: %v", err)
	}
}

// A password Windows would refuse stops lab up before AWS is asked anything.
func TestEC2UpRefusesAWeakPasswordFirst(t *testing.T) {
	f := &fakeAWS{answers: map[string][]fakeAnswer{}}
	if _, err := testEC2Lab().Up(context.Background(), run(f, &bytes.Buffer{}), "weak"); err == nil || len(f.calls) != 0 {
		t.Fatalf("%v, calls %v", err, f.calls)
	}
}

// The wait has an end: the setup log is where to look then.
func TestEC2UpGivesUpAfterTheTimeout(t *testing.T) {
	f := &fakeAWS{answers: map[string][]fakeAnswer{
		"ec2 describe-instances":     {{out: "i-0old\trunning\n"}},
		"ssm send-command":           {{out: "cmd\n"}},
		"ssm get-command-invocation": {{out: "Success\tstill working\n"}},
	}}
	clock := time.Unix(0, 0)
	r := EC2Run{AWS: f, Log: &bytes.Buffer{}, Timeout: time.Minute, Now: func() time.Time { return clock },
		Sleep: func(d time.Duration) { clock = clock.Add(d) }}
	if _, err := testEC2Lab().Up(context.Background(), r, testPassword); err == nil || !strings.Contains(err.Error(), "setup.log") {
		t.Fatalf("%v", err)
	}
}

// lab reset terminates the lab's instances, all of them, once confirmed; a no terminates nothing.
func TestEC2ResetTerminatesTheLabsInstances(t *testing.T) {
	two := []fakeAnswer{{out: "i-1\trunning\ni-2\tstopped\n"}}
	f := &fakeAWS{answers: map[string][]fakeAnswer{"ec2 describe-instances": two}}
	asked := ""
	if err := testEC2Lab().Reset(context.Background(), run(f, &bytes.Buffer{}), func(q string) bool { asked = q; return false }); err == nil {
		t.Fatal("a no must stop it")
	}
	if f.called("ec2 terminate-instances") != 0 || !strings.Contains(asked, "i-1 (running), i-2 (stopped)") {
		t.Fatalf("asked %q, calls %v", asked, f.calls)
	}
	f = &fakeAWS{answers: map[string][]fakeAnswer{"ec2 describe-instances": two}}
	if err := testEC2Lab().Reset(context.Background(), run(f, &bytes.Buffer{}), nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.Join(c[:2], " ") == "ec2 terminate-instances" && !strings.Contains(strings.Join(c, " "), "--instance-ids i-1 i-2") {
			t.Fatalf("terminated: %v", c)
		}
	}
	if f.called("ec2 terminate-instances") != 1 {
		t.Fatalf("calls %v", f.calls)
	}
}
