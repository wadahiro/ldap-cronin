package lab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// AWS runs the aws command (v2) with args and returns its standard output; an error carries its standard error.
type AWS interface {
	Run(ctx context.Context, args ...string) (string, error)
}

// ExecAWS runs the aws command on this machine, with its own configuration (credentials, profile).
type ExecAWS struct{}

func (ExecAWS) Run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "aws", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.String(), fmt.Errorf("aws %s: %s", strings.Join(args[:min(2, len(args))], " "), msg)
	}
	return out.String(), nil
}

// EC2Run is how lab up and lab reset of an EC2 lab run.
type EC2Run struct {
	AWS AWS
	Log io.Writer
	// Sleep waits between two readiness checks (time.Sleep).
	Sleep func(time.Duration)
	// Timeout bounds the wait for the domain controller (DefaultReadyTimeout when zero).
	Timeout time.Duration
	// Now is time.Now (for the timeout).
	Now func() time.Time
}

// Defaults of the wait for an EC2 lab.
const (
	DefaultReadyTimeout = 45 * time.Minute
	readyInterval       = 30 * time.Second
)

// EC2Instance is an instance of the lab, by its tag.
type EC2Instance struct{ ID, State string }

// Instances are the lab's instances that are not terminated (a terminated one keeps its tags for a while).
func (e EC2Lab) Instances(ctx context.Context, aws AWS) ([]EC2Instance, error) {
	out, err := aws.Run(ctx, e.findArgs()...)
	if err != nil {
		return nil, err
	}
	var found []EC2Instance
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			found = append(found, EC2Instance{ID: f[0], State: f[1]})
		}
	}
	return found, nil
}

// Up makes the lab: the instance of its tag is used when running and started when stopped, else made with the
// user data that makes it the domain controller, password the Administrator's; then it waits until the user data
// says READY. It returns the instance. The password goes to the instance in its user data only, through a file
// only its owner reads, removed before the instance is even asked for: never an argument, never a log line.
func (e EC2Lab) Up(ctx context.Context, r EC2Run, password string) (string, error) {
	if err := CheckPassword(password); err != nil {
		return "", err
	}
	userData, err := e.UserData(password)
	if err != nil {
		return "", err
	}
	found, err := e.Instances(ctx, r.AWS)
	if err != nil {
		return "", err
	}
	if len(found) > 1 {
		return "", fmt.Errorf("the lab %s has %d instances (%s): lab reset --config removes them", e.Name, len(found), instanceList(found))
	}
	var id string
	switch {
	case len(found) == 1:
		id = found[0].ID
		fmt.Fprintf(r.Log, "==> The lab's instance %s is %s\n", id, found[0].State)
		if s := found[0].State; s == "stopped" || s == "stopping" {
			if s == "stopping" {
				if _, err := r.AWS.Run(ctx, e.awsArgs("ec2", "wait", "instance-stopped", "--instance-ids", id)...); err != nil {
					return id, err
				}
			}
			fmt.Fprintf(r.Log, "==> Starting %s\n", id)
			if _, err := r.AWS.Run(ctx, e.awsArgs("ec2", "start-instances", "--instance-ids", id)...); err != nil {
				return id, err
			}
		}
	default:
		ami, err := r.AWS.Run(ctx, e.amiArgs()...)
		if err != nil {
			return "", err
		}
		ami = strings.TrimSpace(ami)
		fmt.Fprintf(r.Log, "==> Windows Server %s (%s) as %s in %s\n", e.windows(), ami, e.instanceType(), e.Subnet)
		if id, err = e.run(ctx, r, ami, userData); err != nil {
			return "", err
		}
		fmt.Fprintf(r.Log, "==> Instance %s: it makes itself the domain controller of %s (about 20 minutes, two restarts included)\n", id, e.Domain)
	}
	if _, err := r.AWS.Run(ctx, e.awsArgs("ec2", "wait", "instance-running", "--instance-ids", id)...); err != nil {
		return id, err
	}
	return id, e.waitReady(ctx, r, id)
}

// run launches the instance with the user data, from a file only its owner reads, removed whatever happens.
func (e EC2Lab) run(ctx context.Context, r EC2Run, ami, userData string) (string, error) {
	dir, err := os.MkdirTemp("", "ldap-cronin-ec2-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "user-data.ps1")
	if err := os.WriteFile(path, []byte(userData), 0o600); err != nil {
		return "", err
	}
	out, err := r.AWS.Run(ctx, e.runArgs(ami, path)...)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(out)
	if !strings.HasPrefix(id, "i-") {
		return "", fmt.Errorf("aws ec2 run-instances gave no instance: %q", out)
	}
	return id, nil
}

// waitReady asks the instance through Systems Manager, every 30 seconds, whether its user data has finished, and
// shows the last line of its log meanwhile. Until its agent registers, and while it restarts, the instance is not
// there to ask: that is "not yet", as a command that answers nothing.
func (e EC2Lab) waitReady(ctx context.Context, r EC2Run, id string) error {
	now, sleep, timeout := r.Now, r.Sleep, r.Timeout
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = time.Sleep
	}
	if timeout == 0 {
		timeout = DefaultReadyTimeout
	}
	deadline, last := now().Add(timeout), ""
	for {
		answer, err := e.ask(ctx, r, id)
		switch {
		case err != nil && ctx.Err() != nil:
			return ctx.Err()
		case err != nil:
			answer = "(" + notYet(err) + ")"
		case answer == "READY":
			fmt.Fprintf(r.Log, "==> %s is ready\n", id)
			return nil
		}
		if answer != "" && answer != last {
			fmt.Fprintf(r.Log, "    %s\n", answer)
			last = answer
		}
		if now().After(deadline) {
			return fmt.Errorf("%s did not say READY within %s: its C:\\ldap-cronin\\setup.log says why (Session Manager or Fleet Manager)", id, timeout)
		}
		sleep(readyInterval)
	}
}

// ask sends the readiness script and reads its answer: "" while it runs, the last line of the log, or READY.
func (e EC2Lab) ask(ctx context.Context, r EC2Run, id string) (string, error) {
	out, err := r.AWS.Run(ctx, e.pollArgs(id)...)
	if err != nil {
		return "", err
	}
	command := strings.TrimSpace(out)
	for i := 0; i < 10; i++ {
		res, err := r.AWS.Run(ctx, e.invocationArgs(command, id)...)
		if err != nil {
			if strings.Contains(err.Error(), "InvocationDoesNotExist") { // not yet known right after send-command
				r.sleepShort()
				continue
			}
			return "", err
		}
		status, output, _ := strings.Cut(strings.TrimSpace(res), "\t")
		switch status {
		case "Pending", "InProgress", "Delayed":
			r.sleepShort()
			continue
		case "Success":
			return strings.TrimSpace(output), nil
		}
		return "", nil // failed, cancelled, timed out: not yet
	}
	return "", nil
}

func (r EC2Run) sleepShort() {
	if r.Sleep != nil {
		r.Sleep(2 * time.Second)
	}
}

// notYet says what an error asking the instance means, as long as it may be answered later.
func notYet(err error) string {
	switch msg := err.Error(); {
	case strings.Contains(msg, "InvalidInstanceId"):
		return "Systems Manager does not know the instance yet, or it restarts"
	default:
		return msg
	}
}

// Reset terminates the lab's instances (and their volumes), after confirm says yes to them.
func (e EC2Lab) Reset(ctx context.Context, r EC2Run, confirm func(string) bool) error {
	found, err := e.Instances(ctx, r.AWS)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		fmt.Fprintf(r.Log, "==> The lab %s has no instance\n", e.Name)
		return nil
	}
	if confirm != nil && !confirm(fmt.Sprintf("Terminate the lab %s: %s (the domain and its data are lost)?", e.Name, instanceList(found))) {
		return errors.New("aborted: nothing was terminated")
	}
	args := []string{"ec2", "terminate-instances", "--instance-ids"}
	for _, i := range found {
		args = append(args, i.ID)
	}
	if _, err := r.AWS.Run(ctx, e.awsArgs(append(args, "--query", "TerminatingInstances[].InstanceId", "--output", "text")...)...); err != nil {
		return err
	}
	fmt.Fprintf(r.Log, "==> Terminating %s\n", instanceList(found))
	return nil
}

func instanceList(found []EC2Instance) string {
	var s []string
	for _, i := range found {
		s = append(s, i.ID+" ("+i.State+")")
	}
	return strings.Join(s, ", ")
}
