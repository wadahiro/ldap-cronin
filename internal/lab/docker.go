// Package lab starts and stops an AD-compatible Samba4 on docker for verification, and takes and restores snapshots.
//
// It does not depend on docker compose and only calls the docker command (the target environment may have no compose).
// It does not use the docker SDK either: that would add a large dependency, and being able to swap the
// command sequence for a fake in tests suits this use better.
package lab

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Cmd is a single invocation passed to docker.
type Cmd struct {
	Args []string
	// Env holds environment variables for the docker command. It is used to pass the password via the environment, not as an argument
	// (writing `-e NAME` makes docker inherit the value from its own environment, so it never shows up in the process list).
	Env    []string
	Stdin  io.Reader // if non-nil, fed to standard input
	Stdout io.Writer // if non-nil, standard output goes here and the returned string is empty
	Stderr io.Writer // if non-nil, standard error goes here too (it is still included in the error message on failure)
}

// Docker abstracts invoking the docker command. Tests replace it with a fake.
type Docker interface {
	Do(c Cmd) (string, error)
}

// Process is a docker command that stays running and is driven over stdin/stdout.
type Process struct {
	Stdin  io.WriteCloser
	Stdout io.Reader
	// Wait waits for the process to exit. Call it after closing stdin.
	Wait func() error
}

// Streamer is a Docker that can start a docker command and keep talking to it. Used for the native import helper container.
type Streamer interface {
	Start(c Cmd) (*Process, error)
}

// DockerError is a failed docker command. It includes standard error output.
type DockerError struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *DockerError) Error() string {
	msg := fmt.Sprintf("docker %s: %v", strings.Join(redact(e.Args), " "), e.Err)
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

func (e *DockerError) Unwrap() error { return e.Err }

// redact hides the values of environment variables that carry one (-e NAME=value) in the arguments left in an error message.
func redact(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i+1 < len(out); i++ {
		if out[i] == "-e" {
			if name, _, ok := strings.Cut(out[i+1], "="); ok {
				out[i+1] = name + "=***"
			}
		}
	}
	return out
}

// IsNotFound reports whether inspect or similar failed because the object does not exist.
func IsNotFound(err error) bool {
	var de *DockerError
	if !errors.As(err, &de) {
		return false
	}
	s := strings.ToLower(de.Stderr)
	return strings.Contains(s, "no such")
}

// ExecDocker actually runs the docker command.
type ExecDocker struct{}

func (ExecDocker) Do(c Cmd) (string, error) {
	cmd := exec.Command("docker", c.Args...)
	if len(c.Env) > 0 {
		cmd.Env = append(cmd.Environ(), c.Env...)
	}
	cmd.Stdin = c.Stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if c.Stderr != nil {
		cmd.Stderr = io.MultiWriter(&stderr, c.Stderr)
	}
	if c.Stdout != nil {
		cmd.Stdout = c.Stdout
		if err := cmd.Run(); err != nil {
			return "", &DockerError{Args: c.Args, Stderr: strings.TrimSpace(stderr.String()), Err: err}
		}
		return "", nil
	}
	out, err := cmd.Output()
	if err != nil {
		return "", &DockerError{Args: c.Args, Stderr: strings.TrimSpace(stderr.String()), Err: err}
	}
	return strings.TrimSpace(string(out)), nil
}

// Start launches the docker command and wires up stdin/stdout. Standard error goes to c.Stderr (discarded if nil).
func (ExecDocker) Start(c Cmd) (*Process, error) {
	cmd := exec.Command("docker", c.Args...)
	if len(c.Env) > 0 {
		cmd.Env = append(cmd.Environ(), c.Env...)
	}
	cmd.Stderr = c.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, &DockerError{Args: c.Args, Err: err}
	}
	return &Process{Stdin: in, Stdout: out, Wait: cmd.Wait}, nil
}
