// Package prompt obtains passwords. By default it reads them from the terminal without echo.
// The environment variable is a fallback for non-interactive runs such as CI and E2E; it is deliberately not accepted as an argument so it never lands in shell history.
package prompt

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// Password returns the value of envName if set, otherwise reads it from the terminal without echo.
func Password(label, envName string, confirm bool) (string, error) {
	if v := os.Getenv(envName); v != "" {
		return v, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("%s: stdin is not a terminal; set %s", label, envName)
	}
	pw, err := read(fd, label)
	if err != nil {
		return "", err
	}
	if confirm {
		again, err := read(fd, label+" (confirm)")
		if err != nil {
			return "", err
		}
		if again != pw {
			return "", errors.New(label + ": the two entries do not match")
		}
	}
	return pw, nil
}

func read(fd int, label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errors.New(label + ": empty password")
	}
	return string(b), nil
}
