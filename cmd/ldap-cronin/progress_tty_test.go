//go:build !windows

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/creack/pty"
)

// screen replays what a terminal of width columns shows for a byte stream, with the few controls the progress
// display sends (carriage return, newline, erase line, cursor up). Text past the last column wraps, and is counted:
// a wrapped status line would be erased only in part.
type screen struct {
	width    int
	lines    [][]rune
	row, col int
	wrapped  int
}

func (s *screen) feed(b []byte) {
	text := []rune(string(b))
	for i := 0; i < len(text); i++ {
		switch r := text[i]; {
		case r == '\r':
			s.col = 0
		case r == '\n':
			s.row++
		case r == 0x1b && i+1 < len(text) && text[i+1] == '[':
			j := i + 2
			for j < len(text) && (text[j] >= '0' && text[j] <= '9' || text[j] == ';' || text[j] == '?') {
				j++
			}
			if j == len(text) {
				return
			}
			n, err := strconv.Atoi(string(text[i+2 : j]))
			if err != nil {
				n = 1
			}
			switch text[j] {
			case 'K':
				s.line()
				s.lines[s.row] = nil
			case 'A':
				s.row = max(s.row-n, 0)
			}
			i = j
		default:
			if s.col >= s.width {
				s.wrapped++
				s.row, s.col = s.row+1, 0
			}
			s.line()
			for len(s.lines[s.row]) < s.col {
				s.lines[s.row] = append(s.lines[s.row], ' ')
			}
			if s.col < len(s.lines[s.row]) {
				s.lines[s.row][s.col] = r
			} else {
				s.lines[s.row] = append(s.lines[s.row], r)
			}
			s.col++
		}
	}
}

func (s *screen) line() {
	for len(s.lines) <= s.row {
		s.lines = append(s.lines, nil)
	}
}

// text is what the screen holds at the end, without the empty lines at the bottom.
func (s *screen) text() []string {
	var out []string
	for _, l := range s.lines {
		out = append(out, strings.TrimRight(string(l), " "))
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

// On a terminal clone keeps its status at the bottom while the log scrolls above it: every phase is drawn, no
// status line wraps (on a terminal narrower than the log lines), and once it is done the screen holds the log and the summary only, every line whole and once,
// as a run without progress writes them.
func TestTheProgressOnATerminal(t *testing.T) {
	const width = 40
	master, tty, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	defer master.Close()
	if err := pty.Setsize(master, &pty.Winsize{Rows: 30, Cols: width}); err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	read := make(chan struct{})
	go func() { io.Copy(&stream, master); close(read) }() // the terminal must be read, or a full buffer blocks the run

	_, _, cfg := cli(t)
	saved := os.Stderr
	os.Stderr = tty
	code := run(context.Background(), []string{"clone", "-y", "-config", cfg}, tty, tty)
	os.Stderr = saved
	tty.Close()
	<-read
	if code != 0 {
		t.Fatalf("clone: %d\n%q", code, stream.String())
	}

	raw := stream.String()
	for _, want := range []string{"clone → ldaps://dst:636", "[1/6] OUs and parents", "[2/6] group", "[3/6] user", "[6/6] references", "added 3 · updated 0"} {
		if !strings.Contains(raw, want) {
			t.Errorf("the status never showed %q:\n%q", want, raw)
		}
	}
	s := &screen{width: width}
	s.feed(stream.Bytes())

	_, _, cfg = cli(t)
	var plain bytes.Buffer
	if code := run(context.Background(), []string{"clone", "-y", "-progress", "off", "-config", cfg}, &plain, &plain); code != 0 {
		t.Fatalf("clone without progress: %d\n%s", code, plain.String())
	}
	// A log line longer than the terminal wraps as it would without progress; a status line never may.
	bare := &screen{width: width}
	bare.feed(bytes.ReplaceAll(plain.Bytes(), []byte("\n"), []byte("\r\n"))) // as the terminal's line discipline does
	if s.wrapped != bare.wrapped {
		t.Errorf("%d lines wrapped on a %d-column terminal, %d without progress", s.wrapped, width, bare.wrapped)
	}
	got, want := s.text(), bare.text()
	sort.Strings(got) // the workers write in their own order
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the screen after the run:\n%s\n\nwant what a run without progress shows:\n%s", strings.Join(s.text(), "\n"), strings.Join(bare.text(), "\n"))
	}
}

// check shows the kind it reads and then the target's schema, and once done the screen holds its report alone, as a
// run without progress writes it.
func TestTheProgressOfCheckOnATerminal(t *testing.T) {
	const width = 60
	master, tty, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	defer master.Close()
	if err := pty.Setsize(master, &pty.Winsize{Rows: 40, Cols: width}); err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	read := make(chan struct{})
	go func() { io.Copy(&stream, master); close(read) }()

	_, _, cfg := cli(t)
	saved := os.Stderr
	os.Stderr = tty
	code := run(context.Background(), []string{"check", "-config", cfg}, tty, tty)
	os.Stderr = saved
	tty.Close()
	<-read
	raw := stream.String()
	for _, want := range []string{"check ldaps://src:636", "[1/6] ou", "[3/6] user", "[6/6] the target's schema"} {
		if !strings.Contains(raw, want) {
			t.Errorf("the status never showed %q:\n%q", want, raw)
		}
	}
	s := &screen{width: width}
	s.feed(stream.Bytes())

	var plain bytes.Buffer // the same config: check writes nothing
	if again := run(context.Background(), []string{"check", "-progress", "off", "-config", cfg}, &plain, &plain); again != code {
		t.Fatalf("check exits %d without progress, %d with it\n%s", again, code, plain.String())
	}
	bare := &screen{width: width}
	bare.feed(bytes.ReplaceAll(plain.Bytes(), []byte("\n"), []byte("\r\n")))
	if got, want := strings.Join(s.text(), "\n"), strings.Join(bare.text(), "\n"); got != want {
		t.Fatalf("the screen after check:\n%s\n\nwant what a run without progress shows:\n%s", got, want)
	}
}
