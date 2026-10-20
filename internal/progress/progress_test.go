package progress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clockAt returns a Bar clock that a test moves by hand.
func clockAt(now *time.Time) func() time.Time { return func() time.Time { return *now } }

func TestThePhaseSaysHowFarAndHowLongIsLeft(t *testing.T) {
	now := time.Unix(1_000, 0)
	b := &Bar{clock: clockAt(&now)}
	if _, ok := b.snapshot(); ok {
		t.Fatal("nothing to show before the first phase")
	}
	b.Phase("reading the source", -1)
	if s, _ := b.snapshot(); phaseText(s, false) != "reading the source" {
		t.Fatalf("a phase before the count is known has no number: %q", phaseText(s, false))
	}
	b.Phases(5)
	b.Phase("OUs and parents", 10)
	b.Add(10)
	b.Phase("user", 11727)
	b.Stats(func() string { return "added 5180" })
	now = now.Add(time.Second)
	b.Add(85)
	if s, _ := b.snapshot(); phaseText(s, false) != "[2/5] user  85/11727  0%" {
		t.Fatalf("no rate before the phase has run a while: %q", phaseText(s, false))
	}
	now = now.Add(60 * time.Second)
	b.Add(5200 - 85)
	s, _ := b.snapshot()
	if got := phaseText(s, false); got != "[2/5] user  5200/11727  44%  85/s  ~1m17s left" {
		t.Fatalf("%q", got)
	}
	if got := phaseText(s, true); !strings.Contains(got, "user  ████████░░░░░░░░░░░░  5200/11727") {
		t.Fatalf("the bar: %q", got)
	}
	if got := plainLine(s, 2*time.Minute+3*time.Second); got != "progress: [2/5] user  5200/11727  44%  85/s  ~1m17s left; added 5180; elapsed 2m03s" {
		t.Fatalf("%q", got)
	}
	b.Add(20000) // the source grew since it was counted
	if s, _ := b.snapshot(); !strings.Contains(phaseText(s, false), "11727/11727  100%") {
		t.Fatalf("never past 100%%: %q", phaseText(s, false))
	}
	b.Phase("references", -1)
	b.Add(3)
	if s, _ := b.snapshot(); phaseText(s, false) != "[3/5] references  3 done" {
		t.Fatalf("%q", phaseText(s, false))
	}
}

func TestLiveLinesNeverWrap(t *testing.T) {
	s := state{phases: 5, index: 3, name: "user", total: 11727, done: 5200, inPhase: time.Minute, stats: "added 5180 · updated 20"}
	for _, width := range []int{20, 40, 200} {
		lines := liveLines("clone → ldaps://dc1.test.example.com:636", s, time.Minute, width)
		if len(lines) != 4 {
			t.Fatalf("separator, title, phase, stats: %q", lines)
		}
		for _, l := range lines {
			if n := len([]rune(l)); n > width-1 {
				t.Fatalf("width %d: a line of %d would wrap: %q", width, n, l)
			}
		}
	}
	if got := short(2*time.Hour + 3*time.Minute + 30*time.Second); got != "2h03m" {
		t.Fatalf("%q", got)
	}
}

// A line written to the terminal scrolls above the status: the status is erased, the line written, the status
// drawn again. A partial line waits for its newline, and Stop writes what is left and clears the status.
func TestTheLogScrollsAboveTheStatus(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "screen"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Display{bar: &Bar{}, status: f, live: true, stop: make(chan struct{}), done: make(chan struct{})}
	close(d.done) // no loop runs: the test draws by hand
	d.lines = []string{"--", "status"}
	d.draw()
	log := &above{d: d, w: f}
	d.writers = append(d.writers, log)
	for _, w := range []string{"add    CN=A\nadd    CN=", "B\n", "upd", "ate CN=C"} { // the last two hold no newline
		log.Write([]byte(w))
	}
	d.Stop()
	raw, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	erase := "\r\x1b[2K\x1b[1A\x1b[2K"
	want := "--\nstatus" + erase + "add    CN=A\n--\nstatus" + erase + "add    CN=B\n--\nstatus" + erase + "update CN=C"
	if string(raw) != want {
		t.Fatalf("screen:\n%q\nwant\n%q", raw, want)
	}
}

func TestOffShowsNothing(t *testing.T) {
	d, b := Start(Off, os.Stderr, "x")
	b.Phase("user", 1) // a nil Bar does nothing
	b.Add(1)
	d.Stop()
	if w := d.Writer(os.Stdout); w != os.Stdout {
		t.Fatal("a nil Display passes writers through")
	}
	if _, err := ParseMode("live"); err == nil {
		t.Fatal("live is chosen by auto, not asked for")
	}
}
