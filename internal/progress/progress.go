// Package progress shows how far a clone or a diff has got. On a terminal it keeps a status at the bottom of the
// screen, redrawn a few times a second, while the log scrolls above it; anywhere else it prints a line now and
// then, so a log file or a CI log gets no control characters.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

// Mode is how the progress is shown.
type Mode string

const (
	// Auto is Live on a terminal, Plain otherwise.
	Auto Mode = "auto"
	// Live keeps the status at the bottom of the terminal.
	Live Mode = "live"
	// Plain prints a line every plainEvery.
	Plain Mode = "plain"
	// Off shows nothing.
	Off Mode = "off"
)

// ParseMode reads the -progress flag; live is not offered, as Auto chooses it whenever it can be drawn.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case Auto, Plain, Off:
		return m, nil
	}
	return "", fmt.Errorf("-progress %q: use auto, plain or off", s)
}

const (
	liveEvery  = 250 * time.Millisecond
	plainEvery = 10 * time.Second
	// etaAfter is how long a phase runs before its rate is trusted for an estimate.
	etaAfter = 2 * time.Second
	barWidth = 20
)

// Bar is where a run is: its phase and how much of it is done. A run calls it from its workers; a nil Bar does
// nothing, so a run without progress needs no checks.
type Bar struct {
	mu      sync.Mutex
	phases  int // 0 while not known
	index   int // phases started since phases was known: the one in progress is index of phases
	counted bool
	name    string
	total   int // < 0: not known
	done    int
	started time.Time
	stats   func() string
	clock   func() time.Time
	// onPhase, set by the Display, draws a new phase at once instead of at the next tick, so a short phase is seen.
	onPhase func()
}

// Phases says how many phases the run has, once it knows; the phases started from then on are numbered.
func (b *Bar) Phases(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.phases = n
}

// Phase starts the next phase, with total items (< 0 when it is not known).
func (b *Bar) Phase(name string, total int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.counted = b.phases > 0
	if b.counted {
		b.index++
	}
	b.name, b.total, b.done, b.started = name, total, 0, b.now()
	draw := b.onPhase
	b.mu.Unlock()
	if draw != nil {
		draw() // outside b.mu: it takes a snapshot
	}
}

// Add marks n more items of the phase done.
func (b *Bar) Add(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done += n
}

// Stats sets what the status says besides the phase (the counts of the run). f is called by the display alone,
// with no lock of the display held, so it may take the run's own locks.
func (b *Bar) Stats(f func() string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stats = f
}

func (b *Bar) now() time.Time {
	if b.clock != nil {
		return b.clock()
	}
	return time.Now()
}

// state is a copy of a Bar to draw from.
type state struct {
	phases, index, total, done int
	name                       string
	inPhase                    time.Duration
	stats                      string
}

func (b *Bar) snapshot() (state, bool) {
	b.mu.Lock()
	s := state{index: b.index, name: b.name, total: b.total, done: b.done, inPhase: b.now().Sub(b.started)}
	if b.counted {
		s.phases = b.phases
	}
	stats := b.stats
	b.mu.Unlock()
	if s.name == "" {
		return s, false
	}
	if stats != nil {
		s.stats = stats()
	}
	return s, true
}

// phaseText is "[3/6] user  5200/11727  44%  85/s  ~1m17s left", with the bar between the name and the counts
// when bar is set.
func phaseText(s state, bar bool) string {
	var b strings.Builder
	if s.phases > 0 {
		fmt.Fprintf(&b, "[%d/%d] ", s.index, s.phases)
	}
	b.WriteString(s.name)
	if s.total < 0 {
		if s.done > 0 {
			fmt.Fprintf(&b, "  %d done", s.done)
		}
		return b.String()
	}
	done := min(s.done, s.total) // the source may have grown since it was counted
	pct := 100
	if s.total > 0 {
		pct = done * 100 / s.total
	}
	if bar {
		filled := barWidth * pct / 100
		fmt.Fprintf(&b, "  %s%s", strings.Repeat("█", filled), strings.Repeat("░", barWidth-filled))
	}
	fmt.Fprintf(&b, "  %d/%d  %d%%", done, s.total, pct)
	if s.inPhase >= etaAfter && s.done > 0 {
		rate := float64(s.done) / s.inPhase.Seconds()
		fmt.Fprintf(&b, "  %.0f/s", rate)
		if left := s.total - done; left > 0 {
			fmt.Fprintf(&b, "  ~%s left", short(time.Duration(float64(left)/rate*float64(time.Second))))
		}
	}
	return b.String()
}

// short is a duration to the second: 45s, 1m17s, 2h03m.
func short(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

// liveLines is the status kept at the bottom of a terminal of width columns.
func liveLines(title string, s state, elapsed time.Duration, width int) []string {
	lines := []string{
		strings.Repeat("─", max(min(width-1, 72), 1)),
		" " + title + "  ·  elapsed " + short(elapsed),
		" " + phaseText(s, true),
	}
	if s.stats != "" {
		lines = append(lines, " "+s.stats)
	}
	for i, l := range lines {
		lines[i] = cut(l, width-1)
	}
	return lines
}

// plainLine is the line printed now and then where the status cannot be drawn.
func plainLine(s state, elapsed time.Duration) string {
	l := "progress: " + phaseText(s, false)
	if s.stats != "" {
		l += "; " + s.stats
	}
	return l + "; elapsed " + short(elapsed)
}

// cut shortens l to at most n characters, so a line never wraps (a wrapped line would break the redraw).
func cut(l string, n int) string {
	if n <= 0 || utf8.RuneCountInString(l) <= n {
		return l
	}
	return string([]rune(l)[:n])
}

// Display draws a Bar on status until Stop.
type Display struct {
	bar    *Bar
	title  string
	status *os.File
	live   bool
	start  time.Time

	mu      sync.Mutex // guards what is on the screen: drawn, lines and the writes of every Writer
	lines   []string
	drawn   int // status lines on the screen, the cursor at the end of the last
	stopped bool
	writers []*above

	stop chan struct{}
	done chan struct{}
}

// Start shows the progress of a run on status (standard error) in mode, under title ("clone → ldaps://dc1").
// With Off it returns a nil Display and a nil Bar, which do nothing.
func Start(mode Mode, status *os.File, title string) (*Display, *Bar) {
	if mode == Off {
		return nil, nil
	}
	live := mode == Live || (mode == Auto && term.IsTerminal(int(status.Fd())))
	d := &Display{bar: &Bar{}, title: title, status: status, live: live, start: time.Now(), stop: make(chan struct{}), done: make(chan struct{})}
	every := plainEvery
	if live {
		every = liveEvery
	}
	if live {
		d.bar.onPhase = d.tick
	}
	go d.loop(every)
	return d, d.bar
}

func (d *Display) loop(every time.Duration) {
	defer close(d.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-d.stop:
			return
		case <-t.C:
			d.tick()
		}
	}
}

func (d *Display) tick() {
	s, ok := d.bar.snapshot() // outside d.mu: it calls the run's Stats
	if !ok {
		return // nothing to show before the first phase (passwords and the confirmation are asked then)
	}
	elapsed := time.Since(d.start)
	if !d.live {
		d.mu.Lock()
		defer d.mu.Unlock()
		if !d.stopped {
			fmt.Fprintln(d.status, plainLine(s, elapsed))
		}
		return
	}
	width := 80
	if w, _, err := term.GetSize(int(d.status.Fd())); err == nil && w > 0 {
		width = w
	}
	lines := liveLines(d.title, s, elapsed, width)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return
	}
	d.lines = lines
	d.erase()
	d.draw()
}

// erase clears the status lines, leaving the cursor at the start of the first.
func (d *Display) erase() {
	if d.drawn == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("\r\x1b[2K")
	for range d.drawn - 1 {
		b.WriteString("\x1b[1A\x1b[2K")
	}
	io.WriteString(d.status, b.String())
	d.drawn = 0
}

// draw writes the status lines from the cursor, which must be at the start of a line, without a final newline.
func (d *Display) draw() {
	if len(d.lines) == 0 {
		return
	}
	io.WriteString(d.status, strings.Join(d.lines, "\n"))
	d.drawn = len(d.lines)
}

// Writer returns w so that what is written to it scrolls above the status, when w shows on the same terminal; any
// other w (a file, a pipe) is returned as it is. Whole lines are written; the rest waits for its newline.
func (d *Display) Writer(w io.Writer) io.Writer {
	if d == nil || !d.live {
		return w
	}
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return w
	}
	a := &above{d: d, w: w}
	d.mu.Lock()
	d.writers = append(d.writers, a)
	d.mu.Unlock()
	return a
}

type above struct {
	d       *Display
	w       io.Writer
	pending []byte
}

func (a *above) Write(p []byte) (int, error) {
	a.d.mu.Lock()
	defer a.d.mu.Unlock()
	a.pending = append(a.pending, p...)
	end := strings.LastIndexByte(string(a.pending), '\n')
	if end < 0 {
		return len(p), nil
	}
	if a.d.stopped {
		_, err := a.w.Write(a.pending[:end+1])
		a.pending = a.pending[end+1:]
		return len(p), err
	}
	a.d.erase()
	_, err := a.w.Write(a.pending[:end+1])
	a.pending = append([]byte(nil), a.pending[end+1:]...)
	a.d.draw()
	return len(p), err
}

// Stop ends the display and clears the status, so what follows (the summary) is written as usual. It is safe to
// call more than once, and on a nil Display.
func (d *Display) Stop() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		return
	}
	d.stopped = true
	d.erase()
	for _, a := range d.writers {
		if len(a.pending) > 0 {
			a.w.Write(a.pending)
			a.pending = nil
		}
	}
	d.mu.Unlock()
	close(d.stop)
	<-d.done
}
