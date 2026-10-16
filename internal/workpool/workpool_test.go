package workpool

import (
	"errors"
	"sync/atomic"
	"testing"
)

func TestEachRunsAllItemsWithinWorkerLimit(t *testing.T) {
	var running, peak, done atomic.Int32
	items := make([]int, 50)
	err := Each(4, items, func(int) error {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		done.Add(1)
		running.Add(-1)
		return nil
	})
	if err != nil || done.Load() != 50 || peak.Load() > 4 {
		t.Fatalf("err=%v done=%d peak=%d", err, done.Load(), peak.Load())
	}
}

func TestEachReturnsFirstError(t *testing.T) {
	boom := errors.New("boom")
	if err := Each(1, []int{1, 2, 3}, func(i int) error {
		if i == 2 {
			return boom
		}
		return nil
	}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}
