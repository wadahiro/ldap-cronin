package workpool

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestEachRunsAllItemsWithinWorkerLimit(t *testing.T) {
	var running, peak, done atomic.Int32
	items := make([]int, 50)
	err := Each(context.Background(), 4, items, func(context.Context, int) error {
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
	if err := Each(context.Background(), 1, []int{1, 2, 3}, func(_ context.Context, i int) error {
		if i == 2 {
			return boom
		}
		return nil
	}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}

// A failing item cancels the context of the items still running, and the first error, not the cancellation, is returned.
func TestFirstErrorCancelsRunningWorkers(t *testing.T) {
	boom := errors.New("boom")
	var cancelled atomic.Int32
	err := Each(context.Background(), 4, []int{0, 1, 2, 3}, func(ctx context.Context, i int) error {
		if i == 0 {
			time.Sleep(10 * time.Millisecond) // let the others start and block
			return boom
		}
		select {
		case <-ctx.Done():
			cancelled.Add(1)
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return nil
		}
	})
	if !errors.Is(err, boom) || cancelled.Load() != 3 {
		t.Fatalf("err=%v cancelled=%d", err, cancelled.Load())
	}
}

// A cancelled parent stops the producer: emit returns the cancellation instead of starting more work.
func TestParentCancellationStopsProducer(t *testing.T) {
	var started atomic.Int32
	for _, workers := range []int{1, 4} {
		started.Store(0)
		ctx, cancel := context.WithCancel(context.Background())
		err := Feed(ctx, workers, func(_ context.Context, emit func(int) error) error {
			for i := 0; i < 100; i++ {
				if i == 10 {
					cancel()
				}
				if err := emit(i); err != nil {
					return err
				}
			}
			return nil
		}, func(context.Context, int) error {
			started.Add(1)
			return nil
		})
		cancel()
		if !errors.Is(err, context.Canceled) || started.Load() > 10 {
			t.Fatalf("workers=%d: err=%v started=%d", workers, err, started.Load())
		}
	}
}
