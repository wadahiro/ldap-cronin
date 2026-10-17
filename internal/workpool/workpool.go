// Package workpool provides bounded parallel execution.
package workpool

import (
	"context"
	"sync"
)

// Feed passes the elements emitted by produce to fn with at most workers running in parallel.
// emit blocks the caller until a slot frees up (backpressure), so even if produce reads everything,
// no more than workers pending elements are held in memory.
//
// produce and fn receive a context that is cancelled on the first error (as errgroup.WithContext does), so workers
// still running stop at their next operation instead of finishing their item. emit then returns that error and
// stops produce from scanning further. The first error is returned, not the cancellations it caused.
// When workers <= 1, fn runs sequentially inside emit.
func Feed[T any](ctx context.Context, workers int, produce func(ctx context.Context, emit func(T) error) error, fn func(context.Context, T) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if workers <= 1 {
		return produce(ctx, func(it T) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fn(ctx, it)
		})
	}
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		sem      = make(chan struct{}, workers)
	)
	current := func() error {
		mu.Lock()
		defer mu.Unlock()
		return firstErr
	}
	emit := func(it T) error {
		if err := current(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			if err := current(); err != nil {
				return err
			}
			return ctx.Err()
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			if err := fn(ctx, it); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				mu.Unlock()
			}
		}()
		return nil
	}
	produceErr := produce(ctx, emit)
	wg.Wait()
	if err := current(); err != nil {
		return err
	}
	return produceErr
}

// Each passes items to fn with at most workers running in parallel. On the first error it stops starting new work,
// cancels the context given to the running ones, and returns that error.
func Each[T any](ctx context.Context, workers int, items []T, fn func(context.Context, T) error) error {
	return Feed(ctx, workers, func(_ context.Context, emit func(T) error) error {
		for _, it := range items {
			if err := emit(it); err != nil {
				return err
			}
		}
		return nil
	}, fn)
}
