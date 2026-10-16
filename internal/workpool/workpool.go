// Package workpool provides bounded parallel execution.
package workpool

import "sync"

// Feed passes the elements emitted by produce to fn with at most workers running in parallel.
// emit blocks the caller until a slot frees up (backpressure), so even if produce reads everything,
// no more than workers pending elements are held in memory.
// On the first error, emit returns that error and stops produce from scanning further.
// When workers <= 1, fn runs sequentially inside emit.
func Feed[T any](workers int, produce func(emit func(T) error) error, fn func(T) error) error {
	if workers <= 1 {
		return produce(fn)
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
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			if err := fn(it); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
		return nil
	}
	produceErr := produce(emit)
	wg.Wait()
	if err := current(); err != nil {
		return err
	}
	return produceErr
}

// Each passes items to fn with at most workers running in parallel. On the first error it stops starting new work and returns that error.
func Each[T any](workers int, items []T, fn func(T) error) error {
	return Feed(workers, func(emit func(T) error) error {
		for _, it := range items {
			if err := emit(it); err != nil {
				return err
			}
		}
		return nil
	}, fn)
}
