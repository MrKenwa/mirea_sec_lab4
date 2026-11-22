package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	Status   string
	Password string
	Attempts uint64
	Elapsed  time.Duration
}

func search(ctx context.Context, cfg Config, target *dvwa) (result, error) {
	start := time.Now()
	workCtx, cancel := context.WithCancel(ctx)

	defer cancel()

	var attempts atomic.Uint64

	type outcome struct {
		password string
		err      error
	}

	outcomes := make(chan outcome, 1)

	var once sync.Once

	finish := func(value outcome) {
		once.Do(func() {
			outcomes <- value

			cancel()
		})
	}
	jobs := make(chan Job)

	var group sync.WaitGroup

	group.Add(1)

	go func() {
		defer group.Done()

		defer close(jobs)

		for _, job := range Jobs(cfg) {
			select {
			case <-workCtx.Done():
				return

			case jobs <- job:
			}
		}
	}()

	for range cfg.Workers {
		group.Add(1)

		go func() {
			defer group.Done()

			storage := make([]byte, cfg.MaxLength)

			for job := range jobs {
				cursor, err := NewCursor(cfg.Charset.Symbols, job, storage)

				if err != nil {
					finish(outcome{err: err})

					return
				}

				for {
					if workCtx.Err() != nil {
						return
					}

					matched, err := target.check(workCtx, cursor.Value())

					if err != nil {
						if workCtx.Err() == nil {
							finish(outcome{err: err})
						}

						return
					}

					attempts.Add(1)

					if matched {
						finish(outcome{password: string(cursor.Value())})

						return
					}

					if !cursor.Next() {
						break
					}
				}
			}
		}()
	}

	group.Wait()

	value := result{Status: "exhausted", Attempts: attempts.Load(), Elapsed: time.Since(start)}

	select {
	case outcome := <-outcomes:
		if outcome.err != nil {
			value.Status = "error"

			return value, outcome.err
		}

		value.Status, value.Password = "found", outcome.password

		return value, nil

	default:
	}

	if ctx.Err() != nil {
		value.Status = "cancelled"

		return value, ctx.Err()
	}

	return value, nil
}
