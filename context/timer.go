// Copyright (c) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package context

import (
	"sync"
	"sync/atomic"
	"time"
)

// Timer can be used for retransmission, it will manage retry times automatically.
//
// Ported from the AMF, which carries the same type for its NAS timers, so that the two network
// functions retransmit on the same semantics. One difference: Stop is idempotent here. The
// original documents that calling it more than once is unsafe, which is a hazard for a timer
// stopped by an incoming message — a retransmitted acknowledgement racing an abort would stop
// it twice, and a second send on the closed channel panics.
type Timer struct {
	ticker        *time.Ticker
	expireTimes   atomic.Int32
	maxRetryTimes atomic.Int32
	done          chan bool
	stopOnce      sync.Once
	wg            sync.WaitGroup
}

// NewTimer returns a Timer and starts a goroutine that calls expiredFunc on every interval d
// until Stop is called. Once the number of expiries exceeds maxRetryTimes the timer calls
// cancelFunc and turns itself off. expiredFunc receives the current expiry count.
func NewTimer(d time.Duration, maxRetryTimes int,
	expiredFunc func(expireTimes int32),
	cancelFunc func(),
) *Timer {
	t := &Timer{}
	t.expireTimes.Store(0)
	t.maxRetryTimes.Store(int32(maxRetryTimes))
	t.done = make(chan bool, 1)
	t.ticker = time.NewTicker(d)

	t.wg.Add(1)
	go func(ticker *time.Ticker) {
		defer t.wg.Done()
		defer ticker.Stop()

		for {
			select {
			case <-t.done:
				return
			case <-ticker.C:
				t.expireTimes.Add(1)
				if t.ExpireTimes() > t.MaxRetryTimes() {
					cancelFunc()
					return
				}
				expiredFunc(t.ExpireTimes())
			}
		}
	}(t.ticker)

	return t
}

// MaxRetryTimes returns the max retry times of the timer.
func (t *Timer) MaxRetryTimes() int32 {
	return t.maxRetryTimes.Load()
}

// ExpireTimes returns the current expire times of the timer.
func (t *Timer) ExpireTimes() int32 {
	return t.expireTimes.Load()
}

// Stop turns off the timer. After Stop returns, no further expiry event is triggered: Stop waits
// for the timer's own goroutine to exit rather than merely signalling it, because the select in
// that goroutine gives no priority between the done channel and the ticker — a tick already
// queued when Stop is called can still be the one chosen, and without waiting here that callback
// would be free to run after Stop had already returned to a caller who believed the timer dead.
// Stop is safe to call more than once and safe to call concurrently with the timer aborting on
// its own. It must not be called from expiredFunc or cancelFunc themselves: those run on the
// goroutine this waits for, and calling Stop from there deadlocks.
func (t *Timer) Stop() {
	t.stopOnce.Do(func() {
		t.done <- true
		close(t.done)
	})
	t.wg.Wait()
}
