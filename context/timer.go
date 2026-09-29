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

	go func(ticker *time.Ticker) {
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

// Stop turns off the timer. Stop is safe to call more than once and safe to call concurrently with
// the timer aborting on its own.
//
// Stop does not wait for the timer's goroutine. An expiry that is already due when Stop is called
// can still be delivered afterwards: the goroutine selects between the stop signal and the ticker,
// and Go's select picks at random when both are ready. A caller whose callbacks must not act for a
// stopped timer has to check that the timer is still the one it is using, under the same lock that
// it holds when it calls Stop. Waiting here for a callback in progress is not an alternative, since
// callers stop the timer under the lock their callbacks take.
func (t *Timer) Stop() {
	t.stopOnce.Do(func() {
		t.done <- true
		close(t.done)
	})
}
