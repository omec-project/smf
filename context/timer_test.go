// Copyright (c) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTimerRetransmitsThenCancels(t *testing.T) {
	var expiries atomic.Int32
	cancelled := make(chan struct{})

	NewTimer(5*time.Millisecond, 4,
		func(int32) { expiries.Add(1) },
		func() { close(cancelled) },
	)

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("timer never cancelled")
	}

	if got := expiries.Load(); got != 4 {
		t.Errorf("retransmissions = %d, want 4 before the fifth expiry aborts", got)
	}
}

func TestTimerStopIsIdempotent(t *testing.T) {
	timer := NewTimer(time.Hour, 4, func(int32) {}, func() {})

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			timer.Stop() // a second send on the closed channel would panic
		}()
	}
	wg.Wait()
}

func TestTimerStoppedBeforeExpiryDoesNotFire(t *testing.T) {
	var expiries atomic.Int32
	var cancels atomic.Int32

	timer := NewTimer(20*time.Millisecond, 4,
		func(int32) { expiries.Add(1) },
		func() { cancels.Add(1) },
	)
	timer.Stop()
	time.Sleep(120 * time.Millisecond)

	if got := expiries.Load(); got != 0 {
		t.Errorf("expiries after Stop = %d, want 0", got)
	}
	if got := cancels.Load(); got != 0 {
		t.Errorf("cancels after Stop = %d, want 0", got)
	}
}

// A tick racing Stop must never produce a callback that outlives Stop's return: the select
// inside the timer's goroutine has no preference between the done channel and the ticker, so a
// tick already queued when Stop is called can still be the one chosen. Stop must wait for that
// callback rather than let it run unobserved after telling its caller the timer is dead.
func TestTimerStopWaitsOutACallbackRacingIt(t *testing.T) {
	for i := range 200 {
		var stopped atomic.Int32
		observedAfterStop := func() {
			if stopped.Load() != 0 {
				t.Errorf("iteration %d: a callback ran after Stop returned", i)
			}
		}

		timer := NewTimer(time.Microsecond, 1_000_000,
			func(int32) { observedAfterStop() },
			observedAfterStop,
		)

		time.Sleep(time.Microsecond) // let a tick queue before racing Stop against it
		timer.Stop()
		stopped.Store(1)
	}
}

// If a caller breaks the contract documented on Stop (holding a lock expiredFunc/cancelFunc also
// needs), Stop must still return — bounded by stopWaitTimeout — rather than join the timer's
// goroutine in a permanent deadlock. The callback is free to still be blocked on the lock after
// Stop returns in that case; that is the documented fallout of the caller's own bug, not something
// this test asserts against.
func TestTimerStopTimesOutRatherThanDeadlockingOnACallbackLock(t *testing.T) {
	previous := stopWaitTimeout
	stopWaitTimeout = 20 * time.Millisecond
	t.Cleanup(func() { stopWaitTimeout = previous })

	var callbackLock sync.Mutex
	var enteredOnce sync.Once
	entered := make(chan struct{})

	// Acquired before the timer is even started - and not released until cleanup - so the
	// callback below is guaranteed to block on it rather than racing this goroutine for it.
	callbackLock.Lock() // simulate the caller already holding the lock expiredFunc needs

	timer := NewTimer(time.Microsecond, 1_000_000,
		func(int32) {
			// Once Stop times out it may still race its own goroutine's select against the
			// 1-microsecond ticker after this callback finally unblocks (done is ready but not
			// guaranteed to win over ticker.C), so expiredFunc can run more than once; guard the
			// channel close against that instead of assuming a single invocation.
			enteredOnce.Do(func() { close(entered) })
			callbackLock.Lock()
			defer callbackLock.Unlock()
		},
		func() {},
	)
	t.Cleanup(func() {
		callbackLock.Unlock()
		timer.Stop()
	})

	// callbackLock is already held above, so the callback closing entered right before its own
	// Lock() call proves it is now blocked on that lock, not merely about to attempt it.
	<-entered

	stopReturned := make(chan struct{})
	go func() {
		timer.Stop()
		close(stopReturned)
	}()

	select {
	case <-stopReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within its timeout while a callback was blocked on a caller-held lock")
	}
}

// T3591's abandonment stops the session's T3591 from inside the timer's own cancellation callback,
// holding SMLock, and an acknowledgement stops it holding SMLock while a callback may be waiting for
// that lock. Both have to return at once. Stop waits for the timer's goroutine -- the goroutine the
// first case runs on, and one the second blocks -- until its timeout, so StopT3591 cancels without
// waiting.
func TestStopT3591FromItsOwnCallbackDoesNotWait(t *testing.T) {
	sm := &SMContext{}
	returned := make(chan time.Duration, 1)

	sm.SMLock.Lock()
	sm.NwModificationPending = true
	sm.T3591 = NewTimer(10*time.Millisecond, 0, func(int32) {}, func() {
		sm.SMLock.Lock()
		defer sm.SMLock.Unlock()
		start := time.Now()
		sm.StopT3591()
		returned <- time.Since(start)
	})
	sm.SMLock.Unlock()

	select {
	case took := <-returned:
		if took > time.Second {
			t.Errorf("StopT3591 from the timer's own callback took %s; it waited on itself", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the timer never expired")
	}
}
