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
	var enterOnce sync.Once
	entered := make(chan struct{})
	timer := NewTimer(time.Microsecond, 1_000_000,
		func(int32) {
			enterOnce.Do(func() { close(entered) })
			callbackLock.Lock()
			defer callbackLock.Unlock()
		},
		func() {},
	)
	t.Cleanup(func() {
		callbackLock.Unlock()
		timer.Stop()
	})

	<-entered // wait for a callback to be in flight and blocked on the lock below

	callbackLock.Lock() // simulate the caller already holding the lock expiredFunc needs

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
