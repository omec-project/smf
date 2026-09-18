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
	var expiries int32
	cancelled := make(chan struct{})

	NewTimer(5*time.Millisecond, 4,
		func(int32) { atomic.AddInt32(&expiries, 1) },
		func() { close(cancelled) },
	)

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("timer never cancelled")
	}

	if got := atomic.LoadInt32(&expiries); got != 4 {
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
	var expiries int32
	var cancels int32

	timer := NewTimer(20*time.Millisecond, 4,
		func(int32) { atomic.AddInt32(&expiries, 1) },
		func() { atomic.AddInt32(&cancels, 1) },
	)
	timer.Stop()
	time.Sleep(120 * time.Millisecond)

	if got := atomic.LoadInt32(&expiries); got != 0 {
		t.Errorf("expiries after Stop = %d, want 0", got)
	}
	if got := atomic.LoadInt32(&cancels); got != 0 {
		t.Errorf("cancels after Stop = %d, want 0", got)
	}
}
