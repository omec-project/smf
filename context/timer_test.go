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
