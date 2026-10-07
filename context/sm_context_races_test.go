// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// A context is published into the pool for anything to find. Until it is fully built, "anything"
// includes code that reads fields the constructor has not assigned yet, which is a data race on
// every one of them and a nil dereference on the loggers. Run this under -race: without the fix
// the detector reports the writes in NewSMContext against the reads here.
func TestCreatingSessionsConcurrentlyWithPoolReadsIsRaceFree(t *testing.T) {
	const writers, perWriter = 4, 50

	var churn sync.WaitGroup
	for w := range writers {
		churn.Add(1)
		go func(w int) {
			defer churn.Done()
			for i := range perWriter {
				smContext := NewSMContext(fmt.Sprintf("imsi-20893%03d%05d", w, i), int32(i%15+1))
				if smContext.PFCPContext == nil {
					t.Errorf("a context was returned before its PFCP map was made")
				}
			}
		}(w)
	}

	// Read from the pool while it is being written, the way anything holding a ref does, and keep
	// reading until the writers are done. A single pass would be a false negative: with 200
	// sessions to create, the reader can finish its sweep before the writers have published
	// anything and report success without the two ever having overlapped.
	stop := make(chan struct{})
	var observed atomic.Int64

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			for w := range writers {
				for i := range perWriter {
					ref, err := ResolveRef(fmt.Sprintf("imsi-20893%03d%05d", w, i), int32(i%15+1))
					if err != nil {
						continue // not created yet
					}
					smContext := GetSMContext(ref)
					if smContext == nil {
						continue
					}
					observed.Add(1)
					if smContext.PFCPContext == nil {
						t.Errorf("a context was reachable from the pool before its PFCP map was made")
					}
					if smContext.SubCtxLog == nil {
						t.Errorf("a context was reachable from the pool before its loggers were set")
					}
				}
			}
		}
	}()

	churn.Wait()
	close(stop)
	<-done

	// Without this the test can pass having proved nothing, which is the failure mode a race probe
	// is most likely to have: it says the detector found no race, not that the two sides ever met.
	if observed.Load() == 0 {
		t.Fatal("the reader never found a published context, so it never overlapped the writers")
	}
	t.Logf("pool reads that met a published context: %d", observed.Load())
}

// releaseTunnel (producer package) rebuilds PendingUPF under SMLock while the PFCP
// modification/deletion response handlers delete from it without SMLock (they can't take SMLock:
// the producer side holds it across a blocking channel wait). Without every accessor going
// through the PendingUPFLock-guarded helper methods, this is a concurrent map read/write, which
// for Go maps panics the process rather than just tripping the race detector. Run this under
// -race: without the lock, both the panic and a race report are possible depending on scheduling.
func TestPendingUPFSurvivesConcurrentRebuildAndResponseHandling(t *testing.T) {
	smContext := &SMContext{}

	const iterations = 2000
	var wg sync.WaitGroup

	// Simulates releaseTunnel: reset then repopulate, as the replacement and normal release paths
	// do under SMLock.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range iterations {
			smContext.ResetPendingUPF(nil)
			smContext.AddPendingUPF(fmt.Sprintf("10.0.0.%d", i%255))
		}
	}()

	// Simulates the unlocked response handlers: delete the responding UPF, then check IsEmpty.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range iterations {
			smContext.DeletePendingUPF(fmt.Sprintf("10.0.0.%d", i%255))
		}
	}()

	wg.Wait()
}

// MarshalJSON and ToBsonM walk SMContext's exported fields outside of PendingUPFLock. If
// PendingUPF were still among those fields, a concurrent unlocked response handler mutating it
// (as the PFCP modification/deletion handlers do) would race the encoder's map iteration, and for
// Go maps that is a potential process-crashing fatal error, not just a race report. PendingUPF is
// excluded from JSON/BSON for exactly this reason; this test guards against that exclusion being
// silently reverted. Run under -race.
func TestSerializationDoesNotRaceConcurrentPendingUPFMutation(t *testing.T) {
	smContext := &SMContext{PFCPContext: make(map[string]*PFCPSessionContext)}

	const iterations = 500
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range iterations {
			smContext.AddPendingUPF(fmt.Sprintf("10.0.0.%d", i%255))
			smContext.DeletePendingUPF(fmt.Sprintf("10.0.0.%d", i%255))
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range iterations {
			_ = ToBsonM(smContext)
			if _, err := smContext.MarshalJSON(); err != nil {
				t.Errorf("MarshalJSON failed: %v", err)
			}
		}
	}()

	wg.Wait()
}

// AggregateEstablishmentResponse is the only correct way the establishment response handlers touch
// PendingUPF and the EstablishmentFailed latch: it runs the whole check/delete/empty/latch sequence
// under PendingUPFLock. Those handlers can run concurrently for different UPFs of one session, so a
// direct map access would be a concurrent read/write -- a process-crashing fatal error for Go maps,
// not just a race report. Run under -race. Exactly the response that drains the last pending UPF
// signals the verdict, no matter which goroutine that turns out to be.
func TestAggregateEstablishmentResponseIsRaceFree(t *testing.T) {
	const upfs = 64
	smContext := &SMContext{PendingUPF: make(PendingUPF)}
	for i := range upfs {
		smContext.AddPendingUPF(fmt.Sprintf("10.0.0.%d", i))
	}

	var wg sync.WaitGroup
	var signals atomic.Int64
	for i := range upfs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, signal, _ := smContext.AggregateEstablishmentResponse(fmt.Sprintf("10.0.0.%d", i), true); signal {
				signals.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if got := signals.Load(); got != 1 {
		t.Errorf("responses that signalled a verdict = %d, want exactly 1 (the one that empties the batch)", got)
	}
	if !smContext.PendingUPFIsEmpty() {
		t.Errorf("PendingUPF not empty after every UPF responded")
	}
}

// AggregateEstablishmentResponse decides the single create verdict from the whole batch of UPF
// responses: success only if every tracked UPF accepted, failure if any rejected (latched so the
// order responses arrive in cannot change the outcome), and a response from a UPF outside the batch
// changes nothing.
func TestAggregateEstablishmentResponseVerdict(t *testing.T) {
	t.Run("all accepted yields success once the batch empties", func(t *testing.T) {
		smContext := &SMContext{PendingUPF: PendingUPF{"a": true, "b": true}}
		if tracked, signal, _ := smContext.AggregateEstablishmentResponse("a", true); !tracked || signal {
			t.Fatalf("first of two responses: tracked=%v signal=%v, want tracked=true signal=false", tracked, signal)
		}
		tracked, signal, verdict := smContext.AggregateEstablishmentResponse("b", true)
		if !tracked || !signal || verdict != SessionEstablishSuccess {
			t.Fatalf("second response: tracked=%v signal=%v verdict=%v, want true/true/SessionEstablishSuccess", tracked, signal, verdict)
		}
	})

	t.Run("a rejection is latched across a later acceptance", func(t *testing.T) {
		smContext := &SMContext{PendingUPF: PendingUPF{"a": true, "b": true}}
		// The first UPF rejects; the second accepts. The latch must outlast the acceptance so the
		// batch verdict is failure, not whichever response happened to arrive last.
		smContext.AggregateEstablishmentResponse("a", false)
		_, signal, verdict := smContext.AggregateEstablishmentResponse("b", true)
		if !signal || verdict != SessionEstablishFailed {
			t.Fatalf("verdict after one rejection: signal=%v verdict=%v, want signal=true SessionEstablishFailed", signal, verdict)
		}
		// Cleared once the verdict is produced, so the next batch on this context starts clean.
		if smContext.EstablishmentFailed {
			t.Errorf("EstablishmentFailed still set after the verdict was produced")
		}
	})

	t.Run("a response from outside the batch changes nothing", func(t *testing.T) {
		smContext := &SMContext{PendingUPF: PendingUPF{"a": true}}
		tracked, signal, _ := smContext.AggregateEstablishmentResponse("not-pending", false)
		if tracked || signal {
			t.Fatalf("untracked response: tracked=%v signal=%v, want both false", tracked, signal)
		}
		if smContext.EstablishmentFailed {
			t.Errorf("an untracked rejection must not latch EstablishmentFailed")
		}
		if smContext.PendingUPFIsEmpty() {
			t.Errorf("an untracked response must not drain the pending batch")
		}
	})
}

// ResetPendingUPF starts a new response batch. A prior batch that recorded a rejection but was
// abandoned before draining to a verdict (e.g. another request failed synchronously and woke the
// create waiter) leaves EstablishmentFailed latched; without clearing it here, an all-accepted retry
// would still be reported as failed. The latch must be reset together with the map, under the lock.
func TestResetPendingUPFClearsEstablishmentFailedLatch(t *testing.T) {
	smContext := &SMContext{PendingUPF: PendingUPF{"a": true, "b": true}}

	// First batch: one UPF rejects, the batch is abandoned before the second responds, so the latch
	// is left set.
	smContext.AggregateEstablishmentResponse("a", false)
	if !smContext.EstablishmentFailed {
		t.Fatal("precondition: a rejection should have latched EstablishmentFailed")
	}

	// A retry replaces the batch.
	smContext.ResetPendingUPF(PendingUPF{"a": true, "b": true})
	if smContext.EstablishmentFailed {
		t.Fatal("ResetPendingUPF did not clear the stale EstablishmentFailed latch")
	}

	// The all-accepted retry must now produce success, not the stale failure.
	smContext.AggregateEstablishmentResponse("a", true)
	_, signal, verdict := smContext.AggregateEstablishmentResponse("b", true)
	if !signal || verdict != SessionEstablishSuccess {
		t.Fatalf("all-accepted retry: signal=%v verdict=%v, want signal=true SessionEstablishSuccess", signal, verdict)
	}
}
