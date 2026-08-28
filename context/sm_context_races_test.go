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
