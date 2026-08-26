// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/omec-project/smf/context"
)

// A context is published into the pool for anything to find. Until it is fully built, "anything"
// includes code that reads fields the constructor has not assigned yet, which is a data race on
// every one of them. Run this under -race: without the fix the detector reports the write in
// NewSMContext against the read here.
func TestCreatingSessionsConcurrentlyWithPoolReadsIsRaceFree(t *testing.T) {
	const writers, perWriter = 4, 50

	var churn sync.WaitGroup
	for w := range writers {
		churn.Add(1)
		go func(w int) {
			defer churn.Done()
			for i := range perWriter {
				smContext := context.NewSMContext(fmt.Sprintf("imsi-20893%03d%05d", w, i), int32(i%15+1))
				if smContext.PFCPContext == nil {
					t.Errorf("a context was returned before its PFCP map was made")
				}
			}
		}(w)
	}

	// Read from the pool while it is being written, the way anything holding a ref does. Without
	// the fix, GetSMContext can return a context whose fields the constructor has not reached.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for w := range writers {
			for i := range perWriter {
				ref, err := context.ResolveRef(fmt.Sprintf("imsi-20893%03d%05d", w, i), int32(i%15+1))
				if err != nil {
					continue // not created yet
				}
				if smContext := context.GetSMContext(ref); smContext != nil && smContext.PFCPContext == nil {
					t.Errorf("a context was reachable from the pool before its PFCP map was made")
				}
			}
		}
	}()

	churn.Wait()
	<-done
}
