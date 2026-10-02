// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"testing"
	"time"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"go.uber.org/zap"
)

// Work the SMF queues for a session runs in the session's transaction slot: a second task does not
// start while the first is still running. A held policy decision is queued this way so that it
// starts only once the transaction that ended the modification before it -- its state machine
// included -- has finished.
func TestSessionTasksRunOneAtATime(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig.Configuration = &factory.Configuration{}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}
	sm := &smf_context.SMContext{SubFsmLog: zap.NewNop().Sugar(), SubCtxLog: zap.NewNop().Sugar(), SubPduSessLog: zap.NewNop().Sugar()}

	firstRunning, releaseFirst, secondRan := make(chan struct{}), make(chan struct{}), make(chan struct{})
	queueSessionTask(sm, func() {
		close(firstRunning)
		<-releaseFirst
	})
	select {
	case <-firstRunning:
	case <-time.After(5 * time.Second):
		t.Fatal("a queued task never ran")
	}
	queueSessionTask(sm, func() { close(secondRan) })

	select {
	case <-secondRan:
		t.Fatal("a second task for the session ran while the first was still in its slot")
	case <-time.After(300 * time.Millisecond):
	}

	close(releaseFirst)
	select {
	case <-secondRan:
	case <-time.After(5 * time.Second):
		t.Fatal("the second task never ran after the first finished")
	}

	// The lifecycle goes on past the task -- saving and ending the transaction -- and reads the
	// configuration this test installed, so the queue has to drain before the test cleans up.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		sm.SMTxnBusLock.Lock()
		idle := sm.ActiveTxn == nil && len(sm.TxnBus) == 0
		sm.SMTxnBusLock.Unlock()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the session's transaction queue never drained")
		}
	}
}
