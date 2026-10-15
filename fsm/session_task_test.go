// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"testing"
	"time"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/transaction"
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

// step runs one stage of a transaction's lifecycle and returns the stage it leads to.
func step(t *testing.T, stage func(*transaction.Transaction) (transaction.TxnEvent, error), txn *transaction.Transaction) transaction.TxnEvent {
	t.Helper()

	event, err := stage(txn)
	if err != nil {
		t.Fatalf("transaction stage failed: %v", err)
	}

	return event
}

func sessionTaskTxn(sm *smf_context.SMContext) *transaction.Transaction {
	txn := transaction.NewTransaction(func() {}, nil, svcmsgtypes.SessionTask)
	txn.Ctxt = sm
	return txn
}

// Of two transactions arriving together for an idle session, only one runs. A held decision starting
// as the quiet interval ends is one such pair with an update from the AMF: run at once, the update
// could put the session back to Active while the decision's modification waited for the user plane,
// and the user plane's answer, delivered only in SmStatePfcpModify, never reached it. The stages are
// driven in the order that exposes it, the second posted before the first has run, rather than raced.
func TestOnlyOneOfTwoTransactionsArrivingTogetherRuns(t *testing.T) {
	sm := &smf_context.SMContext{}
	first, second := sessionTaskTxn(sm), sessionTaskTxn(sm)

	if event := step(t, SmfTxnFsmHandle.TxnCtxtPost, first); event != transaction.TxnEventRun {
		t.Fatalf("the first transaction for an idle session was not run: %v", event)
	}
	// The first has not reached TxnCtxtRun yet.
	if event := step(t, SmfTxnFsmHandle.TxnCtxtPost, second); event != transaction.TxnEventQueue {
		t.Errorf("the second transaction was run (%v) while the first held the session; both would run at once", event)
	}
}

// And the slot passes straight from a transaction that ends to the one queued behind it, so one
// arriving in between is queued too rather than run alongside it.
func TestTheSlotPassesStraightToTheNextQueuedTransaction(t *testing.T) {
	sm := &smf_context.SMContext{}
	first, queued, late := sessionTaskTxn(sm), sessionTaskTxn(sm), sessionTaskTxn(sm)

	step(t, SmfTxnFsmHandle.TxnCtxtPost, first)
	step(t, SmfTxnFsmHandle.TxnCtxtRun, first)
	if event := step(t, SmfTxnFsmHandle.TxnCtxtPost, queued); event != transaction.TxnEventQueue {
		t.Fatalf("a transaction arriving while another runs was not queued: %v", event)
	}

	if event := step(t, SmfTxnFsmHandle.TxnEnd, first); event != transaction.TxnEventRun || first.NextTxn != queued {
		t.Fatalf("the queued transaction was not started when the first ended: %v", event)
	}
	// The queued one has not reached TxnCtxtRun yet.
	if event := step(t, SmfTxnFsmHandle.TxnCtxtPost, late); event != transaction.TxnEventQueue {
		t.Errorf("a transaction arriving as the slot was handed on was run (%v) alongside the one it was handed to", event)
	}
}
