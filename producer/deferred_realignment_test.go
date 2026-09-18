// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"
	"time"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
)

// The radio refusing the whole modification ends it, and the decision held behind it starts.
func TestARadioRefusingTheModificationStartsTheHeldDecision(t *testing.T) {
	s := newDeferralSession(t)
	s.startAndHold(t)

	deliverModifyResponse(t, s.sm, craftModifyResponseTransfer(t, nil, []int64{1}))
	s.waitForSend(t, "the held decision, once the radio refused the first modification")
	s.waitUntilArmed(t, 2)
}

// A correction after a partial rejection goes ahead of a held decision, and holds new ones behind
// it from the moment it is committed to, before its goroutine has started anything.
func TestACorrectionGoesAheadOfHeldDecisions(t *testing.T) {
	s := newDeferralSession(t)
	s.startAndHold(t)

	original := applyModification
	t.Cleanup(func() { applyModification = original })
	corrected := make(chan struct{}, 1)
	applyModification = func(*smf_context.SMContext, *qos.PolicyUpdate) error {
		corrected <- struct{}{}
		return nil
	}

	// The UE completes; the radio had refused part of the update.
	s.sm.SMLock.Lock()
	s.sm.StopT3591()
	realignSession(s.sm, &smf_context.PendingRealignment{RefusedQFIs: []int64{2}}, &qos.PolicyUpdate{})
	s.sm.SMLock.Unlock()

	s.notify(t)
	s.expectNoSend(t, "a decision arriving while the correction is committed to")

	<-corrected

	s.sm.SMLock.Lock()
	defer s.sm.SMLock.Unlock()
	if got := len(s.sm.DeferredPolicyDecisions); got != 2 {
		t.Errorf("held decisions = %d, want 2: neither may start ahead of the correction", got)
	}
}

// With nothing to correct, the completion ends the modification, and the held decision starts.
func TestNothingToCorrectStartsTheHeldDecision(t *testing.T) {
	s := newDeferralSession(t)
	s.startAndHold(t)

	s.sm.SMLock.Lock()
	s.sm.StopT3591()
	realignSession(s.sm, &smf_context.PendingRealignment{RefusedQFIs: []int64{2}}, nil)
	s.sm.SMLock.Unlock()

	s.waitForSend(t, "the held decision, with nothing to correct")
	s.waitUntilArmed(t, 2)
}

// The correction is queued in the session's transaction slot rather than started on a goroutine of
// its own, so that the completion's state machine has finished before it moves the session.
func TestACorrectionIsQueuedBehindTheCompletion(t *testing.T) {
	s := newDeferralSession(t)
	s.startAndHold(t)

	originalQueue, originalApply := queueSessionTask, applyModification
	t.Cleanup(func() { queueSessionTask, applyModification = originalQueue, originalApply })
	queued := make(chan func(), 2)
	queueSessionTask = func(_ *smf_context.SMContext, task func()) { queued <- task }
	applied := make(chan struct{}, 1)
	applyModification = func(*smf_context.SMContext, *qos.PolicyUpdate) error {
		applied <- struct{}{}
		return nil
	}

	s.sm.SMLock.Lock()
	s.sm.StopT3591()
	realignSession(s.sm, &smf_context.PendingRealignment{RefusedQFIs: []int64{2}}, &qos.PolicyUpdate{})
	s.sm.SMLock.Unlock()

	select {
	case <-applied:
		t.Fatal("the correction started before the session's queue reached it")
	case <-time.After(100 * time.Millisecond):
	}

	(<-queued)()
	select {
	case <-applied:
	case <-time.After(2 * time.Second):
		t.Fatal("the queued correction never ran")
	}
}
