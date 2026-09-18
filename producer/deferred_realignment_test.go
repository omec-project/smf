// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net/http"
	"testing"
	"time"

	"github.com/omec-project/nas/v2"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
)

// The radio refusing the whole modification ends it, and the decision held behind it starts.
func TestARadioRefusingTheModificationStartsTheHeldDecision(t *testing.T) {
	s := newDeferralSession(t)
	s.startAndHold(t)
	s.sm.SMLock.Lock()
	s.sm.RanAnswerPending = true // the radio has not answered yet
	s.sm.SMLock.Unlock()

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
	case <-time.After(queuedWorkTimeout):
		t.Fatal("the queued correction never ran")
	}
}

// flowsUpdate is a pending update that carries two flows, so a correction for it has something to
// withdraw.
func flowsUpdate() *qos.PolicyUpdate {
	return &qos.PolicyUpdate{QosFlowUpdate: qos.GetQosFlowDescUpdate(
		map[string]models.QosData{
			"1": {QosId: "1", Var5qi: openapi.PtrInt32(9)},
			"2": {QosId: "2", Var5qi: openapi.PtrInt32(1)},
		},
		map[string]*models.QosData{},
	)}
}

// The radio's answer is part of the modification. A decision arriving after the UE has completed
// but before the radio has answered is held, and starts once the radio answers.
func TestADecisionWaitsForTheRadiosAnswerToo(t *testing.T) {
	s := newDeferralSession(t)
	s.notify(t)
	s.waitForSend(t, "the first decision")

	s.sm.SMLock.Lock()
	s.sm.RanAnswerPending = true // the radio has not answered yet
	s.sm.SMLock.Unlock()
	s.answer(t, nas.MsgTypePDUSessionModificationComplete)

	s.notify(t)
	s.expectNoSend(t, "a decision arriving while the radio's answer is outstanding")
	if s.lastStatus != http.StatusNoContent {
		t.Errorf("the PCF was answered %d for a held decision, want 204", s.lastStatus)
	}

	deliverModifyResponse(t, s.sm, craftModifyResponseTransfer(t, []int64{1}, nil))
	s.waitForSend(t, "the held decision, once the radio answered")
	s.waitUntilArmed(t, 2)
}

// The wait for the radio's answer is bounded by one T3591 interval. A radio that never answers
// would otherwise hold every later decision for the session.
func TestARadioThatNeverAnswersStopsHoldingDecisions(t *testing.T) {
	const guard = 300 * time.Millisecond

	s := newDeferralSession(t)
	s.sm.T3591Value = guard
	original := retransmitModificationCommand
	t.Cleanup(func() { retransmitModificationCommand = original })
	retransmitModificationCommand = func(*smf_context.SMContext, func() bool) error { return nil }

	s.notify(t)
	s.waitForSend(t, "the first decision")
	s.sm.SMLock.Lock()
	s.sm.RanAnswerPending = true
	s.sm.SMLock.Unlock()
	s.answer(t, nas.MsgTypePDUSessionModificationComplete)
	s.sm.SMLock.Lock()
	s.sm.T3591Value = 16 * time.Second // for the held decision's own timer
	s.sm.SMLock.Unlock()

	s.notify(t)
	s.expectNoSend(t, "a decision arriving while the radio's answer is outstanding")

	s.waitForSend(t, "the held decision, once the wait for the radio lapsed")
	s.waitUntilArmed(t, 2)
}

// A correction after a Command that was retransmitted waits out the interval in which the UE may
// still answer another copy of it, and an answer arriving meanwhile -- a late one to that Command
// -- changes nothing. Taken as the correction's answer, it would commit the correction unanswered.
func TestACorrectionWaitsOutTheCorrectedCommandsCopies(t *testing.T) {
	const interval = 500 * time.Millisecond

	s := newDeferralSession(t)
	s.retransmitOnce(t, interval)

	originalApply := applyModification
	t.Cleanup(func() { applyModification = originalApply })
	corrected := make(chan struct{}, 1)
	applyModification = func(*smf_context.SMContext, *qos.PolicyUpdate) error {
		corrected <- struct{}{}
		return nil
	}

	// The radio refused flow 2, so the UE's completion starts a correction.
	s.sm.SMLock.Lock()
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{flowsUpdate()}
	s.sm.Realign = &smf_context.PendingRealignment{EstablishedQFIs: []int64{1}, RefusedQFIs: []int64{2}}
	s.sm.SMLock.Unlock()
	s.answer(t, nas.MsgTypePDUSessionModificationComplete)

	// Another copy's answer.
	s.answer(t, nas.MsgTypePDUSessionModificationComplete)
	s.sm.SMLock.Lock()
	reserved := s.sm.NwModificationPending
	s.sm.SMLock.Unlock()
	if !reserved {
		t.Error("a late answer to the corrected Command ended the correction before it started")
	}

	select {
	case <-corrected:
		t.Fatal("the correction started while the UE could still answer a copy of the Command it corrects")
	case <-time.After(interval / 2):
	}
	select {
	case <-corrected:
	case <-time.After(queuedWorkTimeout):
		t.Fatal("the correction never started")
	}
}
