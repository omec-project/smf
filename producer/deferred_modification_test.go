// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/nas/v2"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/transaction"
	"github.com/omec-project/util/httpwrapper"
)

const deferralPduSessionID = 10

// queuedWorkTimeout bounds how long a test waits for work the session runs asynchronously. Generous
// rather than tight: a loaded runner, and the race detector, can hold queued work back by seconds,
// and the bound only decides how long a real failure takes to be reported.
const queuedWorkTimeout = 10 * time.Second

// deferralSession is an active session with the network's sends stubbed: every PFCP modification
// it sends is counted and announced on pfcp, and every Command transfer succeeds.
type deferralSession struct {
	sm         *smf_context.SMContext
	pfcp       chan struct{}
	sends      atomic.Int32
	lastStatus int
}

func newDeferralSession(t *testing.T) *deferralSession {
	t.Helper()

	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })

	s := &deferralSession{pfcp: make(chan struct{}, 8)}
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		s.sends.Add(1)
		s.pfcp <- struct{}{}
		return nil
	}
	sendQosN1N2TransferMsg = commandHandedToTheAMF

	sm := smf_context.NewSMContext("imsi-208930100007601", deferralPduSessionID)
	t.Cleanup(func() {
		sm.SMLock.Lock()
		sm.StopT3591()
		sm.SMLock.Unlock()
		smf_context.RemoveSMContext(sm.Ref)
	})
	sm.SMContextState = smf_context.SmStateActive
	sm.Tunnel = &smf_context.UPTunnel{DataPathPool: smf_context.DataPathPool{}}
	sm.T3591Value = 16 * time.Second
	// ChangeState reads these when leaving SmStateActive, to label the session metric. Provided by
	// the UPF, so that removing the session at cleanup has no allocator to give it back to.
	sm.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.21"), UpfProvided: true}
	sm.Identifier = sm.Supi
	s.sm = sm

	return s
}

func (s *deferralSession) notify(t *testing.T) {
	t.Helper()

	txn := &transaction.Transaction{
		Req:  models.SmPolicyNotification{SmPolicyDecision: &models.SmPolicyDecision{}},
		Ctxt: s.sm,
	}
	if err := HandleSMPolicyUpdateNotify(txn); err != nil {
		t.Fatalf("HandleSMPolicyUpdateNotify returned an error: %v", err)
	}
	// 204 for a held decision (TS 29.512 subclause 4.2.3.2 NOTE), 200 for one applied at once, as
	// this endpoint has always answered.
	if rsp, ok := txn.Rsp.(*httpwrapper.Response); !ok || (rsp.Status != http.StatusOK && rsp.Status != http.StatusNoContent) {
		t.Fatalf("the PCF was answered %+v, want a success", txn.Rsp)
	}
	s.lastStatus = txn.Rsp.(*httpwrapper.Response).Status
}

// waitForSend waits for the PFCP modification the session sends next.
func (s *deferralSession) waitForSend(t *testing.T, what string) {
	t.Helper()

	select {
	case <-s.pfcp:
	case <-time.After(queuedWorkTimeout):
		t.Fatalf("%s: no PFCP modification was sent", what)
	}
}

// waitUntilArmed waits until the session's gen-th modification has armed its T3591, which is the
// last thing a modification does: past this, nothing of it is left running to outlive the test.
func (s *deferralSession) waitUntilArmed(t *testing.T, gen uint64) {
	t.Helper()

	deadline := time.Now().Add(queuedWorkTimeout)
	for time.Now().Before(deadline) {
		s.sm.SMLock.Lock()
		armed := s.sm.NwModificationGen == gen && s.sm.T3591 != nil
		s.sm.SMLock.Unlock()
		if armed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("modification %d never armed its T3591", gen)
}

// expectNoSend fails if the session sends a PFCP modification within a short window.
func (s *deferralSession) expectNoSend(t *testing.T, what string) {
	t.Helper()

	select {
	case <-s.pfcp:
		t.Fatalf("%s: a PFCP modification was sent", what)
	case <-time.After(100 * time.Millisecond):
	}
}

// startAndHold starts one modification and has a second decision arrive while it waits for the UE.
func (s *deferralSession) startAndHold(t *testing.T) {
	t.Helper()

	s.notify(t)
	s.waitForSend(t, "the first decision")

	s.sm.SMLock.Lock()
	armed := s.sm.T3591 != nil
	s.sm.SMLock.Unlock()
	if !armed {
		t.Fatal("T3591 was not armed for the first modification")
	}

	s.notify(t)
	s.expectNoSend(t, "a decision arriving while the first modification waits for the UE")
}

// encodeModificationAnswerFor encodes the UE's answer to a Command, as carrying pduSessionID.
func encodeModificationAnswerFor(t *testing.T, messageType, pduSessionID uint8) []byte {
	t.Helper()

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(messageType)

	switch messageType {
	case nas.MsgTypePDUSessionModificationComplete:
		msg := nasMessage.NewPDUSessionModificationComplete(0)
		msg.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
		msg.SetMessageType(messageType)
		msg.SetPDUSessionID(pduSessionID)
		m.PDUSessionModificationComplete = msg
	case nas.MsgTypePDUSessionModificationCommandReject:
		msg := nasMessage.NewPDUSessionModificationCommandReject(0)
		msg.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
		msg.SetMessageType(messageType)
		msg.SetPDUSessionID(pduSessionID)
		msg.SetCauseValue(nasMessage.Cause5GSMRequestRejectedUnspecified)
		m.PDUSessionModificationCommandReject = msg
	default:
		t.Fatalf("not a modification answer: %d", messageType)
	}

	payload := new(bytes.Buffer)
	if err := m.GsmMessageEncode(payload); err != nil {
		t.Fatalf("could not encode the modification answer: %v", err)
	}

	return payload.Bytes()
}

// answer delivers the UE's answer to the Command, through the handler the AMF's update reaches and
// under the lock HandlePDUSessionSMContextUpdate holds across it.
func (s *deferralSession) answer(t *testing.T, messageType uint8) {
	t.Helper()
	s.answerAs(t, messageType, deferralPduSessionID)
}

// answerAs delivers the UE's answer as carrying pduSessionID, to this session's context.
func (s *deferralSession) answerAs(t *testing.T, messageType, pduSessionID uint8) {
	t.Helper()

	request := models.UpdateSmContextRequest{}
	request.SetJsonData(models.SmContextUpdateData{})
	request.SetBinaryDataN1SmMessage(n1SmMessageFile(t, encodeModificationAnswerFor(t, messageType, pduSessionID)))

	txn := transaction.NewTransaction(request, nil, svcmsgtypes.UpdateSmContext)
	txn.Ctxt = s.sm

	s.sm.SMLock.Lock()
	defer s.sm.SMLock.Unlock()

	if err := HandleUpdateN1Msg(txn, models.NewUpdateSmContext200Response(), &pfcpAction{}); err != nil {
		t.Fatalf("handling the UE's answer: %v", err)
	}
}

// A decision arriving while the network's modification still waits for the UE is held rather than
// applied, and the procedure in flight is left exactly as it was: same pending update, same timer.
// Applying it replaced the pending update and stopped the first T3591, and the UE's answer to the
// first Command, which cannot say which Command it answers, then committed the second update.
func TestAPolicyDecisionArrivingWhileTheUeHasNotAnsweredIsHeld(t *testing.T) {
	s := newDeferralSession(t)

	s.notify(t)
	s.waitForSend(t, "the first decision")
	if s.lastStatus != http.StatusOK {
		t.Errorf("the PCF was answered %d for a decision applied at once, want 200", s.lastStatus)
	}

	s.sm.SMLock.Lock()
	first, pending := s.sm.T3591, s.sm.SmPolicyUpdates[0]
	s.sm.SMLock.Unlock()

	s.notify(t)
	s.expectNoSend(t, "a decision arriving while the first modification waits for the UE")

	s.sm.SMLock.Lock()
	defer s.sm.SMLock.Unlock()

	if got := len(s.sm.DeferredPolicyDecisions); got != 1 {
		t.Errorf("held decisions = %d, want 1", got)
	}
	if s.lastStatus != http.StatusNoContent {
		t.Errorf("the PCF was answered %d for a held decision, want 204 (TS 29.512 subclause 4.2.3.2 NOTE)", s.lastStatus)
	}
	if s.sm.T3591 != first {
		t.Error("the first modification's T3591 was replaced; its retransmissions would stop")
	}
	if len(s.sm.SmPolicyUpdates) != 1 || s.sm.SmPolicyUpdates[0] != pending {
		t.Error("the first modification's pending update was replaced; the UE's answer to it would commit another")
	}
}

// Each way the network's procedure ends starts the decision held behind it, as a procedure of its
// own: the UE completing it, the UE rejecting it, and T3591 abandoning it.
func TestAHeldDecisionStartsWhenTheProcedureEnds(t *testing.T) {
	ends := map[string]func(*testing.T, *deferralSession){
		"completed": func(t *testing.T, s *deferralSession) {
			s.answer(t, nas.MsgTypePDUSessionModificationComplete)
		},
		"rejected": func(t *testing.T, s *deferralSession) {
			s.answer(t, nas.MsgTypePDUSessionModificationCommandReject)
		},
		// Nothing to do: the timer runs short here, retransmits into a stub and abandons by itself.
		"abandoned by T3591": func(*testing.T, *deferralSession) {},
	}

	for name, end := range ends {
		t.Run(name, func(t *testing.T) {
			s := newDeferralSession(t)
			if name == "abandoned by T3591" {
				original := retransmitModificationCommand
				t.Cleanup(func() { retransmitModificationCommand = original })
				retransmitModificationCommand = func(*smf_context.SMContext, func() bool) error { return nil }
				s.sm.T3591Value = 50 * time.Millisecond // five expiries, past expectNoSend's window
			}
			s.startAndHold(t)
			// Only the first modification's timer runs short. The held decision's runs at the
			// ordinary interval, so nothing of it is still firing into the stub when the test ends.
			s.sm.SMLock.Lock()
			s.sm.T3591Value = 16 * time.Second
			s.sm.SMLock.Unlock()

			end(t, s)
			s.waitForSend(t, "the held decision, once the first modification "+name)
			s.waitUntilArmed(t, 2)

			s.sm.SMLock.Lock()
			defer s.sm.SMLock.Unlock()

			if got := len(s.sm.DeferredPolicyDecisions); got != 0 {
				t.Errorf("held decisions = %d after the first modification %s, want 0", got, name)
			}
			if s.sm.NwModificationGen != 2 {
				t.Errorf("modifications started = %d, want 2", s.sm.NwModificationGen)
			}
		})
	}
}

// A modification whose delivery failed is reverted with a PFCP exchange of its own, and the held
// decision starts only once that exchange has its answer. The session has one response channel
// and nothing correlates on it, so two exchanges in flight at once can each take the other's
// answer.
func TestAHeldDecisionWaitsForTheRevertBeforeIt(t *testing.T) {
	s := newDeferralSession(t)
	s.startAndHold(t)

	var inFlight, overlapped atomic.Int32
	var mu sync.Mutex
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		if inFlight.Add(1) > 1 {
			overlapped.Store(1)
		}
		mu.Lock()
		time.Sleep(100 * time.Millisecond)
		mu.Unlock()
		inFlight.Add(-1)
		s.pfcp <- struct{}{}
		return nil
	}

	txn := &transaction.Transaction{Ctxt: s.sm}
	if _, _, err := HandlePduSessN1N2TransFailInd(txn); err != nil {
		t.Fatalf("handling the failure indication: %v", err)
	}

	s.waitForSend(t, "the revert")
	s.waitForSend(t, "the held decision, after the revert")
	s.waitUntilArmed(t, 2)

	if overlapped.Load() != 0 {
		t.Error("the held decision's modification was sent while the revert was still waiting for its answer")
	}
}

// The UE can acknowledge before the transfer call returns, and the held decision can then start
// before the first modification's call has finished. The first one's tail must leave the session's
// timer to the procedure that now owns it: arming its own stopped the second one's T3591.
func TestAnEarlyAcknowledgementLeavesTheNextProcedureItsTimer(t *testing.T) {
	s := newDeferralSession(t)

	var second *smf_context.Timer
	var calls atomic.Int32
	sendQosN1N2TransferMsg = func(sm *smf_context.SMContext) error {
		if err := commandHandedToTheAMF(sm); err != nil {
			return err
		}
		if calls.Add(1) != 1 {
			return nil // the held decision's own transfer
		}

		// A second decision arrives and is held, then the UE answers while this transfer is still in
		// flight, and the held decision starts.
		s.notify(t)
		s.answer(t, nas.MsgTypePDUSessionModificationComplete)
		s.waitForSend(t, "the held decision, after the early acknowledgement")

		deadline := time.Now().Add(queuedWorkTimeout)
		for time.Now().Before(deadline) {
			sm.SMLock.Lock()
			second = sm.T3591
			sm.SMLock.Unlock()
			if second != nil {
				return nil
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Error("the held decision never armed its T3591")

		return nil
	}

	s.notify(t)
	s.waitForSend(t, "the first decision")

	s.sm.SMLock.Lock()
	defer s.sm.SMLock.Unlock()

	if second == nil {
		t.Fatal("the held decision's T3591 was never observed")
	}
	if s.sm.T3591 != second {
		t.Error("the first modification armed a timer after the UE had answered it, replacing the one the next modification runs on")
	}
}

// Held decisions are applied in turn, and one whose own programming fails does not strand the ones
// behind it: that failure ends its procedure too, and the next held decision starts from there.
func TestAHeldDecisionThatFailsToProgramStartsTheNext(t *testing.T) {
	s := newDeferralSession(t)
	s.startAndHold(t)
	s.notify(t) // a third decision, held behind the second
	s.expectNoSend(t, "a third decision arriving while the first modification waits for the UE")

	var sends atomic.Int32
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		s.pfcp <- struct{}{}
		if sends.Add(1) == 1 {
			return errors.New("upf unreachable") // the second decision
		}
		return nil
	}

	s.answer(t, nas.MsgTypePDUSessionModificationComplete)
	s.waitForSend(t, "the second decision")
	s.waitForSend(t, "the third decision, after the second failed to program")
	s.waitUntilArmed(t, 3)

	s.sm.SMLock.Lock()
	defer s.sm.SMLock.Unlock()

	if got := len(s.sm.DeferredPolicyDecisions); got != 0 {
		t.Errorf("held decisions = %d, want 0", got)
	}
}

// A held decision is queued in the session's transaction queue, not started on a goroutine of its
// own. The caller is the transaction that ended the modification before it, and that transaction's
// state machine still applies its own state after the handler returns: a modification started in
// between had its SmStatePfcpModify put back to Active, and the user plane's answer, delivered only
// in SmStatePfcpModify, never reached it.
func TestAHeldDecisionIsQueuedBehindTheTransactionThatEndedItsPredecessor(t *testing.T) {
	s := newDeferralSession(t)
	s.startAndHold(t)

	original := queueSessionTask
	t.Cleanup(func() { queueSessionTask = original })
	queued := make(chan func(), 1)
	queueSessionTask = func(_ *smf_context.SMContext, task func()) { queued <- task }

	s.answer(t, nas.MsgTypePDUSessionModificationComplete)
	s.expectNoSend(t, "the held decision, before the queue reached it")

	var task func()
	select {
	case task = <-queued:
	default:
		t.Fatal("the held decision was not queued")
	}

	task()
	s.waitForSend(t, "the held decision, once the queue ran it")
	s.waitUntilArmed(t, 2)
}

// retransmitOnce starts a modification on a short T3591, stubs the retransmission, and waits until
// the timer has retransmitted the Command once. The caller answers before the timer's next expiry,
// so the stub's one call is the only read of the seam the timer makes; waiting on the call is what
// orders that read before the seam is restored. Later modifications run on the ordinary interval.
func (s *deferralSession) retransmitOnce(t *testing.T, interval time.Duration) {
	t.Helper()

	original := retransmitModificationCommand
	t.Cleanup(func() { retransmitModificationCommand = original })
	retransmitted := make(chan struct{}, 1)
	retransmitModificationCommand = func(*smf_context.SMContext, func() bool) error {
		select {
		case retransmitted <- struct{}{}:
		default:
		}
		return nil
	}

	s.sm.T3591Value = interval
	s.notify(t)
	s.waitForSend(t, "the first decision")

	s.sm.SMLock.Lock()
	s.sm.T3591Value = 16 * time.Second
	s.sm.SMLock.Unlock()

	select {
	case <-retransmitted:
	case <-time.After(queuedWorkTimeout):
		t.Fatal("T3591 never retransmitted the Command")
	}
}

// The UE answers every copy of a Command, and a network-requested Command carries no procedure
// transaction identity. After a retransmitted Command is answered, a late answer to another copy
// can still arrive, and would be taken as the next Command's: it would stop that Command's T3591
// and commit an update the UE never acknowledged. So the held decision waits one T3591 interval
// first, the network-side counterpart of the PTI the UE keeps for T3591 (TS 24.501 subclause
// 6.3.2.3 NOTE 5).
func TestAHeldDecisionWaitsOutTheRetransmittedCommandsAnswers(t *testing.T) {
	const interval = 500 * time.Millisecond

	s := newDeferralSession(t)
	s.retransmitOnce(t, interval)
	s.notify(t)
	s.expectNoSend(t, "a decision arriving while the first modification waits for the UE")

	s.answer(t, nas.MsgTypePDUSessionModificationComplete)
	select {
	case <-s.pfcp:
		t.Fatal("the held decision started while the UE could still answer a copy of the first Command")
	case <-time.After(interval / 2):
	}

	s.waitForSend(t, "the held decision, once the first Command's answers have had their interval")
	s.waitUntilArmed(t, 2)
}

// A decision that arrives in that interval is held too, and applied once it is over.
func TestADecisionArrivingWhileACopyCanStillBeAnsweredIsHeld(t *testing.T) {
	const interval = 500 * time.Millisecond

	s := newDeferralSession(t)
	s.retransmitOnce(t, interval)
	s.answer(t, nas.MsgTypePDUSessionModificationComplete)

	s.notify(t)
	select {
	case <-s.pfcp:
		t.Fatal("a decision was applied while the UE could still answer a copy of the previous Command")
	case <-time.After(interval / 2):
	}

	s.waitForSend(t, "the held decision, once the interval is over")
	s.waitUntilArmed(t, 2)
}

// An answer carrying another PDU session's identity is ignored, not taken as this session's: TS
// 24.501 subclause 7.3.2 d). Taken, a Complete committed this session's pending update and a
// Command Reject abandoned it, and either stopped its T3591.
func TestAnAnswerForAnotherSessionLeavesThisOneAlone(t *testing.T) {
	for name, messageType := range map[string]uint8{
		"Complete":       nas.MsgTypePDUSessionModificationComplete,
		"Command Reject": nas.MsgTypePDUSessionModificationCommandReject,
	} {
		t.Run(name, func(t *testing.T) {
			s := newDeferralSession(t)
			s.notify(t)
			s.waitForSend(t, "the decision")

			s.sm.SMLock.Lock()
			timer, pending := s.sm.T3591, s.sm.SmPolicyUpdates[0]
			s.sm.SMLock.Unlock()

			s.answerAs(t, messageType, deferralPduSessionID+1)

			s.sm.SMLock.Lock()
			defer s.sm.SMLock.Unlock()
			if !s.sm.NwModificationPending || s.sm.T3591 != timer {
				t.Error("another session's answer ended this session's procedure")
			}
			if len(s.sm.SmPolicyUpdates) != 1 || s.sm.SmPolicyUpdates[0] != pending {
				t.Error("another session's answer committed or discarded this session's pending update")
			}
		})
	}
}

// commandHandedToTheAMF stands in for the Command's transfer in tests: it records the Command as
// handed to the AMF, as the transfer does, and sends nothing.
func commandHandedToTheAMF(sm *smf_context.SMContext) error {
	sm.SMLock.Lock()
	defer sm.SMLock.Unlock()
	sm.NwModificationUnsent = false

	return nil
}

// A late answer to an earlier Command that arrives while the next modification is being started --
// its user plane programmed, its Command not yet handed to the AMF -- is ignored. The UE has
// nothing of the new modification to answer, and taken as its answer the Complete would commit an
// update the UE was never sent.
func TestAnAnswerBeforeTheCommandIsSentIsIgnored(t *testing.T) {
	for name, late := range map[string]uint8{
		"Complete":       nas.MsgTypePDUSessionModificationComplete,
		"Command Reject": nas.MsgTypePDUSessionModificationCommandReject,
	} {
		t.Run(name, func(t *testing.T) {
			s := newDeferralSession(t)
			s.startAndHold(t)

			release := make(chan struct{})
			transferring := make(chan struct{}, 1)
			sendQosN1N2TransferMsg = func(sm *smf_context.SMContext) error {
				transferring <- struct{}{}
				<-release
				return commandHandedToTheAMF(sm)
			}

			s.answer(t, nas.MsgTypePDUSessionModificationComplete)
			s.waitForSend(t, "the held decision")
			select {
			case <-transferring:
			case <-time.After(queuedWorkTimeout):
				t.Fatal("the held decision never reached its transfer")
			}

			s.sm.SMLock.Lock()
			pending := s.sm.SmPolicyUpdates[0]
			s.sm.SMLock.Unlock()

			// The first Command's answer, again.
			s.answer(t, late)

			s.sm.SMLock.Lock()
			stillPending := s.sm.NwModificationPending && len(s.sm.SmPolicyUpdates) == 1 && s.sm.SmPolicyUpdates[0] == pending
			s.sm.SMLock.Unlock()
			close(release)
			if !stillPending {
				t.Fatal("an answer that arrived before the Command was sent ended the procedure and committed its update")
			}
			s.waitUntilArmed(t, 2)
		})
	}
}

// A decision arriving while an older one is held is held behind it, even with nothing in progress.
// The older one is started as a session task, and a notification already in the session's queue
// runs before that task: applied at once, it would be overtaken, and then overwritten, by the older
// decision.
func TestANewerDecisionDoesNotOvertakeAHeldOne(t *testing.T) {
	s := newDeferralSession(t)
	s.startAndHold(t)

	original := queueSessionTask
	t.Cleanup(func() { queueSessionTask = original })
	queued := make(chan func(), 4)
	queueSessionTask = func(_ *smf_context.SMContext, task func()) { queued <- task }

	// The first modification ends; the held decision's task is queued but has not run.
	s.answer(t, nas.MsgTypePDUSessionModificationComplete)

	// A newer decision reaches the session first.
	s.notify(t)
	s.expectNoSend(t, "a newer decision, while an older one is held")
	if s.lastStatus != http.StatusNoContent {
		t.Errorf("the PCF was answered %d for a decision held behind an older one, want 204", s.lastStatus)
	}

	// The older decision runs first.
	(<-queued)()
	s.waitForSend(t, "the older held decision")
	s.waitUntilArmed(t, 2)

	s.sm.SMLock.Lock()
	defer s.sm.SMLock.Unlock()
	if got := len(s.sm.DeferredPolicyDecisions); got != 1 {
		t.Errorf("held decisions = %d after the older one started, want the newer one still held", got)
	}
}
