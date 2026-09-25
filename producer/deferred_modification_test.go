// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"bytes"
	"errors"
	"net"
	"net/http"
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

// deferralSession is an active session with the network's sends stubbed: every PFCP modification
// it sends is counted and announced on pfcp, and every Command transfer succeeds.
type deferralSession struct {
	sm    *smf_context.SMContext
	pfcp  chan struct{}
	sends atomic.Int32
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
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return nil }

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
	if rsp, ok := txn.Rsp.(*httpwrapper.Response); !ok || rsp.Status != http.StatusOK {
		t.Fatalf("the PCF was answered %+v, want 200", txn.Rsp)
	}
}

// waitForSend waits for the PFCP modification the session sends next.
func (s *deferralSession) waitForSend(t *testing.T, what string) {
	t.Helper()

	select {
	case <-s.pfcp:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: no PFCP modification was sent", what)
	}
}

// waitUntilArmed waits until the session's gen-th modification has armed its T3591, which is the
// last thing a modification does: past this, nothing of it is left running to outlive the test.
func (s *deferralSession) waitUntilArmed(t *testing.T, gen uint64) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
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

func encodeModificationAnswer(t *testing.T, messageType uint8) []byte {
	t.Helper()

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(messageType)

	switch messageType {
	case nas.MsgTypePDUSessionModificationComplete:
		msg := nasMessage.NewPDUSessionModificationComplete(0)
		msg.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
		msg.SetMessageType(messageType)
		msg.SetPDUSessionID(deferralPduSessionID)
		m.PDUSessionModificationComplete = msg
	case nas.MsgTypePDUSessionModificationCommandReject:
		msg := nasMessage.NewPDUSessionModificationCommandReject(0)
		msg.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
		msg.SetMessageType(messageType)
		msg.SetPDUSessionID(deferralPduSessionID)
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

	request := models.UpdateSmContextRequest{}
	request.SetJsonData(models.SmContextUpdateData{})
	request.SetBinaryDataN1SmMessage(n1SmMessageFile(t, encodeModificationAnswer(t, messageType)))

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
// answer. The modification here changed rates on the user plane, so its revert has something to
// send.
func TestAHeldDecisionWaitsForTheRevertBeforeIt(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })

	sent := make(chan struct{}, 4)
	var inFlight, overlapped atomic.Int32
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		if inFlight.Add(1) > 1 {
			overlapped.Store(1)
		}
		time.Sleep(100 * time.Millisecond)
		inFlight.Add(-1)
		sent <- struct{}{}
		return nil
	}
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return nil }

	s := programmedRateChange(t)
	s.sm.SMLock.Lock()
	s.sm.DeferredPolicyDecisions = append(s.sm.DeferredPolicyDecisions, &models.SmPolicyDecision{})
	s.sm.SMLock.Unlock()
	t.Cleanup(func() {
		s.sm.SMLock.Lock()
		s.sm.StopT3591()
		s.sm.SMLock.Unlock()
	})

	if !revertModification(s.sm, "n1n2_transfer_failed", s.sm.NwModificationGen) {
		t.Fatal("the revert reported failure")
	}

	for _, what := range []string{"the revert", "the held decision, after the revert"} {
		select {
		case <-sent:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no PFCP modification was sent", what)
		}
	}

	if overlapped.Load() != 0 {
		t.Error("the held decision's modification was sent while the revert was still waiting for its answer")
	}

	// The held decision runs to the end before the test does, so nothing of it outlives the stubs.
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.sm.SMLock.Lock()
		armed := s.sm.T3591 != nil
		s.sm.SMLock.Unlock()
		if armed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the held decision never armed its T3591")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The UE can acknowledge before the transfer call returns, and the held decision can then start
// before the first modification's call has finished. The first one's tail must leave the session's
// timer to the procedure that now owns it: arming its own stopped the second one's T3591.
func TestAnEarlyAcknowledgementLeavesTheNextProcedureItsTimer(t *testing.T) {
	s := newDeferralSession(t)

	// Hold a decision behind the first modification before it is even started: the first
	// notification's transfer delivers the UE's answer, and the second decision arrives first.
	s.sm.SMLock.Lock()
	s.sm.DeferredPolicyDecisions = append(s.sm.DeferredPolicyDecisions, &models.SmPolicyDecision{})
	s.sm.SMLock.Unlock()

	var second *smf_context.Timer
	var calls atomic.Int32
	sendQosN1N2TransferMsg = func(sm *smf_context.SMContext) error {
		if calls.Add(1) != 1 {
			return nil // the held decision's own transfer
		}

		// The UE answers while this transfer is still in flight, and the held decision starts.
		s.answer(t, nas.MsgTypePDUSessionModificationComplete)
		s.waitForSend(t, "the held decision, after the early acknowledgement")

		deadline := time.Now().Add(2 * time.Second)
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
	case <-time.After(2 * interval):
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
