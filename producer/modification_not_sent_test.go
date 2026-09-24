// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/transaction"
	"github.com/omec-project/util/httpwrapper"
	"go.uber.org/zap"
)

// modificationOutcome is one way a modification can end without being applied: the send failing
// before anything went out, or the request going out and being answered with a failure verdict.
type modificationOutcome struct {
	name    string
	sendErr error
	verdict smf_context.PFCPSessionResponseStatus
}

var modificationOutcomes = []modificationOutcome{
	{name: "never sent", sendErr: errors.New("PFCP Context not found")},
	{name: "refused", verdict: smf_context.SessionUpdateFailed},
	{name: "unanswered", verdict: smf_context.SessionUpdateTimeout},
}

// sessionWhoseModificationEnds is an active session whose next modification ends as outcome says.
// The send is replaced for the test. When it succeeds, the verdict is already on the session's
// channel, where the response handler or the send-error handler puts it, so the handler under test
// reads a real answer. The downlink rule gives the UE-initiated modification a user plane to record
// as pending.
func sessionWhoseModificationEnds(t *testing.T, outcome modificationOutcome) *smf_context.SMContext {
	t.Helper()

	send := sendModificationRequest
	sendModificationRequest = func(smf_context.NodeID, *smf_context.SMContext, []*smf_context.PDR, []*smf_context.FAR,
		[]*smf_context.BAR, []*smf_context.QER, []*smf_context.PDR, []*smf_context.FAR, []*smf_context.QER, uint16,
	) error {
		return outcome.sendErr
	}
	t.Cleanup(func() { sendModificationRequest = send })

	node := smf_context.NewDataPathNode()
	node.UPF = &smf_context.UPF{NodeID: *smf_context.NewNodeID("127.0.0.1")}
	node.DownLinkTunnel.PDR["default"] = &smf_context.PDR{FAR: &smf_context.FAR{}}

	path := smf_context.NewDataPath()
	path.IsDefaultPath = true
	path.FirstDPNode = node

	smContext := smf_context.NewSMContext("imsi-208930000000046", 7)
	smContext.Tunnel = smf_context.NewUPTunnel()
	smContext.Tunnel.DataPathPool[1] = path
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP("10.1.0.7")}
	smContext.SMContextState = smf_context.SmStateActive

	if outcome.sendErr == nil {
		smContext.SBIPFCPCommunicationChan <- outcome.verdict
	}

	return smContext
}

// A modification that failed puts the session back in SmStateActive. Callers move it into
// SmStatePfcpModify before sending, and that state has no FSM handlers at all: left there, the
// session answers every later event with "unhandled event", so it can no longer be modified and
// no longer be released.
//
// Whatever the failure, and not only when nothing was sent. The UE-initiated path answers a
// failure with a PDU Session Release Command, and the UE's Release Complete arrives as an update,
// which only SmStateActive handles -- so a session held back in SmStatePfcpModify because the user
// plane had answered could not complete the release the SMF itself asked for.
func TestAPolicyUpdateThatFailedLeavesTheSessionActive(t *testing.T) {
	for _, outcome := range modificationOutcomes {
		t.Run(outcome.name, func(t *testing.T) {
			smContext := sessionWhoseModificationEnds(t, outcome)

			txn := &transaction.Transaction{Req: models.SmPolicyNotification{}, Ctxt: smContext}

			if err := HandleSMPolicyUpdateNotify(txn); err == nil {
				t.Fatal("a policy update that was not applied was reported as applied")
			}

			if len(smContext.SBIPFCPCommunicationChan) != 0 {
				t.Fatal("the answer was never read: the test did not reach the path it is about")
			}

			if got := smContext.SMContextState; got != smf_context.SmStateActive {
				t.Errorf("state = %s, want SmStateActive: no FSM handler accepts an event in any other state this can leave", got)
			}
		})
	}
}

// The same for a modification the UE's own update asked for, here the user plane connection going
// inactive -- and the pending user-plane entry that path records goes too. The modification
// response handler signals the session's channel only once those entries are gone, so one left
// behind by a failed request means the next operation to wait on that channel waits for good.
func TestAUeUpdateThatFailedLeavesTheSessionActive(t *testing.T) {
	for _, outcome := range modificationOutcomes {
		t.Run(outcome.name, func(t *testing.T) {
			smContext := sessionWhoseModificationEnds(t, outcome)

			request := models.UpdateSmContextRequest{}
			data := models.NewSmContextUpdateData()
			data.SetUpCnxState(models.UPCNXSTATE_DEACTIVATED)
			request.SetJsonData(*data)

			txn := &transaction.Transaction{Req: request, Ctxt: smContext}

			if err := HandlePDUSessionSMContextUpdate(txn); err != nil {
				t.Fatalf("the update was not answered: %v", err)
			}

			if len(smContext.SBIPFCPCommunicationChan) != 0 {
				t.Fatal("the answer was never read: the test did not reach the path it is about")
			}

			if rsp, ok := txn.Rsp.(*httpwrapper.Response); !ok || rsp.Status != http.StatusServiceUnavailable {
				t.Fatalf("answer = %+v, want the modification-failure answer", txn.Rsp)
			}

			if got := smContext.SMContextState; got != smf_context.SmStateActive {
				t.Errorf("state = %s, want SmStateActive: the release this answers with cannot complete in any other state", got)
			}

			if len(smContext.PendingUPF) != 0 {
				t.Errorf("pending user planes = %v after a failed request; no answer will ever delete them, so the next exchange on this session waits for good",
					smContext.PendingUPF)
			}
		})
	}
}

// A modification with no tunnel to send through returns rather than waiting: nothing will answer a
// request that was never sent.
func TestAModificationWithNoTunnelReturnsAnError(t *testing.T) {
	smContext := sessionWhoseModificationEnds(t, modificationOutcomes[0])
	smContext.Tunnel = nil

	if err := SendPfcpSessionModifyReq(smContext, &pfcpParam{}); err == nil {
		t.Fatal("a modification with no tunnel reported success")
	}
}

// A policy notification for a session whose tunnel is gone is refused, and refused without leaving
// the session locked. BuildPfcpParam reads through the tunnel without looking, so the notification
// took the SMF down in the builder while it held SMLock; the unlock there is not deferred, and the
// transaction lifecycle's recover catches the panic without releasing the lock, so every later
// operation on the session waited on it for good. A guard in the send was never reached: the
// builder had already dereferenced nil.
func TestAPolicyUpdateForASessionWithNoTunnelIsRefusedAndLeavesItUnlocked(t *testing.T) {
	smContext := &smf_context.SMContext{
		Supi:           "imsi-208930000000045",
		PDUSessionID:   6,
		SMContextState: smf_context.SmStateActive,
		SubCtxLog:      zap.NewNop().Sugar(),
		SubPduSessLog:  zap.NewNop().Sugar(),
		PDUAddress:     &smf_context.UeIpAddr{Ip: net.ParseIP("10.1.0.9")},
	}

	txn := &transaction.Transaction{Req: models.SmPolicyNotification{}, Ctxt: smContext}

	if err := HandleSMPolicyUpdateNotify(txn); err == nil {
		t.Error("a policy update for a session with no tunnel was accepted")
	}

	if !smContext.SMLock.TryLock() {
		t.Fatal("SMLock is still held after the refusal; every later operation on this session would wait on it for good")
	}

	smContext.SMLock.Unlock()

	if got := smContext.SMContextState; got != smf_context.SmStateActive {
		t.Errorf("state = %s, want it untouched: nothing was attempted", got)
	}
}
