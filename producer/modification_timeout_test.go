// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"fmt"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/transaction"
	"github.com/omec-project/util/httpwrapper"
	"go.uber.org/zap"
)

// A modification the user plane never answered releases the session, and it has to do so in the
// release state. The deletion answers that release waits on -- a response, or the timeout of a
// deletion the user plane does not answer either -- are delivered only to a session in
// SmStatePfcpRelease. The branch moved the session to SmStatePfcpModify instead, so every one was
// withheld and the release waited for good. That was unreachable only while a modification
// timeout could not find its session.
//
// The tunnel is absent so the release sends nothing, and its answer is already waiting: what this
// pins is the state the release is carried out in, which the deletion tests in pfcp/message show is
// the one state a failed deletion answers.
func TestAModificationTimeoutReleasesTheSessionInTheReleaseState(t *testing.T) {
	smContext := &smf_context.SMContext{
		Supi:                     "imsi-208930000000047",
		PDUSessionID:             8,
		SMContextState:           smf_context.SmStatePfcpModify,
		SubCtxLog:                zap.NewNop().Sugar(),
		SubPduSessLog:            zap.NewNop().Sugar(),
		SubPfcpLog:               zap.NewNop().Sugar(),
		PDUAddress:               &smf_context.UeIpAddr{Ip: net.ParseIP("10.1.0.11")},
		SBIPFCPCommunicationChan: make(chan smf_context.PFCPSessionResponseStatus, 1),
	}
	smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess

	var stateDuringRelease smf_context.SMContextState

	done := make(chan struct{})

	go func() {
		defer close(done)

		HandlePFCPResponse(smContext, smf_context.SessionUpdateTimeout)
		stateDuringRelease = smContext.SMContextState
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the release after a modification timeout did not finish")
	}

	if stateDuringRelease != smf_context.SmStatePfcpRelease {
		t.Errorf("the session was released in %s, want SmStatePfcpRelease: every deletion answer is withheld from any other state", stateDuringRelease)
	}
}

// sessionTheUserPlaneAnswers is an active session whose modification goes out and is answered
// with the given verdict. The send is replaced for the test and reports success, and the verdict is
// already on the session's channel, where the response handler or the send-error handler puts it:
// that the timeout gets there is what the tests in pfcp/message pin. So the handler under test
// reads a real answer, rather than failing before it sends.
func sessionTheUserPlaneAnswers(t *testing.T, verdict smf_context.PFCPSessionResponseStatus) *smf_context.SMContext {
	t.Helper()

	send := sendModificationRequest
	sendModificationRequest = func(smf_context.NodeID, *smf_context.SMContext, []*smf_context.PDR, []*smf_context.FAR,
		[]*smf_context.BAR, []*smf_context.QER, []*smf_context.PDR, []*smf_context.FAR, []*smf_context.QER, uint16,
	) error {
		return nil
	}
	t.Cleanup(func() { sendModificationRequest = send })

	node := smf_context.NewDataPathNode()
	node.UPF = &smf_context.UPF{NodeID: *smf_context.NewNodeID("127.0.0.1")}
	// A downlink rule, so the UE-initiated modification below has a user plane to wait on.
	node.DownLinkTunnel.PDR["default"] = &smf_context.PDR{FAR: &smf_context.FAR{}}

	path := smf_context.NewDataPath()
	path.IsDefaultPath = true
	path.FirstDPNode = node

	smContext := smf_context.NewSMContext(fmt.Sprintf("imsi-20893000008%04d", time.Now().UnixNano()%10000), 5)
	smContext.Tunnel = smf_context.NewUPTunnel()
	smContext.Tunnel.DataPathPool[1] = path
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP("10.1.0.12")}
	smContext.SMContextState = smf_context.SmStateActive
	smContext.SBIPFCPCommunicationChan <- verdict

	return smContext
}

// awaitHandler runs one of the handlers under test and fails if it does not return.
func awaitHandler(t *testing.T, handle func()) {
	t.Helper()

	done := make(chan struct{})

	go func() {
		defer close(done)
		handle()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not return after the user plane's answer")
	}
}

// The two answers that end a modification without applying it: the user plane refusing it, and
// the timeout of one it never answered.
var failedModificationVerdicts = []smf_context.PFCPSessionResponseStatus{
	smf_context.SessionUpdateFailed,
	smf_context.SessionUpdateTimeout,
}

// A policy update the user plane refused or never answered leaves the session usable. The handler
// moves it into SmStatePfcpModify before sending and returns an error on either answer, and the
// FSM applies no state on an error -- so it stayed in the one state with no FSM handlers, and
// every later event on it was refused as unhandled.
func TestAPolicyUpdateTheUserPlaneDidNotApplyLeavesTheSessionActive(t *testing.T) {
	for _, verdict := range failedModificationVerdicts {
		t.Run(verdict.String(), func(t *testing.T) {
			smContext := sessionTheUserPlaneAnswers(t, verdict)

			txn := &transaction.Transaction{Req: models.SmPolicyNotification{}, Ctxt: smContext}

			awaitHandler(t, func() {
				if err := HandleSMPolicyUpdateNotify(txn); err == nil {
					t.Error("a policy update the user plane did not apply was reported as applied")
				}
			})

			if len(smContext.SBIPFCPCommunicationChan) != 0 {
				t.Fatal("the answer was never read: the test did not reach the path it is about")
			}

			if got := smContext.SMContextState; got != smf_context.SmStateActive {
				t.Errorf("state = %s, want SmStateActive: no FSM handler accepts an event in any other state this can leave", got)
			}
		})
	}
}

// And the same for a modification the UE's own update asked for, here the user plane connection
// going inactive. There it matters twice over: the error answer carries a PDU Session Release
// Command, and the UE's Release Complete arrives as an update, which only SmStateActive handles --
// so a session left in SmStatePfcpModify could not even complete the release the SMF asked for.
func TestAUeUpdateTheUserPlaneDidNotApplyLeavesTheSessionActive(t *testing.T) {
	for _, verdict := range failedModificationVerdicts {
		t.Run(verdict.String(), func(t *testing.T) {
			smContext := sessionTheUserPlaneAnswers(t, verdict)

			request := models.UpdateSmContextRequest{}
			data := models.NewSmContextUpdateData()
			data.SetUpCnxState(models.UPCNXSTATE_DEACTIVATED)
			request.SetJsonData(*data)

			txn := &transaction.Transaction{Req: request, Ctxt: smContext}

			awaitHandler(t, func() {
				if err := HandlePDUSessionSMContextUpdate(txn); err != nil {
					t.Errorf("the update was not answered: %v", err)
				}
			})

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
				t.Errorf("pending user planes = %v after the modification ended; the next one would wait for an answer to this", smContext.PendingUPF)
			}
		})
	}
}

// The modification this package sends and then waits for is sent as awaited. The tests above
// replace the send, so this is what pins the real one: sent as unawaited, its native timeout
// answers nothing, and the wait these fixes end would be back.
func TestTheWaitedForModificationIsSentAsAwaited(t *testing.T) {
	got := reflect.ValueOf(sendModificationRequest).Pointer()
	want := reflect.ValueOf(pfcp_message.SendAwaitedPfcpSessionModificationRequest).Pointer()

	if got != want {
		t.Error("SendPfcpSessionModifyReq sends through something other than SendAwaitedPfcpSessionModificationRequest")
	}
}
