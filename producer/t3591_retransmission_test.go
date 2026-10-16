// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
	"go.uber.org/zap"
)

// A retransmission for a procedure that has ended is not sent. The check runs under SMLock before
// anything is built or transferred, so this needs no AMF. This session has nothing to build a command
// from, so a send that got past the check would fail in the builder instead of reporting the
// procedure as superseded.
func TestARetransmissionForAnEndedModificationIsNotSent(t *testing.T) {
	smContext := &smf_context.SMContext{
		Supi:          testSupi,
		PDUSessionID:  10,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubPfcpLog:    zap.NewNop().Sugar(),
	}

	err := buildAndSendQosN1N2TransferMsg(smContext, func() bool { return false })
	if !errors.Is(err, errModificationSuperseded) {
		t.Fatalf("err = %v, want errModificationSuperseded", err)
	}
}

// Stop does not wait for an expiry that is already due, so a T3591 tick can arrive after the UE has
// acknowledged the command and the timer has been stopped. The retransmission it triggers asks
// whether its own timer is still the session's T3591, which stays true while the procedure runs and
// turns false once the timer is stopped: that is what keeps a late tick from resending the command.
//
// The retransmission is held until the assertions are made. Returning at once, it let the timer run
// on, and a runner that delayed the test by a few expiries saw T3591 abandon the procedure first: the
// check then read false while the timer should still have been running.
func TestAT3591ExpiryRetransmitsOnlyWhileItsTimerIsCurrent(t *testing.T) {
	stillCurrent := make(chan func() bool, 1)
	release := make(chan struct{})

	original := retransmitModificationCommand
	retransmitModificationCommand = func(_ *smf_context.SMContext, current func() bool) error {
		select {
		case stillCurrent <- current:
		default:
		}
		<-release

		return nil
	}
	t.Cleanup(func() { retransmitModificationCommand = original })

	smContext := &smf_context.SMContext{
		Supi:          testSupi,
		PDUSessionID:  10,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		T3591Value:    10 * time.Millisecond,
	}

	smContext.SMLock.Lock()
	startT3591Locked(smContext, 4)
	timer := smContext.T3591
	smContext.SMLock.Unlock()
	// Registered after the stub's restoration, so it runs first: the timer's goroutine is done with
	// the stub before the stub is put back.
	t.Cleanup(func() {
		smContext.SMLock.Lock()
		smContext.StopT3591()
		smContext.SMLock.Unlock()
		select {
		case <-release:
		default:
			close(release)
		}
		timer.Stop()
	})

	var current func() bool
	select {
	case current = <-stillCurrent:
	case <-time.After(2 * time.Second):
		t.Fatal("T3591 never expired")
	}

	smContext.SMLock.Lock()
	running := current()
	smContext.StopT3591()
	stopped := current()
	smContext.SMLock.Unlock()
	close(release)

	if !running {
		t.Error("the retransmission was told its procedure had ended while its timer was still running")
	}
	if stopped {
		t.Error("the retransmission's check still held after its timer was stopped, so a late tick would resend the command")
	}
}

// And the check that decides it is the one in the hold of SMLock that starts the transfer. An
// acknowledgement that lands while the command is being built stops T3591 before the transfer
// begins, and the command must not go out after all.
func TestARetransmissionIsAbandonedIfItsProcedureEndsWhileItIsBuilt(t *testing.T) {
	smContext := commandBuildingSession()

	checks := 0
	err := buildAndSendQosN1N2TransferMsg(smContext, func() bool {
		checks++
		return checks == 1 // current while the command is built, over by the time it would be sent
	})

	if !errors.Is(err, errModificationSuperseded) {
		t.Fatalf("err = %v, want errModificationSuperseded: the command was sent for a procedure that had ended", err)
	}
	if checks != 2 {
		t.Errorf("checked %d times, want twice: at the build and again when the transfer starts", checks)
	}
}

// A Command that went out more than once on its first transfer -- a transfer that got no HTTP
// answer, retried against another AMF -- may have reached the UE twice, and the UE answers every
// copy. Its procedure's end then waits out one T3591 interval, as after a retransmission, so a late
// answer to the other copy cannot be taken as the next Command's.
func TestACommandSentTwiceOnItsFirstTransferIsTreatedAsRetransmitted(t *testing.T) {
	original := sendModificationTransfer
	t.Cleanup(func() { sendModificationTransfer = original })
	sendModificationTransfer = func(context.Context, *smf_context.SMContext, *models.N1N2MessageTransferRequest) (*models.N1N2MessageTransferRspData, int, error) {
		return models.NewN1N2MessageTransferRspData(models.N1N2MESSAGETRANSFERCAUSE_N1_N2_TRANSFER_INITIATED), 2, nil
	}

	smContext := commandBuildingSession()
	smContext.T3591Value = 16 * time.Second

	if err := buildAndSendQosN1N2TransferMsg(smContext, nil); err != nil {
		t.Fatalf("sending the command: %v", err)
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	if smContext.NwModificationQuietFor != smContext.T3591Value {
		t.Errorf("quiet interval = %s, want %s: the UE may answer the Command's other copy", smContext.NwModificationQuietFor, smContext.T3591Value)
	}
}

// commandBuildingSession is a session whose Command builds: a committed session rule and default
// flow, which the NGAP transfer reads, and a pending update that changes nothing.
func commandBuildingSession() *smf_context.SMContext {
	smContext := modifyingSession()
	smContext.SubPfcpLog = zap.NewNop().Sugar()
	smContext.SubGsmLog = zap.NewNop().Sugar()
	smContext.SmPolicyData.Initialize()
	smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule = &models.SessionRule{
		SessRuleId:   "rule-1",
		AuthSessAmbr: &models.Ambr{Uplink: "100 Mbps", Downlink: "100 Mbps"},
		AuthDefQos:   &models.AuthorizedDefaultQos{Var5qi: openapi.PtrInt32(9)},
	}
	defaultFlow := &models.QosData{QosId: "1", Var5qi: openapi.PtrInt32(9)}
	defaultFlow.SetDefQosFlowIndication(true)
	smContext.SmPolicyData.SmCtxtQosData.QosData["1"] = defaultFlow

	return smContext
}

// A transfer that was attempted and failed may still have reached the UE -- its answer lost, and no
// other AMF to try -- so its procedure's end waits out a T3591 interval too.
func TestAFailedTransferThatWasAttemptedIsTreatedAsRetransmitted(t *testing.T) {
	original := sendModificationTransfer
	t.Cleanup(func() { sendModificationTransfer = original })
	sendModificationTransfer = func(context.Context, *smf_context.SMContext, *models.N1N2MessageTransferRequest) (*models.N1N2MessageTransferRspData, int, error) {
		return nil, 1, errors.New("no HTTP answer, and no other AMF to try")
	}

	smContext := commandBuildingSession()
	smContext.T3591Value = 16 * time.Second

	if err := buildAndSendQosN1N2TransferMsg(smContext, nil); err == nil {
		t.Fatal("a failed transfer was reported as sent")
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	if smContext.NwModificationQuietFor != smContext.T3591Value {
		t.Errorf("quiet interval = %s, want %s: the Command may have reached the UE", smContext.NwModificationQuietFor, smContext.T3591Value)
	}
}

// A transfer that failed before anything was sent -- no AMF found, or no client to send with --
// cannot have reached the UE, so it leaves no quiet interval behind.
func TestATransferThatWasNeverSentLeavesNoQuietInterval(t *testing.T) {
	original := sendModificationTransfer
	t.Cleanup(func() { sendModificationTransfer = original })
	sendModificationTransfer = func(context.Context, *smf_context.SMContext, *models.N1N2MessageTransferRequest) (*models.N1N2MessageTransferRspData, int, error) {
		return nil, 0, errors.New("no AMF to send to")
	}

	smContext := commandBuildingSession()
	smContext.T3591Value = 16 * time.Second

	if err := buildAndSendQosN1N2TransferMsg(smContext, nil); err == nil {
		t.Fatal("a failed transfer was reported as sent")
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	if smContext.NwModificationQuietFor != 0 {
		t.Errorf("quiet interval = %s, want none: nothing was sent", smContext.NwModificationQuietFor)
	}
}

// sentTransfers replaces the transfer the Command goes out on with one that keeps what it is handed.
func sentTransfers(t *testing.T) *[]*models.N1N2MessageTransferRequest {
	t.Helper()

	var sent []*models.N1N2MessageTransferRequest
	original := sendModificationTransfer
	t.Cleanup(func() { sendModificationTransfer = original })
	sendModificationTransfer = func(_ context.Context, _ *smf_context.SMContext, request *models.N1N2MessageTransferRequest) (*models.N1N2MessageTransferRspData, int, error) {
		sent = append(sent, request)
		return models.NewN1N2MessageTransferRspData(models.N1N2MESSAGETRANSFERCAUSE_N1_N2_TRANSFER_INITIATED), 1, nil
	}

	return &sent
}

// carriesRadioRequest reports whether a transfer carries the radio's part, and fails the test if it
// does not carry the UE's.
func carriesRadioRequest(t *testing.T, request *models.N1N2MessageTransferRequest) bool {
	t.Helper()

	jsonData := request.GetJsonData()
	if request.GetBinaryDataN1Message() == nil || !jsonData.HasN1MessageContainer() {
		t.Fatal("the transfer does not carry the UE's Command")
	}
	_, withContainer := jsonData.GetN2InfoContainerOk()
	withPayload := request.GetBinaryDataN2Information() != nil
	if withContainer != withPayload {
		t.Fatalf("the transfer's N2 container (%t) and N2 payload (%t) disagree", withContainer, withPayload)
	}

	return withPayload
}

// A retransmission goes to the radio as well while the radio has not answered: its first request
// may never have reached it.
func TestARetransmissionBeforeTheRadioAnswersCarriesTheRadioRequest(t *testing.T) {
	sent := sentTransfers(t)
	smContext := commandBuildingSession()
	smContext.RanAnswerPending = true

	if err := buildAndSendQosN1N2TransferMsg(smContext, func() bool { return true }); err != nil {
		t.Fatalf("retransmitting the command: %v", err)
	}

	if len(*sent) != 1 || !carriesRadioRequest(t, (*sent)[0]) {
		t.Error("a retransmission before the radio answered did not carry the radio's part")
	}
}

// Once the radio has answered, a retransmission is the UE's Command alone. The radio accepts flow 2
// and refuses flow 3, and T3591 then expires before the UE completes. A second radio request could
// establish flow 3, and its answer would be ignored, as the first has been taken; the correction
// the UE's completion starts would then withdraw flow 3 from the UE and the record and leave it on
// the radio.
func TestARetransmissionAfterThePartialRadioAnswerIsTheUEsCommandAlone(t *testing.T) {
	smContext := commandBuildingSession()
	smContext.SMContextState = smf_context.SmStateActive
	smContext.RanAnswerPending = true
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{
		QosFlowUpdate: qos.GetQosFlowDescUpdate(
			map[string]models.QosData{
				"1": *smContext.SmPolicyData.SmCtxtQosData.QosData["1"],
				"2": {QosId: "2", Var5qi: openapi.PtrInt32(1)},
				"3": {QosId: "3", Var5qi: openapi.PtrInt32(1)},
			},
			smContext.SmPolicyData.SmCtxtQosData.QosData,
		),
	}}

	deliverModifyResponse(t, smContext, craftModifyResponseTransfer(t, []int64{2}, []int64{3}))
	if smContext.Realign == nil || smContext.RanAnswerPending {
		t.Fatalf("the partial answer was not taken: realign %v, still waiting for the radio %t", smContext.Realign, smContext.RanAnswerPending)
	}

	sent := sentTransfers(t)
	if err := buildAndSendQosN1N2TransferMsg(smContext, func() bool { return true }); err != nil {
		t.Fatalf("retransmitting the command: %v", err)
	}

	if len(*sent) != 1 || carriesRadioRequest(t, (*sent)[0]) {
		t.Error("a retransmission after the radio's answer asked the radio again, whose answer would be ignored")
	}
}

// And the question is asked in the hold that sends, as the radio's answer is taken under that lock:
// an answer taken while the Command is built still keeps the radio's part off it.
func TestARadioAnswerTakenWhileTheRetransmissionIsBuiltKeepsTheRadioRequestOff(t *testing.T) {
	sent := sentTransfers(t)
	smContext := commandBuildingSession()
	smContext.RanAnswerPending = true

	checks := 0
	err := buildAndSendQosN1N2TransferMsg(smContext, func() bool {
		checks++
		if checks == 2 { // the hold that sends, with the answer taken since the build
			smContext.RanAnswerPending = false
		}
		return true
	})
	if err != nil {
		t.Fatalf("retransmitting the command: %v", err)
	}

	if len(*sent) != 1 || carriesRadioRequest(t, (*sent)[0]) {
		t.Error("the radio's part went out although its answer had been taken before the send")
	}
}

// The first Command asks the radio too, which needs ApplyModification to expect the radio's answer
// before it sends: the transfer reads that expectation to decide whether the radio is asked.
func TestTheFirstCommandIsSentExpectingTheRadioAnswer(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error { return nil }
	var sent, expected bool
	sendQosN1N2TransferMsg = func(sm *smf_context.SMContext) error {
		sm.SMLock.Lock()
		defer sm.SMLock.Unlock()
		sent, expected = true, sm.RanAnswerPending

		return nil
	}

	smContext := withTunnel(modifyingSession())
	smContext.ChangeState(smf_context.SmStateActive)
	smContext.T3591Value = 16 * time.Second
	t.Cleanup(func() {
		smContext.SMLock.Lock()
		smContext.StopT3591()
		smContext.SMLock.Unlock()
	})

	if err := ApplyModification(smContext, &qos.PolicyUpdate{}); err != nil {
		t.Fatalf("applying the modification: %v", err)
	}
	if !sent {
		t.Fatal("the Command was not sent")
	}
	if !expected {
		t.Error("the Command was sent before the radio's answer was expected, so it went without the radio's part")
	}
}
