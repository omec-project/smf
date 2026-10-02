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
func TestAT3591ExpiryRetransmitsOnlyWhileItsTimerIsCurrent(t *testing.T) {
	stillCurrent := make(chan func() bool, 1)

	original := retransmitModificationCommand
	retransmitModificationCommand = func(_ *smf_context.SMContext, current func() bool) error {
		select {
		case stillCurrent <- current:
		default:
		}

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
	smContext.SMLock.Unlock()
	t.Cleanup(func() {
		smContext.SMLock.Lock()
		smContext.StopT3591()
		smContext.SMLock.Unlock()
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
