// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"os"
	"testing"

	"github.com/omec-project/nas/v2"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/transaction"
	"go.uber.org/zap"
)

// craftReleaseRequest encodes a PDU SESSION RELEASE REQUEST, the message an AMF relays to the SMF
// as an UpdateSmContext's N1 payload when the UE (re)asks to release a session.
func craftReleaseRequest(t *testing.T, pduSessionID int32, pti uint8) []byte {
	t.Helper()

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseRequest)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionReleaseRequest = nasMessage.NewPDUSessionReleaseRequest(0x0)
	req := m.PDUSessionReleaseRequest
	req.SetMessageType(nas.MsgTypePDUSessionReleaseRequest)
	req.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	req.SetPDUSessionID(uint8(pduSessionID))
	req.SetPTI(pti)

	buf, err := m.PlainNasEncode()
	if err != nil {
		t.Fatalf("could not encode a release request: %v", err)
	}
	return buf
}

// A retransmitted PDU SESSION RELEASE REQUEST for a session already on its way out (Tunnel
// already cleared by releaseTunnel) must not be reprocessed as if it were the first one: the
// Tunnel == nil branch of the N1 handler used to leave the context in SmStateModify, which
// HandlePDUSessionSMContextUpdate's final dispatch unconditionally promotes to SmStateActive --
// reactivating a session whose user plane no longer exists instead of just acknowledging the
// retransmission.
func TestRetransmittedReleaseRequestAgainstATornDownSessionDoesNotReactivate(t *testing.T) {
	const pduSessionID = int32(10)

	prevConfig := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prevConfig })
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled}},
	}

	sm := &smf_context.SMContext{
		PDUSessionID:   pduSessionID,
		SMContextState: smf_context.SmStateInActivePending,
		// Tunnel is nil: releaseTunnel has already cleared it by the time a session reaches
		// SmStateInActivePending.
		Tunnel:        nil,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		SubGsmLog:     zap.NewNop().Sugar(),
		SubFsmLog:     zap.NewNop().Sugar(),
	}

	file, err := os.CreateTemp(t.TempDir(), "n1sm")
	if err != nil {
		t.Fatalf("could not create the N1 payload file: %v", err)
	}
	if _, err = file.Write(craftReleaseRequest(t, pduSessionID, 7)); err != nil {
		t.Fatalf("could not write the N1 payload: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })

	var body models.UpdateSmContextRequest
	body.SetBinaryDataN1SmMessage(file)
	body.SetJsonData(*models.NewSmContextUpdateData())

	txn := &transaction.Transaction{Req: body, Ctxt: sm}
	if err := HandleEvent(sm, SmEventPduSessModify, SmEventData{Txn: txn}); err != nil {
		t.Fatalf("HandleEvent returned an error: %v", err)
	}

	if sm.SMContextState == smf_context.SmStateActive {
		t.Errorf("SM context state = %v, want it to remain inactive; the retransmitted release request reactivated a session whose user plane was already torn down",
			sm.SMContextState.String())
	}
}
