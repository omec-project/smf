// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"net/http"
	"os"
	"testing"

	"github.com/omec-project/nas/v2"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/transaction"
	"github.com/omec-project/util/httpwrapper"
	"go.uber.org/zap"
)

// craftModificationRequest encodes a PDU SESSION MODIFICATION REQUEST, the message an AMF relays
// to the SMF as an UpdateSmContext's N1 payload.
func craftModificationRequest(t *testing.T, pduSessionID int32, pti uint8) []byte {
	t.Helper()

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionModificationRequest)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionModificationRequest = nasMessage.NewPDUSessionModificationRequest(0x0)
	req := m.PDUSessionModificationRequest
	req.SetMessageType(nas.MsgTypePDUSessionModificationRequest)
	req.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	req.SetPDUSessionID(uint8(pduSessionID))
	req.SetPTI(pti)

	buf, err := m.PlainNasEncode()
	if err != nil {
		t.Fatalf("could not encode a modification request: %v", err)
	}
	return buf
}

// dispatchModification drives a PDU SESSION MODIFICATION REQUEST through the real FSM dispatch
// SmfFsmHandler uses in production, rather than calling a producer handler directly.
func dispatchModification(t *testing.T, state smf_context.SMContextState, pduSessionID int32) (*httpwrapper.Response, error) {
	t.Helper()

	// Leaving a non-terminal state may publish to Kafka; keep it disabled and quiet for this test.
	prevConfig := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prevConfig })
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled}},
	}

	sm := &smf_context.SMContext{
		PDUSessionID:   pduSessionID,
		SMContextState: state,
		SubPduSessLog:  zap.NewNop().Sugar(),
		SubCtxLog:      zap.NewNop().Sugar(),
		SubGsmLog:      zap.NewNop().Sugar(),
		SubFsmLog:      zap.NewNop().Sugar(),
	}

	file, err := os.CreateTemp(t.TempDir(), "n1sm")
	if err != nil {
		t.Fatalf("could not create the N1 payload file: %v", err)
	}
	if _, err = file.Write(craftModificationRequest(t, pduSessionID, 7)); err != nil {
		t.Fatalf("could not write the N1 payload: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })

	var body models.UpdateSmContextRequest
	body.SetBinaryDataN1SmMessage(file)
	body.SetJsonData(*models.NewSmContextUpdateData())

	txn := &transaction.Transaction{Req: body, Ctxt: sm}
	err = HandleEvent(sm, SmEventPduSessModify, SmEventData{Txn: txn})

	rsp, _ := txn.Rsp.(*httpwrapper.Response)
	return rsp, err
}

// Before the FSM table routed SmStateInit and SmStateInActivePending for SmEventPduSessModify,
// this event met EmptyEventHandler: HandleUpdateN1Msg's #43 refusal (TS 24.501 subclause 6.4.2.6
// item b) was never reached, and the AMF got a bare 500 with no N1 answer at all.
func TestModificationAgainstAnInactiveSessionIsRefusedThroughFsmDispatch(t *testing.T) {
	tests := []struct {
		name  string
		state smf_context.SMContextState
	}{
		{"session never established", smf_context.SmStateInit},
		{"session on its way out", smf_context.SmStateInActivePending},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const pduSessionID = int32(10)

			rsp, err := dispatchModification(t, tc.state, pduSessionID)
			if err != nil {
				t.Fatalf("HandleEvent returned an error: %v", err)
			}
			if rsp == nil {
				t.Fatal("no HTTP response was set; the AMF would see a bare system failure with no N1 answer")
			}
			if rsp.Status != http.StatusOK {
				t.Errorf("status = %d, want %d", rsp.Status, http.StatusOK)
			}

			response, ok := rsp.Body.(models.UpdateSmContext200Response)
			if !ok {
				t.Fatalf("response body type = %T, want models.UpdateSmContext200Response", rsp.Body)
			}
			n1File := response.GetBinaryDataN1SmMessage()
			if n1File == nil {
				t.Fatal("the response carries no N1 SM message: the UE was left with no reject to answer")
			}
			if _, err = n1File.Seek(0, 0); err != nil {
				t.Fatalf("could not rewind the response payload: %v", err)
			}
			contents, err := os.ReadFile(n1File.Name())
			if err != nil {
				t.Fatalf("could not read the response payload: %v", err)
			}

			m := nas.NewMessage()
			if err := m.GsmMessageDecode(&contents); err != nil {
				t.Fatalf("could not decode the response payload: %v", err)
			}
			if got := m.GsmHeader.GetMessageType(); got != nas.MsgTypePDUSessionModificationReject {
				t.Fatalf("message type = 0x%02x, want a PDU SESSION MODIFICATION REJECT (0x%02x)",
					got, nas.MsgTypePDUSessionModificationReject)
			}
			if got := m.PDUSessionModificationReject.GetCauseValue(); got != nasMessage.Cause5GSMInvalidPDUSessionIdentity {
				t.Errorf("5GSM cause = #%d, want #43 invalid PDU session identity", got)
			}
		})
	}
}
