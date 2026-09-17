// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"bytes"
	"testing"
	"time"

	"github.com/omec-project/nas/v2"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/transaction"
)

func encodeReleaseComplete(t *testing.T, pduSessionID, pti uint8) []byte {
	t.Helper()

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseComplete)

	msg := nasMessage.NewPDUSessionReleaseComplete(0)
	msg.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	msg.SetMessageType(nas.MsgTypePDUSessionReleaseComplete)
	msg.SetPDUSessionID(pduSessionID)
	msg.SetPTI(pti)
	m.PDUSessionReleaseComplete = msg

	payload := new(bytes.Buffer)
	if err := m.GsmMessageEncode(payload); err != nil {
		t.Fatalf("could not encode PDU session release complete: %v", err)
	}
	return payload.Bytes()
}

// TestReleaseCompleteRemovesTheContext is a regression test: the UE's PDU Session Release
// Complete is its confirmation that a release procedure has finished (TS 23.502 clause 4.3.4), so
// the session must actually be torn down here. It used to transition to SmStateInit and stop,
// leaving the context registered under its ref and canonical name forever - resolvable by the SMF
// long after Kafka consumers were told (via the terminal Del this same transition now publishes)
// that the session was gone.
func TestReleaseCompleteRemovesTheContext(t *testing.T) {
	const pduSessionID = 10

	smContext := smf_context.NewSMContext("imsi-208930100007777", pduSessionID)
	smContext.SMContextState = smf_context.SmStateInActivePending
	ref := smContext.Ref

	if smf_context.GetSMContext(ref) == nil {
		t.Fatalf("precondition: the context must be resolvable before the release completes")
	}

	request := models.UpdateSmContextRequest{}
	request.SetJsonData(models.SmContextUpdateData{})
	request.SetBinaryDataN1SmMessage(n1SmMessageFile(t, encodeReleaseComplete(t, pduSessionID, requestPti)))

	txn := transaction.NewTransaction(request, nil, svcmsgtypes.UpdateSmContext)
	txn.Ctxt = smContext

	response := models.NewUpdateSmContext200Response()
	if err := HandleUpdateN1Msg(txn, response, &pfcpAction{}); err != nil {
		t.Fatalf("HandleUpdateN1Msg returned %v, want the release complete to be handled without error", err)
	}

	if got := response.GetJsonData(); got.GetUpCnxState() != models.UPCNXSTATE_DEACTIVATED {
		t.Errorf("UpCnxState = %v, want DEACTIVATED", got.GetUpCnxState())
	}
	if got := smf_context.GetSMContext(ref); got != nil {
		t.Errorf("the context is still resolvable by ref after its release completed; RemoveSMContext was not called")
	}
	if smContext.SMContextState != smf_context.SmStateRelease {
		t.Errorf("SMContextState = %v, want SmStateRelease", smContext.SMContextState)
	}
}

// TestDuplicatePduSessionIDReleaseIsLockSafe is a regression test: the duplicate-session-ID branch
// of the N2 PDU Session Resource Release Response runs with smContext.SMLock already held by
// HandlePDUSessionSMContextUpdate. It used to call the unlocked RemoveSMContext, which re-locks
// that same, non-reentrant mutex and deadlocks the caller instead of tearing down the context.
func TestDuplicatePduSessionIDReleaseIsLockSafe(t *testing.T) {
	const pduSessionID = 12

	smContext := smf_context.NewSMContext("imsi-208930100007779", pduSessionID)
	smContext.SMContextState = smf_context.SmStateInActivePending
	smContext.PDUSessionRelease_DUE_TO_DUP_PDU_ID = true
	ref := smContext.Ref

	jsonData := models.SmContextUpdateData{}
	jsonData.SetN2SmInfoType(models.N2SMINFOTYPE_PDU_RES_REL_RSP)
	request := models.UpdateSmContextRequest{}
	request.SetJsonData(jsonData)

	txn := transaction.NewTransaction(request, nil, svcmsgtypes.UpdateSmContext)
	txn.Ctxt = smContext

	response := models.NewUpdateSmContext200Response()

	// Simulates HandlePDUSessionSMContextUpdate, which holds SMLock for the duration of the N2
	// handling this test drives.
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	done := make(chan error, 1)
	go func() {
		done <- HandleUpdateN2Msg(txn, response, &pfcpAction{}, &pfcpParam{})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleUpdateN2Msg returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HandleUpdateN2Msg deadlocked trying to re-lock smContext.SMLock")
	}

	if got := smf_context.GetSMContext(ref); got != nil {
		t.Errorf("the context is still resolvable by ref after the duplicate-ID release completed; RemoveSMContext was not called")
	}
}
