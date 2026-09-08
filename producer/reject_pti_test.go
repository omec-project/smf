// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/omec-project/nas/v2"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/smferrors"
	"github.com/omec-project/smf/transaction"
	"github.com/omec-project/util/httpwrapper"
)

// requestPti is the procedure transaction identity the simulated UE allocates for its request.
// It is deliberately neither 0 nor 1: 0 is the value the defect these tests guard against
// produced, and 1 is what the nasTestpacket builders hardcode, so a test asserting either could
// pass by accident.
const requestPti uint8 = 0x27

// unservedDnn is not configured anywhere, so RetrieveDnnInformation returns nil for it and the
// establishment is refused at the first branch of HandlePDUSessionSMContextCreate - before the
// request is parsed, and without needing UDM, PCF or UPF.
const unservedDnn = "notserved"

func encodeEstablishmentRequest(t *testing.T, pduSessionID, pti uint8) []byte {
	t.Helper()

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionEstablishmentRequest)

	request := nasMessage.NewPDUSessionEstablishmentRequest(0)
	request.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	request.SetMessageType(nas.MsgTypePDUSessionEstablishmentRequest)
	request.SetPDUSessionID(pduSessionID)
	request.SetPTI(pti)
	request.SetMaximumDataRatePerUEForUserPlaneIntegrityProtectionForDownLink(0xff)
	request.SetMaximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink(0xff)
	m.PDUSessionEstablishmentRequest = request

	payload := new(bytes.Buffer)
	if err := m.GsmMessageEncode(payload); err != nil {
		t.Fatalf("could not encode PDU session establishment request: %v", err)
	}
	return payload.Bytes()
}

func encodeReleaseRequest(t *testing.T, pduSessionID, pti uint8) []byte {
	t.Helper()

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseRequest)

	request := nasMessage.NewPDUSessionReleaseRequest(0)
	request.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	request.SetMessageType(nas.MsgTypePDUSessionReleaseRequest)
	request.SetPDUSessionID(pduSessionID)
	request.SetPTI(pti)
	m.PDUSessionReleaseRequest = request

	payload := new(bytes.Buffer)
	if err := m.GsmMessageEncode(payload); err != nil {
		t.Fatalf("could not encode PDU session release request: %v", err)
	}
	return payload.Bytes()
}

// n1SmMessageFile mirrors what the AMF's multipart request delivers: the N1 SM message arrives as
// a file, which the producer consumes with io.ReadAll, so it has to be written and rewound rather
// than passed as bytes.
func n1SmMessageFile(t *testing.T, payload []byte) *os.File {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "n1sm")
	if err != nil {
		t.Fatalf("could not create N1 SM message file: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })

	if _, err = file.Write(payload); err != nil {
		t.Fatalf("could not write N1 SM message file: %v", err)
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("could not rewind N1 SM message file: %v", err)
	}
	return file
}

// decodeGsmPti reads the 5GSM message the SMF built and returns its message type and PTI, so the
// assertions read what went on the wire rather than a field the test arranged.
//
// The message is decoded to prove it is well formed, but the PTI is taken from the encoded octet:
// TS 24.501 clause 9.6 puts the procedure transaction identity in the third octet of every 5GSM
// message, which makes the read independent of the message type and of how the library populates
// its header struct.
func decodeGsmPti(t *testing.T, file *os.File) (msgType, pti uint8) {
	t.Helper()

	if file == nil {
		t.Fatal("no N1 SM message was attached to the rejection")
	}
	// The SMF builds the rejection into a temp file of its own and nothing in a test will clean it
	// up, so this helper does.
	t.Cleanup(func() {
		name := file.Name()
		_ = file.Close()
		_ = os.Remove(name)
	})

	payload, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("could not read the rejection's N1 SM message: %v", err)
	}
	if len(payload) < 4 {
		t.Fatalf("the rejection's N1 SM message is %d bytes, too short to be a 5GSM message", len(payload))
	}

	// Decode from a copy: GsmMessageDecode takes a pointer to the slice and consumes it, and the
	// octet is read from the payload afterwards.
	decoded := make([]byte, len(payload))
	copy(decoded, payload)
	m := nas.NewMessage()
	if err = m.GsmMessageDecode(&decoded); err != nil {
		t.Fatalf("could not decode the rejection's N1 SM message: %v", err)
	}
	return m.GsmHeader.GetMessageType(), payload[2]
}

// TestEstablishmentRejectEchoesRequestPti drives the producer, not the reject builder. That
// distinction is the whole test: GeneratePDUSessionEstablishmentReject reads smContext.Pti, so a
// test that builds the rejection itself supplies the value the producer is supposed to have
// recorded, and cannot fail when the producer does not record it.
func TestEstablishmentRejectEchoesRequestPti(t *testing.T) {
	const pduSessionID = 10

	// A context that has never handled a request: Pti is the zero value, exactly as it is when an
	// establishment is refused before HandlePDUSessionEstablishmentRequest runs.
	smContext := smf_context.NewSMContext("imsi-208930100007488", pduSessionID)

	request := models.NewPostSmContextsRequest()
	request.SetJsonData(models.SmContextCreateData{
		Supi:         openapi.PtrString("imsi-208930100007488"),
		PduSessionId: openapi.PtrInt32(pduSessionID),
		Dnn:          openapi.PtrString(unservedDnn),
		// SNssai must be set: the refusal logs createData.SNssai.Sst before building the
		// rejection, so a nil S-NSSAI panics before the message under test exists.
		SNssai: &models.Snssai{Sst: 1, Sd: openapi.PtrString("010203")},
	})
	request.SetBinaryDataN1SmMessage(n1SmMessageFile(t, encodeEstablishmentRequest(t, pduSessionID, requestPti)))

	txn := transaction.NewTransaction(*request, nil, svcmsgtypes.CreateSmContext)
	txn.Ctxt = smContext

	// The refusal is reported as an error, which is expected and not what this test is about.
	if err := HandlePDUSessionSMContextCreate(txn); err == nil {
		t.Fatal("expected the unserved DNN to be refused, but the establishment was accepted")
	}

	response, ok := txn.Rsp.(*httpwrapper.Response)
	if !ok {
		t.Fatalf("expected an httpwrapper.Response, got %T", txn.Rsp)
	}
	body, ok := response.Body.(*models.PostSmContexts400Response)
	if !ok {
		t.Fatalf("expected a PostSmContexts400Response, got %T", response.Body)
	}

	msgType, pti := decodeGsmPti(t, body.GetBinaryDataN1SmMessage())
	if msgType != nas.MsgTypePDUSessionEstablishmentReject {
		t.Fatalf("built message type = %#02x, want PDU SESSION ESTABLISHMENT REJECT (%#02x)",
			msgType, nas.MsgTypePDUSessionEstablishmentReject)
	}
	if pti != requestPti {
		t.Errorf("rejection carries PTI %#02x, want the request's %#02x: TS 24.501 clause 7.3.1 "+
			"item e) requires the UE to ignore an establishment reject whose PTI is unassigned, so "+
			"a refusal sent with PTI 0 is not delivered at all", pti, requestPti)
	}
}

// TestReleaseRejectEchoesRequestPti covers the sibling instance: the release request that names a
// PDU session the context does not hold takes a branch that skips
// HandlePDUSessionReleaseRequest, and so skips the only place the PTI was recorded.
func TestReleaseRejectEchoesRequestPti(t *testing.T) {
	const (
		contextPduSessionID   = 10
		requestedPduSessionID = 99
	)

	// The context is deliberately left in its initial state rather than driven to SmStateActive.
	// The branch under test does not depend on the state - the handler only logs when it is not
	// active - and ChangeState reports subscriber metrics through smContext.PDUAddress.Ip whenever
	// either state is active, which a context with no allocated address cannot satisfy.
	smContext := smf_context.NewSMContext("imsi-208930100007488", contextPduSessionID)

	request := models.UpdateSmContextRequest{}
	request.SetJsonData(models.SmContextUpdateData{})
	request.SetBinaryDataN1SmMessage(n1SmMessageFile(t, encodeReleaseRequest(t, requestedPduSessionID, requestPti)))

	txn := transaction.NewTransaction(request, nil, svcmsgtypes.UpdateSmContext)
	txn.Ctxt = smContext

	response := models.NewUpdateSmContext200Response()
	if err := HandleUpdateN1Msg(txn, response, &pfcpAction{}); err != nil {
		t.Fatalf("HandleUpdateN1Msg returned %v, want the release to be refused without error", err)
	}

	msgType, pti := decodeGsmPti(t, response.GetBinaryDataN1SmMessage())
	if msgType != nas.MsgTypePDUSessionReleaseReject {
		t.Fatalf("built message type = %#02x, want PDU SESSION RELEASE REJECT (%#02x)",
			msgType, nas.MsgTypePDUSessionReleaseReject)
	}
	// Assert equality with the request rather than merely non-zero: this context belongs to an
	// established session, so it can carry a stale assigned PTI from an earlier procedure, which
	// clause 7.3.1 item b) makes the UE answer with cause 47 rather than ignore.
	if pti != requestPti {
		t.Errorf("rejection carries PTI %#02x, want the request's %#02x", pti, requestPti)
	}
}

// TestErrorCauseRejectsCarryContextPti is the weaker, builder-level guard. It cannot fail for the
// defect the two tests above cover, because it supplies the PTI itself - it guards the encoder and
// the cause table against a rejection that drops the identity on the way to the wire.
//
// It iterates smferrors.ErrorType rather than smferrors.ErrorCause, because ErrorCause also holds
// InvalidPDUSessionIdentity, which belongs to the release path: GeneratePDUSessionEstablishmentReject
// dereferences ErrorType[cause].Status, so a key present in only one of the two maps would panic
// here rather than report anything. smf#633 pins that relationship between the maps.
func TestErrorCauseRejectsCarryContextPti(t *testing.T) {
	for cause := range smferrors.ErrorType {
		t.Run(cause, func(t *testing.T) {
			smContext := smf_context.NewSMContext("imsi-208930100007488", 10)
			smContext.Pti = requestPti

			response := smContext.GeneratePDUSessionEstablishmentReject(cause)
			body, ok := response.Body.(*models.PostSmContexts400Response)
			if !ok {
				t.Fatalf("expected a PostSmContexts400Response, got %T", response.Body)
			}

			msgType, pti := decodeGsmPti(t, body.GetBinaryDataN1SmMessage())
			if msgType != nas.MsgTypePDUSessionEstablishmentReject {
				t.Fatalf("built message type = %#02x, want PDU SESSION ESTABLISHMENT REJECT (%#02x)",
					msgType, nas.MsgTypePDUSessionEstablishmentReject)
			}
			if pti != requestPti {
				t.Errorf("rejection for %q carries PTI %#02x, want %#02x", cause, pti, requestPti)
			}
		})
	}
}
