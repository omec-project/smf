// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/nas/v2"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/transaction"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// craftModificationRequest encodes a real PDU SESSION MODIFICATION REQUEST (0xC9), the message the
// SMF used to decode, debug-log and drop.
const testSupi = "imsi-208930100007487"

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

// postUpdateSmContext drives the real N1 dispatch the way an UpdateSmContext from the AMF does:
// the NAS message arrives as a file on the multipart body.
func postUpdateSmContext(t *testing.T, n1 []byte, smContext *smf_context.SMContext) *models.UpdateSmContext200Response {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "n1sm")
	if err != nil {
		t.Fatalf("could not create the N1 payload file: %v", err)
	}
	if _, err := file.Write(n1); err != nil {
		t.Fatalf("could not write the N1 payload: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })

	body := models.UpdateSmContextRequest{}
	body.SetBinaryDataN1SmMessage(file)

	response := models.NewUpdateSmContext200Response()
	txn := &transaction.Transaction{Req: body, Ctxt: smContext}

	if err := HandleUpdateN1Msg(txn, response, &pfcpAction{}); err != nil {
		t.Fatalf("HandleUpdateN1Msg returned an error: %v", err)
	}
	return response
}

// decodeReject reads the N1 message the SMF put on the response and decodes it.
func decodeReject(t *testing.T, response *models.UpdateSmContext200Response) *nas.Message {
	t.Helper()

	file := response.GetBinaryDataN1SmMessage()
	if file == nil {
		t.Fatal("the response carries no N1 SM message: the SMF answered with nothing, which is the defect this refusal exists to fix")
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatalf("could not rewind the response payload: %v", err)
	}
	contents, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatalf("could not read the response payload: %v", err)
	}

	m := nas.NewMessage()
	if err := m.GsmMessageDecode(&contents); err != nil {
		t.Fatalf("the SMF produced an N1 message that does not decode: %v", err)
	}
	return m
}

func activeSmContext(pduSessionID int32) *smf_context.SMContext {
	return &smf_context.SMContext{
		PDUSessionID:   pduSessionID,
		SMContextState: smf_context.SmStateActive,
		SubPduSessLog:  zap.NewNop().Sugar(),
		SubCtxLog:      zap.NewNop().Sugar(),
		SubGsmLog:      zap.NewNop().Sugar(),
		SubPfcpLog:     zap.NewNop().Sugar(),
		SubConsumerLog: zap.NewNop().Sugar(),
		SubFsmLog:      zap.NewNop().Sugar(),
		SubQosLog:      zap.NewNop().Sugar(),
	}
}

// A UE-requested modification is refused with #32, and the refusal comes back on the
// UpdateSmContext response.
//
// Before the dispatch case existed, a 0xC9 was decoded, debug-logged and dropped: the SMF answered
// 200 with no N1 or N2 content, so the UE retransmitted until T3581 expired and then abandoned the
// procedure. That reads as a UE fault in a capture, which is why it went unnoticed.
//
// #32 rather than a generic rejection because TS 24.501 subclause 6.4.2.4.3 item a makes the UE
// back off on its own for #32 and #33.
func TestUeRequestedModificationIsRefusedWithServiceOptionNotSupported(t *testing.T) {
	const pduSessionID, pti = int32(10), uint8(7)

	response := postUpdateSmContext(t, craftModificationRequest(t, pduSessionID, pti), activeSmContext(pduSessionID))
	m := decodeReject(t, response)

	if got := m.GsmHeader.GetMessageType(); got != nas.MsgTypePDUSessionModificationReject {
		t.Fatalf("message type = 0x%02x, want a PDU SESSION MODIFICATION REJECT (0x%02x)",
			got, nas.MsgTypePDUSessionModificationReject)
	}
	reject := m.PDUSessionModificationReject
	if got := reject.GetCauseValue(); got != nasMessage.Cause5GSMServiceOptionNotSupported {
		t.Errorf("5GSM cause = #%d, want #32 service option not supported", got)
	}
	if got := reject.GetPTI(); got != pti {
		t.Errorf("PTI = %d, want %d echoed from the request: the UE cannot match the reject to its procedure otherwise", got, pti)
	}
	if got := int32(reject.GetPDUSessionID()); got != pduSessionID {
		t.Errorf("PDU session id = %d, want %d", got, pduSessionID)
	}
	jsonData := response.GetJsonData()
	if got := jsonData.GetN1SmMsg().ContentId; got != "PDUSessionModificationReject" {
		t.Errorf("N1SmMsg content id = %q, want %q", got, "PDUSessionModificationReject")
	}
}

// An identity the SMF does not hold, or one whose session is not established, takes #43 instead.
// TS 24.501 subclause 6.4.2.6 item b.
func TestModificationForAnInactiveOrUnknownSessionIsRefusedWithInvalidIdentity(t *testing.T) {
	tests := []struct {
		name         string
		requestedID  int32
		contextID    int32
		contextState smf_context.SMContextState
	}{
		{"identity the context does not hold", 11, 10, smf_context.SmStateActive},
		{"session never established", 10, 10, smf_context.SmStateInit},
		{"session on its way out", 10, 10, smf_context.SmStateInActivePending},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			smContext := activeSmContext(tc.contextID)
			smContext.SMContextState = tc.contextState

			response := postUpdateSmContext(t, craftModificationRequest(t, tc.requestedID, 3), smContext)
			m := decodeReject(t, response)

			if got := m.GsmHeader.GetMessageType(); got != nas.MsgTypePDUSessionModificationReject {
				t.Fatalf("message type = 0x%02x, want a PDU SESSION MODIFICATION REJECT", got)
			}
			if got := m.PDUSessionModificationReject.GetCauseValue(); got != nasMessage.Cause5GSMInvalidPDUSessionIdentity {
				t.Errorf("5GSM cause = #%d, want #43 invalid PDU session identity", got)
			}
			// The reject must carry the identity the UE asked about, not the one the SMF holds,
			// or the UE cannot tell which of its sessions was refused.
			if got := int32(m.PDUSessionModificationReject.GetPDUSessionID()); got != tc.requestedID {
				t.Errorf("PDU session id = %d, want the requested %d", got, tc.requestedID)
			}
		})
	}
}

// The refusal must not go out as a network-requested modification. TS 23.502 subclause 4.3.3.2
// step 3a puts it on the UpdateSmContext response; step 3b's N1N2 transfer is for the network's
// own procedure. Sending it that way would also start T3591 for a procedure the network never
// initiated.
func TestRefusalDoesNotStartTheNetworkModificationTimer(t *testing.T) {
	smContext := activeSmContext(10)

	postUpdateSmContext(t, craftModificationRequest(t, 10, 1), smContext)

	if smContext.T3591 != nil {
		t.Error("T3591 was started for a refusal; it belongs to the network's own modification procedure")
	}
}

// An N1 message type the dispatch has no case for is logged at error level rather than dropped in
// silence.
//
// 5GSM STATUS is used here because it is a real UE-to-network message the SMF still has no case
// for, so this is the next instance of the same defect rather than an invented one. The switch had
// no default branch at all: an unhandled type was decoded, debug-logged and dropped, and the SMF
// answered 200 with nothing. Finding that took a packet capture. It should take a log line.
func TestUnhandledN1MessageTypeIsLoggedLoudly(t *testing.T) {
	core, recorded := observer.New(zapcore.ErrorLevel)

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypeStatus5GSM)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.Status5GSM = nasMessage.NewStatus5GSM(0x0)
	m.Status5GSM.SetMessageType(nas.MsgTypeStatus5GSM)
	m.Status5GSM.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.Status5GSM.SetPDUSessionID(10)
	m.Status5GSM.SetPTI(0)
	m.Status5GSM.SetCauseValue(nasMessage.Cause5GSMInvalidPDUSessionIdentity)
	buf, err := m.PlainNasEncode()
	if err != nil {
		t.Fatalf("could not encode a 5GSM STATUS: %v", err)
	}

	smContext := activeSmContext(10)
	smContext.SubPduSessLog = zap.New(core).Sugar()

	postUpdateSmContext(t, buf, smContext)

	entries := recorded.FilterMessageSnippet("unhandled N1 SM message type").All()
	if len(entries) == 0 {
		t.Fatal("an unhandled N1 message type produced no error-level log; the next missing case will need a packet capture to find")
	}
	if got := entries[0].Message; !strings.Contains(got, "0xd6") {
		t.Errorf("log line %q does not name the message type; it has to say which case is missing", got)
	}
}

// A network-initiated modification sends the Command and arms T3591.
//
// This is the trigger X-14 step 3 exercises and the one an operator policy change takes:
// SmPolicyUpdateNotify -> PFCP modify -> Command over N1N2. Until the send seams were adopted at
// its call sites it was the only modification path with no test, because a test of it would have
// opened a real PFCP association.
//
// T3591 matters as much as the Command. Without the timer the SMF sends once and never learns that
// the UE did not answer, which on a satellite link is the ordinary case rather than the exception.
func TestNetworkInitiatedModificationSendsTheCommandAndArmsT3591(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })

	var pfcpSent, commandSent int
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error { pfcpSent++; return nil }
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { commandSent++; return nil }

	smContext := activeSmContext(10)
	smContext.Supi = testSupi
	smContext.T3591Value = 16 * time.Second
	// ChangeState reads these when leaving SmStateActive, to label the session metric. A session
	// that reached SmStateActive always has them, so this is fixture rather than new exposure.
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.19")}
	smContext.Identifier = testSupi

	t.Cleanup(func() { smContext.StopT3591() })

	txn := &transaction.Transaction{
		Req:  models.SmPolicyNotification{SmPolicyDecision: &models.SmPolicyDecision{}},
		Ctxt: smContext,
	}
	if err := HandleSMPolicyUpdateNotify(txn); err != nil {
		t.Fatalf("HandleSMPolicyUpdateNotify returned an error: %v", err)
	}

	if pfcpSent != 1 {
		t.Errorf("PFCP session modifications sent = %d, want 1", pfcpSent)
	}
	if commandSent != 1 {
		t.Errorf("modification commands sent = %d, want 1", commandSent)
	}
	if smContext.T3591 == nil {
		t.Error("T3591 was not armed, so an unanswered command would never be retransmitted or abandoned")
	}
}

// A UE request arriving while the network is modifying the same session is disregarded, not
// refused. TS 24.501 subclause 6.3.2.5 item d.
//
// Three things have to hold together, and asserting only the first would miss the point: the UE
// gets no reject, the network's own procedure is untouched, and T3591 keeps running so the
// Command is still retransmitted and still abandoned on time.
func TestCollidingUeRequestIsDisregardedNotRefused(t *testing.T) {
	smContext := activeSmContext(10)
	smContext.T3591Value = 16 * time.Second
	smContext.NwModificationPending = true
	smContext.T3591 = smf_context.NewTimer(smContext.T3591Value, 4, func(int32) {}, func() {})
	t.Cleanup(func() { smContext.StopT3591() })

	response := postUpdateSmContext(t, craftModificationRequest(t, 10, 5), smContext)

	if file := response.GetBinaryDataN1SmMessage(); file != nil {
		t.Error("the UE was answered; a colliding request must be disregarded, and a reject would have it back off on a session that is about to change")
	}
	if !smContext.NwModificationPending {
		t.Error("the network's own modification was cancelled by the UE's request")
	}
	if smContext.T3591 == nil {
		t.Error("T3591 was stopped, so the network's command would never be retransmitted or abandoned")
	}
}

// The collision exception is specific to the session the network is modifying. A request for a
// different session is still refused, or a second session could never be told anything while any
// other one was mid-modification.
func TestCollisionExceptionAppliesOnlyToTheSessionBeingModified(t *testing.T) {
	smContext := activeSmContext(10)
	smContext.NwModificationPending = true

	response := postUpdateSmContext(t, craftModificationRequest(t, 11, 5), smContext)
	m := decodeReject(t, response)

	if got := m.PDUSessionModificationReject.GetCauseValue(); got != nasMessage.Cause5GSMInvalidPDUSessionIdentity {
		t.Errorf("5GSM cause = #%d, want #43: a different session is not the collision case", got)
	}
}

// With no network modification running, a UE request is refused as usual. This is what stops the
// indicator from being read the wrong way round.
func TestUeRequestIsRefusedWhenNoNetworkModificationIsRunning(t *testing.T) {
	smContext := activeSmContext(10)
	if smContext.NwModificationPending {
		t.Fatal("fixture is wrong: nothing should be pending")
	}

	response := postUpdateSmContext(t, craftModificationRequest(t, 10, 5), smContext)
	m := decodeReject(t, response)

	if got := m.PDUSessionModificationReject.GetCauseValue(); got != nasMessage.Cause5GSMServiceOptionNotSupported {
		t.Errorf("5GSM cause = #%d, want #32", got)
	}
}

// A modification that fails before it starts must not leave the session looking as though one were
// running. If it did, every later UE request for that session would be disregarded silently and
// for good — a worse failure than the refusal this replaced.
func TestFailedNetworkModificationDoesNotLeaveTheSessionLookingBusy(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })

	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		return errors.New("upf unreachable")
	}
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return nil }

	smContext := activeSmContext(10)
	smContext.Supi = testSupi
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.19")}
	smContext.Identifier = testSupi

	txn := &transaction.Transaction{
		Req:  models.SmPolicyNotification{SmPolicyDecision: &models.SmPolicyDecision{}},
		Ctxt: smContext,
	}
	if err := HandleSMPolicyUpdateNotify(txn); err == nil {
		t.Fatal("expected the PFCP failure to be reported")
	}

	if smContext.NwModificationPending {
		t.Fatal("the session still looks as though the network were modifying it, so every later UE request would be disregarded for good")
	}

	// And prove it by the behaviour, not only the flag.
	response := postUpdateSmContext(t, craftModificationRequest(t, 10, 5), smContext)
	if response.GetBinaryDataN1SmMessage() == nil {
		t.Error("a UE request after the failed modification was disregarded rather than refused")
	}
}

// The collision, end to end: the network's own procedure marks the session, and a UE request that
// arrives while it is running is disregarded.
//
// The other collision test sets the indicator on the fixture directly, so it cannot see whether
// the real path ever sets it — removing the assignment leaves that test passing. This one drives
// HandleSMPolicyUpdateNotify first, so the two halves are joined.
func TestNetworkProcedureMarksTheSessionSoAUeRequestCollides(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error { return nil }
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return nil }

	smContext := activeSmContext(10)
	smContext.Supi = testSupi
	smContext.Identifier = testSupi
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.19")}
	smContext.T3591Value = 16 * time.Second
	t.Cleanup(func() { smContext.StopT3591() })

	txn := &transaction.Transaction{
		Req:  models.SmPolicyNotification{SmPolicyDecision: &models.SmPolicyDecision{}},
		Ctxt: smContext,
	}
	if err := HandleSMPolicyUpdateNotify(txn); err != nil {
		t.Fatalf("the network's modification failed to start: %v", err)
	}

	response := postUpdateSmContext(t, craftModificationRequest(t, 10, 5), smContext)

	if response.GetBinaryDataN1SmMessage() != nil {
		t.Error("the UE was refused during the network's own modification; TS 24.501 subclause 6.3.2.5 item d says disregard it")
	}
	if smContext.T3591 == nil {
		t.Error("the network's procedure lost its timer to the UE's request")
	}
}

// A UE request arriving while the network's PFCP round trip is still in flight is already a
// collision, before T3591 exists.
//
// This is the whole reason the session carries its own indicator rather than being read off
// T3591. The timer is armed only after the Command goes out; the procedure begins a PFCP exchange
// earlier, and on a satellite bench that exchange is not brief. A request landing in that window
// is disregarded by the specification just the same, and would otherwise be refused.
//
// The colliding request is sent from inside the PFCP stub, which is exactly where the window is.
func TestUeRequestDuringThePfcpRoundTripIsAlreadyACollision(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })

	smContext := activeSmContext(10)
	smContext.Supi = testSupi
	smContext.Identifier = testSupi
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.19")}
	smContext.T3591Value = 16 * time.Second
	t.Cleanup(func() { smContext.StopT3591() })

	var refusedMidFlight bool
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		// Mid-procedure: the Command has not been sent, so T3591 is not armed yet.
		if smContext.T3591 != nil {
			t.Error("T3591 is already armed inside the PFCP round trip; this test no longer covers the window it was written for")
		}
		response := postUpdateSmContext(t, craftModificationRequest(t, 10, 5), smContext)
		refusedMidFlight = response.GetBinaryDataN1SmMessage() != nil
		return nil
	}
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return nil }

	txn := &transaction.Transaction{
		Req:  models.SmPolicyNotification{SmPolicyDecision: &models.SmPolicyDecision{}},
		Ctxt: smContext,
	}
	if err := HandleSMPolicyUpdateNotify(txn); err != nil {
		t.Fatalf("the network's modification failed to start: %v", err)
	}

	if refusedMidFlight {
		t.Error("a UE request arriving during the PFCP round trip was refused; the procedure had already begun, so it is a collision to be disregarded")
	}
}

// The N1 handlers run with SMLock already held, and must never take it again.
//
// This is the defect a cluster run found that the whole unit suite missed: every other test here
// calls HandleUpdateN1Msg directly, so the lock is free and the handlers pass. In production
// HandlePDUSessionSMContextUpdate takes SMLock with a defer and calls them under it, so a second
// acquisition deadlocks — the session wedges permanently, its HTTP handler never returns, and the
// AMF is left waiting. A UE that answered a modification correctly was what triggered it.
//
// The test holds the lock the way the real caller does. It fails by timing out rather than by
// asserting, because a deadlock has no return value.
func TestN1HandlersDoNotRetakeTheSessionLock(t *testing.T) {
	cases := map[string][]byte{
		"modification complete": craftModificationComplete(t, 10, 0),
		"modification request":  craftModificationRequest(t, 10, 7),
	}

	for name, n1 := range cases {
		t.Run(name, func(t *testing.T) {
			smContext := activeSmContext(10)
			smContext.Supi = testSupi
			smContext.Identifier = testSupi
			smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.19")}

			file, err := os.CreateTemp(t.TempDir(), "n1sm")
			if err != nil {
				t.Fatalf("could not create the payload file: %v", err)
			}
			if _, err := file.Write(n1); err != nil {
				t.Fatalf("could not write the payload: %v", err)
			}
			body := models.UpdateSmContextRequest{}
			body.SetBinaryDataN1SmMessage(file)
			txn := &transaction.Transaction{Req: body, Ctxt: smContext}

			done := make(chan struct{})
			go func() {
				// Exactly what HandlePDUSessionSMContextUpdate does before dispatching.
				smContext.SMLock.Lock()
				defer smContext.SMLock.Unlock()
				if err := HandleUpdateN1Msg(txn, models.NewUpdateSmContext200Response(), &pfcpAction{}); err != nil {
					t.Errorf("handler returned an error: %v", err)
				}
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the handler did not return with SMLock held: it deadlocked, which wedges the session and never answers the AMF")
			}
		})
	}
}

// craftModificationComplete encodes a PDU SESSION MODIFICATION COMPLETE at PTI 0, which is what a
// UE sends to acknowledge a network-requested modification.
func craftModificationComplete(t *testing.T, pduSessionID int32, pti uint8) []byte {
	t.Helper()

	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionModificationComplete)
	m.GsmHeader.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	m.PDUSessionModificationComplete = nasMessage.NewPDUSessionModificationComplete(0x0)
	c := m.PDUSessionModificationComplete
	c.SetMessageType(nas.MsgTypePDUSessionModificationComplete)
	c.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	c.SetPDUSessionID(uint8(pduSessionID))
	c.SetPTI(pti)

	buf, err := m.PlainNasEncode()
	if err != nil {
		t.Fatalf("could not encode a modification complete: %v", err)
	}
	return buf
}
