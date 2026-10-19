// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"io"
	"net"
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
//
// The retry exists because the UE never saw the first PDU Session Release Command (TS 24.501
// clause 6.3.3.3), so ignoring it silently would leave the UE retransmitting until it gives up
// and the context stuck in SmStateInActivePending; the fix must also resend that Command.
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

	if sm.SMContextState != smf_context.SmStateInActivePending {
		t.Errorf("SM context state = %v, want it to remain SmStateInActivePending; the retransmitted release request reactivated a session whose user plane was already torn down",
			sm.SMContextState.String())
	}

	rsp, ok := txn.Rsp.(*httpwrapper.Response)
	if !ok {
		t.Fatalf("expected an httpwrapper.Response, got %T", txn.Rsp)
	}
	rspBody, ok := rsp.Body.(models.UpdateSmContext200Response)
	if !ok {
		t.Fatalf("expected an UpdateSmContext200Response, got %T", rsp.Body)
	}

	msgType, gotPduSessionID := decodeReleaseCommand(t, rspBody.GetBinaryDataN1SmMessage())
	if msgType != nas.MsgTypePDUSessionReleaseCommand {
		t.Fatalf("N1 message type = %#02x, want PDU SESSION RELEASE COMMAND (%#02x); a UE retransmitting "+
			"because it never saw the first one has nothing to complete the release handshake with",
			msgType, nas.MsgTypePDUSessionReleaseCommand)
	}
	if int32(gotPduSessionID) != pduSessionID {
		t.Errorf("PDU session id in the resent Release Command = %d, want %d", gotPduSessionID, pduSessionID)
	}

	jsonData := rspBody.GetJsonData()
	n1ContentID := jsonData.GetN1SmMsg().ContentId
	n2ContentID := jsonData.GetN2SmInfo().ContentId
	if n1ContentID == "" || n2ContentID == "" {
		t.Fatalf("N1/N2 Content-IDs = %q/%q, want both set", n1ContentID, n2ContentID)
	}
	if n1ContentID == n2ContentID {
		t.Errorf("N1 and N2 Content-IDs are both %q, want distinct values so the AMF can resolve each attachment", n1ContentID)
	}
}

// decodeReleaseCommand reads and decodes the N1 SM message file the producer attached to the
// response, returning its message type and PDU session id.
func decodeReleaseCommand(t *testing.T, file *os.File) (msgType, pduSessionID uint8) {
	t.Helper()

	if file == nil {
		t.Fatal("no N1 SM message was attached to the response: the retransmission was silently dropped")
	}
	t.Cleanup(func() {
		name := file.Name()
		_ = file.Close()
		_ = os.Remove(name)
	})

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("could not rewind the response payload: %v", err)
	}
	payload, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("could not read the response's N1 SM message: %v", err)
	}

	decoded := make([]byte, len(payload))
	copy(decoded, payload)
	m := nas.NewMessage()
	if err = m.GsmMessageDecode(&decoded); err != nil {
		t.Fatalf("could not decode the response's N1 SM message: %v", err)
	}
	if m.PDUSessionReleaseCommand == nil {
		t.Fatal("decoded message is not a PDU Session Release Command")
	}
	return m.GsmHeader.GetMessageType(), m.PDUSessionReleaseCommand.GetPDUSessionID()
}

// releaseRequestTxn wraps a release request for the given PDU session/PTI into the transaction
// shape HandleEvent expects for SmEventPduSessModify.
func releaseRequestTxn(t *testing.T, sm *smf_context.SMContext, pduSessionID int32, pti uint8) *transaction.Transaction {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "n1sm")
	if err != nil {
		t.Fatalf("could not create the N1 payload file: %v", err)
	}
	if _, err = file.Write(craftReleaseRequest(t, pduSessionID, pti)); err != nil {
		t.Fatalf("could not write the N1 payload: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })

	var body models.UpdateSmContextRequest
	body.SetBinaryDataN1SmMessage(file)
	body.SetJsonData(*models.NewSmContextUpdateData())

	return &transaction.Transaction{Req: body, Ctxt: sm}
}

// singleUpfTunnel builds the minimal UPTunnel releaseTunnel can walk without a network: one
// DataPathNode with real (non-nil) UpLink/DownLinkTunnel structs (NewDataPathNode, required or
// DeactivateTunnelAndPDR nil-derefs on them) but empty PDR maps, so deactivation has nothing to
// do and no PFCP session deletion is actually sent (GetUPFID fails harmlessly: this UPF is not
// registered in the global UserPlaneInformation pool).
func singleUpfTunnel(nodeIP string) *smf_context.UPTunnel {
	node := smf_context.NewDataPathNode()
	node.UPF = &smf_context.UPF{NodeID: *smf_context.NewNodeID(nodeIP)}

	return &smf_context.UPTunnel{
		DataPathPool: smf_context.DataPathPool{
			1: {IsDefaultPath: true, FirstDPNode: node},
		},
	}
}

// The normal first-release path never actually stops at SmStateInActivePending in production:
// HandleStateActiveEventPduSessModify (fsm/handler.go) used to return a hardcoded SmStateActive
// regardless of what producer.HandlePDUSessionSMContextUpdate's own internal dispatch had just set
// the context to, and HandleEvent applies that return value unconditionally -- so a real release
// (Active -> PfcpModify -> PfcpRelease -> InActivePending, all set internally by the producer call)
// was stomped straight back to Active the instant the producer call returned, repeating the UE IP
// release and PFCP delete on the next retransmission instead of hitting the isSmContextInactive
// guard. Seeding SmStateInActivePending directly (as the sibling test above does) cannot catch
// this: it never exercises HandleStateActiveEventPduSessModify at all.
func TestFirstReleaseFromActiveReachesInActivePendingAndRetransmissionResendsCommand(t *testing.T) {
	const pduSessionID = int32(10)

	prevConfig := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prevConfig })
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled}},
	}

	// releaseTunnel's GetUPFID lookup dereferences this package-level singleton unconditionally;
	// a non-nil, empty UserPlaneInformation makes the lookup miss harmlessly (logged, no PFCP
	// session deletion sent) instead of nil-pointer-panicking. Shared global state: save/restore.
	prevUPI := smf_context.SMF_Self().UserPlaneInformation
	t.Cleanup(func() { smf_context.SMF_Self().UserPlaneInformation = prevUPI })
	smf_context.SMF_Self().UserPlaneInformation = &smf_context.UserPlaneInformation{}

	sm := &smf_context.SMContext{
		PDUSessionID:             pduSessionID,
		SMContextState:           smf_context.SmStateActive,
		Tunnel:                   singleUpfTunnel("10.0.0.1"),
		SBIPFCPCommunicationChan: make(chan smf_context.PFCPSessionResponseStatus, 1),
		SubPduSessLog:            zap.NewNop().Sugar(),
		SubCtxLog:                zap.NewNop().Sugar(),
		SubGsmLog:                zap.NewNop().Sugar(),
		SubFsmLog:                zap.NewNop().Sugar(),
	}

	// Buffered channel: queue the verdict before the blocking read inside SendPfcpSessionReleaseReq
	// reaches it, so the real release path completes synchronously with no PFCP peer involved.
	sm.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess

	firstTxn := releaseRequestTxn(t, sm, pduSessionID, 7)
	if err := HandleEvent(sm, SmEventPduSessModify, SmEventData{Txn: firstTxn}); err != nil {
		t.Fatalf("first release: HandleEvent returned an error: %v", err)
	}
	if sm.SMContextState != smf_context.SmStateInActivePending {
		t.Fatalf("after the first release, state = %v, want SmStateInActivePending; the FSM dispatch "+
			"overwrote the producer's own post-release state", sm.SMContextState.String())
	}

	retransmitTxn := releaseRequestTxn(t, sm, pduSessionID, 7)
	if err := HandleEvent(sm, SmEventPduSessModify, SmEventData{Txn: retransmitTxn}); err != nil {
		t.Fatalf("retransmitted release: HandleEvent returned an error: %v", err)
	}
	if sm.SMContextState != smf_context.SmStateInActivePending {
		t.Errorf("after the retransmission, state = %v, want it to remain SmStateInActivePending",
			sm.SMContextState.String())
	}

	rsp, ok := retransmitTxn.Rsp.(*httpwrapper.Response)
	if !ok {
		t.Fatalf("expected an httpwrapper.Response, got %T", retransmitTxn.Rsp)
	}
	rspBody, ok := rsp.Body.(models.UpdateSmContext200Response)
	if !ok {
		t.Fatalf("expected an UpdateSmContext200Response, got %T", rsp.Body)
	}
	msgType, gotPduSessionID := decodeReleaseCommand(t, rspBody.GetBinaryDataN1SmMessage())
	if msgType != nas.MsgTypePDUSessionReleaseCommand {
		t.Fatalf("N1 message type = %#02x, want PDU SESSION RELEASE COMMAND (%#02x)",
			msgType, nas.MsgTypePDUSessionReleaseCommand)
	}
	if int32(gotPduSessionID) != pduSessionID {
		t.Errorf("PDU session id in the resent Release Command = %d, want %d", gotPduSessionID, pduSessionID)
	}
}

// The AMF can send ReleaseSmContext (TS 29.502 clause 5.2.2.3.2) for a session the NAS release
// already moved to SmStateInActivePending, before the UE's own Release Complete ever arrives.
// InitFsm used to register SmEventPduSessRelease only for SmStateActive, so dispatch for this
// context reached EmptyEventHandler, returning an error that surfaced as an HTTP 500 and left the
// context registered forever. This also exercises the producer's unconditional ReleaseUeIpAddr
// call a second time (the N1 release handler already released the address once): it must be a
// no-op rather than re-releasing it.
func TestReleaseSmContextInActivePendingCompletesCleanup(t *testing.T) {
	const pduSessionID = int32(10)

	prevConfig := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prevConfig })
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled}},
	}

	// releaseTunnel's GetUPFID lookup dereferences this package-level singleton unconditionally;
	// a non-nil, empty UserPlaneInformation makes the lookup miss harmlessly (logged, no PFCP
	// session deletion sent) instead of nil-pointer-panicking. Shared global state: save/restore.
	prevUPI := smf_context.SMF_Self().UserPlaneInformation
	t.Cleanup(func() { smf_context.SMF_Self().UserPlaneInformation = prevUPI })
	smf_context.SMF_Self().UserPlaneInformation = &smf_context.UserPlaneInformation{}

	allocator, err := smf_context.NewIPAllocator("192.168.139.0/30")
	if err != nil {
		t.Fatalf("build the UE IP allocator: %v", err)
	}
	const supi = "imsi-208930100007488"
	ueIP, err := allocator.Allocate(supi)
	if err != nil {
		t.Fatalf("allocate the UE address: %v", err)
	}

	sm := &smf_context.SMContext{
		Supi:                     supi,
		PDUSessionID:             pduSessionID,
		SMContextState:           smf_context.SmStateActive,
		Tunnel:                   singleUpfTunnel("10.0.0.1"),
		SBIPFCPCommunicationChan: make(chan smf_context.PFCPSessionResponseStatus, 1),
		DNNInfo:                  &smf_context.SnssaiSmfDnnInfo{UeIPAllocator: allocator},
		PDUAddress:               &smf_context.UeIpAddr{Ip: ueIP},
		SubPduSessLog:            zap.NewNop().Sugar(),
		SubCtxLog:                zap.NewNop().Sugar(),
		SubGsmLog:                zap.NewNop().Sugar(),
		SubFsmLog:                zap.NewNop().Sugar(),
	}

	// Buffered channel: queue the verdict before the blocking read inside SendPfcpSessionReleaseReq
	// reaches it, so the NAS release path completes synchronously with no PFCP peer involved.
	sm.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess

	firstTxn := releaseRequestTxn(t, sm, pduSessionID, 7)
	if err = HandleEvent(sm, SmEventPduSessModify, SmEventData{Txn: firstTxn}); err != nil {
		t.Fatalf("first (NAS) release: HandleEvent returned an error: %v", err)
	}
	if sm.SMContextState != smf_context.SmStateInActivePending {
		t.Fatalf("after the NAS release, state = %v, want SmStateInActivePending", sm.SMContextState.String())
	}
	if !sm.PDUAddress.Ip.Equal(net.IPv4zero) {
		t.Fatalf("after the NAS release, UE address = %v, want it released (0.0.0.0)", sm.PDUAddress.Ip)
	}

	// The AMF's ReleaseSmContext: a separate SBI request, not another N1 message, so it is
	// dispatched directly as SmEventPduSessRelease rather than through releaseRequestTxn.
	releaseTxn := &transaction.Transaction{Req: *models.NewReleaseSmContextRequest(), Ctxt: sm}
	if err = HandleEvent(sm, SmEventPduSessRelease, SmEventData{Txn: releaseTxn}); err != nil {
		t.Fatalf("ReleaseSmContext in SmStateInActivePending returned an error (the AMF would see an "+
			"HTTP 500 and the context would never be removed): %v", err)
	}

	rsp, ok := releaseTxn.Rsp.(*httpwrapper.Response)
	if !ok {
		t.Fatalf("expected an httpwrapper.Response, got %T", releaseTxn.Rsp)
	}
	if rsp.Status != http.StatusNoContent {
		t.Errorf("ReleaseSmContext response status = %d, want %d (no PFCP peer left to delete from)",
			rsp.Status, http.StatusNoContent)
	}
	if !sm.PDUAddress.Ip.Equal(net.IPv4zero) {
		t.Errorf("UE address after ReleaseSmContext = %v, want it to remain released, not re-released",
			sm.PDUAddress.Ip)
	}

	// The address the NAS release freed must still be the one handed back out. The pool's /30
	// allocator has only two usable addresses, both already handed out exactly once by this point
	// (ueIP to supi, then the one below to the next caller), so a third allocate can only succeed
	// by reusing ueIP's freed slot -- which a second ReleaseUeIpAddr call that mishandled the
	// already-zeroed sentinel, instead of leaving it a no-op, could have corrupted.
	if _, err = allocator.Allocate("imsi-208930100007499"); err != nil {
		t.Fatalf("allocate the pool's other address: %v", err)
	}
	reallocated, err := allocator.Allocate("imsi-208930100007500")
	if err != nil {
		t.Fatalf("re-allocate ueIP's freed slot: %v", err)
	}
	if !reallocated.Equal(ueIP) {
		t.Errorf("re-allocated address = %v, want the one ReleaseUeIpAddr freed (%v)", reallocated, ueIP)
	}
}
