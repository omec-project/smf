// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/lisequence"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// modificationResponse builds an accepted Session Modification Response carrying the
// given sequence number, addressed to seid.

// liTestUPFNode is the UPF the LI modifications in these tests are recorded against.
const liTestUPFNode = "1.1.1.1"

func modificationResponse(seq uint32, seid uint64) *udp.Message {
	return &udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 8805},
		PfcpMessage: message.NewSessionModificationResponse(0, 0, seid, seq, 0, ie.NewCause(ie.CauseRequestAccepted)),
	}
}

func modifyingSession(t *testing.T) (*context.SMContext, uint64) {
	t.Helper()

	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	nodeID := context.NewNodeID("1.1.1.1")
	upfIP := nodeID.ResolveNodeIdToIp().String()
	smContext := context.NewSMContext("imsi-123456789012399", 12)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })

	datapath := &context.DataPath{FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}}}
	smContext.AllocateLocalSEIDForDataPath(datapath)
	seid := smContext.PFCPContext[upfIP].LocalSEID

	// The subscriber's own modification is outstanding to this UPF.
	smContext.ChangeState(context.SmStatePfcpModify)
	smContext.PendingUPF = context.PendingUPF{upfIP: true}

	return smContext, seid
}

// TestLIModificationResponseDoesNotCompleteTheSessionsOwnProcedureInAdapterMode is the
// native handler's guard, asserted on the path taken when enableUPFAdapter is set.
//
// The two handlers do the same correlation and only one of them recognised an
// LI-originated answer. In adapter mode sendSessionModification routes the response
// here, so an LI modification's answer landing during the subscriber's own
// modification cleared the pending entry that procedure was waiting on and completed
// it — interception-driven signalling mistaken for the session's own, which is the one
// thing interception may never do. Nothing about the deployment mode changes that;
// only which function saw the message.
func TestLIModificationResponseDoesNotCompleteTheSessionsOwnProcedureInAdapterMode(t *testing.T) {
	smContext, seid := modifyingSession(t)

	// An LI modification goes out while the subscriber's is outstanding: a warrant
	// changed, which happens on the provisioning plane's schedule and not the session's.
	const liSeq = uint32(5252)
	// The request the modification carried, as the send site records it: the answer is
	// correlated with what was asked, because the send clears the FAR state that would
	// otherwise say.
	lisequence.Mark(liSeq, lisequence.Request{SEID: seid, NodeID: liTestUPFNode, Duplicating: true})

	if err := adapter.HandlePfcpSessionModificationResponse(modificationResponse(liSeq, seid)); err != nil {
		t.Fatalf("the response was refused: %v", err)
	}

	if smContext.PendingUPF.IsEmpty() {
		t.Error("the LI modification's answer cleared the UPF the subscriber's own " +
			"modification was waiting on — that procedure would now complete on an " +
			"answer that was never sent to it")
	}
	select {
	case <-smContext.SBIPFCPCommunicationChan:
		t.Error("the LI modification's answer completed the session's own procedure")
	default:
	}
}

// TestOrdinaryModificationResponseStillCompletesInAdapterMode is the other side of the
// guard: it must recognise only LI-originated sequences, or in adapter mode every
// ordinary modification stops being answered and every session update hangs.
func TestOrdinaryModificationResponseStillCompletesInAdapterMode(t *testing.T) {
	smContext, seid := modifyingSession(t)

	if err := adapter.HandlePfcpSessionModificationResponse(modificationResponse(7373, seid)); err != nil {
		t.Fatalf("the response was refused: %v", err)
	}

	if !smContext.PendingUPF.IsEmpty() {
		t.Error("an ordinary modification's answer did not clear the UPF it came from")
	}
	select {
	case <-smContext.SBIPFCPCommunicationChan:
	default:
		t.Error("an ordinary modification's answer did not complete the session's procedure")
	}
}

// TestLIAnswerSurvivesAReleasedSessionInAdapterMode is the native handler's
// TestLIAnswerSurvivesAReleasedSession on the adapter path, which is the one a deployment
// with enableUPFAdapter takes. A modification this element sent for interception is
// answered on the sequence number alone, and it must still be answered when the session it
// referred to has since been released: discarding it at the context lookup leaves a refused
// activation never retried, or a refused withdrawal believed to have succeeded.
func TestLIAnswerSurvivesAReleasedSessionInAdapterMode(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	const seq uint32 = 5253
	req := lisequence.Request{SEID: 0xDEADBEEF, NodeID: "5.5.5.5", Duplicating: true}
	lisequence.Mark(seq, req)

	var gotReq lisequence.Request
	var called bool

	orig := adapter.LIModificationAnswered
	adapter.LIModificationAnswered = func(r lisequence.Request, _ uint8, _ bool) {
		gotReq, called = r, true
	}
	t.Cleanup(func() { adapter.LIModificationAnswered = orig })

	// No SM context is registered for this SEID, so the lookup yields nil.
	if err := adapter.HandlePfcpSessionModificationResponse(modificationResponse(seq, 0xDEADBEEF)); err != nil {
		t.Fatalf("the response was refused: %v", err)
	}

	if !called {
		t.Fatal("the interception answer was not made for a released session; the nil guard " +
			"is placed ahead of the interception block")
	}
	if gotReq.NodeID != req.NodeID || gotReq.Duplicating != req.Duplicating {
		t.Errorf("answered with the wrong request: got %+v, want %+v", gotReq, req)
	}
}

// An answer to an LI modification whose Cause cannot be read says nothing about whether the
// datapath applied it, and is handed on as unanswered — which the LI subsystem retries —
// rather than discarded with the response, as an ordinary response without a Cause is.
func TestAnLIAnswerWithoutACauseIsHandedOnAsUnansweredInAdapterMode(t *testing.T) {
	_, seid := modifyingSession(t)

	const liSeq = uint32(5254)
	lisequence.Mark(liSeq, lisequence.Request{SEID: seid, NodeID: liTestUPFNode, Duplicating: true})

	var (
		calls    int
		answered bool
	)
	orig := adapter.LIModificationAnswered
	adapter.LIModificationAnswered = func(_ lisequence.Request, _ uint8, a bool) {
		calls++
		answered = a
	}
	t.Cleanup(func() { adapter.LIModificationAnswered = orig })

	noCause := &udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 8805},
		PfcpMessage: message.NewSessionModificationResponse(0, 0, seid, liSeq, 0),
	}
	if err := adapter.HandlePfcpSessionModificationResponse(noCause); err != nil {
		t.Fatalf("the LI answer was refused: %v", err)
	}

	if calls != 1 || answered {
		t.Errorf("LI answer hook called %d times with answered=%v, want once with false: a "+
			"duplication change the datapath may not have applied is then never retried", calls, answered)
	}
}

// TestARepeatedLIModificationResponseIsStillLIInAdapterMode is the native handler's
// TestARepeatedLIModificationResponseIsStillLI on the adapter path. A UPF can answer both an LI
// modification and the SMF's retransmission of it; the second answer must still be recognised
// as LI, kept out of the subscriber's concurrent procedure, and not read a second time.
func TestARepeatedLIModificationResponseIsStillLIInAdapterMode(t *testing.T) {
	smContext, seid := modifyingSession(t)
	// Buffered, so a wrongly completed procedure is observed rather than blocking the handler.
	smContext.SBIPFCPCommunicationChan = make(chan context.PFCPSessionResponseStatus, 1)

	answers := 0
	orig := adapter.LIModificationAnswered
	adapter.LIModificationAnswered = func(lisequence.Request, uint8, bool) { answers++ }
	t.Cleanup(func() { adapter.LIModificationAnswered = orig })

	const liSeq = uint32(5255)
	lisequence.Mark(liSeq, lisequence.Request{SEID: seid, NodeID: liTestUPFNode, Duplicating: true})

	for range 2 {
		if err := adapter.HandlePfcpSessionModificationResponse(modificationResponse(liSeq, seid)); err != nil {
			t.Fatalf("the response was refused: %v", err)
		}
	}

	if answers != 1 {
		t.Errorf("the LI answer was read %d times, want once", answers)
	}
	if smContext.PendingUPF.IsEmpty() {
		t.Error("the repeated LI answer cleared the UPF the subscriber's own modification " +
			"was waiting on")
	}
	select {
	case got := <-smContext.SBIPFCPCommunicationChan:
		t.Errorf("the repeated LI answer completed the session's own procedure with %v", got)
	default:
	}
}
