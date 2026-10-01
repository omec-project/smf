// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// A data path through several user planes establishes a session on each, and in adapter mode each
// answer is dispatched inline, on the goroutine that reads the session's channel only once they
// have all been sent. The channel holds one verdict. So the second answer found it full, and a
// blocking write parked that goroutine on its own channel: two user planes that both accepted
// wedged the session for good. This is the second answer arriving to a full channel; it has to
// come back.
func TestASecondEstablishmentAnswerDoesNotWedgeTheSession(t *testing.T) {
	prev := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prev })

	disabled := false
	factory.SmfConfig = factory.Config{Configuration: &factory.Configuration{
		KafkaInfo:        factory.KafkaInfo{EnableKafka: &disabled},
		EnableUpfAdapter: true,
	}}

	upfIP := "10.0.0.21"
	upf := context.NewUPF(context.NewNodeID(upfIP), nil)

	node := context.NewDataPathNode()
	node.UPF = upf

	path := context.NewDataPath()
	path.FirstDPNode = node
	path.IsDefaultPath = true

	smContext := context.NewSMContext("imsi-208930000000046", 7)
	smContext.Tunnel = context.NewUPTunnel()
	smContext.Tunnel.AddDataPath(path)
	smContext.AllocateLocalSEIDForDataPath(path)
	smContext.SMContextState = context.SmStatePfcpCreatePending

	seid := smContext.PFCPContext[upfIP].LocalSEID

	// The first user plane's verdict, already waiting to be read.
	smContext.SBIPFCPCommunicationChan <- context.SessionEstablishSuccess

	const seq = 4242
	InsertPfcpTxn(seq, context.NewNodeID(upfIP))

	rsp := message.NewSessionEstablishmentResponse(0, 0, seid, seq, 0,
		ie.NewNodeID(upfIP, "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(99, net.ParseIP(upfIP), nil))

	done := make(chan struct{})

	go func() {
		defer close(done)

		if err := HandlePfcpSessionEstablishmentResponse(&udp.Message{PfcpMessage: rsp}); err != nil {
			t.Errorf("a usable second answer was reported as unusable: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the second establishment answer is still blocked on the session's channel; in adapter mode that is the goroutine that would read it")
	}

	if len(smContext.SBIPFCPCommunicationChan) != 1 {
		t.Errorf("channel holds %d verdicts, want the one the create procedure will read", len(smContext.SBIPFCPCommunicationChan))
	}
}

// TestHandlePfcpSessionEstablishmentResponseAcceptedWithNoSeidAdapter covers a response that
// carries CauseRequestAccepted but no UP F-SEID: it must be treated as a rejection
// (SessionEstablishFailed) and none of RemoteSEID, the UE address, the TEID or the N3 interface --
// all of which the response also carries, as a real UPF reply would -- may be applied, since a
// later modification or deletion would have nothing but a stale RemoteSEID to address the session
// with at the UPF.
func TestHandlePfcpSessionEstablishmentResponseAcceptedWithNoSeidAdapter(t *testing.T) {
	prev := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prev })

	disabled := false
	factory.SmfConfig = factory.Config{Configuration: &factory.Configuration{
		KafkaInfo:        factory.KafkaInfo{EnableKafka: &disabled},
		EnableUpfAdapter: true,
	}}

	upfIP := "10.0.0.22"
	nodeID := context.NewNodeID(upfIP)
	upf := context.NewUPF(nodeID, nil)
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(*nodeID) })

	node := context.NewDataPathNode()
	node.UPF = upf
	node.UpLinkTunnel.TEID = 111

	path := context.NewDataPath()
	path.FirstDPNode = node
	path.IsDefaultPath = true

	smContext := context.NewSMContext("imsi-208930000000047", 7)
	smContext.SMContextState = context.SmStatePfcpCreatePending
	smContext.PDUAddress = &context.UeIpAddr{Ip: net.ParseIP("10.1.0.6")}
	smContext.Tunnel = context.NewUPTunnel()
	smContext.Tunnel.AddDataPath(path)
	smContext.AllocateLocalSEIDForDataPath(path)

	pfcpCtx := smContext.PFCPContext[upfIP]
	if pfcpCtx == nil || pfcpCtx.LocalSEID == 0 {
		t.Fatal("failed to allocate a local SEID for the test SMContext")
	}
	pfcpCtx.RemoteSEID = 999

	const seq = 4343
	InsertPfcpTxn(seq, nodeID)

	// Accepted, with a CreatedPDR carrying a UE address and F-TEID as a real UPF reply would --
	// but no F-SEID IE, the condition this handles.
	rsp := message.NewSessionEstablishmentResponse(0, 0, pfcpCtx.LocalSEID, seq, 0,
		ie.NewNodeID(upfIP, "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(time.Now()),
		ie.NewCreatedPDR(
			ie.NewFTEID(0, 4321, net.ParseIP(upfIP), nil, 0),
			ie.NewUEIPAddress(2, "9.9.9.9", "", 0, 0),
		),
	)

	if err := HandlePfcpSessionEstablishmentResponse(&udp.Message{PfcpMessage: rsp}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case status := <-smContext.SBIPFCPCommunicationChan:
		if status != context.SessionEstablishFailed {
			t.Errorf("expected SessionEstablishFailed, got %v", status)
		}
	default:
		t.Error("expected a send to SBIPFCPCommunicationChan for an accepted response with no UP F-SEID")
	}

	if pfcpCtx.RemoteSEID != 999 {
		t.Errorf("RemoteSEID applied from a response that must be treated as rejected: got %d, want 999", pfcpCtx.RemoteSEID)
	}
	if gotTEID := node.UpLinkTunnel.TEID; gotTEID != 111 {
		t.Errorf("TEID applied from a response that must be treated as rejected: got %d, want 111", gotTEID)
	}
	if len(upf.N3Interfaces) != 0 {
		t.Errorf("N3Interfaces applied from a response that must be treated as rejected: got %v, want none", upf.N3Interfaces)
	}
	if !smContext.PDUAddress.Ip.Equal(net.ParseIP("10.1.0.6")) || smContext.PDUAddress.UpfProvided {
		t.Errorf("PDUAddress applied from a response that must be treated as rejected: got %+v", smContext.PDUAddress)
	}
}
