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

		HandlePfcpSessionEstablishmentResponse(&udp.Message{PfcpMessage: rsp})
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
