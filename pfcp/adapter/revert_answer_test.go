// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// A revert's answer reaches the revert even if the session is no longer in SmStatePfcpModify. A
// NAS or NGAP handler starts the revert from inside a transaction, and that transaction's state
// machine sets Active after the handler returns -- possibly after the revert has moved the session
// to SmStatePfcpModify for its exchange. Dropped, the answer left the revert waiting for good, and
// every later transaction for the session waiting on it.
func TestARevertsAnswerIsDeliveredWhateverTheState(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig = factory.Config{Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &off}}}
	}

	const ip = "1.1.1.21"
	nodeID := context.NewNodeID(ip)
	smContext := context.NewSMContext("imsi-100000000000021", 11)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}}})
	localSEID := smContext.PFCPContext[ip].LocalSEID

	smContext.SMContextState = context.SmStateActive
	smContext.ResetPendingUPF(context.PendingUPF{ip: true})
	smContext.RevertOwed.Store(true)

	if err := adapter.HandlePfcpSessionModificationResponse(&udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP(ip), Port: 8805},
		PfcpMessage: message.NewSessionModificationResponse(0, 0, localSEID, 1, 0, ie.NewCause(ie.CauseRequestAccepted)),
	}); err != nil {
		t.Fatalf("the response was refused: %v", err)
	}

	select {
	case verdict := <-smContext.SBIPFCPCommunicationChan:
		if verdict != context.SessionUpdateSuccess {
			t.Errorf("verdict = %v, want SessionUpdateSuccess", verdict)
		}
	case <-time.After(time.Second):
		t.Fatal("the revert's answer was dropped because the session was not in SmStatePfcpModify")
	}
}
