// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package handler_test

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/handler"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The establishment response is what records which incarnation of the node holds the session:
// restoration reads that record to leave alone a session the restarted node already has. A record
// set by hand in a restoration test cannot show the handler writes it, so this drives the handler.
func TestAnEstablishmentRecordsTheIncarnationThatAcknowledgedIt(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: boolPointer(false)},
				EnableUpfAdapter: false,
			},
		}
	}

	const ip = "1.1.1.9"
	nodeID := context.NewNodeID(ip)
	held := time.Unix(1_790_000_000, 0)
	upf := context.NewUPF(nodeID, nil)
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: held}
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(*nodeID) })

	smContext := context.NewSMContext("imsi-100000000000009", 10)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })
	smContext.SMContextState = context.SmStatePfcpCreatePending
	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			10: &context.DataPath{
				IsDefaultPath: true,
				FirstDPNode:   &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
			},
		},
	}
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{
		FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
	})
	localSEID := smContext.PFCPContext[ip].LocalSEID

	seq := uint32(localSEID)
	pfcp_message.InsertPfcpTxn(seq, nodeID)
	handler.HandlePfcpSessionEstablishmentResponse(&udp.Message{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 8805},
		PfcpMessage: message.NewSessionEstablishmentResponse(0, 0, localSEID, seq, 0,
			ie.NewCause(ie.CauseRequestAccepted),
			ie.NewNodeID(ip, "", ""),
			ie.NewFSEID(0x77, net.ParseIP(ip), nil)),
	})

	got := smContext.PFCPContext[ip]
	if got.RemoteSEID != 0x77 {
		t.Fatalf("RemoteSEID = %#x, want 0x77: the response was not processed as an acknowledgement", got.RemoteSEID)
	}
	if !got.AcknowledgedAtRecovery.Equal(held) {
		t.Errorf("AcknowledgedAtRecovery = %v, want the node's held recovery timestamp %v: without it, "+
			"restoration re-establishes a session the restarted node already holds", got.AcknowledgedAtRecovery, held)
	}
}
