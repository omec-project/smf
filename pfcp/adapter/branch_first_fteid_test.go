// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// A UPF shared by two data paths receives one batched create and may answer with the branch path's
// F-TEID first. Every uplink tunnel must take the F-TEID of its own PDR: the default tunnel's TEID
// is the one advertised to the RAN.
func TestEstablishmentResponseUpdatesEveryUplinkTunnelBranchFirst(t *testing.T) {
	off := false
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: &off},
				EnableUpfAdapter: false,
			},
		}
	}

	const ip = "1.1.1.52"
	nodeID := context.NewNodeID(ip)
	context.NewUPF(nodeID, nil)
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(*nodeID) })
	smContext := context.NewSMContext("imsi-100000000000052", 10)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })
	smContext.SMContextState = context.SmStatePfcpCreatePending
	defaultNode := &context.DataPathNode{
		UPF:          &context.UPF{NodeID: *nodeID},
		UpLinkTunnel: &context.GTPTunnel{PDR: map[string]*context.PDR{"default": {PDRID: 1}}},
	}
	branchNode := &context.DataPathNode{
		UPF:          &context.UPF{NodeID: *nodeID},
		UpLinkTunnel: &context.GTPTunnel{PDR: map[string]*context.PDR{"branch": {PDRID: 2}}},
	}
	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			10: &context.DataPath{IsDefaultPath: true, FirstDPNode: defaultNode},
			11: &context.DataPath{FirstDPNode: branchNode},
		},
	}
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{
		FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
	})
	localSEID := smContext.PFCPContext[ip].LocalSEID
	seq := uint32(localSEID)
	adapter.InsertPfcpTxn(seq, nodeID)

	// The shared UPF answers the branch path's PDR before the default path's.
	rsp := message.NewSessionEstablishmentResponse(0, 0, localSEID, seq, 0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID(ip, "", ""),
		ie.NewFSEID(0xABCD, net.ParseIP(ip), nil),
		ie.NewCreatedPDR(ie.NewPDRID(2), ie.NewFTEID(0x01, 0x222, net.ParseIP("10.0.0.2"), nil, 0)),
		ie.NewCreatedPDR(ie.NewPDRID(1), ie.NewFTEID(0x01, 0x111, net.ParseIP("10.0.0.1"), nil, 0)),
	)
	udpMsg := &udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP(ip), Port: 8805},
		PfcpMessage: rsp,
	}
	if err := adapter.HandlePfcpSessionEstablishmentResponse(udpMsg); err != nil {
		t.Fatalf("the establishment response was refused: %v", err)
	}

	if got := defaultNode.UpLinkTunnel.TEID; got != 0x111 {
		t.Errorf("default tunnel TEID = %#x, want 0x111 (it would be advertised to the RAN)", got)
	}
	if got := branchNode.UpLinkTunnel.TEID; got != 0x222 {
		t.Errorf("branch tunnel TEID = %#x, want 0x222", got)
	}
	// The RAN is told the default tunnel's TEID, so it must be paired with that tunnel's address,
	// not the branch entry's that came first.
	upf := context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil || len(upf.N3Interfaces) != 1 || len(upf.N3Interfaces[0].IPv4EndPointAddresses) != 1 {
		t.Fatalf("N3Interfaces not set to a single address: %+v", upf)
	}
	if got := upf.N3Interfaces[0].IPv4EndPointAddresses[0]; !got.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("advertised N3 address = %v, want 10.0.0.1 (the default tunnel's)", got)
	}
}
