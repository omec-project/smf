// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// enableULCLSupport flips the package-level ULCLSupport flag HandlePfcpSessionEstablishmentResponse
// and HandlePfcpSessionModificationResponse both gate their PSA/ULCL continuation on, restoring it
// once the test is done so other tests in the binary are not affected by it.
func enableULCLSupport(t *testing.T) {
	t.Helper()
	self := context.SMF_Self()
	prev := self.ULCLSupport
	self.ULCLSupport = true
	t.Cleanup(func() { self.ULCLSupport = prev })
}

// TestHandlePfcpSessionEstablishmentResponseAbortsRejectedPSA covers a PSA/ULCL branch addition a
// UPF has rejected: left only logging the rejection, BPStatus stays AddingPSA forever (the only
// trigger for a fresh attempt checks for UnInitialized), the activating path's PDR/FAR/QER state
// stays applied, and its pending bookkeeping stays populated. The rejection must instead roll the
// attempt back: the activating path deactivated, BPManager.PendingUPF cleared, and BPStatus moved
// to a real failure state.
func TestHandlePfcpSessionEstablishmentResponseAbortsRejectedPSA(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: openapi.PtrBool(false)},
				EnableUpfAdapter: false,
			},
		}
	}
	enableULCLSupport(t)

	nodeID := context.NewNodeID("1.1.1.9")
	upf := &context.UPF{NodeID: *nodeID}
	smContext := context.NewSMContext("imsi-100000000000007", 10)
	// Not create-pending: this covers the branch addition path, which runs independently of the
	// initial create's own channel gate.
	smContext.SMContextState = context.SmStateActive

	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			10: &context.DataPath{
				IsDefaultPath: true,
				FirstDPNode:   &context.DataPathNode{UPF: upf},
			},
		},
	}
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{FirstDPNode: &context.DataPathNode{UPF: upf}})

	pfcpCtx := smContext.PFCPContext[nodeID.ResolveNodeIdToIp().String()]
	if pfcpCtx == nil || pfcpCtx.LocalSEID == 0 {
		t.Fatal("failed to allocate a local SEID for the test SMContext")
	}

	activatingNode := context.NewDataPathNode()
	activatingNode.UPF = upf
	activatingPath := &context.DataPath{
		FirstDPNode: activatingNode,
		Activated:   true,
	}
	smContext.BPManager = context.NewBPManager(smContext.Supi)
	smContext.BPManager.BPStatus = context.AddingPSA
	smContext.BPManager.ActivatingPath = activatingPath
	smContext.BPManager.PendingUPF[nodeID.ResolveNodeIdToIp().String()] = true

	seq := uint32(pfcpCtx.LocalSEID)
	pfcp_message.InsertPfcpTxn(seq, nodeID)

	rsp := message.NewSessionEstablishmentResponse(
		0, 0, pfcpCtx.LocalSEID, seq, 0,
		ie.NewCause(ie.CauseRequestRejected),
		ie.NewNodeID("1.1.1.9", "", ""),
		ie.NewRecoveryTimeStamp(time.Now()),
	)

	udpMessage := udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.9"), Port: 8809},
		PfcpMessage: rsp,
	}

	HandlePfcpSessionEstablishmentResponse(&udpMessage)

	if smContext.BPManager.BPStatus != context.InitializedFail {
		t.Errorf("BPStatus = %v, want InitializedFail", smContext.BPManager.BPStatus)
	}
	if !smContext.BPManager.PendingUPF.IsEmpty() {
		t.Errorf("BPManager.PendingUPF = %v, want empty after the rejection is rolled back", smContext.BPManager.PendingUPF)
	}
	if activatingPath.Activated {
		t.Error("activating path left Activated after a rejected branch addition")
	}
}

// TestHandlePfcpSessionModificationResponseAbortsRejectedPSA is the modification-response
// equivalent of TestHandlePfcpSessionEstablishmentResponseAbortsRejectedPSA: a rejected
// modification during AddingPSA must roll the attempt back the same way a rejected establishment
// does.
func TestHandlePfcpSessionModificationResponseAbortsRejectedPSA(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: openapi.PtrBool(false)},
				EnableUpfAdapter: false,
			},
		}
	}
	enableULCLSupport(t)

	nodeID := context.NewNodeID("1.1.1.10")
	upf := &context.UPF{NodeID: *nodeID}
	smContext := context.NewSMContext("imsi-100000000000008", 10)
	smContext.SMContextState = context.SmStateActive

	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			10: &context.DataPath{
				IsDefaultPath: true,
				FirstDPNode:   &context.DataPathNode{UPF: upf},
			},
		},
	}
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{FirstDPNode: &context.DataPathNode{UPF: upf}})

	pfcpCtx := smContext.PFCPContext[nodeID.ResolveNodeIdToIp().String()]
	if pfcpCtx == nil || pfcpCtx.LocalSEID == 0 {
		t.Fatal("failed to allocate a local SEID for the test SMContext")
	}

	activatingNode := context.NewDataPathNode()
	activatingNode.UPF = upf
	activatingPath := &context.DataPath{
		FirstDPNode: activatingNode,
		Activated:   true,
	}
	smContext.BPManager = context.NewBPManager(smContext.Supi)
	smContext.BPManager.BPStatus = context.AddingPSA
	smContext.BPManager.ActivatingPath = activatingPath
	smContext.BPManager.PendingUPF[nodeID.ResolveNodeIdToIp().String()] = true

	rsp := message.NewSessionModificationResponse(
		0, 0, pfcpCtx.LocalSEID, 1, 0,
		ie.NewCause(ie.CauseRequestRejected),
	)

	udpMessage := udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.10"), Port: 8809},
		PfcpMessage: rsp,
	}

	HandlePfcpSessionModificationResponse(&udpMessage)

	if smContext.BPManager.BPStatus != context.InitializedFail {
		t.Errorf("BPStatus = %v, want InitializedFail", smContext.BPManager.BPStatus)
	}
	if !smContext.BPManager.PendingUPF.IsEmpty() {
		t.Errorf("BPManager.PendingUPF = %v, want empty after the rejection is rolled back", smContext.BPManager.PendingUPF)
	}
	if activatingPath.Activated {
		t.Error("activating path left Activated after a rejected branch addition")
	}
}
