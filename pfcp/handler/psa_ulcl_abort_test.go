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

// TestAbortAddingPSAKeepsSharedSessionButDeletesOrphanedTailSession covers the compensation split
// abortAddingPSA must make between the two kinds of node a PSA/ULCL branch addition can touch: the
// ULCL node is shared with the already-active path (same PFCP session, only a branch PDR/FAR added
// to it), while a node past it exists only for this attempt (its own, brand-new session). A
// rejection elsewhere in the attempt must remove the accepted branch rule from the shared node's
// existing session without touching that session itself, and must delete the tail node's session
// outright since this attempt is the only thing that ever referenced it.
func TestAbortAddingPSAKeepsSharedSessionButDeletesOrphanedTailSession(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: openapi.PtrBool(false)},
				EnableUpfAdapter: false,
			},
		}
	}

	ulclNodeID := context.NewNodeID("1.1.1.20")
	ulclUPF := &context.UPF{NodeID: *ulclNodeID}
	tailNodeID := context.NewNodeID("1.1.1.21")
	tailUPF := &context.UPF{NodeID: *tailNodeID}

	smContext := context.NewSMContext("imsi-100000000000009", 10)
	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			10: &context.DataPath{
				IsDefaultPath: true,
				FirstDPNode:   &context.DataPathNode{UPF: ulclUPF},
			},
		},
	}

	// The ULCL node already has a PFCP session from the already-active path.
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{FirstDPNode: &context.DataPathNode{UPF: ulclUPF}})
	ulclIP := ulclNodeID.ResolveNodeIdToIp().String()
	smContext.PFCPContext[ulclIP].RemoteSEID = 0xAAAA

	// The tail node's own session, established only for this attempt.
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{FirstDPNode: &context.DataPathNode{UPF: tailUPF}})
	tailIP := tailNodeID.ResolveNodeIdToIp().String()
	smContext.PFCPContext[tailIP].RemoteSEID = 0xBBBB

	ulclNode := context.NewDataPathNode()
	ulclNode.UPF = ulclUPF
	ulclNode.UpLinkTunnel.PDR["default"] = &context.PDR{
		PDRID: 1,
		FAR:   &context.FAR{FARID: 1},
		QER:   []*context.QER{{QERID: 1}},
	}
	tailNode := context.NewDataPathNode()
	tailNode.UPF = tailUPF
	ulclNode.AddNext(tailNode)
	tailNode.AddPrev(ulclNode)

	activatingPath := &context.DataPath{FirstDPNode: ulclNode, Activated: true}

	smContext.BPManager = context.NewBPManager(smContext.Supi)
	smContext.BPManager.BPStatus = context.AddingPSA
	smContext.BPManager.ActivatingPath = activatingPath
	smContext.BPManager.ULCL = ulclUPF
	// The ULCL modification was already accepted before the (unrelated) rejection that triggers
	// this abort.
	smContext.BPManager.AcceptedModificationUPFs[ulclIP] = true

	abortAddingPSA(smContext)

	if _, stillShared := smContext.PFCPContext[ulclIP]; !stillShared {
		t.Error("abortAddingPSA deleted the ULCL node's pre-existing PFCP session; it is shared with the active path and must survive")
	}
	if _, pending := smContext.BPManager.AcceptedModificationUPFs[ulclIP]; pending {
		t.Error("AcceptedModificationUPFs entry for the ULCL node was not consumed")
	}
	if _, stillTail := smContext.PFCPContext[tailIP]; stillTail {
		t.Error("abortAddingPSA left the orphaned tail session's PFCPContext entry behind")
	}
	if smContext.BPManager.BPStatus != context.InitializedFail {
		t.Errorf("BPStatus = %v, want InitializedFail", smContext.BPManager.BPStatus)
	}
	if activatingPath.Activated {
		t.Error("activating path left Activated after a rejected branch addition")
	}
}
