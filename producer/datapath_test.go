// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
)

// disableUpfAdapter points SendPFCPRules at the native UDP send path instead of the adapter's
// HTTP one, so these tests exercise PendingUPF bookkeeping without depending on an adapter being
// reachable.
func disableUpfAdapter(t *testing.T) {
	t.Helper()
	prev := factory.SmfConfig
	disabled := false
	factory.SmfConfig = factory.Config{Configuration: &factory.Configuration{
		KafkaInfo:        factory.KafkaInfo{EnableKafka: &disabled},
		EnableUpfAdapter: false,
	}}
	t.Cleanup(func() { factory.SmfConfig = prev })
}

// TestSendPFCPRulesDoesNotClobberPendingUPFDuringOverlappingModification covers restoration
// reissuing rules (SendPFCPRules) while an unrelated, awaited modification is in flight for the
// same session (SmStatePfcpModify, documented as a supported overlap in
// pfcp/message/send.go:421-424). PendingUPF is shared between the create procedure and that
// modification; replacing it unconditionally here would discard the modification's own
// bookkeeping and leave it unable to tell when its own responses are all in.
func TestSendPFCPRulesDoesNotClobberPendingUPFDuringOverlappingModification(t *testing.T) {
	disableUpfAdapter(t)

	modifyingUPFIP := "10.0.1.1"
	modifyingNodeID := smf_context.NewNodeID(modifyingUPFIP)

	resettingUPFIP := "10.0.1.2"
	resettingNodeID := smf_context.NewNodeID(resettingUPFIP)

	modifyingNode := smf_context.NewDataPathNode()
	modifyingNode.UPF = &smf_context.UPF{NodeID: *modifyingNodeID}

	resettingNode := smf_context.NewDataPathNode()
	resettingNode.UPF = &smf_context.UPF{NodeID: *resettingNodeID}
	modifyingNode.AddNext(resettingNode)

	path := smf_context.NewDataPath()
	path.FirstDPNode = modifyingNode
	path.Activated = true
	path.IsDefaultPath = true

	smContext := smf_context.NewSMContext("imsi-208930000000050", 7)
	smContext.Tunnel = smf_context.NewUPTunnel()
	smContext.Tunnel.AddDataPath(path)
	smContext.AllocateLocalSEIDForDataPath(path)

	// The modifying UPF already holds a session (so SendPFCPRules will issue it a modification,
	// not an establishment); the resetting one does not (e.g. restoration cleared its RemoteSEID),
	// so SendPFCPRules will (re)issue it an establishment request.
	smContext.PFCPContext[modifyingUPFIP].RemoteSEID = 0xA1A1
	smContext.PFCPContext[resettingUPFIP].RemoteSEID = 0

	// An unrelated modification is in flight and awaiting exactly this one response.
	smContext.SMContextState = smf_context.SmStatePfcpModify
	smContext.PendingUPF = smf_context.PendingUPF{modifyingUPFIP: true}

	SendPFCPRules(smContext)

	if _, stillPending := smContext.PendingUPF[modifyingUPFIP]; !stillPending {
		t.Errorf("SendPFCPRules discarded the in-flight modification's PendingUPF entry for UPF[%s]", modifyingUPFIP)
	}
}

// TestSendPFCPRulesFoldsSynchronousEstablishmentFailuresIntoTheBatch covers the create-pending path
// when the native sends fail synchronously (no PFCP server is listening). Every UPF's failure is
// folded into PendingUPF rather than answered immediately, so the batch drains to empty and a single
// aggregate SessionEstablishFailed verdict is queued only once the whole batch has drained. A
// synchronous failure on one UPF of a multi-UPF create must not answer -- and roll back -- the create
// while the other establishment requests are still in flight; that batch is what SendPFCPRules
// populates completely, with every UPF being established, before sending the first request.
func TestSendPFCPRulesFoldsSynchronousEstablishmentFailuresIntoTheBatch(t *testing.T) {
	disableUpfAdapter(t)

	firstUPFIP := "10.0.2.1"
	secondUPFIP := "10.0.2.2"

	firstNode := smf_context.NewDataPathNode()
	firstNode.UPF = &smf_context.UPF{NodeID: *smf_context.NewNodeID(firstUPFIP)}

	secondNode := smf_context.NewDataPathNode()
	secondNode.UPF = &smf_context.UPF{NodeID: *smf_context.NewNodeID(secondUPFIP)}
	firstNode.AddNext(secondNode)

	path := smf_context.NewDataPath()
	path.FirstDPNode = firstNode
	path.Activated = true
	path.IsDefaultPath = true

	smContext := smf_context.NewSMContext("imsi-208930000000051", 7)
	smContext.Tunnel = smf_context.NewUPTunnel()
	smContext.Tunnel.AddDataPath(path)
	smContext.AllocateLocalSEIDForDataPath(path)
	smContext.SMContextState = smf_context.SmStatePfcpCreatePending

	SendPFCPRules(smContext)

	// Both UPFs had been tracked (SendPFCPRules registers the complete set before sending), and both
	// synchronous failures were folded back out, so the batch is now empty.
	if !smContext.PendingUPFIsEmpty() {
		t.Errorf("synchronous establishment failures were not folded into the batch; PendingUPF still holds %v", smContext.PendingUPF)
	}

	// The aggregate verdict is queued only once the batch drained -- never immediately on the first
	// UPF's failure, which would roll the create back with the second request still outstanding.
	select {
	case verdict := <-smContext.SBIPFCPCommunicationChan:
		if verdict != smf_context.SessionEstablishFailed {
			t.Errorf("verdict = %v, want SessionEstablishFailed once the batch drained", verdict)
		}
	default:
		t.Error("no aggregate verdict was queued after every UPF's establishment failed")
	}

	// And exactly one: the aggregate is emitted once per batch, not once per UPF.
	select {
	case verdict := <-smContext.SBIPFCPCommunicationChan:
		t.Errorf("a second verdict %v was queued; the aggregate must be emitted once, when the batch empties", verdict)
	default:
	}
}
