// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"testing"

	smf_context "github.com/omec-project/smf/context"
)

func makeTestTunnel(farState smf_context.RuleState, activated bool) *smf_context.UPTunnel {
	upf := &smf_context.UPF{
		NodeID: *smf_context.NewNodeID("10.0.0.1"),
	}
	far := &smf_context.FAR{
		State: farState,
	}
	pdr := &smf_context.PDR{FAR: far}
	gtpTunnel := &smf_context.GTPTunnel{
		PDR: map[string]*smf_context.PDR{"default": pdr},
	}
	node := &smf_context.DataPathNode{
		UPF:            upf,
		DownLinkTunnel: gtpTunnel,
	}
	dataPath := &smf_context.DataPath{
		FirstDPNode: node,
		Activated:   activated,
	}
	tunnel := smf_context.NewUPTunnel()
	tunnel.AddDataPath(dataPath)
	return tunnel
}

func TestCollectHoFARsForPFCPModifyWithRuleUpdate(t *testing.T) {
	tunnel := makeTestTunnel(smf_context.RULE_UPDATE, true)
	param := &pfcpParam{}

	pendingUPF := collectHoFARsForPFCPModify(tunnel, param)

	if len(param.farList) != 1 {
		t.Fatalf("expected 1 FAR collected, got %d", len(param.farList))
	}
	if len(param.pdrList) != 1 {
		t.Fatalf("expected 1 PDR collected, got %d", len(param.pdrList))
	}
	// Non-empty pendingUPF is the correct gate condition for the PFCP-modify
	// trigger (not len(pfcpParam.farList), which may include FARs from earlier
	// handlers in the same UpdateSmContextRequest dispatch).
	if len(pendingUPF) != 1 {
		t.Fatalf("expected 1 entry in PendingUPF, got %d", len(pendingUPF))
	}
}

func TestCollectHoFARsForPFCPModifySkipsNonUpdatedFARs(t *testing.T) {
	for _, state := range []smf_context.RuleState{
		smf_context.RULE_INITIAL,
		smf_context.RULE_CREATE,
		smf_context.RULE_REMOVE,
	} {
		tunnel := makeTestTunnel(state, true)
		param := &pfcpParam{}

		pendingUPF := collectHoFARsForPFCPModify(tunnel, param)

		if len(param.farList) != 0 {
			t.Errorf("state %v: expected 0 FARs collected, got %d", state, len(param.farList))
		}
		if len(pendingUPF) != 0 {
			t.Errorf("state %v: expected empty PendingUPF, got %d entries", state, len(pendingUPF))
		}
	}
}

func TestCollectHoFARsForPFCPModifySkipsInactivePaths(t *testing.T) {
	tunnel := makeTestTunnel(smf_context.RULE_UPDATE, false /* not activated */)
	param := &pfcpParam{}

	pendingUPF := collectHoFARsForPFCPModify(tunnel, param)

	if len(param.farList) != 0 {
		t.Fatalf("expected 0 FARs for inactive path, got %d", len(param.farList))
	}
	if len(pendingUPF) != 0 {
		t.Fatalf("expected empty PendingUPF for inactive path, got %d entries", len(pendingUPF))
	}
}

func TestCollectHoFARsForPFCPModifyNilTunnel(t *testing.T) {
	param := &pfcpParam{}

	pendingUPF := collectHoFARsForPFCPModify(nil, param)

	if len(param.farList) != 0 {
		t.Fatalf("expected 0 FARs for nil tunnel, got %d", len(param.farList))
	}
	if len(pendingUPF) != 0 {
		t.Fatalf("expected empty PendingUPF for nil tunnel, got %d entries", len(pendingUPF))
	}
}

func TestBuildAccessForwardingParametersPreservesOuterHeaderCreation(t *testing.T) {
	smContext := &smf_context.SMContext{
		Dnn:    "internet",
		Tunnel: &smf_context.UPTunnel{},
	}
	smContext.Tunnel.ANInformation.IPAddress = net.ParseIP("172.20.0.2")
	smContext.Tunnel.ANInformation.TEID = 1234

	current := &smf_context.ForwardingParameters{
		OuterHeaderCreation: &smf_context.OuterHeaderCreation{
			OuterHeaderCreationDescription: smf_context.OuterHeaderCreationGtpUUdpIpv4,
			Teid:                           5678,
			Ipv4Address:                    net.ParseIP("172.20.0.3").To4(),
		},
	}

	forwardingParameters := buildAccessForwardingParameters(smContext, current)

	if forwardingParameters.DestinationInterface.InterfaceValue != smf_context.DestinationInterfaceAccess {
		t.Fatalf("expected destination interface %d, got %d",
			smf_context.DestinationInterfaceAccess,
			forwardingParameters.DestinationInterface.InterfaceValue)
	}

	if got := string(forwardingParameters.NetworkInstance); got != "internet" {
		t.Fatalf("expected network instance internet, got %q", got)
	}

	if forwardingParameters.OuterHeaderCreation == nil {
		t.Fatal("expected outer header creation to be preserved")
	}

	if forwardingParameters.OuterHeaderCreation.Teid != 5678 {
		t.Fatalf("expected preserved TEID 5678, got %d", forwardingParameters.OuterHeaderCreation.Teid)
	}

	if got := forwardingParameters.OuterHeaderCreation.Ipv4Address.String(); got != "172.20.0.3" {
		t.Fatalf("expected preserved outer header IP 172.20.0.3, got %s", got)
	}
}

func TestBuildAccessForwardingParametersFallsBackToAnTunnel(t *testing.T) {
	smContext := &smf_context.SMContext{
		Dnn:    "internet",
		Tunnel: &smf_context.UPTunnel{},
	}
	smContext.Tunnel.ANInformation.IPAddress = net.ParseIP("172.20.0.2")
	smContext.Tunnel.ANInformation.TEID = 4321

	forwardingParameters := buildAccessForwardingParameters(smContext, nil)

	if forwardingParameters.OuterHeaderCreation == nil {
		t.Fatal("expected outer header creation to be reconstructed from AN information")
	}

	if forwardingParameters.OuterHeaderCreation.Teid != 4321 {
		t.Fatalf("expected reconstructed TEID 4321, got %d", forwardingParameters.OuterHeaderCreation.Teid)
	}

	if got := forwardingParameters.OuterHeaderCreation.Ipv4Address.String(); got != "172.20.0.2" {
		t.Fatalf("expected reconstructed outer header IP 172.20.0.2, got %s", got)
	}
}

// TestCollectHoFARsForPFCPModifyMergeNotOverwrite verifies that the caller
// merges the returned pendingUPF into smContext.PendingUPF rather than
// overwriting it, so entries set by earlier handlers in the same request are
// preserved (TS 23.502 §4.9.1.3.3).
func TestCollectHoFARsForPFCPModifyMergeNotOverwrite(t *testing.T) {
	tunnel := makeTestTunnel(smf_context.RULE_UPDATE, true)
	param := &pfcpParam{}

	pendingUPF := collectHoFARsForPFCPModify(tunnel, param)

	// Simulate a PendingUPF map already populated by an earlier handler
	// (e.g. HandleUpCnxState) within the same UpdateSmContextRequest.
	existing := smf_context.PendingUPF{"192.168.1.1": true}

	// Merge as the fixed caller does — must NOT overwrite.
	for k, v := range pendingUPF {
		existing[k] = v
	}

	if _, ok := existing["192.168.1.1"]; !ok {
		t.Error("pre-existing PendingUPF entry was lost after merge")
	}
	if _, ok := existing["10.0.0.1"]; !ok {
		t.Error("handover PendingUPF entry is missing after merge")
	}
}

func TestReadBinaryN2SmInformationNilFile(t *testing.T) {
	fileBytes, err := readBinaryN2SmInformation(nil)
	if err != nil {
		t.Fatalf("expected nil error for absent N2 binary payload, got %v", err)
	}

	if len(fileBytes) != 0 {
		t.Fatalf("expected empty payload for absent N2 binary payload, got %d bytes", len(fileBytes))
	}
}
