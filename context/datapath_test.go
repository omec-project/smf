// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
)

const testDnn = "internet"

func TestActivateUpLinkPdr(t *testing.T) {
	smContext := &context.SMContext{
		PDUAddress: &context.UeIpAddr{
			Ip: net.IPv4(192, 168, 1, 1),
		},
		Dnn: testDnn,
	}

	defQER := &context.QER{}

	dpNode := &context.DataPathNode{
		UPF: &context.UPF{},
		UpLinkTunnel: &context.GTPTunnel{
			PDR: map[string]*context.PDR{
				"default": {
					Precedence: 0,
					FAR:        &context.FAR{},
				},
			},
		},
	}

	err := dpNode.ActivateUpLinkPdr(smContext, defQER, 10)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	pdr := dpNode.UpLinkTunnel.PDR["default"]
	if pdr == nil {
		t.Fatalf("expected pdr to be not nil")
		return
	}

	if pdr.PDI.SourceInterface.InterfaceValue != context.SourceInterfaceAccess {
		t.Errorf("expected SourceInterface to be %v, got %v", context.SourceInterfaceAccess, pdr.PDI.SourceInterface.InterfaceValue)
	}
	if pdr.PDI.LocalFTeid == nil {
		t.Errorf("expected pdr.PDI.LocalFTeid to be not nil")
	}
	if !pdr.PDI.LocalFTeid.Ch {
		t.Errorf("expected pdr.PDI.LocalFTeid.Ch to be true")
	}
	if pdr.PDI.UEIPAddress == nil {
		t.Errorf("expected pdr.PDI.UEIPAddress to be not nil")
	}
	if !pdr.PDI.UEIPAddress.V4 {
		t.Errorf("expected pdr.PDI.UEIPAddress.V4 to be true")
	}
	if !pdr.PDI.UEIPAddress.Ipv4Address.Equal(net.IP{192, 168, 1, 1}) {
		t.Errorf("expected pdr.PDI.UEIPAddress.Ipv4Address to be %v, got %v", net.IP{192, 168, 1, 1}, pdr.PDI.UEIPAddress.Ipv4Address)
	}
	if string(pdr.PDI.NetworkInstance) != testDnn {
		t.Errorf("expected pdr.PDI.NetworkInstance to be 'internet', got %v", string(pdr.PDI.NetworkInstance))
	}
}

// The RAN is told one uplink TEID per PDU session, so every uplink PDR of the tunnel has to ask for
// the same F-TEID. A PDR left to a TEID of its own matches no packet, and with two PCC rules that
// lost all uplink the told rule did not match on about half the sessions.
func TestEveryUplinkPdrOfATunnelAsksForOneFTEID(t *testing.T) {
	smContext := &context.SMContext{
		PDUAddress: &context.UeIpAddr{Ip: net.IPv4(192, 168, 1, 1)},
		Dnn:        testDnn,
	}
	dpNode := &context.DataPathNode{
		UPF: &context.UPF{},
		UpLinkTunnel: &context.GTPTunnel{
			PDR: map[string]*context.PDR{
				"ALLOW-ALL": {FAR: &context.FAR{}},
				"CIR-TEST":  {FAR: &context.FAR{}},
			},
		},
	}

	if err := dpNode.ActivateUpLinkPdr(smContext, &context.QER{}, 10); err != nil {
		t.Fatalf("ActivateUpLinkPdr: %v", err)
	}

	var chooseID *uint8
	for name, pdr := range dpNode.UpLinkTunnel.PDR {
		fteid := pdr.PDI.LocalFTeid
		if fteid == nil {
			t.Fatalf("PDR %q has no local F-TEID", name)
		}
		if !fteid.Ch || !fteid.Chid {
			t.Errorf("PDR %q: CH=%v CHID=%v, want both: the UPF assigns a PDR without CHOOSE ID a TEID "+
				"of its own", name, fteid.Ch, fteid.Chid)
		}
		// TS 29.244 clause 8.2.3: at least one of V4 and V6, CHOOSE included.
		if !fteid.V4 {
			t.Errorf("PDR %q: V4 unset, so the CHOOSE names no address family", name)
		}
		if chooseID == nil {
			chooseID = &fteid.ChooseId
		} else if fteid.ChooseId != *chooseID {
			t.Errorf("PDR %q: CHOOSE ID %d, another PDR of the tunnel has %d", name, fteid.ChooseId, *chooseID)
		}
	}
}

func TestActivateDlLinkPdr(t *testing.T) {
	smContext := &context.SMContext{
		PDUAddress: &context.UeIpAddr{
			Ip: net.IP{192, 168, 1, 1},
		},
		Dnn: testDnn,
		Tunnel: &context.UPTunnel{
			ANInformation: struct {
				IPAddress net.IP
				TEID      uint32
			}{
				IPAddress: net.IP{10, 0, 0, 1},
				TEID:      12345,
			},
		},
	}

	defQER := &context.QER{}

	dpNode := &context.DataPathNode{
		UPF: &context.UPF{},
		DownLinkTunnel: &context.GTPTunnel{
			PDR: map[string]*context.PDR{
				"default": {
					Precedence: 0,
					FAR:        &context.FAR{},
				},
			},
		},
	}

	dataPath := &context.DataPath{
		FirstDPNode: dpNode,
	}

	err := dpNode.ActivateDlLinkPdr(smContext, defQER, 10, dataPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	pdr := dpNode.DownLinkTunnel.PDR["default"]
	if pdr == nil {
		t.Fatalf("expected pdr to be not nil")
		return
	}

	if pdr.PDI.SourceInterface.InterfaceValue != context.SourceInterfaceCore {
		t.Errorf("expected SourceInterface to be %v, got %v", context.SourceInterfaceCore, pdr.PDI.SourceInterface.InterfaceValue)
	}
	if pdr.PDI.UEIPAddress == nil {
		t.Errorf("expected pdr.PDI.UEIPAddress to be not nil")
	}
	if !pdr.PDI.UEIPAddress.V4 {
		t.Errorf("expected pdr.PDI.UEIPAddress.V4 to be true")
	}
	if !pdr.PDI.UEIPAddress.Ipv4Address.Equal(net.IP{192, 168, 1, 1}) {
		t.Errorf("expected pdr.PDI.UEIPAddress.Ipv4Address to be %v, got %v", net.IP{192, 168, 1, 1}, pdr.PDI.UEIPAddress.Ipv4Address)
	}
}

// TestFindNodeMatchesConfiguredNodeIDAcrossDnsRefresh is a regression test for the establishment
// handler's F-TEID routing. FindNode must correlate a response to its data path node by the configured
// NodeID, not by a resolved address. An earlier version resolved both the caller's NodeID and each
// node's NodeID to an IP and compared the strings; a DNS refresh landing between the caller's
// resolution and FindNode's own made the same configured UPF fail to match, so the handler skipped its
// F-TEID update while still counting its acceptance -- and a successful create could then advertise the
// access tunnel's stale TEID. Comparing the configured NodeID is immune to that drift.
func TestFindNodeMatchesConfiguredNodeIDAcrossDnsRefresh(t *testing.T) {
	const (
		fqdn        = "upf.findnode-drift.test"
		dispatchIP  = "10.70.0.1"
		refreshedIP = "10.70.0.2"
	)

	// The address the UPF was reachable at when the establishment request went out.
	context.InsertDnsHostIp(fqdn, net.ParseIP(dispatchIP))

	nodeID := context.NewNodeID(fqdn)
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(*nodeID) })
	node := context.NewDataPathNode()
	node.UPF = context.NewUPF(nodeID, nil)
	path := context.NewDataPath()
	path.FirstDPNode = node

	// What the caller (the establishment response handler) resolved the responding UPF to before any
	// refresh -- the key the old resolved-string FindNode would have been handed.
	callerResolved := nodeID.ResolveNodeIdToIp().String()
	if callerResolved != dispatchIP {
		t.Fatalf("precondition: NodeID resolved to %q, want %q", callerResolved, dispatchIP)
	}

	// The DNS cache moves the UPF to a new address -- as the periodic refresh would -- after the caller
	// resolved but before the node is matched. The node now resolves to a different address than the
	// caller captured, so the old lookup (FindNode(callerResolved) compared against node.GetNodeIP())
	// would miss the very node that responded.
	context.InsertDnsHostIp(fqdn, net.ParseIP(refreshedIP))
	if got := node.GetNodeIP(); got == callerResolved {
		t.Fatalf("precondition: node still resolves to the caller's address %q; the refresh did not take", got)
	}

	// Matching on the configured NodeID finds the responding UPF's node regardless of the drift.
	if got := path.FindNode(*nodeID); got != node {
		t.Errorf("FindNode did not match the responding UPF's node after a DNS refresh; the handler would skip its F-TEID update while still counting the acceptance")
	}
}

// A response can come from a UPF that is on a non-default path only (SendPFCPRules sends to every
// activated path; EstablishPSA2 to the activating path). The pool lookup must find it, and for a UPF
// shared by several paths pick the node whose tunnel owns the created PDR.
func TestDataPathPoolFindNodeSearchesEveryPath(t *testing.T) {
	newNode := func(ip string, pdrID uint16) *context.DataPathNode {
		n := context.NewDataPathNode()
		n.UPF = context.NewUPF(context.NewNodeID(ip), nil)
		// One cleanup per allocation: RemoveUPFNodeByNodeID removes a single matching UPF per call,
		// and this registers one UPF for every node, two of them for the same address.
		t.Cleanup(func() { context.RemoveUPFNodeByNodeID(*context.NewNodeID(ip)) })
		n.UpLinkTunnel.PDR["default"] = &context.PDR{PDRID: pdrID}
		return n
	}

	defaultNode := newNode("10.71.0.1", 1)
	defaultPath := context.NewDataPath()
	defaultPath.IsDefaultPath = true
	defaultPath.FirstDPNode = defaultNode

	sharedOnBranch := newNode("10.71.0.1", 2)
	branchOnly := newNode("10.71.0.2", 3)
	sharedOnBranch.AddNext(branchOnly)
	branchPath := context.NewDataPath()
	branchPath.FirstDPNode = sharedOnBranch

	pool := context.DataPathPool{1: defaultPath, 2: branchPath}

	if got := pool.FindNode(*context.NewNodeID("10.71.0.2"), 3, true); got != branchOnly {
		t.Errorf("a UPF only on the branch path was not found")
	}
	if got := pool.FindNode(*context.NewNodeID("10.71.0.1"), 2, true); got != sharedOnBranch {
		t.Errorf("shared UPF: the node owning PDR 2 was not chosen")
	}
	if got := pool.FindNode(*context.NewNodeID("10.71.0.1"), 1, true); got != defaultNode {
		t.Errorf("shared UPF: the node owning PDR 1 was not chosen")
	}
	if got := pool.FindNode(*context.NewNodeID("10.71.0.1"), 0, false); got != defaultNode {
		t.Errorf("without a PDR ID the default path's node should win")
	}
	if got := pool.FindNode(*context.NewNodeID("10.71.0.9"), 0, false); got != nil {
		t.Errorf("a UPF on no path matched")
	}
}
