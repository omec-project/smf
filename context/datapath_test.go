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

const (
	staticPool = "192.168.100.0/24"
	staticSupi = "imsi-001010100007510"
	staticAddr = "192.168.100.100"
)

// ueipUpf advertises the UEIP feature, as bess-upf does with enable_ue_ip_alloc set.
func ueipUpf() *context.UPF {
	return &context.UPF{
		UPFunctionFeatures: &context.UPFunctionFeatures{
			SupportedFeatures1: context.UpFunctionFeatures1Ueip,
		},
	}
}

// staticAllocator holds one subscriber's configured address.
func staticAllocator(t *testing.T) *context.IPAllocator {
	t.Helper()

	allocator, err := context.NewIPAllocator(staticPool)
	if err != nil {
		t.Fatalf("NewIPAllocator(%q): %v", staticPool, err)
	}
	allocator.ReserveStaticIps(&map[string]string{staticSupi: staticAddr})

	return allocator
}

// session returns a session for supi holding the address the allocator gives it.
func session(t *testing.T, supi string) *context.SMContext {
	t.Helper()

	allocator := staticAllocator(t)

	ip, err := allocator.Allocate(supi)
	if err != nil {
		t.Fatalf("Allocate(%q): %v", supi, err)
	}

	return &context.SMContext{
		Supi: supi,
		Dnn:  testDnn,
		PDUAddress: &context.UeIpAddr{
			Ip:     ip,
			Static: allocator.StaticIpForImsi(supi) != nil,
		},
		DNNInfo: &context.SnssaiSmfDnnInfo{UeIPAllocator: allocator},
		Tunnel: &context.UPTunnel{
			ANInformation: struct {
				IPAddress net.IP
				TEID      uint32
			}{IPAddress: net.IP{10, 0, 0, 1}, TEID: 12345},
		},
	}
}

func uplinkNode(upf *context.UPF) *context.DataPathNode {
	return &context.DataPathNode{
		UPF: upf,
		UpLinkTunnel: &context.GTPTunnel{
			PDR: map[string]*context.PDR{"default": {FAR: &context.FAR{}}},
		},
	}
}

func downlinkNode(upf *context.UPF) *context.DataPathNode {
	return &context.DataPathNode{
		UPF: upf,
		DownLinkTunnel: &context.GTPTunnel{
			PDR: map[string]*context.PDR{"default": {FAR: &context.FAR{}}},
		},
	}
}

// Asking a UPF that allocates to choose (CHV4) discards staticIpInfo in silence: it allocates from
// its own pool, and the SMF adopts that address and releases the configured one.
func TestStaticUeIpIsNamedInTheRuleWhenTheUpfAllocates(t *testing.T) {
	want := net.ParseIP(staticAddr).To4()

	t.Run("uplink", func(t *testing.T) {
		smContext := session(t, staticSupi)
		dpNode := uplinkNode(ueipUpf())

		if err := dpNode.ActivateUpLinkPdr(smContext, &context.QER{}, 10); err != nil {
			t.Fatalf("ActivateUpLinkPdr: %v", err)
		}

		assertNamesAddress(t, dpNode.UpLinkTunnel.PDR["default"], want)
	})

	t.Run("downlink", func(t *testing.T) {
		smContext := session(t, staticSupi)
		dpNode := downlinkNode(ueipUpf())

		dataPath := &context.DataPath{FirstDPNode: dpNode}
		if err := dpNode.ActivateDlLinkPdr(smContext, &context.QER{}, 10, dataPath); err != nil {
			t.Fatalf("ActivateDlLinkPdr: %v", err)
		}

		assertNamesAddress(t, dpNode.DownLinkTunnel.PDR["default"], want)
	})
}

func assertNamesAddress(t *testing.T, pdr *context.PDR, want net.IP) {
	t.Helper()

	if pdr == nil || pdr.PDI.UEIPAddress == nil {
		t.Fatalf("rule carries no UE IP Address IE")
	}
	if pdr.PDI.UEIPAddress.CHV4 {
		t.Errorf("CHV4 set: the UPF is asked to choose an address although %s is configured for %s",
			want, staticSupi)
	}
	if !pdr.PDI.UEIPAddress.V4 {
		t.Errorf("V4 unset, so the rule names no address")
	}
	if !pdr.PDI.UEIPAddress.Ipv4Address.Equal(want) {
		t.Errorf("rule names %v, want the configured %v", pdr.PDI.UEIPAddress.Ipv4Address, want)
	}
}

// A subscriber with no configured address is still left to the UPF's allocator.
func TestDynamicUeIpStillAsksTheUpfToChoose(t *testing.T) {
	smContext := session(t, "imsi-001010100007511")
	dpNode := uplinkNode(ueipUpf())

	if err := dpNode.ActivateUpLinkPdr(smContext, &context.QER{}, 10); err != nil {
		t.Fatalf("ActivateUpLinkPdr: %v", err)
	}

	ueIP := dpNode.UpLinkTunnel.PDR["default"].PDI.UEIPAddress
	if ueIP == nil {
		t.Fatalf("rule carries no UE IP Address IE")
	}
	if !ueIP.CHV4 {
		t.Errorf("CHV4 unset for a subscriber with no configured address, so the SMF's own choice "+
			"(%v) is imposed on a UPF that allocates", ueIP.Ipv4Address)
	}
	if ueIP.V4 {
		t.Errorf("V4 set alongside CHV4, which TS 29.244 clause 8.2.62 does not allow: the two are "+
			"mutually exclusive, and the address carried (%v) is not the one the UE will hold",
			ueIP.Ipv4Address)
	}
}

// A rule rebuilt for a session that outlived the SMF names the address the UE holds, which only
// the session carries: a restored SMContext has an allocator that marshalled as {}.
func TestStaticUeIpSurvivesIntoARestoredSession(t *testing.T) {
	restored := &context.SMContext{
		Supi: staticSupi,
		Dnn:  testDnn,
		PDUAddress: &context.UeIpAddr{
			Ip:     net.ParseIP(staticAddr).To4(),
			Static: true,
		},
		DNNInfo: &context.SnssaiSmfDnnInfo{UeIPAllocator: &context.IPAllocator{}},
	}

	if !restored.HasStaticUeIpAddr() {
		t.Fatalf("a restored session with a configured address does not report one")
	}

	dpNode := uplinkNode(ueipUpf())
	if err := dpNode.ActivateUpLinkPdr(restored, &context.QER{}, 10); err != nil {
		t.Fatalf("ActivateUpLinkPdr: %v", err)
	}

	assertNamesAddress(t, dpNode.UpLinkTunnel.PDR["default"], net.ParseIP(staticAddr).To4())
}

// ReleaseUeIpAddr writes 0.0.0.0 back, and the user plane reads it as any address, so a rule
// built after that must ask rather than name it. producer/callback.go guards the same sentinel.
func TestTheReleasedAddressSentinelIsNotNamedInARule(t *testing.T) {
	smContext := session(t, staticSupi)
	smContext.PDUAddress = &context.UeIpAddr{Ip: net.IPv4zero.To4(), Static: true}

	dpNode := uplinkNode(ueipUpf())
	if err := dpNode.ActivateUpLinkPdr(smContext, &context.QER{}, 10); err != nil {
		t.Fatalf("ActivateUpLinkPdr: %v", err)
	}

	ueIP := dpNode.UpLinkTunnel.PDR["default"].PDI.UEIPAddress
	if ueIP == nil {
		t.Fatalf("rule carries no UE IP Address IE")
	}
	if !ueIP.CHV4 {
		t.Errorf("rule names %v, which matches every subscriber", ueIP.Ipv4Address)
	}
}

// A UPF that allocated over a static address leaves Static set and UpfProvided true. The address
// the session holds is then the UPF's, so it is not reported as the configured one.
func TestAStaticAddressTheUpfOverrodeIsNoLongerStatic(t *testing.T) {
	smContext := session(t, staticSupi)
	if !smContext.HasStaticUeIpAddr() {
		t.Fatalf("%s does not hold its configured address to begin with", staticSupi)
	}

	// What pfcp/handler and pfcp/adapter do with an address out of the UPF's own pool.
	smContext.PDUAddress.Ip = net.IPv4(192, 168, 100, 3).To4()
	smContext.PDUAddress.UpfProvided = true

	if smContext.HasStaticUeIpAddr() {
		t.Errorf("%v is reported as %s's configured address %s", smContext.PDUAddress.Ip, staticSupi, staticAddr)
	}
}
