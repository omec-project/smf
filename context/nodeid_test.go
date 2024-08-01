// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package context_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
)

func TestNewNodeIDIpv4(t *testing.T) {
	nodeID := context.NewNodeID("1.2.3.4")

	if nodeID.NodeIdType != context.NodeIdTypeIpv4Address {
		t.Errorf("expected NodeIdType to be %d, got %d", context.NodeIdTypeIpv4Address, nodeID.NodeIdType)
	}

	if net.IP(nodeID.NodeIdValue).String() != net.ParseIP("1.2.3.4").String() {
		t.Errorf("expected 1.2.3.4 got %v", net.IP(nodeID.NodeIdValue))
	}
}

func TestNewNodeIDIpv6(t *testing.T) {
	nodeID := context.NewNodeID("2001:db8::68")

	if nodeID.NodeIdType != context.NodeIdTypeIpv6Address {
		t.Errorf("expected NodeIdType to be %d, got %d", context.NodeIdTypeIpv6Address, nodeID.NodeIdType)
	}

	if net.IP(nodeID.NodeIdValue).String() != net.ParseIP("2001:db8::68").String() {
		t.Errorf("expected 2001:db8::68 got %v", net.IP(nodeID.NodeIdValue))
	}
}

func TestNewNodeIDFqdn(t *testing.T) {
	nodeID := context.NewNodeID("example.com")

	if nodeID.NodeIdType != context.NodeIdTypeFqdn {
		t.Errorf("expected NodeIdType to be %d, got %d", context.NodeIdTypeFqdn, nodeID.NodeIdType)
	}

	if string(nodeID.NodeIdValue) != "example.com" {
		t.Errorf("expected example.com got %s", nodeID.NodeIdValue)
	}
}

func TestResolveNodeIdToIpForIpv4(t *testing.T) {
	nodeID := context.NewNodeID("1.2.3.4")

	if nodeID.ResolveNodeIdToIp().String() != net.ParseIP("1.2.3.4").String() {
		t.Errorf("expected 1.2.3.4 got %v", nodeID.ResolveNodeIdToIp())
	}
}

func TestResolveNodeIdToIpForIpv6(t *testing.T) {
	nodeID := context.NewNodeID("2001:db8::68")

	if nodeID.ResolveNodeIdToIp().String() != net.ParseIP("2001:db8::68").String() {
		t.Errorf("expected 2001:db8::68 got %v", nodeID.ResolveNodeIdToIp())
	}
}

func TestResolveNodeIdToIpForFqdn(t *testing.T) {
	context.InsertDnsHostIp("test.com", net.ParseIP("1.2.3.4"))
	nodeID := context.NewNodeID("test.com")

	ip := nodeID.ResolveNodeIdToIp()

	if ip.String() != net.ParseIP("1.2.3.4").String() {
		t.Errorf("expected 1.2.3.4 got %v", ip)
	}
}
