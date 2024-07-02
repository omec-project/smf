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

	if nodeID.NodeIdType != 0 {
		t.Errorf("Expected 0, got %v", nodeID.NodeIdType)
	}
	if net.IP(nodeID.NodeIdValue).String() != net.ParseIP("1.2.3.4").String() {
		t.Errorf("Expected 1.2.3.4 got %v", net.IP(nodeID.NodeIdValue))
	}
}

func TestNodeIDIPv6(t *testing.T) {
	nodeID := context.NewNodeID("2001:db8::68")

	if nodeID.NodeIdType != 1 {
		t.Errorf("Expected 1, got %v", nodeID.NodeIdType)
	}
	if net.IP(nodeID.NodeIdValue).String() != net.ParseIP("2001:db8::68").String() {
		t.Errorf("Expected 2001:db8::68 got %v", net.IP(nodeID.NodeIdValue))
	}
}

func TestNodeIDFqdn(t *testing.T) {
	nodeID := context.NewNodeID("test.com")

	if nodeID.NodeIdType != 2 {
		t.Errorf("Expected 2, got %v", nodeID.NodeIdType)
	}
	if string(nodeID.NodeIdValue) != "test.com" {
		t.Errorf("Expected test.com got %v", string(nodeID.NodeIdValue))
	}
}

func TestResolveNodeIdToIpForIpv4(t *testing.T) {
	nodeID := context.NewNodeID("1.2.3.4")

	if nodeID.ResolveNodeIdToIp().String() != net.ParseIP("1.2.3.4").String() {
		t.Errorf("Expected 1.2.3.4 got %v", nodeID.ResolveNodeIdToIp())
	}
}

func TestResolveNodeIdToIpForIpv6(t *testing.T) {
	nodeID := context.NewNodeID("2001:db8::68")

	if nodeID.ResolveNodeIdToIp().String() != net.ParseIP("2001:db8::68").String() {
		t.Errorf("Expected 2001:db8::68 got %v", nodeID.ResolveNodeIdToIp())
	}
}

func TestResolveNodeIdToIpForFqdn(t *testing.T) {
	context.InsertDnsHostIp("test.com", net.ParseIP("1.2.3.4"))
	nodeID := context.NewNodeID("test.com")

	if nodeID.ResolveNodeIdToIp().String() != net.ParseIP("1.2.3.4").String() {
		t.Errorf("Expected 1.2.3.4 got %v", nodeID.ResolveNodeIdToIp())
	}
}
