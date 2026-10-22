// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
	"testing"
)

// An FQDN UPF's PFCPContext entry is keyed by the address it resolved to when the session was
// allocated. After the DNS refresh moves the address, a key built from a fresh resolution names no
// entry: indexing the map with it yields nil, and the PDR removal that releaseTunnel's deactivation
// performs dereferenced it.
func TestPFCPContextKeyForNodeSurvivesDnsAddressChange(t *testing.T) {
	const fqdn = "upf.key-for-node.test"
	InsertDnsHostIp(fqdn, net.ParseIP("10.81.0.1"))
	nodeID := NewNodeID(fqdn)

	// Built directly, as AllocateLocalSEIDForDataPath would key it: by the address the name resolved to
	// then, with the NodeID recorded.
	const allocatedKey = "10.81.0.1"
	smContext := &SMContext{PFCPContext: map[string]*PFCPSessionContext{
		allocatedKey: {PDRs: make(map[uint16]*PDR), NodeID: *nodeID, LocalSEID: 5},
	}}
	pdr := &PDR{PDRID: 7}
	smContext.PFCPContext[allocatedKey].PDRs[pdr.PDRID] = pdr

	InsertDnsHostIp(fqdn, net.ParseIP("10.81.0.2"))

	if key, ok := smContext.PFCPContextKeyForNode(*nodeID); !ok || key != allocatedKey {
		t.Fatalf("PFCPContextKeyForNode = (%q, %t), want (%q, true)", key, ok, allocatedKey)
	}

	smContext.RemovePDRfromPFCPSession(*nodeID, pdr)
	if _, held := smContext.PFCPContext[allocatedKey].PDRs[pdr.PDRID]; held {
		t.Errorf("the PDR is still recorded in the session after its removal")
	}
}

// A node holding no session is what a teardown finds when the session never reached it. Removing a
// PDR from it must not panic.
func TestRemovePDRfromPFCPSessionWithNoSessionOnTheNode(t *testing.T) {
	smContext := &SMContext{PFCPContext: map[string]*PFCPSessionContext{}}

	if key, ok := smContext.PFCPContextKeyForNode(*NewNodeID("10.81.0.9")); ok {
		t.Errorf("PFCPContextKeyForNode found %q on a context with no sessions", key)
	}
	smContext.RemovePDRfromPFCPSession(*NewNodeID("10.81.0.9"), &PDR{PDRID: 1})
}

// The verdict slot holds one. A second verdict must be dropped, not wait for room: the deletion
// response handlers call this where nothing is reading the slot.
func TestQueuePFCPVerdictNeverBlocks(t *testing.T) {
	smContext := &SMContext{SBIPFCPCommunicationChan: make(chan PFCPSessionResponseStatus, 1)}

	if !smContext.QueuePFCPVerdict(SessionReleaseSuccess) {
		t.Fatal("a verdict was not queued into an empty slot")
	}
	if smContext.QueuePFCPVerdict(SessionReleaseFailed) {
		t.Error("a second verdict was reported queued with the slot taken")
	}
	if got := <-smContext.SBIPFCPCommunicationChan; got != SessionReleaseSuccess {
		t.Errorf("the slot holds %v, want the first verdict", got)
	}
}
