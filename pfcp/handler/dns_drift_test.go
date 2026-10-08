// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handler_test

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/handler"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// PendingUPF and PFCPContext are keyed by the UPF address resolved when the batch was dispatched. An
// FQDN UPF's address can change under the periodic DNS refresh (see ResolveNodeIdToIp) while the
// establishment request is in flight. If the response handler re-resolved the NodeID to key the
// aggregation, the valid response would miss PendingUPF, the batch would never drain, and the create
// FSM's blocking receive on SBIPFCPCommunicationChan would hang forever. The handler must correlate
// through the stable key recovered from the response's local SEID instead.
func TestEstablishmentResponseDrainsBatchAfterDnsAddressChanged(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: boolPointer(false)},
				EnableUpfAdapter: false,
			},
		}
	}

	const fqdn = "upf.dns-drift.test"
	const dispatchIP = "10.80.0.1"
	const refreshedIP = "10.80.0.2"

	// The address the UPF was reachable at when the request went out.
	context.InsertDnsHostIp(fqdn, net.ParseIP(dispatchIP))

	nodeID := context.NewNodeID(fqdn)
	smContext := context.NewSMContext("imsi-100000000000051", 10)
	smContext.SMContextState = context.SmStatePfcpCreatePending
	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			10: &context.DataPath{
				IsDefaultPath: true,
				FirstDPNode:   &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
			},
		},
	}

	// PFCPContext is keyed by the dispatch-time address, and the batch records that same key.
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{
		FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
	})
	pfcpCtx, ok := smContext.PFCPContext[dispatchIP]
	if !ok {
		t.Fatalf("PFCPContext not keyed by the dispatch-time address %q; keys are %v", dispatchIP, keysOf(smContext.PFCPContext))
	}
	smContext.AddPendingUPF(dispatchIP)
	localSEID := pfcpCtx.LocalSEID

	// The DNS cache moves the UPF to a new address while the request is in flight: from now on
	// ResolveNodeIdToIp returns refreshedIP, which is not the key PendingUPF holds.
	context.InsertDnsHostIp(fqdn, net.ParseIP(refreshedIP))
	if got := nodeID.ResolveNodeIdToIp().String(); got != refreshedIP {
		t.Fatalf("precondition: NodeID now resolves to %q, want the refreshed %q", got, refreshedIP)
	}

	seq := uint32(localSEID)
	pfcp_message.InsertPfcpTxn(seq, nodeID)
	rsp := message.NewSessionEstablishmentResponse(0, 0, localSEID, seq, 0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID(dispatchIP, "", ""),
		ie.NewRecoveryTimeStamp(time.Now()),
		ie.NewFSEID(0xBEEF, net.ParseIP(dispatchIP), nil),
	)

	handler.HandlePfcpSessionEstablishmentResponse(&udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP(dispatchIP), Port: 8805},
		PfcpMessage: rsp,
	})

	// The batch drained despite the address change, so the single create verdict was queued. Re-resolving
	// the NodeID would have missed PendingUPF and left the channel empty (the create hanging).
	select {
	case v := <-smContext.SBIPFCPCommunicationChan:
		if v != context.SessionEstablishSuccess {
			t.Fatalf("verdict = %v, want SessionEstablishSuccess", v)
		}
	default:
		t.Fatal("no verdict queued: the response missed PendingUPF after the DNS address changed, so the create would block forever")
	}
	if !smContext.PendingUPFIsEmpty() {
		t.Error("PendingUPF still holds the UPF after its accepted response; the entry was not drained by the stable key")
	}
}

func keysOf(m map[string]*context.PFCPSessionContext) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
