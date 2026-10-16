// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// TestAdapterEstablishmentResponseAggregatesTrackedUPFs drives the adapter handler through a create
// batch of two tracked UPFs and checks the verdict the create procedure reads. In adapter mode each
// response is dispatched inline on the goroutine that later reads the session's channel, so the
// aggregation and gating have to happen in the handler itself -- the existing channel-verdict test
// preloads the channel without a pending batch and never exercises this path, and the context-level
// helper test cannot catch a handler that correlates or gates a response wrong.
//
// Both response orders are covered for each outcome: two acceptances aggregate to a single success,
// and an access-side acceptance with a secondary rejection aggregates to a single failure -- the
// acceptance never overriding the rejection, nor an access-side-only gate masking it.
func TestAdapterEstablishmentResponseAggregatesTrackedUPFs(t *testing.T) {
	for _, tc := range []struct {
		name             string
		secondaryAccepts bool
		accessFirst      bool
		want             context.PFCPSessionResponseStatus
	}{
		{"both accept, access first", true, true, context.SessionEstablishSuccess},
		{"both accept, secondary first", true, false, context.SessionEstablishSuccess},
		{"secondary rejects, access first", false, true, context.SessionEstablishFailed},
		{"secondary rejects, secondary first", false, false, context.SessionEstablishFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smContext, accessSEID := sessionOnTwoUserPlanes(t, context.SmStatePfcpCreatePending)
			secondarySEID := smContext.PFCPContext[secondUpf].LocalSEID

			answerAccess := func() {
				const seq = 5101
				InsertPfcpTxn(seq, context.NewNodeID(firstUpf))
				rsp := message.NewSessionEstablishmentResponse(0, 0, accessSEID, seq, 0,
					ie.NewNodeID(firstUpf, "", ""),
					ie.NewCause(ie.CauseRequestAccepted),
					ie.NewFSEID(99, net.ParseIP(firstUpf), nil))
				if err := HandlePfcpSessionEstablishmentResponse(&udp.Message{PfcpMessage: rsp}); err != nil {
					t.Fatalf("the access-side acceptance was reported as unusable: %v", err)
				}
			}

			answerSecondary := func() {
				const seq = 5102
				InsertPfcpTxn(seq, context.NewNodeID(secondUpf))
				ies := []*ie.IE{ie.NewNodeID(secondUpf, "", ""), ie.NewCause(ie.CauseRequestRejected)}
				if tc.secondaryAccepts {
					ies = []*ie.IE{
						ie.NewNodeID(secondUpf, "", ""),
						ie.NewCause(ie.CauseRequestAccepted),
						ie.NewFSEID(100, net.ParseIP(secondUpf), nil),
					}
				}
				rsp := message.NewSessionEstablishmentResponse(0, 0, secondarySEID, seq, 0, ies...)
				if err := HandlePfcpSessionEstablishmentResponse(&udp.Message{PfcpMessage: rsp}); err != nil {
					t.Fatalf("the secondary response was reported as unusable: %v", err)
				}
			}

			first, second := answerAccess, answerSecondary
			if !tc.accessFirst {
				first, second = answerSecondary, answerAccess
			}

			// The first inline response drains its own entry but leaves the batch pending, so no verdict
			// may reach the channel yet -- whichever UPF answered first.
			first()
			if n := len(smContext.SBIPFCPCommunicationChan); n != 0 {
				t.Fatalf("a verdict was queued after only the first inline response: %d queued", n)
			}

			// The second empties the batch and queues exactly one aggregate verdict.
			second()
			select {
			case v := <-smContext.SBIPFCPCommunicationChan:
				if v != tc.want {
					t.Fatalf("aggregate verdict = %v, want %v", v, tc.want)
				}
			default:
				t.Fatal("no verdict queued after both tracked UPFs answered; the create procedure would block forever")
			}
			if n := len(smContext.SBIPFCPCommunicationChan); n != 0 {
				t.Errorf("more than one verdict queued: %d still waiting", n)
			}
		})
	}
}

// adapterTwoNodeDefaultPath builds a create-pending session (adapter mode) whose single default data
// path chains an access UPF (FirstDPNode, advertised to the RAN) to a secondary UPF behind it, both
// tracked in the create batch. The UPFs are registered in the pool so RetrieveUPFNodeByNodeID finds
// them and removed on cleanup. It returns the context and each node's local SEID.
func adapterTwoNodeDefaultPath(t *testing.T, accessUpfIP, secondaryUpfIP string) (sm *context.SMContext, accessSEID, secondarySEID uint64) {
	t.Helper()
	prev := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prev })
	disabled := false
	factory.SmfConfig = factory.Config{Configuration: &factory.Configuration{
		KafkaInfo:        factory.KafkaInfo{EnableKafka: &disabled},
		EnableUpfAdapter: true,
	}}

	accessNodeID := context.NewNodeID(accessUpfIP)
	secondaryNodeID := context.NewNodeID(secondaryUpfIP)
	accessNode := context.NewDataPathNode()
	accessNode.UPF = context.NewUPF(accessNodeID, nil)
	secondaryNode := context.NewDataPathNode()
	secondaryNode.UPF = context.NewUPF(secondaryNodeID, nil)
	t.Cleanup(func() {
		context.RemoveUPFNodeByNodeID(*accessNodeID)
		context.RemoveUPFNodeByNodeID(*secondaryNodeID)
	})

	// access -> secondary, so the secondary is genuinely on the default path -- the topology the
	// TEID-overwrite bug needs.
	accessNode.AddNext(secondaryNode)
	secondaryNode.AddPrev(accessNode)

	path := context.NewDataPath()
	path.FirstDPNode = accessNode
	path.IsDefaultPath = true

	smContext := context.NewSMContext("imsi-208930000000049", 9)
	smContext.Tunnel = context.NewUPTunnel()
	smContext.Tunnel.AddDataPath(path)
	smContext.AllocateLocalSEIDForDataPath(path)
	smContext.PendingUPF = context.PendingUPF{accessUpfIP: true, secondaryUpfIP: true}
	smContext.SMContextState = context.SmStatePfcpCreatePending

	return smContext, smContext.PFCPContext[accessUpfIP].LocalSEID, smContext.PFCPContext[secondaryUpfIP].LocalSEID
}

// TestAdapterEstablishmentResponseKeepsAccessTunnelTEID is the adapter-mode counterpart of the native
// handler's TEID test: a create whose default data path chains an access UPF to a secondary UPF, both
// accepting with distinct F-TEIDs. The access tunnel must keep the access UPF's own TEID -- the adapter
// handler had the same unconditional assignment a secondary response would otherwise overwrite. Both
// response orders are covered.
func TestAdapterEstablishmentResponseKeepsAccessTunnelTEID(t *testing.T) {
	const (
		accessTEID    = uint32(0x3111)
		secondaryTEID = uint32(0x3222)

		accessFTEIDIP    = "192.168.2.1"
		secondaryFTEIDIP = "192.168.9.3"

		// Dedicated UPF node IPs, distinct from the other adapter tests', so this test owns the only
		// pool entries under them and RetrieveUPFNodeByNodeID returns the very nodes it set up (one UPF
		// per IP, as in production) rather than a leftover duplicate from an earlier test.
		accessUpfIP    = "10.0.3.1"
		secondaryUpfIP = "10.0.3.2"
	)
	for _, tc := range []struct {
		name        string
		accessFirst bool
	}{
		{"access UPF answers first", true},
		{"secondary UPF answers first", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smContext, accessSEID, secondarySEID := adapterTwoNodeDefaultPath(t, accessUpfIP, secondaryUpfIP)

			answerAccess := func() {
				const seq = 5201
				InsertPfcpTxn(seq, context.NewNodeID(accessUpfIP))
				rsp := message.NewSessionEstablishmentResponse(0, 0, accessSEID, seq, 0,
					ie.NewNodeID(accessUpfIP, "", ""),
					ie.NewCause(ie.CauseRequestAccepted),
					ie.NewFSEID(0xA, net.ParseIP(accessUpfIP), nil),
					// Flag 0x01 sets the V4 bit so the IPv4 endpoint is encoded (and parsed back).
					ie.NewCreatedPDR(ie.NewFTEID(0x01, accessTEID, net.ParseIP(accessFTEIDIP), nil, 0)))
				if err := HandlePfcpSessionEstablishmentResponse(&udp.Message{PfcpMessage: rsp}); err != nil {
					t.Fatalf("the access-side acceptance was reported as unusable: %v", err)
				}
			}
			answerSecondary := func() {
				const seq = 5202
				InsertPfcpTxn(seq, context.NewNodeID(secondaryUpfIP))
				rsp := message.NewSessionEstablishmentResponse(0, 0, secondarySEID, seq, 0,
					ie.NewNodeID(secondaryUpfIP, "", ""),
					ie.NewCause(ie.CauseRequestAccepted),
					ie.NewFSEID(0xB, net.ParseIP(secondaryUpfIP), nil),
					ie.NewCreatedPDR(ie.NewFTEID(0x01, secondaryTEID, net.ParseIP(secondaryFTEIDIP), nil, 0)))
				if err := HandlePfcpSessionEstablishmentResponse(&udp.Message{PfcpMessage: rsp}); err != nil {
					t.Fatalf("the secondary acceptance was reported as unusable: %v", err)
				}
			}

			first, second := answerAccess, answerSecondary
			if !tc.accessFirst {
				first, second = answerSecondary, answerAccess
			}
			first()
			second()

			select {
			case v := <-smContext.SBIPFCPCommunicationChan:
				if v != context.SessionEstablishSuccess {
					t.Fatalf("aggregate verdict = %v, want SessionEstablishSuccess", v)
				}
			default:
				t.Fatal("no aggregate verdict after both UPFs accepted")
			}

			defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
			accessNode := defaultPath.FirstDPNode
			secondaryNode := accessNode.Next()

			// The access tunnel carries the access UPF's own TEID, never the secondary's.
			if got := accessNode.UpLinkTunnel.TEID; got != accessTEID {
				t.Errorf("access tunnel TEID = %#x, want the access UPF's own %#x (secondary UPF's is %#x)", got, accessTEID, secondaryTEID)
			}
			if got := secondaryNode.UpLinkTunnel.TEID; got != secondaryTEID {
				t.Errorf("secondary node tunnel TEID = %#x, want %#x", got, secondaryTEID)
			}
			if n3 := accessNode.UPF.N3Interfaces; len(n3) == 0 || len(n3[0].IPv4EndPointAddresses) == 0 {
				t.Fatal("the access UPF has no N3 endpoint recorded")
			} else if got := n3[0].IPv4EndPointAddresses[0]; !got.Equal(net.ParseIP(accessFTEIDIP)) {
				t.Errorf("advertised access N3 address = %v, want %v (the access UPF's own F-TEID address)", got, accessFTEIDIP)
			}
		})
	}
}
