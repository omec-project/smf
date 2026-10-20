// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
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

			first()
			if n := len(smContext.SBIPFCPCommunicationChan); n != 0 {
				t.Fatalf("a verdict was queued after only the first inline response: %d queued", n)
			}

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
