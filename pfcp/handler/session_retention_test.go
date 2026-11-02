// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// TS 29.244 clause 6.2.6.2.2: a re-association deletes the sessions of the association it replaces
// unless the UP function says, with PSREI, that it retained them. A stored session is deleted at its
// node only where that was said, so the association response is where it must be recorded, and
// recorded afresh each time: a later association that does not say it leaves nothing retained.
func TestTheAssociationResponseRecordsWhetherTheSessionsWereRetained(t *testing.T) {
	configured()
	for _, tc := range []struct {
		name  string
		flags []*ie.IE
		want  bool
	}{
		{"PSREI set", []*ie.IE{ie.NewPFCPASRspFlags(0x01)}, true},
		{"flags without PSREI", []*ie.IE{ie.NewPFCPASRspFlags(0x00)}, false},
		{"no flags", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodeIP := "10.41.0.1"
			unchanged := time.Now().Add(-time.Hour)
			upf := upfHolding(t, nodeIP, unchanged)
			upf.UPFStatus = context.AssociatedSettingUp
			upf.SessionsRetained = !tc.want
			pfcp_message.InsertPfcpTxn(91, context.NewNodeID(nodeIP))

			ies := append([]*ie.IE{
				ie.NewCause(ie.CauseRequestAccepted), ie.NewNodeID(nodeIP, "", ""),
				ie.NewRecoveryTimeStamp(unchanged),
			}, tc.flags...)
			HandlePfcpAssociationSetupResponse(&udp.Message{
				RemoteAddr:  at(nodeIP),
				PfcpMessage: message.NewAssociationSetupResponse(91, ies...),
			})

			if _, associated, retained := upf.AssociatedIncarnation(); !associated || retained != tc.want {
				t.Errorf("after the response the UPF is associated %v, retained %v; want associated, retained %v",
					associated, retained, tc.want)
			}
		})
	}
}

// An association the node sets up answers no retention request, since only a request this element
// sends can carry one; whatever an earlier association said no longer holds.
func TestAnAssociationTheNodeSetsUpRetainsNothing(t *testing.T) {
	configured()
	nodeIP := "10.41.0.2"
	unchanged := time.Now().Add(-time.Hour)
	upf := upfHolding(t, nodeIP, unchanged)
	upf.SessionsRetained = true

	HandlePfcpAssociationSetupRequest(&udp.Message{
		RemoteAddr: at(nodeIP),
		PfcpMessage: message.NewAssociationSetupRequest(4,
			ie.NewNodeID(nodeIP, "", ""), ie.NewRecoveryTimeStamp(unchanged)),
	})

	if _, _, retained := upf.AssociatedIncarnation(); retained {
		t.Errorf("an association the UPF set up left its sessions recorded as retained")
	}
}
