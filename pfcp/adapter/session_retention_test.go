// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The adapter's twin of the native handler's test: only one of the two dispatchers runs in a
// deployment, so each must record whether the node retained the sessions of the association it
// replaced (TS 29.244 clause 6.2.6.2.2), and record it afresh on every association.
func TestTheAdapterRecordsWhetherTheSessionsWereRetained(t *testing.T) {
	off := false
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: &off},
				EnableUpfAdapter: false,
			},
		}
	}
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
			const ip = "1.1.1.11"
			nodeID := context.NewNodeID(ip)
			unchanged := time.Unix(1_790_000_000, 0)
			upf := context.NewUPF(nodeID, nil)
			upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: unchanged}
			upf.SessionsRetained = !tc.want
			t.Cleanup(func() { context.RemoveUPFNodeByNodeID(*nodeID) })

			ies := append([]*ie.IE{
				ie.NewCause(ie.CauseRequestAccepted), ie.NewNodeID(ip, "", ""),
				ie.NewRecoveryTimeStamp(unchanged),
			}, tc.flags...)
			if err := adapter.HandleAdapterPfcpRsp(message.NewAssociationSetupResponse(1, ies...), nil); err != nil {
				t.Fatalf("handling the association response: %v", err)
			}

			if _, associated, retained := upf.AssociatedIncarnation(); !associated || retained != tc.want {
				t.Errorf("after the response the UPF is associated %v, retained %v; want associated, retained %v",
					associated, retained, tc.want)
			}
		})
	}
}
