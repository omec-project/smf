// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The adapter's restart paths are the live ones under the chart's default enableUPFAdapter, and
// the interception record is settled only on the way to the restoration (the LI wiring wraps
// context.OnRestart). So each of them must reach that hook, as the native handler's do.

func adapterRestartsObserved(t *testing.T) *[]context.NodeID {
	t.Helper()
	off := false
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &off}},
		}
	}
	previous := context.OnRestart
	seen := make([]context.NodeID, 0)
	context.OnRestart = func(nodeID context.NodeID, _ time.Time) { seen = append(seen, nodeID) }
	t.Cleanup(func() { context.OnRestart = previous })
	return &seen
}

func adapterUPFHolding(t *testing.T, nodeIP string, recovery time.Time) {
	t.Helper()
	nodeID := context.NewNodeID(nodeIP)
	upf := context.NewUPF(nodeID, nil)
	upf.UPFStatus = context.AssociatedSetUpSuccess
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: recovery}
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(*nodeID) })
}

func TestTheAdapterAssociationResponseReachesTheRestartHook(t *testing.T) {
	seen := adapterRestartsObserved(t)
	const nodeIP = "10.41.0.1"
	adapterUPFHolding(t, nodeIP, time.Now().Add(-time.Hour).Truncate(time.Second))

	adapter.HandlePfcpAssociationSetupResponse(&udp.Message{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP(nodeIP), Port: 8805},
		PfcpMessage: message.NewAssociationSetupResponse(1,
			ie.NewCause(ie.CauseRequestAccepted), ie.NewNodeID(nodeIP, "", ""),
			ie.NewRecoveryTimeStamp(time.Now())),
	})

	if len(*seen) != 1 {
		t.Errorf("the adapter's association response reached the restart hook %d time(s), want 1", len(*seen))
	}
}

func TestTheAdapterHeartbeatResponseReachesTheRestartHook(t *testing.T) {
	seen := adapterRestartsObserved(t)
	const nodeIP = "10.41.0.2"
	adapterUPFHolding(t, nodeIP, time.Now().Add(-time.Hour).Truncate(time.Second))
	adapter.InsertPfcpTxn(41002, context.NewNodeID(nodeIP))

	adapter.HandlePfcpHeartbeatResponse(&udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP(nodeIP), Port: 8805},
		PfcpMessage: message.NewHeartbeatResponse(41002, ie.NewRecoveryTimeStamp(time.Now())),
	})

	if len(*seen) != 1 {
		t.Errorf("the adapter's heartbeat response reached the restart hook %d time(s), want 1", len(*seen))
	}
}

func TestTheAdapterLeavesAnUnchangedRecoveryTimestampAlone(t *testing.T) {
	seen := adapterRestartsObserved(t)
	const nodeIP = "10.41.0.3"
	held := time.Now().Add(-time.Hour).Truncate(time.Second)
	adapterUPFHolding(t, nodeIP, held)

	adapter.HandlePfcpAssociationSetupResponse(&udp.Message{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP(nodeIP), Port: 8805},
		PfcpMessage: message.NewAssociationSetupResponse(1,
			ie.NewCause(ie.CauseRequestAccepted), ie.NewNodeID(nodeIP, "", ""),
			ie.NewRecoveryTimeStamp(held)),
	})

	if len(*seen) != 0 {
		t.Errorf("an unchanged recovery timestamp reached the restart hook %d time(s)", len(*seen))
	}
}
