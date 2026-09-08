// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
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

// restartsObserved swaps the restoration hook for a recorder, so each detection path can be tested
// for whether it actually reaches the restoration rather than merely logging.
func restartsObserved(t *testing.T) *[]context.NodeID {
	t.Helper()
	previous := context.OnRestart
	seen := make([]context.NodeID, 0)
	context.OnRestart = func(nodeID context.NodeID, _ time.Time) { seen = append(seen, nodeID) }
	t.Cleanup(func() { context.OnRestart = previous })
	return &seen
}

func configured() {
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{
			KafkaInfo:        factory.KafkaInfo{EnableKafka: boolPointer(false)},
			EnableUpfAdapter: false,
		},
	}
}

func upfHolding(nodeIP string, recovery time.Time) *context.UPF {
	upf := context.NewUPF(context.NewNodeID(nodeIP), nil)
	upf.UPFStatus = context.AssociatedSetUpSuccess
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: recovery}
	return upf
}

func at(nodeIP string) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(nodeIP), Port: 8805}
}

// The path a crash takes: the node is back and announces itself before its absence was noticed.
func TestAssociationSetupRequestReachesTheRestoration(t *testing.T) {
	configured()
	seen := restartsObserved(t)
	nodeIP := "10.40.0.1"
	upfHolding(nodeIP, time.Now().Add(-time.Hour))

	handler.HandlePfcpAssociationSetupRequest(&udp.Message{
		RemoteAddr: at(nodeIP),
		PfcpMessage: message.NewAssociationSetupRequest(1,
			ie.NewNodeID(nodeIP, "", ""), ie.NewRecoveryTimeStamp(time.Now())),
	})

	if len(*seen) != 1 {
		t.Errorf("the association setup request path did not reach the restoration (%d call(s)); a UPF "+
			"announcing its own return is the path a crash takes", len(*seen))
	}
}

// The other half of re-association: this element initiated it, for a UPF it had marked unusable.
func TestAssociationSetupResponseReachesTheRestoration(t *testing.T) {
	configured()
	seen := restartsObserved(t)
	nodeIP := "10.40.0.2"
	upfHolding(nodeIP, time.Now().Add(-time.Hour))
	pfcp_message.InsertPfcpTxn(77, context.NewNodeID(nodeIP))

	handler.HandlePfcpAssociationSetupResponse(&udp.Message{
		RemoteAddr: at(nodeIP),
		PfcpMessage: message.NewAssociationSetupResponse(77,
			ie.NewCause(ie.CauseRequestAccepted), ie.NewNodeID(nodeIP, "", ""),
			ie.NewRecoveryTimeStamp(time.Now())),
	})

	if len(*seen) != 1 {
		t.Errorf("the association setup response path did not reach the restoration (%d call(s))", len(*seen))
	}
}

// A UPF that stops answering and comes back unchanged still holds every rule installed on it.
// Re-establishing its sessions would replace forwarding state that is working.
func TestAnUnchangedRecoveryTimestampDoesNotReachTheRestoration(t *testing.T) {
	configured()
	seen := restartsObserved(t)
	nodeIP := "10.40.0.3"
	unchanged := time.Now().Add(-time.Hour)
	upfHolding(nodeIP, unchanged)

	handler.HandlePfcpAssociationSetupRequest(&udp.Message{
		RemoteAddr: at(nodeIP),
		PfcpMessage: message.NewAssociationSetupRequest(2,
			ie.NewNodeID(nodeIP, "", ""), ie.NewRecoveryTimeStamp(unchanged)),
	})

	if len(*seen) != 0 {
		t.Errorf("a UPF that did not restart reached the restoration; its sessions are intact and " +
			"re-establishing them would replace working forwarding state")
	}
}

// A UPF this SMF has not seen before is a first association, not a restart.
func TestAFirstAssociationIsNotARestart(t *testing.T) {
	configured()
	seen := restartsObserved(t)
	nodeIP := "10.40.0.4"
	context.NewUPF(context.NewNodeID(nodeIP), nil) // no recovery timestamp held

	handler.HandlePfcpAssociationSetupRequest(&udp.Message{
		RemoteAddr: at(nodeIP),
		PfcpMessage: message.NewAssociationSetupRequest(3,
			ie.NewNodeID(nodeIP, "", ""), ie.NewRecoveryTimeStamp(time.Now())),
	})

	if len(*seen) != 0 {
		t.Errorf("a first association was treated as a restart")
	}
}

// Once the held value has been replaced the evidence of the restart is gone. Every path must
// therefore compare before it overwrites, and this asserts it rather than leaving it to inspection.
func TestEveryPathComparesBeforeItOverwritesTheHeldTimestamp(t *testing.T) {
	configured()
	old := time.Now().Add(-time.Hour)

	for _, path := range []struct {
		name    string
		nodeIP  string
		deliver func(nodeIP string, fresh time.Time)
	}{
		{"association setup request", "10.40.0.5", func(nodeIP string, fresh time.Time) {
			handler.HandlePfcpAssociationSetupRequest(&udp.Message{
				RemoteAddr: at(nodeIP),
				PfcpMessage: message.NewAssociationSetupRequest(4,
					ie.NewNodeID(nodeIP, "", ""), ie.NewRecoveryTimeStamp(fresh)),
			})
		}},
		{"association setup response", "10.40.0.6", func(nodeIP string, fresh time.Time) {
			pfcp_message.InsertPfcpTxn(88, context.NewNodeID(nodeIP))
			handler.HandlePfcpAssociationSetupResponse(&udp.Message{
				RemoteAddr: at(nodeIP),
				PfcpMessage: message.NewAssociationSetupResponse(88,
					ie.NewCause(ie.CauseRequestAccepted), ie.NewNodeID(nodeIP, "", ""),
					ie.NewRecoveryTimeStamp(fresh)),
			})
		}},
	} {
		t.Run(path.name, func(t *testing.T) {
			seen := restartsObserved(t)
			upf := upfHolding(path.nodeIP, old)
			fresh := time.Now()

			path.deliver(path.nodeIP, fresh)

			if len(*seen) != 1 {
				t.Fatalf("the restart was not detected, so the comparison did not happen before the overwrite")
			}
			if upf.RecoveryTimeStamp.RecoveryTimeStamp.Unix() != fresh.Unix() {
				t.Errorf("the held timestamp was not updated after the comparison; the next message would " +
					"be read as another restart")
			}
		})
	}
}

// After a restart the identifier the SMF holds for a session names something the UPF no longer has.
// The establishment that restores the session returns a new one, and that is the value every later
// message about the session must carry. Keeping the old one would address a session that does not
// exist on the node now serving it.
func TestRestoringASessionReplacesTheIdentifierFromBeforeTheRestart(t *testing.T) {
	configured()
	nodeIP := "10.41.0.1"
	nodeID := context.NewNodeID(nodeIP)

	const (
		beforeTheRestart = uint64(0xDEAD)
		afterTheRestart  = uint64(0xF00D)
	)

	smContext := context.NewSMContext("imsi-208930000000801", 1)
	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			1: &context.DataPath{
				IsDefaultPath: true,
				FirstDPNode:   &context.DataPathNode{UPF: &context.UPF{}, UpLinkTunnel: &context.GTPTunnel{}},
			},
		},
	}

	// Registers the session under a local identifier and creates its PFCP context for the node,
	// which is what the establishment response is matched against.
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{
		FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
	})
	pfcpCtx, ok := smContext.PFCPContext[nodeIP]
	if !ok {
		t.Fatalf("no PFCP context was created for %s", nodeIP)
	}
	pfcpCtx.RemoteSEID = beforeTheRestart
	pfcp_message.InsertPfcpTxn(4321, nodeID)

	handler.HandlePfcpSessionEstablishmentResponse(&udp.Message{
		RemoteAddr: at(nodeIP),
		PfcpMessage: message.NewSessionEstablishmentResponse(0, 0, pfcpCtx.LocalSEID, 4321, 0,
			ie.NewCause(ie.CauseRequestAccepted),
			ie.NewNodeID(nodeIP, "", ""),
			ie.NewFSEID(afterTheRestart, net.ParseIP(nodeIP), nil),
		),
	})

	got := smContext.PFCPContext[nodeIP].RemoteSEID
	if got == beforeTheRestart {
		t.Errorf("the session still holds the identifier from before the restart (%#x); every later "+
			"message about it would address a session the restarted UPF never created", got)
	}
	if got != afterTheRestart {
		t.Errorf("the session identifier is %#x, want %#x — the value the restoration returned", got, afterTheRestart)
	}
}

// The heartbeat path is deliberately not in the table above. It detects the restart and reaches the
// restoration, but leaves the held timestamp for the re-association it triggers to record.
//
// That is not an oversight, and recording it here was tried and reverted. Recording at the first
// observation silences every later exchange -- including the re-association that is the only thing
// that would notice a UPF which came back after the restoration had given up waiting for it, which
// it does after 60 s. The duplicate restoration this used to cause is prevented by identifying a
// restart by its recovery state instead, so the second observation is recognised as the same one.
func TestTheHeartbeatPathLeavesTheHeldTimestampForTheReassociation(t *testing.T) {
	configured()
	seen := restartsObserved(t)
	nodeIP := "10.40.0.7"
	old := time.Now().Add(-time.Hour)
	upf := upfHolding(nodeIP, old)
	fresh := time.Now()

	pfcp_message.InsertPfcpTxn(89, context.NewNodeID(nodeIP))
	handler.HandlePfcpHeartbeatResponse(&udp.Message{
		RemoteAddr:  at(nodeIP),
		PfcpMessage: message.NewHeartbeatResponse(89, ie.NewRecoveryTimeStamp(fresh)),
	})

	if len(*seen) != 1 {
		t.Fatalf("the heartbeat did not reach the restoration; it is the exchange that usually sees a restart first")
	}
	if upf.RecoveryTimeStamp.RecoveryTimeStamp.Unix() != old.Unix() {
		t.Errorf("the heartbeat recorded the new timestamp; the re-association can then no longer see " +
			"the restart, and a UPF that comes back late is never restored")
	}
	if upf.UPFStatus != context.NotAssociated {
		t.Errorf("the UPF was not marked NotAssociated, so nothing will re-associate it")
	}
}
