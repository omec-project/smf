// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// establishingSession builds an SM context whose default path anchors at one UPF, with a PFCP
// establishment outstanding to it, and returns the local SEID the response must carry and the
// node it came from.
func establishingSession(t *testing.T) (uint64, *context.NodeID) {
	t.Helper()

	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}

		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	nodeID := context.NewNodeID("1.1.1.1")
	upfIP := nodeID.ResolveNodeIdToIp().String()
	smContext := context.NewSMContext("imsi-123456789012399", 12)

	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })

	datapath := &context.DataPath{
		IsDefaultPath: true,
		FirstDPNode:   &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
	}
	smContext.Tunnel = &context.UPTunnel{DataPathPool: context.DataPathPool{1: datapath}}
	smContext.AllocateLocalSEIDForDataPath(datapath)

	return smContext.PFCPContext[upfIP].LocalSEID, nodeID
}

// TestTheAdapterEstablishmentPathReportsAndTasks is the behavioural half of the parity guard.
//
// With `enableUPFAdapter` set — the chart's default — this handler is the only one that runs when
// a PFCP session establishment completes. It carried no Lawful Interception hook at all, so for a
// tasked subscriber the SMF sent the UPF a FAR with the DUPL bit set and then never sent the
// ActivateTask that authorises it: the CC-POI held no task for the session, dropped every copy as
// unattributable, and no establishment record was produced. Nothing raised a fault, because from
// the SMF's side nothing had failed.
//
// Mutation-verify by removing the notify calls from the handler: this test must fail, and it must
// fail naming the product the agency does not get.
func TestTheAdapterEstablishmentPathReportsAndTasks(t *testing.T) {
	seid, nodeID := establishingSession(t)

	var reported, applied, triggered bool

	adapter.ReportEstablishment = func(*context.SMContext) { reported = true }
	adapter.ApplyCCAfterEstablishment = func(*context.SMContext) { applied = true }
	adapter.TriggerCC = func(*context.SMContext) { triggered = true }

	t.Cleanup(func() {
		adapter.ReportEstablishment = nil
		adapter.ApplyCCAfterEstablishment = nil
		adapter.TriggerCC = nil
	})

	const seq = 7

	adapter.InsertPfcpTxn(seq, nodeID)

	rsp := message.NewSessionEstablishmentResponse(0, 0, seid, seq, 0,
		ie.NewNodeID("1.1.1.1", "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
	)

	if err := adapter.HandlePfcpSessionEstablishmentResponse(&udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 8805},
		PfcpMessage: rsp,
		EventData:   udp.PfcpEventData{LSEID: seid},
	}); err != nil {
		t.Fatalf("the response was refused: %v", err)
	}

	if !reported {
		t.Error("no establishment record was produced on the adapter path, so a tasked " +
			"subscriber's session begins with the agency told nothing — indistinguishable from " +
			"a subject who never attached")
	}

	if !applied {
		t.Error("duplication was not re-derived after establishment on the adapter path, so a " +
			"warrant that activated while this session was being set up is applied to its FARs " +
			"by nobody")
	}

	if !triggered {
		t.Error("the CC-POI was not tasked on the adapter path. The DUPL bit rode out with the " +
			"establishment request, so the UPF duplicates this subscriber's traffic while " +
			"holding no task for it and drops every copy as unattributable — interception that " +
			"is running and delivering nothing, with nothing raising a fault")
	}
}

// TestTheAdapterEstablishmentPathIsSilentWhenRejected pins the other direction: a refused
// establishment must not report or task, or the agency is told a session began that did not.
func TestTheAdapterEstablishmentPathIsSilentWhenRejected(t *testing.T) {
	seid, nodeID := establishingSession(t)

	var reported, triggered bool

	adapter.ReportEstablishment = func(*context.SMContext) { reported = true }
	adapter.TriggerCC = func(*context.SMContext) { triggered = true }

	t.Cleanup(func() {
		adapter.ReportEstablishment = nil
		adapter.TriggerCC = nil
	})

	const seq = 8

	adapter.InsertPfcpTxn(seq, nodeID)

	rsp := message.NewSessionEstablishmentResponse(0, 0, seid, seq, 0,
		ie.NewNodeID("1.1.1.1", "", ""),
		ie.NewCause(ie.CauseRequestRejected),
	)

	if err := adapter.HandlePfcpSessionEstablishmentResponse(&udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 8805},
		PfcpMessage: rsp,
		EventData:   udp.PfcpEventData{LSEID: seid},
	}); err != nil {
		t.Fatalf("the response was refused: %v", err)
	}

	if reported {
		t.Error("an establishment record was produced for a session the UPF refused")
	}

	if triggered {
		t.Error("the CC-POI was tasked for a session that was never established")
	}
}
