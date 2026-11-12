// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The decoder does not enforce mandatory IEs, and an IE accessor called on an absent one is a nil
// dereference. A datagram that omits one must be dropped or answered, not crash the process. Each
// message here goes through the decoder as it would arrive, with the IE left out.

func initMissingIEConfig(t *testing.T) {
	t.Helper()
	previous := factory.SmfConfig
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{
			KafkaInfo:        factory.KafkaInfo{EnableKafka: new(false)},
			EnableUpfAdapter: false,
		},
	}
	t.Cleanup(func() { factory.SmfConfig = previous })
}

// decoded marshals m and decodes it again, which is what the read loop does with a datagram.
func decoded(t *testing.T, m message.Message) message.Message {
	t.Helper()
	b := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(b); err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	parsed, err := message.Parse(b)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return parsed
}

func fromUPF(m message.Message) *udp.Message {
	return &udp.Message{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8805}, PfcpMessage: m}
}

func registeredUPF(t *testing.T, ip string) (*context.UPF, *context.NodeID) {
	t.Helper()
	nodeID := context.NewNodeID(ip)
	upf := context.NewUPF(nodeID, nil)
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(*nodeID) })
	return upf, nodeID
}

func TestAHeartbeatResponseWithoutARecoveryTimeStampIsDropped(t *testing.T) {
	initMissingIEConfig(t)
	upf, nodeID := registeredUPF(t, "10.99.0.1")
	upf.UPFStatus = context.AssociatedSetUpSuccess
	const seq = 7001
	pfcp_message.InsertPfcpTxn(seq, nodeID)
	t.Cleanup(func() { pfcp_message.FetchPfcpTxn(seq) })

	rsp := message.NewHeartbeatResponse(seq, nil)
	if rsp.RecoveryTimeStamp != nil {
		t.Fatalf("precondition: the response carries a RecoveryTimeStamp")
	}

	HandlePfcpHeartbeatResponse(fromUPF(decoded(t, rsp)))

	if !upf.RecoveryTimeStamp.RecoveryTimeStamp.IsZero() {
		t.Errorf("a recovery timestamp was recorded from a response that carried none")
	}
}

func TestAnAssociationSetupRequestWithoutARecoveryTimeStampIsDropped(t *testing.T) {
	initMissingIEConfig(t)
	upf, _ := registeredUPF(t, "10.99.0.2")

	req := message.NewAssociationSetupRequest(7002, ie.NewNodeID("10.99.0.2", "", ""))

	HandlePfcpAssociationSetupRequest(fromUPF(decoded(t, req)))

	if !upf.RecoveryTimeStamp.RecoveryTimeStamp.IsZero() {
		t.Errorf("a recovery timestamp was recorded from a request that carried none")
	}
}

func TestAnAssociationSetupResponseMissingAnIEIsDropped(t *testing.T) {
	initMissingIEConfig(t)
	for _, tc := range []struct {
		name string
		ies  []*ie.IE
	}{
		{"no Cause", []*ie.IE{ie.NewNodeID("10.99.0.3", "", ""), ie.NewRecoveryTimeStamp(time.Now())}},
		{"accepted, no RecoveryTimeStamp", []*ie.IE{ie.NewNodeID("10.99.0.3", "", ""), ie.NewCause(ie.CauseRequestAccepted)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upf, nodeID := registeredUPF(t, "10.99.0.3")
			const seq = 7003
			pfcp_message.InsertPfcpTxn(seq, nodeID)
			t.Cleanup(func() { pfcp_message.FetchPfcpTxn(seq) })

			HandlePfcpAssociationSetupResponse(fromUPF(decoded(t, message.NewAssociationSetupResponse(seq, tc.ies...))))

			if upf.UPFStatus == context.AssociatedSetUpSuccess {
				t.Errorf("the node was marked associated by a response this SMF could not act on")
			}
		})
	}
}

func TestASessionReportRequestMissingAnIEIsAnswered(t *testing.T) {
	initMissingIEConfig(t)
	for _, tc := range []struct {
		name string
		ies  []*ie.IE
	}{
		{"no Report Type", nil},
		{"downlink data report announced, none carried", []*ie.IE{ie.NewReportType(0, 0, 0, 1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smContext := context.NewSMContext("imsi-208930000099001", 5)
			smContext.AllocateLocalSEIDForDataPath(&context.DataPath{FirstDPNode: &context.DataPathNode{UPF: &context.UPF{}}})
			t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })
			var seid uint64
			for _, c := range smContext.PFCPContext {
				seid = c.LocalSEID
			}
			smContext.SMLock.Lock()
			smContext.UpCnxState = models.UPCNXSTATE_DEACTIVATED
			smContext.SMLock.Unlock()

			req := message.NewSessionReportRequest(0, 0, seid, 7004, 0, tc.ies...)

			HandlePfcpSessionReportRequest(fromUPF(decoded(t, req)))
		})
	}
}
