// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/nas/v2/nasMessage"
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

// A session the user plane can report downlink data for: it has an access leg to describe in the
// N2 transfer, and an AMF that accepts the paging request, counted by the returned function.
func pageableSession(t *testing.T, supi string) (smContext *context.SMContext, seid uint64, pagings func() int32) {
	t.Helper()

	var paged atomic.Int32
	amf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/n1-n2-messages") {
			paged.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"cause":"ATTEMPTING_TO_REACH_UE"}`)); err != nil {
				t.Error(err)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(amf.Close)

	smContext = context.NewSMContext(supi, 5)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })
	var service models.NFService
	service.SetServiceInstanceId(string(models.SERVICENAME_NAMF_COMM))
	service.SetServiceName(models.SERVICENAME_NAMF_COMM)
	service.SetApiPrefix(amf.URL)
	service.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
	service.SetScheme(models.URISCHEME_HTTP)
	smContext.AMFProfile.SetNfServiceList(map[string]models.NFService{service.GetServiceInstanceId(): service})

	upf := &context.UPF{N3Interfaces: []context.UPFInterfaceInfo{{IPv4EndPointAddresses: []net.IP{net.ParseIP("10.0.0.1")}}}}
	smContext.Tunnel = &context.UPTunnel{DataPathPool: context.DataPathPool{
		1: &context.DataPath{
			IsDefaultPath: true,
			FirstDPNode:   &context.DataPathNode{UPF: upf, UpLinkTunnel: &context.GTPTunnel{TEID: 1}},
		},
	}}
	smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule = &models.SessionRule{
		AuthSessAmbr: &models.Ambr{Uplink: "1 Mbps", Downlink: "1 Mbps"},
	}
	smContext.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
	smContext.UpCnxState = models.UPCNXSTATE_DEACTIVATED

	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{FirstDPNode: &context.DataPathNode{UPF: &context.UPF{}}})
	for _, c := range smContext.PFCPContext {
		seid = c.LocalSEID
	}
	return smContext, seid, paged.Load
}

// A Report Type announcing downlink data carries the Downlink Data Report (TS 29.244 Table
// 7.5.8.1-1). A report that does not is malformed, and the UE is not paged on its account: the
// AMF would be asked to reach a UE for data the user plane did not describe.
func TestAReportAnnouncingDownlinkDataWithoutItDoesNotPageTheUE(t *testing.T) {
	initMissingIEConfig(t)
	for _, tc := range []struct {
		name       string
		ies        []*ie.IE
		wantPaging int32
	}{
		// The control: the same session and AMF, and a well-formed report does page, so the case
		// below is not quiet merely because the fixture never reaches the paging.
		{"well-formed", []*ie.IE{ie.NewReportType(0, 0, 0, 1), ie.NewDownlinkDataReport(ie.NewPDRID(1))}, 1},
		{"report announced, none carried", []*ie.IE{ie.NewReportType(0, 0, 0, 1)}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, seid, pagings := pageableSession(t, "imsi-208930000099002")

			HandlePfcpSessionReportRequest(fromUPF(decoded(t, message.NewSessionReportRequest(0, 0, seid, 7005, 0, tc.ies...))))

			if got := pagings(); got != tc.wantPaging {
				t.Errorf("the AMF was asked to page the UE %d time(s), want %d", got, tc.wantPaging)
			}
		})
	}
}

// A Heartbeat Response or an Association Setup Response the SMF cannot use still consumes the
// pending entry for its sequence number. The transport has completed the request's transaction on
// receiving it, so nothing else would ever remove the entry.
func TestAnAssociationSetupResponseItCannotUseStillConsumesItsPendingEntry(t *testing.T) {
	initMissingIEConfig(t)
	for _, tc := range []struct {
		name string
		ies  []*ie.IE
	}{
		{"no Cause", []*ie.IE{ie.NewNodeID("10.99.0.4", "", ""), ie.NewRecoveryTimeStamp(time.Now())}},
		{"no NodeID", []*ie.IE{ie.NewCause(ie.CauseRequestAccepted), ie.NewRecoveryTimeStamp(time.Now())}},
		{"rejected", []*ie.IE{ie.NewNodeID("10.99.0.4", "", ""), ie.NewCause(ie.CauseRequestRejected)}},
		{"accepted, no RecoveryTimeStamp", []*ie.IE{ie.NewNodeID("10.99.0.4", "", ""), ie.NewCause(ie.CauseRequestAccepted)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, nodeID := registeredUPF(t, "10.99.0.4")
			const seq = 7006
			pfcp_message.InsertPfcpTxn(seq, nodeID)
			t.Cleanup(func() { pfcp_message.FetchPfcpTxn(seq) })

			HandlePfcpAssociationSetupResponse(fromUPF(decoded(t, message.NewAssociationSetupResponse(seq, tc.ies...))))

			if left := pfcp_message.FetchPfcpTxn(seq); left != nil {
				t.Errorf("the pending entry for sequence %d was left behind", seq)
			}
		})
	}
}
