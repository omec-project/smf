// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package message_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
	"go.uber.org/zap"
)

func boolPointer(b bool) *bool {
	return &b
}

var initTestSmfConfigOnce sync.Once

func initTestSmfConfig() {
	initTestSmfConfigOnce.Do(func() {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo: factory.KafkaInfo{
					EnableKafka: boolPointer(false),
				},
				EnableUpfAdapter: false,
			},
		}
	})
}

func setTestServer(t *testing.T, server *udp.PfcpServer) {
	t.Helper()
	originalServer := udp.GetServer()
	udp.SetServer(server)
	t.Cleanup(func() {
		udp.SetServer(originalServer)
	})
}

func TestSendPfcpAssociationSetupRequest(t *testing.T) {
	initTestSmfConfig()
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP("127.0.0.1").To4(),
	}
	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8801,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("error listening on UDP: %v", err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			t.Logf("error closing connection: %v", err)
		}
	}()

	setTestServer(t, &udp.PfcpServer{
		Conn: conn,
	})

	err = message.SendPfcpAssociationSetupRequest(upNodeID, 8801)
	if err != nil {
		t.Errorf("error sending PFCP Association Setup Request: %v", err)
	}
}

func TestSendPfcpAssociationSetupResponse(t *testing.T) {
	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8802,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("error listening on UDP: %v", err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			t.Logf("error closing connection: %v", err)
		}
	}()

	setTestServer(t, &udp.PfcpServer{
		Conn: conn,
	})

	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP("127.0.0.1").To4(),
	}

	err = message.SendPfcpAssociationSetupResponse(upNodeID, ie.CauseRequestAccepted, 8802)
	if err != nil {
		t.Errorf("error sending PFCP Association Setup Response: %v", err)
	}
}

// When the User Plane Node exists in the stored context, then the PFCP Session Establishment Request is sent
func TestSendPfcpSessionEstablishmentRequestUpNodeExists(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	initTestSmfConfig()
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	config := zap.NewProductionConfig()
	log, err := config.Build()
	if err != nil {
		panic(err)
	}
	mockLog := log.Sugar()
	smContext := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upNodeIDStr: {
				NodeID: upNodeID,
			},
		},
		SubPduSessLog: mockLog,
		SubPfcpLog:    mockLog,
	}

	pdrList := []*context.PDR{}
	farList := []*context.FAR{}
	barList := []*context.BAR{}
	qerList := []*context.QER{}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8803,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("error listening on UDP: %v", err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			t.Logf("error closing connection: %v", err)
		}
	}()

	setTestServer(t, &udp.PfcpServer{
		Conn: conn,
	})

	err = message.SendPfcpSessionEstablishmentRequest(upNodeID, smContext, pdrList, farList, barList, qerList, 8803)
	if err != nil {
		t.Errorf("error sending PFCP Session Establishment Request: %v", err)
	}
}

// Given the User Plane Node does not exist in the stored context, then the PFCP Session Establishment Request is not sent
func TestSendPfcpSessionEstablishmentRequestUpNodeDoesNotExist(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	initTestSmfConfig()
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	smContext := &context.SMContext{}

	pdrList := []*context.PDR{}
	farList := []*context.FAR{}
	barList := []*context.BAR{}
	qerList := []*context.QER{}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8804,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("error listening on UDP: %v", err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			t.Logf("error closing connection: %v", err)
		}
	}()

	setTestServer(t, &udp.PfcpServer{
		Conn: conn,
	})

	err = message.SendPfcpSessionEstablishmentRequest(upNodeID, smContext, pdrList, farList, barList, qerList, 8804)
	if err == nil {
		t.Errorf("expected error sending PFCP Session Establishment Request")
	}
}

func TestSendPfcpSessionModificationRequest(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	initTestSmfConfig()
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	config := zap.NewProductionConfig()
	log, err := config.Build()
	if err != nil {
		panic(err)
	}
	mockLog := log.Sugar()
	smContext := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upNodeIDStr: {
				NodeID: upNodeID,
			},
		},
		SubPduSessLog: mockLog,
		SubPfcpLog:    mockLog,
	}

	pdrList := []*context.PDR{}
	farList := []*context.FAR{}
	barList := []*context.BAR{}
	qerList := []*context.QER{}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8806,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("error listening on UDP: %v", err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			t.Logf("error closing connection: %v", err)
		}
	}()

	setTestServer(t, &udp.PfcpServer{
		Conn: conn,
	})

	err = message.SendPfcpSessionModificationRequest(upNodeID, smContext, pdrList, farList, barList, qerList, nil, nil, nil, 8806)
	if err != nil {
		t.Errorf("error sending PFCP Session Modification Request: %v", err)
	}
}

func TestSendPfcpSessionDeletionRequest(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	initTestSmfConfig()
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	config := zap.NewProductionConfig()
	log, err := config.Build()
	if err != nil {
		panic(err)
	}
	mockLog := log.Sugar()
	smContext := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upNodeIDStr: {
				NodeID: upNodeID,
			},
		},
		SubPduSessLog: mockLog,
		SubPfcpLog:    mockLog,
	}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8807,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("error listening on UDP: %v", err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			t.Logf("error closing connection: %v", err)
		}
	}()

	setTestServer(t, &udp.PfcpServer{
		Conn: conn,
	})

	err = message.SendPfcpSessionDeletionRequest(upNodeID, smContext, 8807)
	if err != nil {
		t.Errorf("error sending PFCP Session Deletion Request: %v", err)
	}
}

func TestSendPfcpSessionReportResponse(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 8808,
	}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8808,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("error listening on UDP: %v", err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			t.Logf("error closing connection: %v", err)
		}
	}()

	setTestServer(t, &udp.PfcpServer{
		Conn: conn,
	})

	flags := context.PFCPSRRspFlags{}
	err = message.SendPfcpSessionReportResponse(remoteAddr, ie.CauseRequestAccepted, flags, 1, 1)
	if err != nil {
		t.Errorf("error sending PFCP Session Report Response: %v", err)
	}
}

func TestSendHeartbeatRequest(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	initTestSmfConfig()
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8809,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("error listening on UDP: %v", err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			t.Logf("error closing connection: %v", err)
		}
	}()

	setTestServer(t, &udp.PfcpServer{
		Conn: conn,
	})

	err = message.SendHeartbeatRequest(upNodeID, 8809)
	if err != nil {
		t.Errorf("error sending Heartbeat Request: %v", err)
	}
}

func TestSendHeartbeatResponse(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 7001,
	}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8810,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("error listening on UDP: %v", err)
	}

	defer func() {
		if err = conn.Close(); err != nil {
			t.Logf("error closing connection: %v", err)
		}
	}()

	setTestServer(t, &udp.PfcpServer{
		Conn: conn,
	})

	err = message.SendHeartbeatResponse(remoteAddr, 1)
	if err != nil {
		t.Errorf("error sending Heartbeat Response: %v", err)
	}
}

func JsonBodyToPfcpHeartbeatReq(body []byte) pfcp_message.HeartbeatRequest {
	heartbeatRequest, err := pfcp_message.ParseHeartbeatRequest(body)
	if err != nil {
		panic(fmt.Sprintf("error parsing JSON: %v", err))
	}
	return *heartbeatRequest
}

func TestSendPfcpMsgToAdapter(t *testing.T) {
	timestamp := time.Now()
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected method %s, got %s", http.MethodPost, r.Method)
			return
		}

		// Validate request body
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("could not read request body: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		var udpPodMsg message.UdpPodPfcpMsg
		err = json.Unmarshal(reqBody, &udpPodMsg)
		if err != nil {
			t.Fatalf("error unmarshalling JSON: %v", err)
			return
		}

		heartbeatRequest := JsonBodyToPfcpHeartbeatReq(udpPodMsg.Msg.Body)
		if heartbeatRequest.RecoveryTimeStamp == nil {
			t.Fatalf("expected RecoveryTimeStamp, got nil")
			return
		}

		receivedTimestamp, err := heartbeatRequest.RecoveryTimeStamp.RecoveryTimeStamp()
		if err != nil {
			t.Fatalf("error getting RecoveryTimeStamp: %v", err)
			return
		}
		if timestamp.Truncate(1*time.Second) != receivedTimestamp.Truncate(1*time.Second) {
			t.Fatalf("expected timestamp %v, got %v", timestamp, receivedTimestamp)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	upNodeID := context.NewNodeID("testNodeID")
	msg := pfcp_message.NewHeartbeatRequest(
		1,
		ie.NewRecoveryTimeStamp(timestamp),
		nil,
	)
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	rsp, err := message.SendPfcpMsgToAdapter(*upNodeID, msg, addr, nil, testServer.URL)
	if err != nil {
		t.Fatalf("error sending PFCP message to adapter: %v", err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		t.Errorf("HTTP status code mismatch. got = %d, want = %d", rsp.StatusCode, http.StatusOK)
	}
}

// A send that fails before it creates a transaction has nothing left to answer the caller: the
// timeout that ends SendPfcpSessionModifyReq's wait on SBIPFCPCommunicationChan is raised by that
// transaction. Reporting the failure is what lets the caller stop waiting; logging it and
// returning nil left the caller waiting for a response that could not arrive.
func TestSendPfcpSessionModificationRequestReportsASendThatDidNotHappen(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"

	initTestSmfConfig()

	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}

	log, err := zap.NewProductionConfig().Build()
	if err != nil {
		t.Fatalf("building a logger: %v", err)
	}

	smContext := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upNodeIDStr: {NodeID: upNodeID},
		},
		SubPduSessLog: log.Sugar(),
		SubPfcpLog:    log.Sugar(),
	}

	// No server, so udp.SendPfcp refuses before any transaction exists.
	setTestServer(t, nil)

	if err := message.SendPfcpSessionModificationRequest(upNodeID, smContext,
		nil, nil, nil, nil, nil, nil, nil, 8806); err == nil {
		t.Error("a modification the UDP layer refused was reported as sent; the caller waits for an answer to it")
	}
}

// A modification that never left the SMF has to leave its rules as it found them. The builder
// marks every rule it is handed as applied while it builds, so a send that then failed left the
// session believing the user plane held rules it had never received -- a removal recorded as done,
// an update recorded as applied -- and the next modification, which sends only rules not yet
// applied, skipped them for good.
//
// Removal and update states are used because they build without a full rule behind them, and
// because they are the cases where the damage is quietest: nothing is missing from the SMF's view.
func TestAModificationThatNeverWentOutLeavesItsRulesAsTheyWere(t *testing.T) {
	const upNodeIDStr = "127.0.0.1"

	initTestSmfConfig()

	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}

	log, err := zap.NewProductionConfig().Build()
	if err != nil {
		t.Fatalf("building a logger: %v", err)
	}

	smContext := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upNodeIDStr: {NodeID: upNodeID, LocalSEID: 11, RemoteSEID: 12},
		},
		SubPduSessLog: log.Sugar(),
		SubPfcpLog:    log.Sugar(),
	}

	// No server, so udp.SendPfcp refuses after the request has been built.
	setTestServer(t, nil)

	pdr := &context.PDR{PDRID: 1, State: context.RULE_REMOVE}
	far := &context.FAR{FARID: 1, State: context.RULE_REMOVE}
	qer := &context.QER{QERID: 1, State: context.RULE_UPDATE}

	err = message.SendPfcpSessionModificationRequest(upNodeID, smContext,
		[]*context.PDR{pdr}, []*context.FAR{far}, nil, []*context.QER{qer}, nil, nil, nil, 8806)
	if !errors.Is(err, message.ErrRequestNotSent) {
		t.Fatalf("error = %v, want one saying nothing went out", err)
	}

	if pdr.State != context.RULE_REMOVE || far.State != context.RULE_REMOVE || qer.State != context.RULE_UPDATE {
		t.Errorf("rule states after a request that never went out: PDR %v, FAR %v, QER %v; want them as they were",
			pdr.State, far.State, qer.State)
	}
}
