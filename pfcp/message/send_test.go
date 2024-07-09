// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"
)

func BoolPointer(b bool) *bool {
	return &b
}

func TestSendPfcpAssociationSetupRequest(t *testing.T) {
	const upNodeIDStr = "1.1.1.1"
	kafkaInfo := factory.KafkaInfo{
		EnableKafka: BoolPointer(false),
	}
	configuration := &factory.Configuration{
		KafkaInfo:        kafkaInfo,
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 8805,
	}
	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8801,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		SrcAddr: remoteAddr,
		Conn:    conn,
	}

	err = message.SendPfcpAssociationSetupRequest(remoteAddr, upNodeID)
	if err != nil {
		t.Errorf("Error sending PFCP Association Setup Request: %v", err)
	}
}

func TestSendPfcpAssociationSetupResponse(t *testing.T) {
	const upNodeIDStr = "2.2.2.2"
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 8805,
	}
	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8802,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		SrcAddr: remoteAddr,
		Conn:    conn,
	}

	err = message.SendPfcpAssociationSetupResponse(remoteAddr, ie.CauseRequestAccepted)
	if err != nil {
		t.Errorf("Error sending PFCP Association Setup Response: %v", err)
	}
}

// When the User Plane Node exists in the stored context, then the PFCP Session Establishment Request is sent
func TestSendPfcpSessionEstablishmentRequestUpNodeExists(t *testing.T) {
	const upNodeIDStr = "3.3.3.3"
	configuration := &factory.Configuration{
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	log := logrus.New()
	mockLog := log.WithFields(logrus.Fields{})
	smContext := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upNodeIDStr: {
				NodeID: upNodeID,
			},
		},
		SubPduSessLog: mockLog,
		SubPfcpLog:    mockLog,
	}

	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 8805,
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
		t.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		SrcAddr: remoteAddr,
		Conn:    conn,
	}

	err = message.SendPfcpSessionEstablishmentRequest(remoteAddr, upNodeID, smContext, pdrList, farList, barList, qerList)
	if err != nil {
		t.Errorf("Error sending PFCP Session Establishment Request: %v", err)
	}
}

// Given the User Plane Node does not exist in the stored context, then the PFCP Session Establishment Request is not sent
func TestSendPfcpSessionEstablishmentRequestUpNodeDoesNotExist(t *testing.T) {
	const upNodeIDStr = "4.4.4.4"
	configuration := &factory.Configuration{
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	smContext := &context.SMContext{}

	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 8805,
	}

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
		t.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		SrcAddr: remoteAddr,
		Conn:    conn,
	}

	err = message.SendPfcpSessionEstablishmentRequest(remoteAddr, upNodeID, smContext, pdrList, farList, barList, qerList)
	if err == nil {
		t.Errorf("Expected error sending PFCP Session Establishment Request")
	}
}

func TestSendPfcpSessionModificationRequest(t *testing.T) {
	const upNodeIDStr = "5.5.5.5"
	configuration := &factory.Configuration{
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	log := logrus.New()
	mockLog := log.WithFields(logrus.Fields{})
	smContext := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upNodeIDStr: {
				NodeID: upNodeID,
			},
		},
		SubPduSessLog: mockLog,
		SubPfcpLog:    mockLog,
	}
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 8805,
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
		t.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		SrcAddr: remoteAddr,
		Conn:    conn,
	}

	seq, err := message.SendPfcpSessionModificationRequest(remoteAddr, upNodeID, smContext, pdrList, farList, barList, qerList)
	if err != nil {
		t.Errorf("Error sending PFCP Session Modification Request: %v", err)
	}
	if seq == 0 {
		t.Errorf("Expected sequence number to be non-zero")
	}
}

func TestSendPfcpSessionDeletionRequest(t *testing.T) {
	const upNodeIDStr = "6.6.6.6"
	configuration := &factory.Configuration{
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	log := logrus.New()
	mockLog := log.WithFields(logrus.Fields{})
	smContext := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upNodeIDStr: {
				NodeID: upNodeID,
			},
		},
		SubPduSessLog: mockLog,
		SubPfcpLog:    mockLog,
	}
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 8805,
	}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8807,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}

	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		SrcAddr: remoteAddr,
		Conn:    conn,
	}

	seq, err := message.SendPfcpSessionDeletionRequest(upNodeID, smContext, 8805)
	if err != nil {
		t.Errorf("Error sending PFCP Session Deletion Request: %v", err)
	}
	if seq == 0 {
		t.Errorf("Expected sequence number to be non-zero")
	}
}

func TestSendPfcpSessionReportResponse(t *testing.T) {
	const upNodeIDStr = "7.7.7.7"
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 8805,
	}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8808,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}

	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		SrcAddr: remoteAddr,
		Conn:    conn,
	}

	err = message.SendPfcpSessionReportResponse(remoteAddr, ie.CauseRequestAccepted, true, 1, 1)
	if err != nil {
		t.Errorf("Error sending PFCP Session Report Response: %v", err)
	}
}

func TestSendHeartbeatRequest(t *testing.T) {
	const upNodeIDStr = "8.8.8.8"
	configuration := &factory.Configuration{
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP(upNodeIDStr).To4(),
	}
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(upNodeIDStr),
		Port: 8805,
	}

	localAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8809,
	}

	conn, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		t.Fatalf("Error listening on UDP: %v", err)
	}

	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		SrcAddr: remoteAddr,
		Conn:    conn,
	}

	err = message.SendHeartbeatRequest(remoteAddr, upNodeID)
	if err != nil {
		t.Errorf("Error sending Heartbeat Request: %v", err)
	}
}

func TestSendHeartbeatResponse(t *testing.T) {
	const upNodeIDStr = "9.9.9.9"
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
		t.Fatalf("Error listening on UDP: %v", err)
	}

	defer conn.Close()

	udp.Server = &udp.PfcpServer{
		SrcAddr: remoteAddr,
		Conn:    conn,
	}

	err = message.SendHeartbeatResponse(remoteAddr, 1)
	if err != nil {
		t.Errorf("Error sending Heartbeat Response: %v", err)
	}
}
