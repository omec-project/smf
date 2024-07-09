// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package udp_test

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

var (
	heartbeatRequestReceived    bool
	associationResponseReceived bool
)

func HandlePfcpHeartbeatRequestTest(msg message.Message, remoteAddress *net.UDPAddr) {
	heartbeatRequestReceived = true
}

func HandleAssociationSetupResponseTest(msg message.Message, remoteAddress *net.UDPAddr) {
	associationResponseReceived = true
}

func Dispatch(msg message.Message, remoteAddress *net.UDPAddr) {
	switch msg.MessageType() {
	case message.MsgTypeHeartbeatRequest:
		HandlePfcpHeartbeatRequestTest(msg, remoteAddress)
	case message.MsgTypeAssociationSetupResponse:
		HandleAssociationSetupResponseTest(msg, remoteAddress)
	}
}

func TestRun(t *testing.T) {
	sourceAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8805,
	}

	go udp.Run(sourceAddress, Dispatch)
	err := udp.WaitForServer()
	if err != nil {
		t.Fatalf("Failed to start PFCP server: %v", err)
	}

	time.Sleep(1 * time.Second)

	setupRequest := message.NewHeartbeatRequest(
		1,
		ie.NewRecoveryTimeStamp(time.Now()),
		nil,
	)

	associationResponse := message.NewAssociationSetupResponse(
		1,
		ie.NewNodeID("2.3.4.5", "", ""),
	)

	dstAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8805,
	}

	err = udp.SendPfcp(setupRequest, dstAddr)
	if err != nil {
		t.Errorf("Failed to send PFCP message: %v", err)
	}

	err = udp.SendPfcp(associationResponse, dstAddr)
	if err != nil {
		t.Errorf("Failed to send PFCP message: %v", err)
	}

	time.Sleep(1 * time.Second)

	if !heartbeatRequestReceived {
		t.Error("Expected Heartbeat Request to be received")
	}

	if !associationResponseReceived {
		t.Error("Expected Association Response to be received")
	}
}

func TestNewServer(t *testing.T) {
	sourceAddress := &net.UDPAddr{
		IP:   net.ParseIP("1.2.3.4"),
		Port: 8805,
	}

	s := udp.PfcpServer{
		SrcAddr: sourceAddress,
	}

	if s.SrcAddr != sourceAddress {
		t.Errorf("Expected %v, got %v", sourceAddress, s.SrcAddr)
	}
}

func TestServerSendPfcp(t *testing.T) {
	remoteAddress := &net.UDPAddr{
		IP:   net.ParseIP("10.152.183.116"),
		Port: 8805,
	}

	msg := message.NewAssociationSetupResponse(1)

	err := udp.SendPfcp(msg, remoteAddress)
	if err != nil {
		t.Errorf("Failed to send PFCP message: %v", err)
	}
}

func TestServerNotSetSendPfcp(t *testing.T) {
	udp.Server = nil

	remoteAddress := &net.UDPAddr{
		IP:   net.ParseIP("1.2.3.4"),
		Port: 8805,
	}

	msg := message.NewAssociationSetupResponse(1)

	err := udp.SendPfcp(msg, remoteAddress)

	if err == nil {
		t.Error("Expected error, got nil")
	}
}
