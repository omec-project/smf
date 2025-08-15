// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package udp_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type Server struct {
	addr *net.UDPAddr
	Conn *net.UDPConn
}

func (s *Server) Start() error {
	conn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return err
	}
	s.Conn = conn
	return nil
}

func (s *Server) SendPFCPMessage(msg message.Message, remoteAddress *net.UDPAddr) error {
	buf := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(buf)
	if err != nil {
		return err
	}

	_, err = s.Conn.WriteToUDP(buf, remoteAddress)
	if err != nil {
		return err
	}
	return nil
}

func TestRun(t *testing.T) {
	context.SMF_Self().CPNodeID = context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP("127.0.0.1").To4(),
	}
	context.SMF_Self().PFCPPort = 8811

	gotHeartBeat := make(chan struct{}, 1)
	dispatch := func(msg *udp.Message) {
		if msg != nil && msg.PfcpMessage != nil &&
			msg.PfcpMessage.MessageType() == message.MsgTypeHeartbeatRequest {
			select {
			case gotHeartBeat <- struct{}{}:
			default:
			}
		}
	}

	go udp.Run(dispatch)
	if err := udp.WaitForServer(); err != nil {
		t.Errorf("failed to start PFCP server: %v", err)
	}
	defer func() {
		if udp.Server != nil && udp.Server.Conn != nil {
			_ = udp.Server.Conn.Close()
		}
	}()

	sender := &Server{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}
	if err := sender.Start(); err != nil {
		t.Errorf("start sender: %v", err)
	}
	defer sender.Conn.Close()

	req := message.NewHeartbeatRequest(1, ie.NewRecoveryTimeStamp(time.Now()), nil)
	if err := sender.SendPFCPMessage(req, udp.Server.Addr); err != nil {
		t.Errorf("send PFCP: %v", err)
	}

	select {
	case <-gotHeartBeat:
	case <-time.After(2 * time.Second):
		t.Error("expected Heartbeat Request to be received")
	}
}

func TestServerSendPfcp(t *testing.T) {
	msg := message.NewAssociationSetupResponse(uint32(time.Now().UnixNano()))
	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(context.DefaultPfcpPort)}
	if udp.Server != nil && udp.Server.Conn != nil {
		if err := udp.SendPfcp(msg, remote, nil); err != nil {
			t.Errorf("failed to send PFCP message with running server: %v", err)
		}
		return
	}
	local := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(context.DefaultPfcpPort)}
	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		t.Errorf("error listening on UDP: %v", err)
	}
	defer conn.Close()

	orig := udp.Server
	udp.Server = &udp.PfcpServer{Conn: conn}
	defer func() { udp.Server = orig }()

	if err := udp.SendPfcp(msg, remote, nil); err != nil {
		t.Errorf("failed to send PFCP message: %v", err)
	}
}

func TestServerNotSetSendPfcp(t *testing.T) {
	if udp.Server != nil && udp.Server.Conn != nil {
		t.Skip("PFCP server already running; skipping 'not set' case")
	}

	orig := udp.Server
	udp.Server = &udp.PfcpServer{}
	defer func() { udp.Server = orig }()

	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(context.DefaultPfcpPort)}
	msg := message.NewAssociationSetupResponse(1)

	err := udp.SendPfcp(msg, remote, nil)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not listening") && !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("unexpected error: %v", err)
	}
}
