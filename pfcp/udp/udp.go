// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package udp

import (
	"fmt"
	"net"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/wmnsk/go-pfcp/message"
)

const PFCP_MAX_UDP_LEN = 2048

type PfcpServer struct {
	SrcAddr *net.UDPAddr
	Conn    *net.UDPConn
}

var (
	Server          *PfcpServer
	ServerStartTime time.Time
)

func Run(sourceAddress *net.UDPAddr, Dispatch func(message.Message, *net.UDPAddr)) {
	ServerStartTime = time.Now()
	conn, err := net.ListenUDP("udp", sourceAddress)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to listen on UDP: %v", err)
		return
	}
	defer conn.Close()
	Server = &PfcpServer{
		SrcAddr: sourceAddress,
		Conn:    conn,
	}
	logger.PfcpLog.Infof("PFCP server listening on %s", sourceAddress.String())
	buf := make([]byte, PFCP_MAX_UDP_LEN)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logger.PfcpLog.Errorf("Error reading from UDP: %v", err)
			continue
		}
		msg, err := message.Parse(buf[:n])
		if err != nil {
			logger.PfcpLog.Errorf("Error parsing PFCP message: %v", err)
			continue
		}
		Dispatch(msg, remoteAddr)
	}
}

func WaitForServer() error {
	timeout := 10 * time.Second
	t0 := time.Now()
	for {
		if time.Since(t0) > timeout {
			return fmt.Errorf("timeout waiting for PFCP server to start")
		}
		if Server != nil && Server.Conn != nil {
			return nil
		}
		logger.PfcpLog.Infof("Waiting for PFCP server to start...")
		time.Sleep(1 * time.Second)
	}
}

func SendPfcp(msg message.Message, addr *net.UDPAddr) error {
	if Server == nil {
		return fmt.Errorf("PFCP server is nil")
	}
	if Server.Conn == nil {
		return fmt.Errorf("PFCP server connection is nil")
	}
	buf := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(buf)
	if err != nil {
		metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "Out", "Failure", err.Error())
		return fmt.Errorf("failed to marshal PFCP message: %v", err)
	}
	_, err = Server.Conn.WriteToUDP(buf, addr)
	if err != nil {
		metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "Out", "Failure", err.Error())
		return fmt.Errorf("failed to write PFCP message to udp: %v", err)
	}
	metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "Out", "Success", "")
	return nil
}
