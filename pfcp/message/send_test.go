// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message_test

import (
	"net"
	"testing"
	"time"

	smf_pfcp "github.com/omec-project/smf/pfcp"
	"github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
)

func TestSendPfcpAssociationSetupRequest(t *testing.T) {
}

func TestSendPfcpSessionEstablishmentResponse(t *testing.T) {
}

func TestSendPfcpSessionEstablishmentRequest(t *testing.T) {
}

func TestSendHeartbeatResponse(t *testing.T) {
	udp.Run(smf_pfcp.Dispatch)

	udp.ServerStartTime = time.Now()
	var seq uint32 = 1
	addr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 7001,
	}
	message.SendHeartbeatResponse(addr, seq)
}
