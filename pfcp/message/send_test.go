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
	"github.com/wmnsk/go-pfcp/ie"
)

func BoolPointer(b bool) *bool {
	return &b
}

func TestSendPfcpAssociationSetupRequest(t *testing.T) {
	kafkaInfo := factory.KafkaInfo{
		EnableKafka: BoolPointer(false),
	}
	configuration := &factory.Configuration{
		KafkaInfo: kafkaInfo,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP("2.3.4.5").To4(),
	}
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("2.3.4.5"),
		Port: 8805,
	}

	message.SendPfcpAssociationSetupRequest(remoteAddr, upNodeID)
}

func TestSendPfcpAssociationSetupResponse(t *testing.T) {
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("2.2.3.4"),
		Port: 8805,
	}

	message.SendPfcpAssociationSetupResponse(remoteAddr, ie.CauseRequestAccepted)
}

func TestSendPfcpSessionEstablishmentRequest(t *testing.T) {
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP("2.3.4.5").To4(),
	}

	smContext := &context.SMContext{}

	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("2.3.4.5"),
		Port: 8805,
	}

	pdrList := []*context.PDR{}
	farList := []*context.FAR{}
	barList := []*context.BAR{}
	qerList := []*context.QER{}

	message.SendPfcpSessionEstablishmentRequest(remoteAddr, upNodeID, smContext, pdrList, farList, barList, qerList)
}

func TestSendHeartbeatRequest(t *testing.T) {
	configuration := &factory.Configuration{
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NodeID{
		NodeIdType:  context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP("2.3.4.5").To4(),
	}
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("2.3.4.5"),
		Port: 8805,
	}

	message.SendHeartbeatRequest(remoteAddr, upNodeID)
}

func TestSendHeartbeatResponse(t *testing.T) {
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 7001,
	}

	message.SendHeartbeatResponse(remoteAddr, 1)
}
