// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler_test

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/handler"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type Flag uint8

// setBit sets the bit at the given position to the specified value (true or false)
// Positions go from 1 to 8
func (f *Flag) setBit(position uint8) {
	if position < 1 || position > 8 {
		return
	}
	*f |= 1 << (position - 1)
}

func boolPointer(b bool) *bool {
	return &b
}

func TestFindUEIPAddressNoAddressInCreatedPDR(t *testing.T) {
	sessionEstablishmentResponse := message.NewSessionEstablishmentResponse(
		0,
		0,
		0,
		0,
		0,
		ie.NewCreatedPDR(
			ie.NewPDRID(12345),
		),
	)

	createdPDRIEs := sessionEstablishmentResponse.CreatedPDR

	ipAddress := handler.FindUEIPAddress(createdPDRIEs)

	if ipAddress != nil {
		t.Errorf("Expected nil, got %v", ipAddress)
	}
}

func TestFindUEIPAddressNoUEIPAddressInCreatedPDR(t *testing.T) {
	ueIPAddressFlags := new(Flag)
	ueIPAddressFlags.setBit(2)
	sessionEstablishmentResponse := message.NewSessionEstablishmentResponse(
		0,
		0,
		0,
		0,
		0,
		ie.NewCreatedPDR(
			ie.NewPDRID(12345),
			ie.NewUEIPAddress(uint8(*ueIPAddressFlags), "1.2.3.4", "", 0, 0),
		),
	)

	createdPDRIEs := sessionEstablishmentResponse.CreatedPDR

	ipAddress := handler.FindUEIPAddress(createdPDRIEs)

	if !ipAddress.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("Expected %v, got %v", "1.2.3.4", ipAddress)
	}
}

func TestHandlePfcpAssociationSetupResponse(t *testing.T) {
	kafkaInfo := factory.KafkaInfo{
		EnableKafka: boolPointer(false),
	}
	configuration := &factory.Configuration{
		KafkaInfo:        kafkaInfo,
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NewNodeID("1.1.1.1")
	upf := context.NewUPF(upNodeID, nil)
	SnssaiInfos := make([]context.SnssaiUPFInfo, 0)
	snssaiInfo := context.SnssaiUPFInfo{
		DnnList: []context.DnnUPFInfoItem{
			{
				Dnn: "internet",
			},
		},
	}
	SnssaiInfos = append(SnssaiInfos, snssaiInfo)
	upf.SNssaiInfos = SnssaiInfos
	pfcp_message.InsertPfcpTxn(1, upNodeID)
	recoveryTimestamp := time.Now()
	msg := message.NewAssociationSetupResponse(
		1,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("1.1.1.1", "", ""),
		ie.NewRecoveryTimeStamp(recoveryTimestamp),
	)

	remoteAddress := &net.UDPAddr{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 8810,
	}
	udpMessage := udp.Message{
		RemoteAddr:  remoteAddress,
		PfcpMessage: msg,
	}

	handler.HandlePfcpAssociationSetupResponse(&udpMessage)

	if upf.UPFStatus != context.AssociatedSetUpSuccess {
		t.Errorf("Expected UPFStatus %v, got %v", context.AssociatedSetUpSuccess, upf.UPFStatus)
	}
	if upf.RecoveryTimeStamp.RecoveryTimeStamp.Truncate(1*time.Second) != recoveryTimestamp.Truncate(1*time.Second) {
		t.Errorf("Expected RecoveryTimeStamp %v, got %v", recoveryTimestamp.Truncate(1*time.Second), upf.RecoveryTimeStamp.RecoveryTimeStamp.Truncate(1*time.Second))
	}
}

func TestHandlePfcpSessionEstablishmentResponse(t *testing.T) {
	recoveryTimestamp := time.Now()
	nodeID := context.NewNodeID("1.1.1.1")
	smContext := context.NewSMContext("imsi-123456789012345", 10)

	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			10: &context.DataPath{
				IsDefaultPath: true,
				FirstDPNode: &context.DataPathNode{
					UPF: &context.UPF{},
					UpLinkTunnel: &context.GTPTunnel{
						TEID: 0,
					},
				},
			},
		},
		ANInformation: struct {
			IPAddress net.IP
			TEID      uint32
		}{
			IPAddress: net.ParseIP("192.168.1.1"),
			TEID:      0,
		},
	}

	smContext.PFCPContext = map[string]*context.PFCPSessionContext{
		nodeID.ResolveNodeIdToIp().String(): {
			RemoteSEID: 12345,
		},
	}

	datapath := &context.DataPath{
		FirstDPNode: &context.DataPathNode{
			UPF: &context.UPF{},
		},
	}
	smContext.AllocateLocalSEIDForDataPath(datapath)
	pfcp_message.InsertPfcpTxn(1, nodeID)

	rsp := message.NewSessionEstablishmentResponse(
		0,
		0,
		1,
		1,
		0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("1.1.1.1", "", ""),
		ie.NewRecoveryTimeStamp(recoveryTimestamp),
		ie.NewCreatedPDR(
			ie.NewFTEID(0, 4321, net.ParseIP("192.168.1.1"), nil, 0),
		),
	)

	udpMessage := udp.Message{
		RemoteAddr: &net.UDPAddr{
			IP:   net.ParseIP("1.1.1.1"),
			Port: 8809,
		},
		PfcpMessage: rsp,
	}

	handler.HandlePfcpSessionEstablishmentResponse(&udpMessage)

	if smContext.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode.UpLinkTunnel.TEID != 4321 {
		t.Errorf("Expected TEID 4321, got %d", smContext.Tunnel.ANInformation.TEID)
	}

	expectedIP := net.ParseIP("192.168.1.1")
	if !smContext.Tunnel.ANInformation.IPAddress.Equal(expectedIP) {
		t.Errorf("Expected ANInformation IP %v, got %v", expectedIP, smContext.Tunnel.ANInformation.IPAddress)
	}
}
