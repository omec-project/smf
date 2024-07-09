// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/handler"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type Flag uint8

// SetBit sets the bit at the given position to the specified value (true or false)
// Positions go from 1 to 8
func (f *Flag) SetBit(position uint8) {
	if position < 1 || position > 8 {
		return
	}
	*f |= 1 << (position - 1)
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
	ueIPAddressFlags.SetBit(2)
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
	upNodeID := context.NewNodeID("1.1.1.1")
	context.NewUPF(&upNodeID, nil)
	pfcp_message.InsertPfcpTxn(1, &upNodeID)
	msg := message.NewAssociationSetupResponse(
		1,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("1.1.1.1", "", ""),
		ie.NewUserPlaneIPResourceInformation(uint8(0x61), 0, "1.2.3.4", "", "", ie.SrcInterfaceAccess),
	)

	remoteAddress := &net.UDPAddr{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 8805,
	}

	handler.HandlePfcpAssociationSetupResponse(msg, remoteAddress)
	// panic("TestHandlePfcpAssociationSetupResponse")
}
