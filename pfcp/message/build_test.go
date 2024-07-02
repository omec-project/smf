// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package message_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/util/util_3gpp"
	"github.com/wmnsk/go-pfcp/ie"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
)

func outerHeaderRemovalSet(pdrIEs []*ie.IE) bool {
	for _, pdrIE := range pdrIEs {
		createPdr, err := pdrIE.CreatePDR()
		if err != nil {
			return false
		}

		for _, x := range createPdr {
			outerHeaderRemoval, err := x.OuterHeaderRemoval()
			if err == nil && outerHeaderRemoval != nil {
				return true
			}
		}
	}
	return false
}

func TestBuildPfcpSessionEstablishmentRequest(t *testing.T) {
	cpIpv4Address := net.ParseIP("2.3.4.5")
	upIpv4Adddress := net.ParseIP("1.2.3.4")
	context.SMF_Self().CPNodeID = context.NodeID{
		NodeIdType:  0,
		NodeIdValue: cpIpv4Address,
	}
	upNodeID := context.NodeID{
		NodeIdType:  0,
		NodeIdValue: upIpv4Adddress.To4(),
	}
	ctx := &context.SMContext{
		PFCPContext: map[string]*context.PFCPSessionContext{
			upIpv4Adddress.String(): {
				LocalSEID:  1,
				RemoteSEID: 2,
			},
		},
	}
	pdrList := []*context.PDR{
		{
			OuterHeaderRemoval: &context.OuterHeaderRemoval{},
			PDRID:              1,
			Precedence:         123,
			FAR:                &context.FAR{},
			PDI: context.PDI{
				LocalFTeid:      &context.FTEID{},
				UEIPAddress:     &context.UEIPAddress{},
				SDFFilter:       &context.SDFFilter{},
				ApplicationID:   "app",
				NetworkInstance: util_3gpp.Dnn{},
				SourceInterface: context.SourceInterface{
					InterfaceValue: 0x11,
				},
			},
		},
	}
	farList := []*context.FAR{}
	barList := []*context.BAR{}
	qerList := []*context.QER{}

	msg, err := message.BuildPfcpSessionEstablishmentRequest(upNodeID, ctx, pdrList, farList, barList, qerList)
	if err != nil {
		t.Fatalf("Error building PFCP session establishment request: %v", err)
	}

	if msg.MessageTypeName() != "Session Establishment Request" {
		t.Errorf("Expected message type to be 'ban', got %v", msg.MessageTypeName())
	}

	buf := make([]byte, msg.MarshalLen())
	err = msg.MarshalTo(buf)
	if err != nil {
		t.Fatalf("Error marshalling PFCP session establishment request: %v", err)
	}

	req, err := pfcp_message.ParseSessionEstablishmentRequest(buf)
	if err != nil {
		t.Fatalf("Error parsing PFCP session establishment request: %v", err)
	}

	nodeID, err := req.NodeID.NodeID()
	if err != nil {
		t.Fatalf("Error getting NodeID from PFCP session establishment request: %v", err)
	}

	if nodeID != "2.3.4.5" {
		t.Errorf("Expected NodeID to be '2.3.4.5', got %v", nodeID)
	}

	pdr := req.CreatePDR
	if pdr == nil {
		t.Fatalf("Expected CreatedPDR to be non-nil")
	}

	if !outerHeaderRemovalSet(pdr) {
		t.Errorf("Expected OuterHeaderRemoval to be set")
	}
}
