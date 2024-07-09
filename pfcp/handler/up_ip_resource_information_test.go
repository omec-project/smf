// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package handler_test

import (
	"testing"

	"github.com/omec-project/smf/pfcp/handler"
	"github.com/wmnsk/go-pfcp/ie"
)

func CreateFlags(v4 bool, v6 bool, ni bool, si bool) uint8 {
	flags := new(Flag)
	if v4 {
		flags.SetBit(1)
	}
	if v6 {
		flags.SetBit(2)
	}

	if ni {
		flags.SetBit(6)
	}

	if si {
		flags.SetBit(7)
	}

	return uint8(*flags)
}

func TestUnmarshalUEIPInformationBinaryOnlySourceInterface(t *testing.T) {
	const ipv4Address = "1.2.3.4"
	flags := CreateFlags(true, false, false, true)

	userplaneIE := ie.NewUserPlaneIPResourceInformation(flags, 0, ipv4Address, "", "", ie.SrcInterfaceAccess)

	ueIpInfo, err := handler.UnmarshalUEIPInformationBinary(userplaneIE.Payload)
	if err != nil {
		t.Errorf("Error unmarshalling UE IP Information: %v", err)
	}

	if ueIpInfo.TEIDRange != 0 {
		t.Errorf("Expected TEIDRange 0, got %d", ueIpInfo.TEIDRange)
	}

	if ueIpInfo.IPv4Address.String() != ipv4Address {
		t.Errorf("Expected IP address %v got %s", ipv4Address, ueIpInfo.IPv4Address.String())
	}

	if ueIpInfo.IPv6Address != nil {
		t.Errorf("Expected nil IPv6 address, got %s", ueIpInfo.IPv6Address.String())
	}

	if ueIpInfo.SourceInterface != ie.SrcInterfaceAccess {
		t.Errorf("Expected Source Interface Access, got %d", ueIpInfo.SourceInterface)
	}

	if ueIpInfo.NetworkInstance != "" {
		t.Errorf("Expected empty network instance, got %s", ueIpInfo.NetworkInstance)
	}
}

func TestUnmarshalUEIPInformationBinaryOnlyNetworkInstance(t *testing.T) {
	flags := CreateFlags(true, false, true, false)
	userplaneIE := ie.NewUserPlaneIPResourceInformation(flags, 0, "1.2.3.4", "", "internet", 0)

	ueIpInfo, err := handler.UnmarshalUEIPInformationBinary(userplaneIE.Payload)
	if err != nil {
		t.Errorf("Error unmarshalling UE IP Information: %v", err)
	}

	if ueIpInfo.TEIDRange != 0 {
		t.Errorf("Expected TEIDRange 0, got %d", ueIpInfo.TEIDRange)
	}

	if ueIpInfo.IPv4Address.String() != "1.2.3.4" {
		t.Errorf("Expected IP address 1.2.3.4 got %s", ueIpInfo.IPv4Address.String())
	}

	if ueIpInfo.IPv6Address != nil {
		t.Errorf("Expected nil IPv6 address, got %s", ueIpInfo.IPv6Address.String())
	}

	if ueIpInfo.SourceInterface != 0 {
		t.Errorf("Expected Source Interface 0, got %d", ueIpInfo.SourceInterface)
	}

	if ueIpInfo.NetworkInstance != "internet" {
		t.Errorf("Expected network instance internet, got %s", ueIpInfo.NetworkInstance)
	}
}

func TestUnmarshalUEIPInformationBinary(t *testing.T) {
	flags := CreateFlags(true, false, true, true)
	userplaneIE := ie.NewUserPlaneIPResourceInformation(flags, 0, "1.2.3.4", "", "internet", ie.SrcInterfaceAccess)

	ueIpInfo, err := handler.UnmarshalUEIPInformationBinary(userplaneIE.Payload)
	if err != nil {
		t.Errorf("Error unmarshalling UE IP Information: %v", err)
	}

	if ueIpInfo.Flags != 0x61 {
		t.Errorf("Expected flags 0x61, got %x", ueIpInfo.Flags)
	}

	if ueIpInfo.TEIDRange != 0 {
		t.Errorf("Expected TEIDRange 0, got %d", ueIpInfo.TEIDRange)
	}

	if ueIpInfo.IPv4Address.String() != "1.2.3.4" {
		t.Errorf("Expected IP address 1.2.3.4 got %s", ueIpInfo.IPv4Address.String())
	}

	if ueIpInfo.IPv6Address != nil {
		t.Errorf("Expected nil IPv6 address, got %s", ueIpInfo.IPv6Address.String())
	}

	if ueIpInfo.SourceInterface != ie.SrcInterfaceAccess {
		t.Errorf("Expected Source Interface Access, got %d", ueIpInfo.SourceInterface)
	}

	if ueIpInfo.NetworkInstance != "internet" {
		t.Errorf("Expected network instance internet, got %s", ueIpInfo.NetworkInstance)
	}
}
