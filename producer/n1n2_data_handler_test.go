// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"testing"

	smf_context "github.com/omec-project/smf/context"
)

func TestBuildAccessForwardingParametersPreservesOuterHeaderCreation(t *testing.T) {
	smContext := &smf_context.SMContext{
		Dnn:    "internet",
		Tunnel: &smf_context.UPTunnel{},
	}
	smContext.Tunnel.ANInformation.IPAddress = net.ParseIP("172.20.0.2")
	smContext.Tunnel.ANInformation.TEID = 1234

	current := &smf_context.ForwardingParameters{
		OuterHeaderCreation: &smf_context.OuterHeaderCreation{
			OuterHeaderCreationDescription: smf_context.OuterHeaderCreationGtpUUdpIpv4,
			Teid:                           5678,
			Ipv4Address:                    net.ParseIP("172.20.0.3").To4(),
		},
	}

	forwardingParameters := buildAccessForwardingParameters(smContext, current)

	if forwardingParameters.DestinationInterface.InterfaceValue != smf_context.DestinationInterfaceAccess {
		t.Fatalf("expected destination interface %d, got %d",
			smf_context.DestinationInterfaceAccess,
			forwardingParameters.DestinationInterface.InterfaceValue)
	}

	if got := string(forwardingParameters.NetworkInstance); got != "internet" {
		t.Fatalf("expected network instance internet, got %q", got)
	}

	if forwardingParameters.OuterHeaderCreation == nil {
		t.Fatal("expected outer header creation to be preserved")
	}

	if forwardingParameters.OuterHeaderCreation.Teid != 5678 {
		t.Fatalf("expected preserved TEID 5678, got %d", forwardingParameters.OuterHeaderCreation.Teid)
	}

	if got := forwardingParameters.OuterHeaderCreation.Ipv4Address.String(); got != "172.20.0.3" {
		t.Fatalf("expected preserved outer header IP 172.20.0.3, got %s", got)
	}
}

func TestBuildAccessForwardingParametersFallsBackToAnTunnel(t *testing.T) {
	smContext := &smf_context.SMContext{
		Dnn:    "internet",
		Tunnel: &smf_context.UPTunnel{},
	}
	smContext.Tunnel.ANInformation.IPAddress = net.ParseIP("172.20.0.2")
	smContext.Tunnel.ANInformation.TEID = 4321

	forwardingParameters := buildAccessForwardingParameters(smContext, nil)

	if forwardingParameters.OuterHeaderCreation == nil {
		t.Fatal("expected outer header creation to be reconstructed from AN information")
	}

	if forwardingParameters.OuterHeaderCreation.Teid != 4321 {
		t.Fatalf("expected reconstructed TEID 4321, got %d", forwardingParameters.OuterHeaderCreation.Teid)
	}

	if got := forwardingParameters.OuterHeaderCreation.Ipv4Address.String(); got != "172.20.0.2" {
		t.Fatalf("expected reconstructed outer header IP 172.20.0.2, got %s", got)
	}
}

func TestReadBinaryN2SmInformationNilFile(t *testing.T) {
	fileBytes, err := readBinaryN2SmInformation(nil)
	if err != nil {
		t.Fatalf("expected nil error for absent N2 binary payload, got %v", err)
	}

	if len(fileBytes) != 0 {
		t.Fatalf("expected empty payload for absent N2 binary payload, got %d bytes", len(fileBytes))
	}
}
