// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package upf

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/udp"
)

func configureForNativeDatapath(t *testing.T) {
	t.Helper()
	prev := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prev })

	enabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{
			KafkaInfo:        factory.KafkaInfo{EnableKafka: &enabled},
			EnableUpfAdapter: false,
		},
	}
}

// startSmfPfcpSocket gives the SMF a real socket to send from, which SendPfcpAssociationSetupRequest
// requires: without it the send fails with "PFCP server is not initialized" regardless of state.
func startSmfPfcpSocket(t *testing.T) {
	t.Helper()
	self := context.SMF_Self()
	prevCPNodeID := self.CPNodeID
	prevPFCPPort := self.PFCPPort
	t.Cleanup(func() {
		self.CPNodeID = prevCPNodeID
		self.PFCPPort = prevPFCPPort
		if server := udp.GetServer(); server != nil && server.Conn != nil {
			_ = server.Conn.Close()
		}
		udp.SetServer(nil)
	})

	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserving a port for the SMF: %v", err)
	}
	port := free.LocalAddr().(*net.UDPAddr).Port
	free.Close()

	self.CPNodeID = *context.NewNodeID("127.0.0.1")
	self.PFCPPort = port
	udp.Run(func(*udp.Message) {})
	if err := udp.WaitForServer(); err != nil {
		t.Fatalf("failed to start PFCP server: %v", err)
	}
}

func TestProbeUpfResetsAssociationSetupStuckPastTimeout(t *testing.T) {
	configureForNativeDatapath(t)

	upf := context.NewUPF(context.NewNodeID("127.0.0.1"), nil)
	upf.UPFStatus = context.AssociatedSettingUp
	upf.AssociationSetupSentAt = time.Now().Add(-associationSetupTimeout - time.Second)
	upNode := &context.UPNode{UPF: upf, NodeID: *context.NewNodeID("127.0.0.1"), Port: 1234}

	// No PFCP socket is running, so the retry this triggers fails to send; what matters here is
	// that the stale AssociatedSettingUp was not left in place forever.
	probeUpf(upNode)

	if upf.UPFStatus != context.NotAssociated {
		t.Errorf("UPF stuck in AssociatedSettingUp past the timeout was not reset; got status %v", upf.UPFStatus)
	}
}

func TestProbeUpfLeavesFreshAssociationSetupAlone(t *testing.T) {
	configureForNativeDatapath(t)

	upf := context.NewUPF(context.NewNodeID("127.0.0.1"), nil)
	upf.UPFStatus = context.AssociatedSettingUp
	sentAt := time.Now().Add(-associationSetupTimeout / 2)
	upf.AssociationSetupSentAt = sentAt
	upNode := &context.UPNode{UPF: upf, NodeID: *context.NewNodeID("127.0.0.1"), Port: 1234}

	probeUpf(upNode)

	if upf.UPFStatus != context.AssociatedSettingUp {
		t.Errorf("UPF still within the timeout was reset; got status %v", upf.UPFStatus)
	}
	if !upf.AssociationSetupSentAt.Equal(sentAt) {
		t.Errorf("AssociationSetupSentAt changed for a UPF that was not retried: got %v, want %v", upf.AssociationSetupSentAt, sentAt)
	}
}

// A retry sent from this loop must be tracked the same way as one sent from service.Start: marked
// AssociatedSettingUp with a fresh AssociationSetupSentAt, so a later timeout can catch a response
// that never arrives instead of leaving the UPF to be resent from here every probe interval.
func TestProbeUpfMarksSettingUpAfterSuccessfulSend(t *testing.T) {
	configureForNativeDatapath(t)
	startSmfPfcpSocket(t)

	upf := context.NewUPF(context.NewNodeID("127.0.0.1"), nil)
	upf.UPFStatus = context.NotAssociated
	upNode := &context.UPNode{UPF: upf, NodeID: *context.NewNodeID("127.0.0.1"), Port: 1234}

	before := time.Now()
	probeUpf(upNode)

	if upf.UPFStatus != context.AssociatedSettingUp {
		t.Fatalf("expected UPFStatus %v after a successful send, got %v", context.AssociatedSettingUp, upf.UPFStatus)
	}
	if upf.AssociationSetupSentAt.Before(before) {
		t.Errorf("AssociationSetupSentAt was not refreshed for the new send: got %v, want at/after %v", upf.AssociationSetupSentAt, before)
	}
}
