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
		// Closing Conn ends the read loop, but on another goroutine; waiting for Done before
		// clearing the global keeps that goroutine from lingering into (and racing) the next
		// test's startSmfPfcpSocket call.
		if server := udp.GetServer(); server != nil {
			if server.Conn != nil {
				_ = server.Conn.Close()
			}
			if server.Done != nil {
				<-server.Done
			}
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

// A heartbeat that could not be delivered is one the user plane has not answered, and it counts
// toward declaring the user plane lost. Only sends that succeeded were counted, so a user plane
// behind an adapter that was down or refusing never reached the limit: it stayed associated for
// as long as it was unreachable, and new sessions went on being placed on it.
func TestAHeartbeatThatCouldNotBeSentCountsAsUnanswered(t *testing.T) {
	configureForNativeDatapath(t)
	// No SMF socket, so every send fails with "PFCP server is not initialized".

	upf := context.NewUPF(context.NewNodeID("127.0.0.1"), nil)
	upf.UPFStatus = context.AssociatedSetUpSuccess
	upf.Port = 1234

	heartbeatUpf(upf)

	if upf.NHeartBeat != 1 {
		t.Errorf("NHeartBeat = %d after a heartbeat that could not be sent, want 1", upf.NHeartBeat)
	}
}

// And a user plane that cannot be reached at all is, in the end, declared lost -- which is what
// the count exists for.
func TestAUserPlaneThatCannotBeHeartbeatedIsEventuallyDeclaredLost(t *testing.T) {
	configureForNativeDatapath(t)

	upf := context.NewUPF(context.NewNodeID("127.0.0.1"), nil)
	upf.UPFStatus = context.AssociatedSetUpSuccess
	upf.Port = 1234

	for range maxHeartbeatRetry + 1 {
		heartbeatUpf(upf)
	}

	if upf.UPFStatus != context.NotAssociated {
		t.Errorf("UPFStatus = %v after %d undeliverable heartbeats, want NotAssociated", upf.UPFStatus, maxHeartbeatRetry+1)
	}
}

// TS 29.244 clause 5.8.2: while an association is established the CP function checks the UP
// function's responsiveness with heartbeats. That does not stop when the UPF leaves the
// configuration -- an empty configuration, or one that omits it -- because the association does
// not end there. A UPF that hears nothing from the SMF drops the association after its own read
// timeout, along with every session on it, so going quiet loses state the configuration may be
// about to use again.
func TestAnAssociatedUPFOutsideTheConfigurationIsStillHeartbeated(t *testing.T) {
	configureForNativeDatapath(t)
	// No SMF socket, so the send fails; a failed send is still counted, which is what shows the
	// heartbeat was attempted.

	upf := context.NewUPF(context.NewNodeID("192.0.2.21"), nil)
	upf.UPFStatus = context.AssociatedSetUpSuccess
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(upf.NodeID) })

	idle := context.NewUPF(context.NewNodeID("192.0.2.22"), nil)
	idle.UPFStatus = context.NotAssociated
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(idle.NodeID) })

	saved := context.SMF_Self().UserPlaneInformation
	context.SMF_Self().UserPlaneInformation = &context.UserPlaneInformation{
		UPFs: map[string]*context.UPNode{},
	}
	t.Cleanup(func() { context.SMF_Self().UserPlaneInformation = saved })

	heartbeatAll()

	if upf.NHeartBeat != 1 {
		t.Errorf("NHeartBeat = %d for an associated UPF outside the configuration, want 1", upf.NHeartBeat)
	}
	if idle.NHeartBeat != 0 {
		t.Errorf("NHeartBeat = %d for a UPF that is not associated, want 0", idle.NHeartBeat)
	}
}
