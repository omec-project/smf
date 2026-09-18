// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"
	"time"

	smf_context "github.com/omec-project/smf/context"
	"go.uber.org/zap"
)

// answered runs the send and reports whether it came back at all. Without a bound, a regression
// here does not fail the test -- it stops it, and the package times out ten minutes later with
// nothing to say about which call was stuck.
func answered(t *testing.T, smContext *smf_context.SMContext) (error, bool) {
	t.Helper()

	done := make(chan error, 1)

	go func() { done <- SendPfcpSessionModifyReq(smContext, &pfcpParam{}) }()

	select {
	case err := <-done:
		return err, true
	case <-time.After(2 * time.Second):
		return nil, false
	}
}

// A request that was never sent has no response coming. Waiting on the channel for one is a wait
// that never ends: the goroutine that would revert the modification never returns, the session
// stays mid-modification, and the next transaction to want that channel is behind it.
func TestAModificationThatCouldNotBeSentDoesNotWaitForAnAnswer(t *testing.T) {
	smContext := &smf_context.SMContext{
		SubCtxLog:                zap.NewNop().Sugar(),
		SubPfcpLog:               zap.NewNop().Sugar(),
		SBIPFCPCommunicationChan: make(chan smf_context.PFCPSessionResponseStatus, 1),
		// A tunnel whose user plane has no PFCP context: the send fails before anything is on
		// the wire, which is the case the wait cannot survive.
		Tunnel:      tunnelToUpf("10.0.0.1"),
		PFCPContext: map[string]*smf_context.PFCPSessionContext{},
	}

	err, returned := answered(t, smContext)
	if !returned {
		t.Fatal("the send never returned: it is waiting for a response to a request that was not sent")
	}

	if err == nil {
		t.Error("a modification that was not sent reported success")
	}
}

// The revert path reaches here exactly when something has already gone wrong, and a session being
// torn down underneath it has no tunnel. Dereferencing one ends the process.
func TestAModificationWithNoTunnelIsRefusedRatherThanFatal(t *testing.T) {
	smContext := &smf_context.SMContext{
		SubCtxLog:                zap.NewNop().Sugar(),
		SubPfcpLog:               zap.NewNop().Sugar(),
		SBIPFCPCommunicationChan: make(chan smf_context.PFCPSessionResponseStatus, 1),
	}

	err, returned := answered(t, smContext)
	if !returned {
		t.Fatal("the send never returned for a session with no tunnel")
	}

	if err == nil {
		t.Error("a session with no tunnel reported a successful modification")
	}
}

func tunnelToUpf(ip string) *smf_context.UPTunnel {
	upf := &smf_context.UPF{NodeID: *smf_context.NewNodeID(ip)}
	node := &smf_context.DataPathNode{UPF: upf}

	return &smf_context.UPTunnel{
		DataPathPool: smf_context.DataPathPool{
			1: &smf_context.DataPath{IsDefaultPath: true, FirstDPNode: node},
		},
	}
}
