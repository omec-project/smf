// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"testing"
	"time"

	smf_context "github.com/omec-project/smf/context"
	"go.uber.org/zap"
)

// A modification the user plane never answered releases the session, and it has to do so in the
// release state. The deletion answers that release waits on -- a response, or the timeout of a
// deletion the user plane does not answer either -- are delivered only to a session in
// SmStatePfcpRelease. The branch moved the session to SmStatePfcpModify instead, so every one was
// withheld and the release waited for good. That was unreachable only while a modification
// timeout could not find its session.
//
// The tunnel is absent so the release sends nothing, and its answer is already waiting: what this
// pins is the state the release is carried out in, which the deletion tests in pfcp/message show is
// the one state a failed deletion answers.
func TestAModificationTimeoutReleasesTheSessionInTheReleaseState(t *testing.T) {
	smContext := &smf_context.SMContext{
		Supi:                     "imsi-208930000000047",
		PDUSessionID:             8,
		SMContextState:           smf_context.SmStatePfcpModify,
		SubCtxLog:                zap.NewNop().Sugar(),
		SubPduSessLog:            zap.NewNop().Sugar(),
		SubPfcpLog:               zap.NewNop().Sugar(),
		PDUAddress:               &smf_context.UeIpAddr{Ip: net.ParseIP("10.1.0.11")},
		SBIPFCPCommunicationChan: make(chan smf_context.PFCPSessionResponseStatus, 1),
	}
	smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess

	var stateDuringRelease smf_context.SMContextState

	done := make(chan struct{})

	go func() {
		defer close(done)

		HandlePFCPResponse(smContext, smf_context.SessionUpdateTimeout)
		stateDuringRelease = smContext.SMContextState
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the release after a modification timeout did not finish")
	}

	if stateDuringRelease != smf_context.SmStatePfcpRelease {
		t.Errorf("the session was released in %s, want SmStatePfcpRelease: every deletion answer is withheld from any other state", stateDuringRelease)
	}
}
