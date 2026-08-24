// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"net"
	"testing"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
	"go.uber.org/zap"
)

func modifyingSession() *smf_context.SMContext {
	sm := &smf_context.SMContext{
		Supi:          "imsi-208930100007487",
		PDUSessionID:  10,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		PDUAddress:    &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.1")},
	}
	sm.SmPolicyUpdates = []*qos.PolicyUpdate{{}}
	sm.ChangeState(smf_context.SmStatePfcpModify)
	return sm
}

// The user plane is programmed before the UE is signalled. If the signalling then fails, leaving
// it programmed would have the session enforcing parameters the UE was never told about.
func TestRevertReturnsTheUserPlaneWhenDeliveryFails(t *testing.T) {
	original := sendPfcpSessionModifyReq
	defer func() { sendPfcpSessionModifyReq = original }()

	var reverted bool
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		reverted = true
		return nil
	}

	sm := modifyingSession()
	revertModification(sm, "n1n2_transfer_failed")

	if !reverted {
		t.Error("the user plane must be reprogrammed when a modification cannot be delivered")
	}
	if len(sm.SmPolicyUpdates) != 0 {
		t.Error("the undelivered modification must be discarded, not left pending")
	}
	if sm.SMContextState != smf_context.SmStateActive {
		t.Errorf("state = %s, want the session settled and usable", sm.SMContextState)
	}
}

// If the revert itself cannot be applied, the session is running parameters the network does not
// believe it has. Releasing is the honest outcome; continuing is not.
func TestFailedRevertReleasesTheSession(t *testing.T) {
	original := sendPfcpSessionModifyReq
	defer func() { sendPfcpSessionModifyReq = original }()

	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		return errors.New("upf unreachable")
	}

	sm := modifyingSession()
	revertModification(sm, "n1n2_transfer_failed")

	if sm.SMContextState != smf_context.SmStatePfcpRelease {
		t.Errorf("state = %s, want %s: a session whose user plane cannot be corrected must not keep running",
			sm.SMContextState, smf_context.SmStatePfcpRelease)
	}
}

// A realignment is a modification like any other. If its command cannot be sent, the corrective
// update must not be left pending, or a later commit would apply it silently.
func TestRealignmentDiscardsItsUpdateWhenItCannotBeSent(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	defer func() {
		sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2
	}()

	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error { return nil }
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return errors.New("amf unreachable") }

	sm := modifyingSession()
	sm.SmPolicyUpdates = nil
	realign := &smf_context.PendingRealignment{EstablishedQFIs: []int64{1}, RefusedQFIs: []int64{2}}

	realignSession(sm, realign, &qos.PolicyUpdate{})

	if len(sm.SmPolicyUpdates) != 0 {
		t.Error("a corrective update that could not be sent must be discarded, not left pending")
	}
}

// The user plane must be corrected before the UE is told anything. If it cannot be, the session
// is still enforcing flows the radio access network never established, and sending the UE a
// correction would assert something untrue.
func TestRealignmentStopsIfTheUserPlaneCannotBeCorrected(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	defer func() {
		sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2
	}()

	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		return errors.New("upf unreachable")
	}
	var toldTheUE bool
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error {
		toldTheUE = true
		return nil
	}

	sm := modifyingSession()
	realign := &smf_context.PendingRealignment{EstablishedQFIs: []int64{1}, RefusedQFIs: []int64{2}}

	realignSession(sm, realign, &qos.PolicyUpdate{})

	if toldTheUE {
		t.Error("the UE must not be told flows were removed while the user plane still enforces them")
	}
}
