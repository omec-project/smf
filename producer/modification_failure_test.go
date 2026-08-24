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
// A modification that could not be delivered to the UE must not be left pending.
//
// Same move as the test above: this asserted realignSession's own N1N2 handling, which no longer
// exists. The correction is an ordinary modification now, so the discard-on-delivery-failure
// behaviour belongs to ApplyModification, which reverts through the same path every other
// undelivered modification uses. Testing it there is synchronous and race-free; the old test read
// state the correction's goroutine was writing.
func TestAnUndeliverableModificationIsNotLeftPending(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() {
		sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2
	})

	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error { return nil }
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return errors.New("amf unreachable") }

	sm := modifyingSession()

	if err := ApplyModification(sm, &qos.PolicyUpdate{}); err == nil {
		t.Fatal("a modification that could not be delivered must be reported")
	}

	if len(sm.SmPolicyUpdates) != 0 {
		t.Error("an update that could not be delivered must be discarded, not left pending: the record would then describe parameters the UE was never told about")
	}
	if sm.NwModificationPending {
		t.Error("the session still looks as though a modification were running")
	}
}

// The user plane must be corrected before the UE is told anything. If it cannot be, the session
// is still enforcing flows the radio access network never established, and sending the UE a
// correction would assert something untrue.
// The UE must not be told flows were withdrawn while the user plane still enforces them.
//
// This invariant used to live in realignSession, which did its own user-plane correction and
// checked the result before sending N1N2. The correction is now one ordinary modification, so the
// invariant lives in ApplyModification: it programs the user plane first and returns without
// telling the UE if that fails. Testing it there is also what removes a data race — the
// correction runs on its own goroutine now, and the old test read a flag the goroutine wrote.
func TestTheUeIsNotToldWhenTheUserPlaneCannotBeProgrammed(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() {
		sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2
	})

	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		return errors.New("upf unreachable")
	}
	toldTheUE := false
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error {
		toldTheUE = true
		return nil
	}

	sm := modifyingSession()

	err := ApplyModification(sm, &qos.PolicyUpdate{})

	if err == nil {
		t.Fatal("a user plane that could not be programmed must be reported")
	}
	if !errors.Is(err, ErrPfcpModifyFailed) {
		t.Errorf("error = %v, want it to identify the user plane stage so the caller can answer differently", err)
	}
	if toldTheUE {
		t.Error("the UE was told about a change the user plane never took")
	}
	if sm.NwModificationPending {
		t.Error("the session still looks as though a modification were running")
	}
}

// A modification the user plane refused must leave the session exactly as it was found.
//
// ApplyModification writes the pending update and moves the session to SmStatePfcpModify before it
// programs anything. If the user plane then refuses, both have to be undone: the update describes
// a change that never happened, and a session parked in SmStatePfcpModify never returns to Active
// on its own. The path upstream reached this way left both behind, which mattered less when only
// an operator policy change could reach it; the corrective modification after a partial rejection
// reaches it too.
func TestAFailedUserPlaneProgrammingLeavesTheSessionAsItWasFound(t *testing.T) {
	smContext := modifyingSession()
	smContext.ChangeState(smf_context.SmStateActive)

	originalSend := sendPfcpSessionModifyReq
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		return errors.New("upf unreachable")
	}
	t.Cleanup(func() { sendPfcpSessionModifyReq = originalSend })

	err := ApplyModification(smContext, &qos.PolicyUpdate{})
	if err == nil || !errors.Is(err, ErrPfcpModifyFailed) {
		t.Fatalf("error = %v, want ErrPfcpModifyFailed", err)
	}

	if smContext.SMContextState != smf_context.SmStateActive {
		t.Errorf("state = %s, want SmStateActive: a session parked in SmStatePfcpModify never comes back on its own",
			smContext.SMContextState.String())
	}
	if len(smContext.SmPolicyUpdates) != 0 {
		t.Errorf("pending updates = %d, want 0: the update describes a change the user plane refused",
			len(smContext.SmPolicyUpdates))
	}
	if smContext.NwModificationPending {
		t.Error("the session still looks as though a network modification were running, so every later UE request would be disregarded")
	}
}
