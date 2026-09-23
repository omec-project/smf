// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/transaction"
	"go.uber.org/zap"
)

// The user plane these fixtures wait on; named because goconst counts it across the package.
const testPendingUpf = "10.0.0.1"

// waitingSession is a session in the middle of a modification.
//
// It deliberately does not touch factory.SmfConfig: TestMain loads the real one for this package,
// and replacing it here is a write to shared state that races with the goroutines other tests in
// the package leave running -- which is exactly what -race reported the first time this was
// written that way.
func waitingSession(t *testing.T) *smf_context.SMContext {
	t.Helper()

	return &smf_context.SMContext{
		SMContextState: smf_context.SmStatePfcpModify,
		SubCtxLog:      zap.NewNop().Sugar(),
		// A state change records per-session metrics from the address, which a session in the
		// middle of a modification has.
		PDUAddress: &smf_context.UeIpAddr{Ip: net.ParseIP("10.1.0.7")},
	}
}

// A modification that never left the SMF has to put the session back. Callers move it into
// SmStatePfcpModify before sending, and that state has no FSM handlers at all: left there, the
// session answers every later event with "unhandled event", so it can no longer be modified and
// no longer be released -- for a modification the user plane was never told about.
func TestAModificationThatWasNeverSentPutsTheSessionBack(t *testing.T) {
	smContext := waitingSession(t)

	RestoreStateIfNothingWasSent(smContext, smf_context.SmStateActive,
		fmt.Errorf("%w: it has no tunnel to send through", ErrModificationNotSent))

	if got := smContext.SMContextState; got != smf_context.SmStateActive {
		t.Errorf("state = %s, want SmStateActive: the session is stranded in a state with no handlers", got)
	}
}

// And a modification the user plane answered is left alone: what it did with the request is not
// known here, so reporting the session active would be a claim this cannot make.
func TestAModificationTheUserPlaneAnsweredIsLeftAlone(t *testing.T) {
	smContext := waitingSession(t)

	RestoreStateIfNothingWasSent(smContext, smf_context.SmStateActive,
		fmt.Errorf("pfcp modification failure"))

	if got := smContext.SMContextState; got != smf_context.SmStatePfcpModify {
		t.Errorf("state = %s, want it untouched: the user plane answered, and what it applied is not known here", got)
	}
}

// The three exits that report a modification as not sent all say so in a way the callers can act
// on. A session with no tunnel is the one reachable without a user plane.
func TestANotSentModificationSaysSoToItsCaller(t *testing.T) {
	smContext := waitingSession(t)

	err := SendPfcpSessionModifyReq(smContext, &pfcpParam{})
	if err == nil {
		t.Fatal("a modification with no tunnel reported success")
	}

	if !errors.Is(err, ErrModificationNotSent) {
		t.Errorf("error %q does not identify itself as unsent, so the caller leaves the session stranded", err)
	}
}

// Putting the state back is half the job. Both callers record a pending user-plane entry before
// sending, and the modification response handler signals the session's channel only once those
// entries are gone -- so an entry for a request that was never sent is deleted by no answer, and
// the next operation to wait on that channel waits for good. This is the same reasoning the
// abandon path in this package already carries; the restore goes through it.
func TestAModificationThatWasNeverSentClearsWhatItWouldHaveWaitedFor(t *testing.T) {
	smContext := waitingSession(t)
	smContext.PendingUPF = smf_context.PendingUPF{testPendingUpf: true}

	RestoreStateIfNothingWasSent(smContext, smf_context.SmStateActive,
		fmt.Errorf("%w: it has no tunnel to send through", ErrModificationNotSent))

	if len(smContext.PendingUPF) != 0 {
		t.Errorf("pending user planes = %v after a request that was never sent; no answer will ever delete them, so the next exchange on this session waits for good",
			smContext.PendingUPF)
	}
}

// And a restore to the state the session is already in is not a restore: ChangeState returns
// early on a same-state transition. That is what made the first version of this fix a no-op for
// the update handler, whose switch had already matched SmStatePfcpModify before the state was
// read -- so the value has to come from before the modification sequence began.
func TestRestoringToTheCurrentStateChangesNothing(t *testing.T) {
	smContext := waitingSession(t)

	RestoreStateIfNothingWasSent(smContext, smf_context.SmStatePfcpModify,
		fmt.Errorf("%w: it has no tunnel to send through", ErrModificationNotSent))

	if smContext.SMContextState != smf_context.SmStatePfcpModify {
		t.Errorf("state = %s; this test exists to record that passing the current state is not a restore",
			smContext.SMContextState)
	}
}

// A modification the user plane may already have applied is not one the session can be put back
// from. The adapter's reply arriving and failing to parse, or a POST it refused after possibly
// forwarding the request, both say nothing about what the user plane did -- so the sentinel that
// means "provably untouched" must not be attached to them, or the restore asserts something the
// SMF does not know.
func TestAFailureAfterTheRequestMayHaveGoneOutIsNotTreatedAsUnsent(t *testing.T) {
	answered := fmt.Errorf("pfcp session modification failed: %w",
		fmt.Errorf("reading the adapter's reply: unexpected EOF"))

	smContext := waitingSession(t)
	smContext.PendingUPF = smf_context.PendingUPF{testPendingUpf: true}

	RestoreStateIfNothingWasSent(smContext, smf_context.SmStateActive, answered)

	if smContext.SMContextState != smf_context.SmStatePfcpModify {
		t.Errorf("state = %s, want it untouched: what the user plane applied is not known here",
			smContext.SMContextState)
	}

	if len(smContext.PendingUPF) != 1 {
		t.Error("the pending user plane was cleared for a request that may have been applied; its answer would then find nothing waiting")
	}
}

// A policy notification for a session whose tunnel is gone is refused, and refused without leaving
// the session locked. BuildPfcpParam reads through the tunnel without looking, so the notification
// took the SMF down in the builder while it held SMLock; the unlock there is not deferred, and the
// transaction lifecycle's recover catches the panic without releasing the lock, so every later
// operation on the session waited on it for good. A guard in the send was never reached: the
// builder had already dereferenced nil.
func TestAPolicyUpdateForASessionWithNoTunnelIsRefusedAndLeavesItUnlocked(t *testing.T) {
	smContext := &smf_context.SMContext{
		Supi:           "imsi-208930000000045",
		PDUSessionID:   6,
		SMContextState: smf_context.SmStateActive,
		SubCtxLog:      zap.NewNop().Sugar(),
		SubPduSessLog:  zap.NewNop().Sugar(),
		PDUAddress:     &smf_context.UeIpAddr{Ip: net.ParseIP("10.1.0.9")},
	}

	txn := &transaction.Transaction{Req: models.SmPolicyNotification{}, Ctxt: smContext}

	if err := HandleSMPolicyUpdateNotify(txn); err == nil {
		t.Error("a policy update for a session with no tunnel was accepted")
	}

	if !smContext.SMLock.TryLock() {
		t.Fatal("SMLock is still held after the refusal; every later operation on this session would wait on it for good")
	}

	smContext.SMLock.Unlock()

	if got := smContext.SMContextState; got != smf_context.SmStateActive {
		t.Errorf("state = %s, want it untouched: nothing was attempted", got)
	}
}
