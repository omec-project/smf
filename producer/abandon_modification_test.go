// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"testing"
	"time"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
	"go.uber.org/zap"
)

// testSupi identifies the session these tests act on. Named because the assertions read better
// with one subscriber than with a literal repeated through every fixture.
const testSupi = "imsi-208930100007487"

func TestAbandonModificationDiscardsAndSettlesTheSession(t *testing.T) {
	smContext := &smf_context.SMContext{
		Supi:          testSupi,
		PDUSessionID:  10,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		// ChangeState reads the address when a session enters or leaves the active state; a
		// session being modified always has one.
		PDUAddress: &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.1")},
	}
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{}}
	smContext.ChangeState(smf_context.SmStatePfcpModify)

	abandonModification(smContext, "t3591_expiry", "ue_did_not_acknowledge")

	if len(smContext.SmPolicyUpdates) != 0 {
		t.Errorf("pending updates = %d, want the abandoned one discarded", len(smContext.SmPolicyUpdates))
	}
	if smContext.SMContextState != smf_context.SmStateActive {
		t.Errorf("state = %s, want %s so a later modification can be attempted",
			smContext.SMContextState, smf_context.SmStateActive)
	}
	if smContext.T3591 != nil {
		t.Error("the timer handle must be dropped once the procedure is abandoned")
	}
}

// Abandoning twice must not panic. The timer can abort while an acknowledgement is in flight.
func TestAbandonModificationTwiceIsSafe(t *testing.T) {
	smContext := &smf_context.SMContext{
		Supi:          testSupi,
		PDUSessionID:  10,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		// ChangeState reads the address when a session enters or leaves the active state; a
		// session being modified always has one.
		PDUAddress: &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.1")},
	}
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{}}

	abandonModification(smContext, "t3591_expiry", "ue_did_not_acknowledge")
	abandonModification(smContext, "t3591_expiry", "ue_did_not_acknowledge")
}

// A T3591 expiry belonging to a finished modification must not abandon the one now in progress.
//
// Stopping a timer cannot recall an expiry already in flight. The abort takes SMLock, so it queues
// behind whatever holds it — most likely the acknowledgement that just superseded the procedure.
// After a partial rejection the corrective modification starts in that same window, so the queued
// abort would discard it: the session keeps the flows the radio refused, the UE has been told they
// are gone, and nothing repairs the difference. The window is exactly the satellite case, a UE
// acknowledging at the fifth expiry after a long fade.
func TestASupersededTimerExpiryDoesNotAbandonTheCurrentModification(t *testing.T) {
	smContext := modifyingSession()
	smContext.ChangeState(smf_context.SmStateActive)

	// The session has moved on: a newer procedure owns the timer.
	superseded := smf_context.NewTimer(time.Hour, 1, func(int32) {}, func() {})
	current := smf_context.NewTimer(time.Hour, 1, func(int32) {}, func() {})
	t.Cleanup(func() { superseded.Stop(); current.Stop() })
	smContext.T3591 = current
	smContext.NwModificationPending = true
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{}}

	abandonIfCurrent(smContext, superseded)

	if smContext.T3591 != current {
		t.Error("the superseded expiry cleared the current procedure's timer")
	}
	if !smContext.NwModificationPending {
		t.Error("the superseded expiry settled a modification that is still running")
	}
	if len(smContext.SmPolicyUpdates) == 0 {
		t.Error("the superseded expiry discarded the pending update of the modification now in progress")
	}

	// And the same call for the timer that *is* current does abandon, so this is not passing by
	// refusing to abandon anything.
	abandonIfCurrent(smContext, current)
	if smContext.NwModificationPending {
		t.Error("the current procedure's expiry failed to abandon it")
	}
}

// The realignment marker belongs to the procedure that raised it. An abandonment that leaves it
// behind hands it to the next modification, whose completion would then prune flows this one had
// already given up on and start a corrective procedure for them.
func TestAbandonModificationClearsTheRealignmentMarker(t *testing.T) {
	smContext := &smf_context.SMContext{
		Supi:          testSupi,
		PDUSessionID:  10,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		PDUAddress:    &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.1")},
	}
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{}}
	smContext.Realign = &smf_context.PendingRealignment{}
	smContext.ChangeState(smf_context.SmStatePfcpModify)

	abandonModification(smContext, "t3591_expiry", "ue_did_not_acknowledge")

	if smContext.Realign != nil {
		t.Error("the realignment marker outlived the modification it belonged to")
	}
}

// A session restored from a record written before T3591Value existed carries zero. NewTimer hands
// that to time.NewTicker, which panics -- so the first network-initiated modification after a
// restart would end the process rather than modify a session.
func TestArmingT3591ResolvesAValueARestoredSessionDoesNotCarry(t *testing.T) {
	// The configuration TestMain loads, left alone. Replacing it -- even saved and restored -- is a
	// write to package-global state that the PFCP transaction goroutines other tests leave running
	// read, and -race reports it.

	smContext := &smf_context.SMContext{
		Supi:          testSupi,
		PDUSessionID:  10,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		PDUAddress:    &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.1")},
	}

	if smContext.T3591Value != 0 {
		t.Fatalf("precondition: a restored session carries no resolved value")
	}

	smContext.SMLock.Lock()
	startT3591Locked(smContext, 4)
	value, timer := smContext.T3591Value, smContext.T3591
	smContext.SMLock.Unlock()

	t.Cleanup(func() {
		smContext.SMLock.Lock()
		smContext.StopT3591()
		smContext.SMLock.Unlock()
	})

	if value <= 0 {
		t.Errorf("T3591Value = %s after arming, want the resolved default", value)
	}

	if timer == nil {
		t.Error("no timer was armed for a session that carried no value")
	}
}
