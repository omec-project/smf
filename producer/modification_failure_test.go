// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
	"github.com/omec-project/smf/transaction"
	"go.uber.org/zap"
)

// defaultPdrKey is the key the data path uses for the PDR of a default QoS flow.
const defaultPdrKey = "default"

func modifyingSession() *smf_context.SMContext {
	sm := &smf_context.SMContext{
		Supi:          testSupi,
		PDUSessionID:  10,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		PDUAddress:    &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.1")},
	}
	sm.SmPolicyUpdates = []*qos.PolicyUpdate{{}}
	sm.ChangeState(smf_context.SmStatePfcpModify)
	// A modification in flight is a pending one, and a revert acts only on the one it was asked to.
	sm.NwModificationPending = true
	sm.NwModificationGen = 1
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

	sm := programmedRateChange(t).sm
	revertModification(sm, "n1n2_transfer_failed", sm.NwModificationGen)

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

	sm := programmedRateChange(t).sm
	revertModification(sm, "n1n2_transfer_failed", sm.NwModificationGen)

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

// A rule the update deletes has to leave the user plane too. The radio is told to release the
// flow and the UE is told to stop using it; without this the PDR went on forwarding it, so the
// only party still carrying a withdrawn rule was the one moving the traffic.
func TestBuildPfcpParamWithdrawsTheRulesTheUpdateDeletes(t *testing.T) {
	const withdrawnPdrKey = "going"

	sm := modifyingSession()

	kept := &smf_context.PDR{PDRID: 1, FAR: &smf_context.FAR{FARID: 1}}
	withdrawn := &smf_context.PDR{PDRID: 2, FAR: &smf_context.FAR{FARID: 2}}

	upf := &smf_context.UPF{NodeID: *smf_context.NewNodeID("10.0.0.1")}
	node := &smf_context.DataPathNode{
		UPF:            upf,
		DownLinkTunnel: &smf_context.GTPTunnel{PDR: map[string]*smf_context.PDR{defaultPdrKey: kept, withdrawnPdrKey: withdrawn}},
		UpLinkTunnel:   &smf_context.GTPTunnel{PDR: map[string]*smf_context.PDR{defaultPdrKey: kept, withdrawnPdrKey: withdrawn}},
	}
	sm.Tunnel = &smf_context.UPTunnel{
		DataPathPool: smf_context.DataPathPool{
			1: &smf_context.DataPath{IsDefaultPath: true, Activated: true, FirstDPNode: node},
		},
	}

	// Built the way the PCF's decision builds it: a rule carrying no identity is a deletion.
	decision := &models.SmPolicyDecision{
		PccRules: map[string]models.PccRule{
			defaultPdrKey: {PccRuleId: defaultPdrKey},
			"going":       {},
		},
	}
	sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&sm.SmPolicyData, decision)}

	param := BuildPfcpParam(sm)

	var removed int

	for _, pdr := range param.removePDR {
		if pdr == withdrawn {
			removed++
		}

		if pdr == kept {
			t.Error("a rule the update keeps was withdrawn from the user plane")
		}
	}

	if removed != 2 {
		t.Errorf("withdrawn PDRs = %d, want both directions of the deleted rule", removed)
	}
}

// Putting the user plane back can fail, and the revert then marks the session for release because
// it is running parameters the UE was never told about. Answering "reverted" there has the caller
// move it to Active, which erases exactly the marker that says a human needs to look.
func TestAFailedRevertIsNotReportedAsASessionPutBack(t *testing.T) {
	original := sendPfcpSessionModifyReq
	defer func() { sendPfcpSessionModifyReq = original }()

	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		return errors.New("upf unreachable")
	}

	sm := programmedRateChange(t).sm

	txn := &transaction.Transaction{Ctxt: sm}

	modification, reverted, err := HandlePduSessN1N2TransFailInd(txn)
	if err != nil {
		t.Fatalf("handling the failure indication: %v", err)
	}

	if !modification {
		t.Error("a failure indication for a pending modification was not reported as one")
	}

	if reverted {
		t.Error("a revert whose user-plane restore failed was reported as a session put back")
	}

	if sm.SMContextState != smf_context.SmStatePfcpRelease {
		t.Errorf("state = %s, want %s: the session is running parameters the UE never saw",
			sm.SMContextState, smf_context.SmStatePfcpRelease)
	}
}

// A modification reverted after a delivery failure stops its T3591 rather than only forgetting it.
// The indication arrives with the timer armed, and a timer dropped without being stopped went on
// firing for the whole retransmission sequence.
func TestARevertedModificationStopsItsTimer(t *testing.T) {
	originalPfcp, originalRetransmit := sendPfcpSessionModifyReq, retransmitModificationCommand
	t.Cleanup(func() { sendPfcpSessionModifyReq, retransmitModificationCommand = originalPfcp, originalRetransmit })

	var retransmissions atomic.Int32
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error { return nil }
	retransmitModificationCommand = func(*smf_context.SMContext, func() bool) error {
		retransmissions.Add(1)
		return nil
	}

	sm := modifyingSession()
	sm.T3591Value = 20 * time.Millisecond
	sm.SMLock.Lock()
	startT3591Locked(sm, 4)
	sm.SMLock.Unlock()
	t.Cleanup(func() {
		sm.SMLock.Lock()
		sm.StopT3591()
		sm.SMLock.Unlock()
	})

	if _, _, err := HandlePduSessN1N2TransFailInd(&transaction.Transaction{Ctxt: sm}); err != nil {
		t.Fatalf("handling the failure indication: %v", err)
	}

	// The expiry already due when the timer is stopped can still be delivered (see Timer.Stop), so
	// one is allowed for; the timer left running fires on every interval.
	time.Sleep(150 * time.Millisecond)
	if got := retransmissions.Load(); got > 1 {
		t.Errorf("T3591 fired %d times after the modification was reverted; it was left running", got)
	}
}

// The failure indication reads the session in one hold of the lock and reverts in another, and
// T3591 can abandon the modification between the two and a held decision then start. The revert
// is for the modification the indication read, and leaves the next one alone: discarding it would
// drop an update whose Command is on its way to the UE.
func TestADeliveryFailureForAnEndedModificationLeavesTheNextOneAlone(t *testing.T) {
	original := sendPfcpSessionModifyReq
	t.Cleanup(func() { sendPfcpSessionModifyReq = original })
	var sent atomic.Int32
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		sent.Add(1)
		return nil
	}

	sm := modifyingSession()
	read := sm.NwModificationGen

	// T3591 abandons it, and a held decision starts as the next modification.
	sm.SMLock.Lock()
	abandonModificationLocked(sm)
	next := &qos.PolicyUpdate{}
	sm.SmPolicyUpdates = []*qos.PolicyUpdate{next}
	sm.NwModificationGen++
	sm.NwModificationPending = true
	sm.SMLock.Unlock()

	if !revertModification(sm, "n1n2_transfer_failure_indication", read) {
		t.Error("a revert with nothing of its own to put back was reported as failed")
	}

	if !sm.NwModificationPending || len(sm.SmPolicyUpdates) != 1 || sm.SmPolicyUpdates[0] != next {
		t.Error("the delivery failure of an ended modification discarded the one after it")
	}
	if got := sent.Load(); got != 0 {
		t.Errorf("%d PFCP modifications were sent for a modification that had already ended", got)
	}
}

// A revert after a delivery failure is owed while its exchange is in flight, like every other
// revert: a modification or transaction for the session starting meanwhile would share its one
// PFCP response channel. And it is settled once the exchange is done.
func TestADeliveryFailureRevertIsOwedWhileItIsInFlight(t *testing.T) {
	original := sendPfcpSessionModifyReq
	t.Cleanup(func() { sendPfcpSessionModifyReq = original })
	var owedDuringSend bool
	sendPfcpSessionModifyReq = func(sm *smf_context.SMContext, _ *pfcpParam) error {
		sm.SMLock.Lock()
		owedDuringSend = sm.RevertInFlight != nil && sm.RevertOwed.Load()
		sm.SMLock.Unlock()
		return nil
	}

	sm := programmedRateChange(t).sm
	if !revertModification(sm, "n1n2_transfer_failed", sm.NwModificationGen) {
		t.Fatal("the revert reported failure")
	}

	if !owedDuringSend {
		t.Error("the revert was not recorded as owed while its exchange was in flight")
	}
	sm.SMLock.Lock()
	defer sm.SMLock.Unlock()
	if sm.RevertInFlight != nil || sm.RevertOwed.Load() {
		t.Error("the revert was left owed after it finished")
	}
}
