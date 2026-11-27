// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"slices"
	"strconv"
	"testing"
	"time"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/util/li/types"
)

// A warrant activated while a restarted UPF's sessions wait to be re-established reaches a session
// that still carries the SEID the previous incarnation assigned. Claimed then, the trigger detects
// on nothing at the restarted UPF, and the claim makes the re-establishment's answer skip the
// trigger it should install: the session forwards with no content and nothing reported. The
// trigger is left to that answer.
func TestAnActivationBeforeARestartedUPFReestablishesASessionLeavesItToTheAnswer(t *testing.T) {
	poi := newFakePOI(t)
	sub := triggerSubsystem(t, poi)
	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	previous := time.Unix(1_700_000_000, 0)
	restarted := previous.Add(time.Hour)

	sc := sessionServedBy(testSUPI, trigNodeA)
	pfcpCtx := onlyPFCPContext(t, sc)
	pfcpCtx.AcknowledgedAtRecovery = previous
	stale := pfcpCtx.RemoteSEID

	// The restart, through the gate, which discards the claims at the restarted UPF before
	// restoration starts.
	restore := GateRestoration(RestartHooks{
		Restore: func(smfctx.NodeID, time.Time) {},
		Abandon: func(string, time.Time) {},
		Release: func(smfctx.NodeID, string, time.Time) bool { return true },
	})
	restore(upfNode(trigNodeA), restarted)

	// The warrant arrives, and its scan reaches the session before restoration does.
	if !sub.store.Activate(types.InterceptTask{
		XID:      testXIDPrimary,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}) {
		t.Fatal("activating the warrant")
	}
	sc.SMLock.Lock()
	sub.triggerCC(sc)
	sc.SMLock.Unlock()

	// Restoration re-establishes the session, and the restarted UPF answers.
	sc.SMLock.Lock()
	pfcpCtx.RemoteSEID = stale + 1
	pfcpCtx.AcknowledgedAtRecovery = restarted
	TriggerCC(sc)
	sc.SMLock.Unlock()

	awaitMessages(t, poi, "ActivateTaskRequest", 1)
	// Long enough for an activation the scan dispatched to have been sent too.
	time.Sleep(100 * time.Millisecond)

	seids := poi.elements("ActivateTaskRequest", "SEID")
	if slices.Contains(seids, strconv.FormatUint(stale, 10)) {
		t.Errorf("a trigger was installed at the restarted UPF on the SEID %d its previous incarnation "+
			"assigned (triggers sent on %v)", stale, seids)
	}
	if !slices.Contains(seids, strconv.FormatUint(stale+1, 10)) {
		t.Errorf("the re-established session got no trigger on the SEID %d the restarted UPF assigned "+
			"(triggers sent on %v)", stale+1, seids)
	}
}

// A ForgetPOI that lands while a reconciliation is asking the POI what it holds drops the claim
// of a trigger installed after the POI answered. That trigger is in neither the account nor the
// registry, so the reconciliation asks again instead of marking the POI reconciled, and the
// second account shows it as an orphan to withdraw.
func TestAForgetPOIDuringAReconciliationIsNotOverwritten(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.triggers.sleep = func(time.Duration) {}
	endpoint := s.triggers.endpoints[trigNodeA]

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}

	var dropped types.XID
	poi.mu.Lock()
	poi.delayOn = getAllDetailsRequest
	poi.delay = func() {
		// While the POI composes its first account: a session installs a trigger, which the
		// account will not show, and the POI then stops answering heartbeats.
		s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
		s.triggers.mu.Lock()
		for _, installed := range s.triggers.installed {
			dropped = installed.xid
		}
		s.triggers.mu.Unlock()
		s.triggers.ForgetPOI(trigNodeA)

		// The POI holds the trigger, and says so when it is asked again.
		poi.mu.Lock()
		poi.delayOn = getAllDetailsRequest
		poi.delay = func() {
			poi.mu.Lock()
			poi.holds = append(poi.holds, string(dropped))
			poi.mu.Unlock()
		}
		poi.mu.Unlock()
	}
	poi.mu.Unlock()

	s.reconcileOne()

	if dropped == "" {
		t.Fatal("no trigger was installed during the reconciliation, so this tests nothing")
	}
	if n := poi.countMessages("GetAllDetailsRequest"); n != 2 {
		t.Errorf("the POI was asked what it holds %d times, want 2: the first account predates the "+
			"ForgetPOI", n)
	}
	if !slices.Contains(poi.elements("DeactivateTaskRequest", "xId"), string(dropped)) {
		t.Errorf("the trigger whose claim the ForgetPOI dropped was not withdrawn: it stays at the UPF " +
			"with nothing here tracking it")
	}
	if !endpoint.isReconciled() {
		t.Error("the endpoint is not reconciled after an account taken since the ForgetPOI")
	}
}

// A POI that stopped answering heartbeats has its claims discarded, but it may still hold the
// triggers. A warrant withdrawn before that POI is reconciled again is withdrawn there at once,
// durably, rather than left to the reconciliation or to the POI's own fail-safe.
func TestAWarrantWithdrawnAfterItsPOIWasForgottenIsWithdrawnThere(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	installed := poi.elements("ActivateTaskRequest", "xId")
	if len(installed) != 1 {
		t.Fatalf("installed %v, want one trigger", installed)
	}

	s.triggers.ForgetPOI(trigNodeA)
	s.untriggerWarrant(warrant.XID)

	awaitMessages(t, poi, "DeactivateTaskRequest", 1)
	if got := poi.elements("DeactivateTaskRequest", "xId"); !slices.Equal(got, installed) {
		t.Errorf("withdrew %v, want the trigger the POI may still hold, %v", got, installed)
	}
	awaitPending(t, s.triggers, 0)
}

// A reconciliation leaves no discarded claim behind: what the POI still holds of them is an orphan
// in its account, withdrawn as one, and a later withdrawal of their warrant sends nothing more.
func TestAReconciliationDropsTheClaimsAForgetPOIDiscarded(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	installed := poi.elements("ActivateTaskRequest", "xId")
	if len(installed) != 1 {
		t.Fatalf("installed %v, want one trigger", installed)
	}

	s.triggers.ForgetPOI(trigNodeA)
	poi.mu.Lock()
	poi.holds = installed
	poi.mu.Unlock()
	s.reconcileOne()
	awaitMessages(t, poi, "DeactivateTaskRequest", 1)

	s.untriggerWarrant(warrant.XID)
	time.Sleep(100 * time.Millisecond)
	if n := poi.countMessages("DeactivateTaskRequest"); n != 1 {
		t.Errorf("sent %d withdrawals, want the reconciliation's one", n)
	}
	s.triggers.mu.Lock()
	left := len(s.triggers.discarded)
	s.triggers.mu.Unlock()
	if left != 0 {
		t.Errorf("%d discarded claims remain after the POI was reconciled", left)
	}
}

// deactivateTaskRequest and getAllDetailsRequest select the POI's answers to a withdrawal and to a
// request for its account.
const (
	deactivateTaskRequest = "DeactivateTaskRequest"
	getAllDetailsRequest  = "GetAllDetailsRequest"
)

// A warrant withdrawn while its trigger's ActivateTask is in flight sends a DeactivateTask that the
// POI can apply first and answer 2020, and then apply the activation. The activation's answer can
// reach this element first, and find the withdrawal still pending, so it leaves the trigger to it.
// That 2020 does not end the withdrawal: the POI is asked again once the activation is answered.
func TestANoSuchTaskAnswerWhileTheActivationIsOpenIsNotTheEnd(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.triggers.sleep = func(time.Duration) { time.Sleep(10 * time.Millisecond) }

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}

	poi.mu.Lock()
	poi.delayOn = "ActivateTaskRequest"
	poi.delay = func() {
		// The activation has reached the POI, not been applied. The warrant is withdrawn, and the
		// POI answers the withdrawal first: it holds no such task yet. That answer is slow to
		// arrive.
		poi.mu.Lock()
		poi.refuseOn, poi.refuseCode = deactivateTaskRequest, x1CodeNoSuchTask
		poi.delayOn = deactivateTaskRequest
		poi.delay = func() { time.Sleep(300 * time.Millisecond) }
		poi.mu.Unlock()

		s.untriggerWarrant(warrant.XID)
		// Polled rather than awaited with awaitMessages: this runs on the POI's goroutine.
		for deadline := time.Now().Add(3 * time.Second); poi.countMessages("DeactivateTaskRequest") == 0; {
			if time.Now().After(deadline) {
				t.Error("the withdrawal did not reach the POI")

				break
			}
			time.Sleep(time.Millisecond)
		}

		// Then the activation is applied: the POI now holds the trigger and answers a withdrawal.
		poi.mu.Lock()
		poi.refuseOn = ""
		poi.mu.Unlock()
	}
	poi.mu.Unlock()

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

	awaitMessages(t, poi, "DeactivateTaskRequest", 2)
	awaitPending(t, s.triggers, 0)

	// And once answered, the activation is no longer open: a 2020 from a POI that never applied it
	// would otherwise be retried for ever.
	for _, xid := range poi.elements("ActivateTaskRequest", "xId") {
		if s.triggers.activationOpen(types.XID(xid)) {
			t.Errorf("the activation of %s is still open after the POI answered it", xid)
		}
	}
}

// A POI that reports what it holds without a trigger this element installed there has purged it:
// its fail-safe fired, or it restarted unseen. The keepalive round notices and discards this
// element's account of the POI, so it is reconciled and its live sessions re-triggered.
func TestATriggerThePOINoLongerReportsIsNoticed(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	endpoint := s.triggers.endpoints[trigNodeA]
	endpoint.markReconciled()

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

	s.triggers.keepaliveRound() // the POI reports holding nothing

	if endpoint.isReconciled() {
		t.Error("the endpoint is still reconciled after its POI reported holding none of its triggers")
	}
	if s.triggers.tasksAt(trigNodeA) {
		t.Error("the purged trigger is still claimed, so nothing re-installs it")
	}
}

// A trigger the POI applied after composing its account is missing from that account and has not
// been purged.
func TestATriggerActivatedAfterTheAccountWasAskedForIsNotMissing(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	endpoint := s.triggers.endpoints[trigNodeA]
	endpoint.markReconciled()

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	other := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d192}}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	held := poi.elements("ActivateTaskRequest", "xId")

	poi.mu.Lock()
	poi.holds = held
	poi.delayOn = getAllDetailsRequest
	poi.delay = func() { s.installFor("session-ref-2", []types.InterceptTask{warrant}, other, 8) }
	poi.mu.Unlock()

	s.triggers.keepaliveRound()

	if !endpoint.isReconciled() {
		t.Error("a trigger activated after the account was asked for was taken as purged")
	}
}

// A key re-claimed after a ForgetPOI and dropped by a second one before the POI is reconciled names
// two triggers the POI may hold. A withdrawal of the warrant in that window withdraws both.
func TestEveryClaimTwoForgetPOIsDiscardedIsWithdrawn(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	s.triggers.ForgetPOI(trigNodeA)
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	s.triggers.ForgetPOI(trigNodeA)
	installed := poi.elements("ActivateTaskRequest", "xId")
	if len(installed) != 2 {
		t.Fatalf("installed %v, want two triggers under one key", installed)
	}

	s.untriggerWarrant(warrant.XID)

	awaitMessages(t, poi, deactivateTaskRequest, 2)
	withdrawn := poi.elements(deactivateTaskRequest, "xId")
	for _, xid := range installed {
		if !slices.Contains(withdrawn, xid) {
			t.Errorf("the trigger %s was not withdrawn (withdrew %v)", xid, withdrawn)
		}
	}
}

// An earlier restart settled after a later one does not replace it: the sessions the later
// incarnation acknowledged are still the current ones.
func TestTheNewestRestartIsKept(t *testing.T) {
	s := triggerSubsystem(t, newFakePOI(t))
	newer := time.Unix(1_700_003_600, 0)
	session := upfSession{node: upfNode(trigNodeA), addr: trigNodeA}

	s.triggers.forgetRestartedPOI(session, newer)
	s.triggers.forgetRestartedPOI(session, newer.Add(-time.Hour))

	s.triggers.mu.Lock()
	at := s.triggers.restartedAt[trigNodeA]
	s.triggers.mu.Unlock()
	if !at.Equal(newer) {
		t.Errorf("the restart recorded is %v, want the newest, %v", at, newer)
	}
}

// What a POI last said about a trigger goes with the trigger, when its withdrawal is taken from
// the claims a ForgetPOI discarded as when it is taken from the installed ones.
func TestADiscardedTriggersHealthGoesWithIt(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	installed := poi.elements("ActivateTaskRequest", "xId")
	if len(installed) != 1 {
		t.Fatalf("installed %v, want one trigger", installed)
	}
	s.triggers.noteUnhealthy(types.XID(installed[0]), warrant.XID, testUnhealthyReason)
	s.triggers.ForgetPOI(trigNodeA)

	s.triggers.takeForSession("session-ref-1")

	s.triggers.mu.Lock()
	left := len(s.triggers.unhealthy)
	s.triggers.mu.Unlock()
	if left != 0 {
		t.Errorf("%d health entries remain for a trigger being withdrawn", left)
	}
}

// A session a newer incarnation acknowledged before this element recorded that incarnation's
// restart is current, not stale. That happens when the newer restart's node could not be matched
// at first: the gate records nothing then, the node re-associates, and its new sessions are
// answered before the withheld retry settles the restart. Such a session is triggered.
func TestASessionANewerIncarnationAcknowledgedIsTriggered(t *testing.T) {
	poi := newFakePOI(t)
	sub := triggerSubsystem(t, poi)
	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	recorded := time.Unix(1_700_000_000, 0)
	sub.triggers.forgetRestartedPOI(upfSession{node: upfNode(trigNodeA), addr: trigNodeA}, recorded)

	if !sub.store.Activate(types.InterceptTask{
		XID:      testXIDPrimary,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}) {
		t.Fatal("activating the warrant")
	}

	sc := sessionServedBy(testSUPI, trigNodeA)
	onlyPFCPContext(t, sc).AcknowledgedAtRecovery = recorded.Add(time.Hour)
	sc.SMLock.Lock()
	TriggerCC(sc)
	sc.SMLock.Unlock()

	awaitMessages(t, poi, "ActivateTaskRequest", 1)
}

// unhealthyCount is how many triggers the registry holds a POI's last word on.
func unhealthyCount(s *subsystem) int {
	s.triggers.mu.Lock()
	defer s.triggers.mu.Unlock()

	return len(s.triggers.unhealthy)
}

// installOneAtA installs one trigger at trigNodeA and returns its XID.
func installOneAtA(t *testing.T, s *subsystem, poi *fakePOI) types.XID {
	t.Helper()

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	installed := poi.elements("ActivateTaskRequest", "xId")
	if len(installed) != 1 {
		t.Fatalf("installed %v, want one trigger", installed)
	}

	return types.XID(installed[0])
}

// What a POI last said about a trigger goes when ForgetPOI drops the trigger's claim.
func TestAForgetPOIDropsAClaimsHealth(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	xid := installOneAtA(t, s, poi)
	s.triggers.noteUnhealthy(xid, testXIDPrimary, testUnhealthyReason)

	s.triggers.ForgetPOI(trigNodeA)

	if n := unhealthyCount(s); n != 0 {
		t.Errorf("%d health entries remain after ForgetPOI dropped the claim", n)
	}
}

// And when a reconciliation drops the discarded claims at its POI.
func TestAReconciliationDropsTheHealthOfTheClaimsItClears(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	xid := installOneAtA(t, s, poi)
	s.triggers.ForgetPOI(trigNodeA)
	// Recorded after the discard, so only the reconciliation can drop it.
	s.triggers.noteUnhealthy(xid, testXIDPrimary, testUnhealthyReason)

	if !s.triggers.markReconciledSince(trigNodeA, s.triggers.forgetCount(s.triggers.endpoints[trigNodeA])) {
		t.Fatal("the endpoint was not marked reconciled")
	}

	if n := unhealthyCount(s); n != 0 {
		t.Errorf("%d health entries remain after the reconciliation dropped the discarded claim", n)
	}
}
