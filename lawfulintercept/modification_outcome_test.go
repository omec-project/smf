// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/lisequence"
	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
	"github.com/omec-project/util/li/x2x3"
	"github.com/wmnsk/go-pfcp/ie"
)

// duplicatingSession is a session whose forwarding FARs are marked as a sent LI
// modification leaves them: `RULE_CREATE`, because
// BuildPfcpSessionModificationRequest clears `RULE_UPDATE` on everything it encodes.
//
// That is the state the retry has to work from, and the reason a re-derivation cannot: the
// marker that selects these FARs is gone, and the SMF-side `Dupl` bit already equals what
// the tasking implies, so `applyCC` finds nothing changed.
func duplicatingSession(t *testing.T) *smfctx.SMContext {
	t.Helper()

	sc := pooledSession(t, testSUPI, 1)
	node := smfctx.NewDataPathNode()
	node.UPF = &smfctx.UPF{NodeID: upfNode(trigNodeA)}
	node.UpLinkTunnel.PDR["default"] = &smfctx.PDR{
		FAR: &smfctx.FAR{
			ApplyAction: smfctx.ApplyAction{Forw: true, Dupl: true},
			State:       smfctx.RULE_CREATE,
		},
	}
	sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
		1: &smfctx.DataPath{FirstDPNode: node, IsDefaultPath: true, Activated: true},
	}}
	sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{}
	// Allocated the way the session path allocates it, which is what registers the session
	// in the SEID index. The answer to a modification carries the SEID and nothing else, so
	// a session not in that index is one the retry cannot find — and the test would then
	// pass against a retry that never ran.
	sc.AllocateLocalSEIDForDataPath(sc.Tunnel.DataPathPool[1])
	sc.PFCPContext[trigNodeA].RemoteSEID = 0x2632898145f4d191

	return sc
}

// outcomeFixture is a subsystem whose PFCP modifications are counted rather than sent, with
// a real reporter pointed at a stub ADMF.
// be shaped by which assertions happen to need it today.
//
//nolint:unparam // the subsystem is the thing under test; a fixture that withheld it would
func outcomeFixture(t *testing.T) (*subsystem, *admfStub, func() int) {
	t.Helper()

	admf := newADMFStub(t)
	sub := &subsystem{
		store:    store.New(),
		neID:     testNEID,
		ids:      x2x3.NewIdentity(testNEID, smfInterceptionPoint),
		reporter: x1.NewReporter(admf.srv.URL, testADMFID, testNEID, admf.clientTLS()),
	}
	waitForScans(t, sub)

	var (
		mu   sync.Mutex
		sent int
	)
	restore := sessionModifier
	sessionModifier = func(*smfctx.SMContext) error {
		mu.Lock()
		defer mu.Unlock()
		sent++

		return nil
	}
	t.Cleanup(func() { sessionModifier = restore })

	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	return sub, admf, func() int {
		mu.Lock()
		defer mu.Unlock()

		return sent
	}
}

// answerAndWait delivers a PFCP answer to an LI modification and waits for any re-send it
// started, which runs on its own goroutine.
func answerAndWait(sub *subsystem, req lisequence.Request, cause uint8, answered bool) {
	ModificationAnswered(req, cause, answered)
	sub.resends.Wait()
}

// The answer can arrive on the goroutine that sent the modification while it still holds the
// session lock: with the UPF adapter, the response is dispatched inline. Handling a refusal
// there must not wait for that lock, or the sender waits on itself and the session is wedged
// for every later procedure.
func TestARefusalAnsweredUnderTheSessionLockDoesNotWaitForIt(t *testing.T) {
	sub, _, sent := outcomeFixture(t)
	sc := duplicatingSession(t)

	req := lisequence.Request{
		SEID:        sc.PFCPContext[trigNodeA].LocalSEID,
		NodeID:      trigNodeA,
		Duplicating: true,
	}

	sc.SMLock.Lock()
	done := make(chan struct{})
	go func() {
		ModificationAnswered(req, ie.CauseRequestRejected, true)
		close(done)
	}()
	select {
	case <-done:
		sc.SMLock.Unlock()
	case <-time.After(2 * time.Second):
		// Released before failing, so the stuck handler can finish and the test ends.
		sc.SMLock.Unlock()
		<-done
		sub.resends.Wait()
		t.Fatal("handling a refused LI modification waited for the session lock its sender holds")
	}

	sub.resends.Wait()
	if n := sent(); n != 1 {
		t.Errorf("the refusal produced %d re-sends once the lock was released, want 1", n)
	}
}

// TestARefusedDuplicationIsRetriedAndThenReported is the whole of *the SMF acts on the
// answer to its own PFCP modifications*.
//
// The `lisequence` guard exists so an LI-initiated response cannot complete a subscriber's
// concurrent procedure, which is right and required. It must still read the Cause: the send
// itself cleared the `RULE_UPDATE` marker `ModifySessionForLI` selects on, and `applyCC`
// will not set it again because the SMF-side `Dupl` bit already matches the tasking, so a
// refusal nobody reads leaves the element holding a task it reports as intercepting and a
// datapath that declined it, with nothing to re-send and nothing reported.
//
// Two properties. The refusal is retried, which requires the marker to be re-established.
// And a datapath that keeps refusing is reported rather than asked forever, because it is
// refusing for a reason this element cannot fix.
func TestARefusedDuplicationIsRetriedAndThenReported(t *testing.T) {
	sub, admf, sent := outcomeFixture(t)
	sc := duplicatingSession(t)

	// The session has to be findable by the SEID the answer carries, which is how the
	// response handler correlates it.
	req := lisequence.Request{
		SEID:        sc.PFCPContext[trigNodeA].LocalSEID,
		NodeID:      trigNodeA,
		Duplicating: true,
	}

	// The datapath refuses.
	answerAndWait(sub, req, ie.CauseRequestRejected, true)

	if n := sent(); n != 1 {
		t.Fatalf("a refused duplication produced %d re-sends, want 1: the element recorded the "+
			"change as made and had nothing left to re-send, so the interception never started", n)
	}
	// The marker is back, which is the half a re-derivation cannot supply.
	sc.SMLock.Lock()
	marked := 0
	forEachForwardingFAR(sc, func(far *smfctx.FAR) {
		if far.State == smfctx.RULE_UPDATE {
			marked++
		}
	})
	sc.SMLock.Unlock()
	if marked == 0 {
		t.Error("the re-send carried nothing: the FAR state the send cleared was not " +
			"re-established, so ModifySessionForLI selects no FAR at all")
	}

	// It keeps refusing. Past the bound the element stops asking and tells the ADMF, because
	// a retry loop against a datapath that will not apply it has no exit.
	for range maxModificationAttempts {
		// Each answer leaves the FARs marked again, as the send would.
		sc.SMLock.Lock()
		forEachForwardingFAR(sc, func(far *smfctx.FAR) { far.State = smfctx.RULE_CREATE })
		sc.SMLock.Unlock()
		answerAndWait(sub, req, ie.CauseRequestRejected, true)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(admf.received(), "\n"), "duplicationRefused") {
			// And it stopped asking.
			before := sent()
			answerAndWait(sub, req, ie.CauseRequestRejected, true)
			if after := sent(); after > before+1 {
				t.Errorf("the element sent %d more modifications after giving up", after-before)
			}

			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("a datapath that kept refusing an acknowledged interception was reported to "+
		"nobody:\n%s", strings.Join(admf.received(), "\n"))
}

// TestARefusedWithdrawalIsNotBelieved is the other direction, and the one whose silence is
// worse. A refused activation is an interception that is not running; a refused withdrawal
// is content still being duplicated under authority that has gone, which nothing downstream
// can tell from content that is authorised.
func TestARefusedWithdrawalIsNotBelieved(t *testing.T) {
	sub, admf, sent := outcomeFixture(t)
	sc := duplicatingSession(t)

	// The withdrawal: the FARs were sent with Dupl cleared.
	sc.SMLock.Lock()
	forEachForwardingFAR(sc, func(far *smfctx.FAR) {
		far.ApplyAction.Dupl = false
		far.State = smfctx.RULE_CREATE
	})
	sc.SMLock.Unlock()

	req := lisequence.Request{
		SEID:        sc.PFCPContext[trigNodeA].LocalSEID,
		NodeID:      trigNodeA,
		Duplicating: false,
	}

	answerAndWait(sub, req, ie.CauseRequestRejected, true)

	if n := sent(); n != 1 {
		t.Fatalf("a refused withdrawal produced %d re-sends, want 1: the element believes "+
			"duplication is off while the datapath is still copying a subject's traffic", n)
	}

	for range maxModificationAttempts {
		sc.SMLock.Lock()
		forEachForwardingFAR(sc, func(far *smfctx.FAR) { far.State = smfctx.RULE_CREATE })
		sc.SMLock.Unlock()
		answerAndWait(sub, req, ie.CauseRequestRejected, true)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if joined := strings.Join(admf.received(), "\n"); strings.Contains(joined, "duplicationRefused") {
			if !strings.Contains(joined, "withdrawn") && !strings.Contains(joined, "authority") {
				t.Errorf("the report does not distinguish a refused withdrawal from a refused "+
					"activation; they need opposite actions:\n%s", joined)
			}

			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("a refused withdrawal was reported to nobody:\n%s", strings.Join(admf.received(), "\n"))
}

// TestAnUnansweredModificationIsTreatedAsRefused: silence is not a lesser case. A refusal
// says the datapath declined; silence says this element does not know — and it recorded the
// duplication as applied before it sent. Over-applying duplication is visible to the CC-POI
// as content it can attribute; under-applying it is silent, so the ambiguous case resolves
// toward retry.
func TestAnUnansweredModificationIsTreatedAsRefused(t *testing.T) {
	sub, _, sent := outcomeFixture(t)
	sc := duplicatingSession(t)

	req := lisequence.Request{
		SEID:        sc.PFCPContext[trigNodeA].LocalSEID,
		NodeID:      trigNodeA,
		Duplicating: true,
	}

	// answered=false: no Cause could be read, or none arrived.
	answerAndWait(sub, req, 0, false)

	if n := sent(); n != 1 {
		t.Errorf("an unanswered duplication produced %d re-sends, want 1", n)
	}
}

// TestAnAcceptedModificationIsLeftAlone keeps the fix from becoming a re-send loop on the
// ordinary path: the datapath took it, so there is nothing to do.
func TestAnAcceptedModificationIsLeftAlone(t *testing.T) {
	sub, admf, sent := outcomeFixture(t)
	sc := duplicatingSession(t)

	req := lisequence.Request{
		SEID:        sc.PFCPContext[trigNodeA].LocalSEID,
		NodeID:      trigNodeA,
		Duplicating: true,
	}

	answerAndWait(sub, req, ie.CauseRequestAccepted, true)

	if n := sent(); n != 0 {
		t.Errorf("an accepted modification produced %d re-sends, want 0", n)
	}
	time.Sleep(100 * time.Millisecond)
	if joined := strings.Join(admf.received(), "\n"); strings.Contains(joined, "duplicationRefused") {
		t.Errorf("an accepted modification was reported as refused:\n%s", joined)
	}
}

// TestARefusedDuplicationIsAttributedToItsWarrant is the half the element-scoped report cannot
// carry.
//
// An NE-level report may name no target and no warrant, which is the channel's rule and is
// correct. It does not mean the condition cannot be attributed at all: told only that *some*
// content interception this element triggers is not running, a LIPF holding several warrants
// has a condition nobody can act on. `triggerFaulty` attributes its condition for the same
// reason, on a different path.
//
// It can be attributed: a task report is scoped to a warrant by construction, and the SEID the
// answer carries names the session, which names the warrants covering it.
func TestARefusedDuplicationIsAttributedToItsWarrant(t *testing.T) {
	sub, admf, _ := outcomeFixture(t)
	sc := duplicatingSession(t)

	warrant := types.InterceptTask{
		XID:      testXIDCovering,
		Products: []types.ProductType{types.ProductCC},
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
	}

	if !sub.store.Activate(warrant) {
		t.Fatal("Activate failed")
	}

	req := lisequence.Request{
		SEID:        sc.PFCPContext[trigNodeA].LocalSEID,
		NodeID:      trigNodeA,
		Duplicating: true,
	}

	// The datapath refuses until the element gives up.
	for range maxModificationAttempts + 1 {
		sc.SMLock.Lock()
		forEachForwardingFAR(sc, func(far *smfctx.FAR) { far.State = smfctx.RULE_CREATE })
		sc.SMLock.Unlock()
		answerAndWait(sub, req, ie.CauseRequestRejected, true)
	}

	faults := sub.taskFaults(warrant.XID)
	if len(faults) != 1 || !strings.Contains(faults[0].ErrorDescription, "did not apply") {
		t.Fatalf("a datapath that refused an acknowledged interception is not a fault of the warrant "+
			"covering the session, so a LIPF holding several warrants cannot tell which one stopped. "+
			"Faults: %+v; element reports:\n%s", faults, strings.Join(admf.received(), "\n"))
	}

	// State, not a push: a later modification the datapath applies ends it, and the watcher
	// then retracts the fault (TS 103 221-1 clause 6.5.2.1).
	answerAndWait(sub, req, ie.CauseRequestAccepted, true)

	if f := sub.taskFaults(warrant.XID); len(f) != 0 {
		t.Errorf("the warrant still reports %+v after a modification for the session applied", f)
	}
}

// TestTwoRefusingUPFsAreRetriedWithinTheBound covers a session duplicated at two UPFs that both
// refuse. A re-send for one UPF's refusal must go to that UPF only: re-sending to every UPF
// makes each refusal produce a refusal from both, and a UPF already given up on is asked again,
// so the re-sends never stop.
func TestTwoRefusingUPFsAreRetriedWithinTheBound(t *testing.T) {
	sub, _, _ := outcomeFixture(t)

	sc := pooledSession(t, testSUPI, 1)
	a, b := smfctx.NewDataPathNode(), smfctx.NewDataPathNode()
	a.UPF = &smfctx.UPF{NodeID: upfNode(trigNodeA)}
	b.UPF = &smfctx.UPF{NodeID: upfNode(trigNodeB)}
	for i, node := range []*smfctx.DataPathNode{a, b} {
		node.UpLinkTunnel.PDR["default"] = &smfctx.PDR{FAR: &smfctx.FAR{
			FARID:       uint32(i + 1),
			ApplyAction: smfctx.ApplyAction{Forw: true, Dupl: true},
			State:       smfctx.RULE_UPDATE,
		}}
	}
	a.DownLinkTunnel.SrcEndPoint, b.UpLinkTunnel.SrcEndPoint = b, a
	sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
		1: &smfctx.DataPath{FirstDPNode: a, IsDefaultPath: true, Activated: true},
	}}
	sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{}
	sc.AllocateLocalSEIDForDataPath(sc.Tunnel.DataPathPool[1])

	// The modifier as ModifySessionForLI and the send behave: one modification per UPF with a
	// RULE_UPDATE FAR, which the send marks RULE_CREATE. Each UPF refuses, answering inline as
	// the adapter does.
	var (
		calls   atomic.Int64
		stopped atomic.Bool
	)
	sessionModifier = func(sc *smfctx.SMContext) error {
		calls.Add(1)
		if stopped.Load() {
			return nil
		}
		sentTo := map[string]bool{}
		for _, node := range []*smfctx.DataPathNode{a, b} {
			forEachForwardingFARAt(sc, node.GetNodeIP(), func(far *smfctx.FAR) {
				if far.State == smfctx.RULE_UPDATE {
					far.State = smfctx.RULE_CREATE
					sentTo[node.GetNodeIP()] = true
				}
			})
		}
		for ip := range sentTo {
			ModificationAnswered(lisequence.Request{
				SEID:        sc.PFCPContext[ip].LocalSEID,
				NodeID:      ip,
				Duplicating: true,
			}, ie.CauseRequestRejected, true)
		}

		return nil
	}

	// The first modification, to both UPFs.
	sc.SMLock.Lock()
	sub.modifySession(sc)
	sc.SMLock.Unlock()

	quiet := make(chan struct{})
	go func() {
		sub.resends.Wait()
		close(quiet)
	}()
	select {
	case <-quiet:
	case <-time.After(5 * time.Second):
		stopped.Store(true)
		<-quiet
		t.Fatalf("the re-sends to two refusing UPFs had not stopped after %d modifications", calls.Load())
	}

	// The first modification, then at most maxModificationAttempts-1 re-sends per UPF.
	if n, bound := calls.Load(), int64(1+2*maxModificationAttempts); n > bound {
		t.Errorf("two refusing UPFs took %d modifications, want at most %d", n, bound)
	}
}
