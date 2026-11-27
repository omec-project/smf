// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"context"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/util/li/types"
)

// noGoroutineIn fails unless no goroutine is running any of the named functions.
//
// It names the functions rather than counting goroutines, for two reasons. A count
// is ambiguous — httptest servers, the Go runtime's own workers and the test binary
// all contribute — and, more importantly, a count that has returned to its baseline
// says nothing about *which* goroutines went. What is being asserted here is that
// an initialisation which did not complete left none of its own background work
// running, and the only honest form of that is to look for those functions by name.
//
// The wait exists because a goroutine that has been told to stop takes a scheduling
// quantum to do it; it is not a poll for something that might never happen.
func noGoroutineIn(t *testing.T, names ...string) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		stacks := string(buf[:runtime.Stack(buf, true)])

		var still []string
		for _, name := range names {
			if runningIn(stacks, name) {
				still = append(still, name)
			}
		}
		if len(still) == 0 {
			return
		}
		if time.Now().After(deadline) {
			// Errorf, not Fatalf: what runs after this call is usually the assertion
			// about what that goroutine *did*, and ending the test here would hide it.
			t.Errorf("still running after an initialisation that failed: %s\n%s",
				strings.Join(still, ", "), stacks)

			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// runningIn reports whether any goroutine in a runtime.Stack dump has the named
// function in one of its own frames.
//
// A frame line is the function name followed by its arguments, so the name must be
// followed by "(": otherwise keepalive would match keepaliveRound. And a goroutine's
// "created by" line names the function that started it, not one it is running: a
// reconciliation another test started from keepaliveRound is no keepalive loop.
func runningIn(stacks, name string) bool {
	for _, line := range strings.Split(stacks, "\n") {
		if strings.HasPrefix(line, "created by ") {
			continue
		}
		if strings.Contains(line, name+"(") {
			return true
		}
	}

	return false
}

// TestAFailedInitWithdrawsNothingAndLeavesNothingRunning is the whole of *Outbound
// X1 work has an owner*, reached from the one arrangement that makes it a live
// hazard rather than untidiness.
//
// Reconciliation withdraws every trigger a POI reports that this registry cannot
// account for — which is what makes a previous life's orphans reclaimable — and a
// just-started registry accounts for none. So it may only run once this subsystem is
// the one running. Dispatched from the registry's construction, it would run
// while initialisation could still fail, and the step most likely to fail is the X1
// bind: it fails when another process already holds the port, which is what a
// rolling restart or a duplicated deployment looks like. The process most likely to
// abandon its start-up is therefore the one running alongside a healthy instance
// whose live content interception it is about to withdraw at every UPF it can reach.
//
// Two properties, both of them the failed initialisation's obligation: it withdraws
// nothing, and it leaves nothing of its own running.
func TestAFailedInitWithdrawsNothingAndLeavesNothingRunning(t *testing.T) {
	cert, key, ca := liPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	// A POI holding live content interception, of the kind this process has no record
	// of — which from a fresh registry's point of view is all of it.
	poi := newFakePOI(t)
	poi.mu.Lock()
	poi.holds = []string{testXIDSecondary}
	poi.mu.Unlock()

	// The port is already held, by something that keeps holding it. This is the bind
	// failure as a deployment produces it, not an invalid address.
	held, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", testListenEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close() //nolint:errcheck // test

	err = Init(Config{
		NEID:     testNEID,
		X1Listen: held.Addr().String(),
		MDF2:     testDestinationAddr,
		MDF3:     testMDF3Addr,
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: testADMFID,
		UPFTriggers: []UPFTrigger{
			{NodeID: trigNodeA, X1URL: poi.srv.URL, NEID: testUPFNEID1},
		},
	})
	if err == nil {
		t.Fatal("Init reported success with the X1 port already held: no ADMF could ever task " +
			"this element, and it would report itself as intercepting")
	}
	if active.Load() != nil {
		t.Error("interception was started despite the bind failure")
	}

	// First, that nothing of this initialisation's own is left running. It is also what
	// makes the counts below honest: where reconciliation *did* start, this waits for it
	// to finish, so the withdrawal it sends is counted rather than raced.
	noGoroutineIn(t,
		"lawfulintercept.(*triggerRegistry).resolveLoop",
		"lawfulintercept.(*triggerRegistry).keepalive",
		"lawfulintercept.(*subsystem).reconcileTriggers",
	)

	// Reconciliation begins by interrogating the POI, so no interrogation means it did
	// not begin — and this is the assertion that bites here. **Recorded, because it is
	// the difference between what this fixture reaches and what a deployment does**:
	// Init always builds the requester with credentials, and a credentialed requester
	// refuses an answer it cannot bind to a certificate (x1.Requester.bindsResponder),
	// which this plain-HTTP POI presents none of. So pre-fix, reconciliation here fails
	// to *read* what the POI holds and retries forever — the orphaned goroutine above —
	// where in a deployment with a PKI it reads it and withdraws it. The withdrawal
	// count is asserted all the same, since it is the harm and costs nothing to pin, but
	// it is the interrogation and the goroutine that fail against the pre-fix ordering.
	if n := poi.countMessages("GetAllDetailsRequest"); n != 0 {
		t.Errorf("reconciliation interrogated the POI %d times during an initialisation that "+
			"did not complete: the next thing it does with that answer is withdraw every "+
			"trigger this registry cannot name, which is all of them", n)
	}
	if n := poi.countMessages("DeactivateTaskRequest"); n != 0 {
		t.Errorf("an initialisation that failed sent %d withdrawals to a point of interception "+
			"holding live tasking: content interception at every UPF this SMF can reach was "+
			"stopped by a process that then returned an error and stored nothing", n)
	}
}

// TestTwoRelabelsReachThePOIInOrder: a relabel is the one outbound propagation that
// is last-writer-wins at the POI. Both exchanges succeed, both are acknowledged to
// the ADMF, and what the POI is left holding is whichever ModifyTask finished last —
// so two modifications in quick succession can leave content labelled with a
// delivery identifier the ADMF has already superseded, with nothing anywhere
// recording that the element applied them backwards.
//
// Installs need no ordering (plan skips a claimed triple, so two cannot overwrite
// each other's state) and withdrawals own their own retry loop keyed by the pending
// entry. This is the one that needed it.
//
// The first propagation is made to complete *last*, which is what distinguishes the
// property from the accident: with the two dispatched on bare goroutines the POI
// ends up holding the first relabel's ProductID, and with them ordered the second
// one is not sent until the first has returned.
func TestTwoRelabelsReachThePOIInOrder(t *testing.T) {
	// Its own subsystem and fake POI; nothing package-level is written.
	t.Parallel()

	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	const xid = types.XID(testXIDPrimary)
	base := types.InterceptTask{XID: xid, Products: []types.ProductType{types.ProductCC}}

	s.installFor("session-ref-1", []types.InterceptTask{base},
		[]upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)
	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Fatalf("ActivateTaskRequest = %d, want 1", n)
	}

	// The first ModifyTask is held at the POI until released, so an unordered dispatch
	// would let the second overtake it and the first would land afterwards.
	release := make(chan struct{})
	poi.mu.Lock()
	poi.delayOn = "ModifyTaskRequest"
	poi.delay = func() { <-release }
	poi.mu.Unlock()

	first := base
	first.ProductID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	second := base
	second.ProductID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	// Back to back, as two X1 ModifyTasks arriving in quick succession are: each
	// returns as soon as it has dispatched, which is the property that put the X1
	// exchange off the request goroutine in the first place.
	s.relabelWarrant(base, first)
	s.relabelWarrant(first, second)

	// The first is still held, so with the propagations ordered the second cannot have
	// been sent yet. This is the ordering itself, asserted before the release rather
	// than inferred from the outcome afterwards.
	time.Sleep(100 * time.Millisecond)
	if n := poi.countMessages("ModifyTaskRequest"); n != 1 {
		close(release)
		t.Fatalf("ModifyTaskRequest = %d while the first exchange is still outstanding, want 1: "+
			"the second relabel was dispatched without waiting for the first, so which one the "+
			"POI ends up holding is decided by the network", n)
	}
	close(release)

	deadline := time.Now().Add(5 * time.Second)
	for poi.countMessages("ModifyTaskRequest") < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := poi.countMessages("ModifyTaskRequest"); n != 2 {
		t.Fatalf("ModifyTaskRequest = %d after both relabels, want 2", n)
	}

	// What the POI is left holding: the last ModifyTask it received must be the
	// second modification's, since that is the one the ADMF sent last.
	var last string
	for _, body := range poi.sent() {
		if strings.Contains(body, `xsi:type="ns1:ModifyTaskRequest"`) {
			last = body
		}
	}
	if !strings.Contains(last, string(second.ProductID)) {
		t.Errorf("the last modification the POI received carries the superseded delivery "+
			"identifier: it is now labelling this warrant's content with a value the ADMF has "+
			"replaced, and both exchanges succeeded.\nwant %s in:\n%s", second.ProductID, last)
	}
}

// TestALateInstalledTriggerIsWithdrawnDurably: the X1 exchange runs off the
// signalling path, so a trigger's claim can be gone from the registry by the time
// its activation lands at the POI — released without a withdrawal, or displaced by a
// newer claim under the same key. The trigger is then installed and tracked by
// nothing: a warrant's withdrawal finds it in neither map, a session's release finds
// it in neither map, and reconciliation runs only at start-up.
//
// The fail-safe cannot reclaim it either, and that is the part that made a single
// best-effort attempt the wrong shape: this element's *other* tasking at that POI
// keeps the keepalive relationship alive, so the POI never concludes its triggering
// function has gone and never purges. The requirement beside this one says so. So the
// cleanup withdrawal goes into the same pending-removal state as every other
// withdrawal and is retried until the POI acknowledges it.
func TestALateInstalledTriggerIsWithdrawnDurably(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	// The retry loop's clock, so a withdrawal that backs off in seconds does not cost
	// them. Recorded so the test can prove it actually retried rather than succeeding
	// first time.
	var slept int
	s.triggers.sleep = func(time.Duration) { slept++ }

	const xid = types.XID(testXIDPrimary)
	warrant := types.InterceptTask{XID: xid, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}

	planned, unreachable, undeliverable := s.triggers.plan("session-ref-1",
		fixedTasks([]types.InterceptTask{warrant}), upfs, 7)
	if len(unreachable) != 0 || len(undeliverable) != 0 || len(planned) != 1 {
		t.Fatalf("plan() = %d triggers, %d unreachable, %d undeliverable; want 1, 0, 0",
			len(planned), len(unreachable), len(undeliverable))
	}

	// The claim goes while the activation is in flight, and goes *without* a pending
	// withdrawal — which is what makes this an orphan rather than a race with the
	// withdrawal path. A session release would leave a pending entry whose own retry
	// loop owns the trigger, and stillHolds reports that, so this branch would not run.
	s.triggers.release(planned[0].key)

	// The POI refuses the cleanup withdrawal at first, and only that: the activation
	// itself lands, which is what makes the trigger real at the POI. A single
	// best-effort attempt ends here, with the trigger installed and named by nothing.
	poi.mu.Lock()
	poi.refuseOn = "DeactivateTaskRequest"
	poi.mu.Unlock()

	s.installTriggers(planned)

	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Fatalf("ActivateTaskRequest = %d, want 1", n)
	}

	// The trigger is now this registry's responsibility, tracked, and being retried.
	deadline := time.Now().Add(5 * time.Second)
	for s.triggers.pendingCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := s.triggers.pendingCount(); n != 1 {
		t.Fatalf("pending = %d after an activation that landed with its claim gone, want 1: "+
			"the trigger is installed at the POI and nothing names it, so no warrant "+
			"withdrawal, no session release and no fail-safe will ever take it down", n)
	}

	// It keeps trying. Once the POI answers, the withdrawal completes and the
	// registry's responsibility for the trigger ends.
	for poi.countMessages("DeactivateTaskRequest") < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := poi.countMessages("DeactivateTaskRequest"); n < 2 {
		t.Fatalf("DeactivateTaskRequest = %d, want at least 2 — a refused cleanup withdrawal "+
			"must be retried, not abandoned", n)
	}

	poi.mu.Lock()
	poi.refuseOn = ""
	poi.mu.Unlock()

	for s.triggers.pendingCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after the POI acknowledged the withdrawal, want 0", n)
	}
	if !strings.Contains(strings.Join(poi.sent(), ""), string(planned[0].trigger.XID)) {
		t.Error("the withdrawal did not name the trigger that was installed")
	}
}

// TestARegistryStopEndsItsBackgroundWork pins the lifecycle itself, which is what
// the two properties above rest on: a registry that has been stopped has nothing of
// its own in flight, and Stop may be called on one whose loops were never started.
func TestARegistryStopEndsItsBackgroundWork(t *testing.T) {
	reg := mustRegistry(Config{
		NEID: testNEID,
		MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{
			{NodeID: trigNodeA, X1URL: "https://127.0.0.1:1/X1/NE", NEID: testUPFNEID1},
		},
	})

	// Construction starts nothing. A test that exercises only planning or matching
	// must not have to stop anything, and an initialisation that fails after this
	// point must have nothing to leave behind.
	noGoroutineIn(t,
		"lawfulintercept.(*triggerRegistry).resolveLoop",
		"lawfulintercept.(*triggerRegistry).keepalive",
	)

	reg.Start()
	reg.Stop()

	noGoroutineIn(t,
		"lawfulintercept.(*triggerRegistry).resolveLoop",
		"lawfulintercept.(*triggerRegistry).keepalive",
	)

	// Idempotent, and safe on a registry that was never started.
	reg.Stop()

	unstarted := mustRegistry(Config{NEID: testNEID})
	unstarted.Stop()

	// A stopped registry dispatches nothing further: the propagation it would have
	// ordered has nowhere to be ordered against.
	ran := false
	unstarted.dispatchForWarrant(testXIDPrimary, func() { ran = true })
	unstarted.Stop()
	if ran {
		t.Error("a stopped registry dispatched outbound X1 work")
	}
}

// TestDispatchForWarrantRunsInOrder is the ordering primitive on its own, without an
// X1 exchange: what a test above proves through a POI, this proves about the
// mechanism, so a later change to the propagation cannot quietly lose it.
func TestDispatchForWarrantRunsInOrder(t *testing.T) {
	reg := mustRegistry(Config{NEID: testNEID})
	defer reg.Stop()

	const (
		one = types.XID(testXIDPrimary)
		two = types.XID(testXIDSecondary)
	)

	start := make(chan struct{})
	done := make(chan string, 4)

	// The first job of warrant `one` blocks, so an unordered dispatch would let the
	// second past it.
	reg.dispatchForWarrant(one, func() { <-start; done <- "one-a" })
	reg.dispatchForWarrant(one, func() { done <- "one-b" })
	// A different warrant is not held up by it: the queues are per warrant.
	reg.dispatchForWarrant(two, func() { done <- "two-a" })

	select {
	case got := <-done:
		if got != "two-a" {
			t.Fatalf("first completion was %q; a blocked warrant must not hold up another", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a second warrant's propagation was serialised behind a blocked one")
	}

	close(start)

	var order []string
	for range 2 {
		select {
		case got := <-done:
			order = append(order, got)
		case <-time.After(3 * time.Second):
			t.Fatalf("only %v completed", order)
		}
	}
	if order[0] != "one-a" || order[1] != "one-b" {
		t.Errorf("one warrant's propagations completed %v, want [one-a one-b]", order)
	}
}
