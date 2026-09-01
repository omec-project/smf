// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
)

const (
	restarted = "10.30.0.1"
	untouched = "10.30.0.2"
)

func sessionOn(t *testing.T, supi string, psi int32, nodeIPs ...string) *context.SMContext {
	t.Helper()
	smContext := context.NewSMContext(supi, psi)
	smContext.Tunnel = &context.UPTunnel{DataPathPool: context.DataPathPool{}}
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	for i, ip := range nodeIPs {
		smContext.PFCPContext[ip] = &context.PFCPSessionContext{
			NodeID:     *context.NewNodeID(ip),
			LocalSEID:  uint64(500 + i),
			RemoteSEID: uint64(900 + i),
		}
	}
	return smContext
}

// Clearing the remote identifier is the whole trigger: the activation path sends an establishment
// rather than a modification when it is zero, which is the correct message for a node holding no
// session.
func TestReissueClearsTheRemoteIdentifierForThatNodeOnly(t *testing.T) {
	smContext := sessionOn(t, "imsi-208930000000101", 1, restarted, untouched)

	if !reissue(smContext, restarted) {
		t.Fatalf("expected the session to be re-issued")
	}
	if got := smContext.PFCPContext[restarted].RemoteSEID; got != 0 {
		t.Errorf("remote identifier for the restarted node is %d, want 0 — the activation path will "+
			"send a modification to a node that holds no session", got)
	}
	if got := smContext.PFCPContext[untouched].RemoteSEID; got == 0 {
		t.Errorf("remote identifier for a node that did not restart was cleared; its session is intact " +
			"and re-establishing it would replace working forwarding state")
	}
}

// The snapshot bounds which sessions are candidates; this decides whether each still should be.
func TestReissueSkipsASessionReleasedSinceTheSnapshot(t *testing.T) {
	smContext := sessionOn(t, "imsi-208930000000102", 2, restarted)
	smContext.ChangeState(context.SmStateRelease)

	if reissue(smContext, restarted) {
		t.Errorf("a session being released was re-issued; restoration must not resurrect it")
	}
}

func TestReissueSkipsASessionNoLongerOnThatNode(t *testing.T) {
	smContext := sessionOn(t, "imsi-208930000000103", 3, untouched)

	if reissue(smContext, restarted) {
		t.Errorf("a session that is not anchored on the restarted node was re-issued")
	}
}

// A session caught without a tunnel must not panic the goroutine that is repairing an outage.
func TestReissueSurvivesASessionWithNoTunnel(t *testing.T) {
	smContext := sessionOn(t, "imsi-208930000000104", 4, restarted)
	smContext.Tunnel = nil

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("restoration panicked on a session with no tunnel: %v", r)
		}
	}()
	if reissue(smContext, restarted) {
		t.Errorf("a session with no tunnel was counted as re-issued")
	}
}

// A session whose remote identifier is still unset was never established: the establishment
// response is what sets it. Those are the ones that could not be restored.
func TestStillUnansweredIdentifiesOnlyTheSessionsTheNodeDidNotAccept(t *testing.T) {
	answered := sessionOn(t, "imsi-208930000000105", 5, restarted)
	unanswered := sessionOn(t, "imsi-208930000000106", 6, restarted)
	unanswered.PFCPContext[restarted].RemoteSEID = 0
	elsewhere := sessionOn(t, "imsi-208930000000107", 7, untouched)

	if got := outcomeOf(answered, restarted); got != waveAnswered {
		t.Errorf("a session the node acknowledged classified as %v, want waveAnswered", got)
	}
	if got := outcomeOf(unanswered, restarted); got != waveUnanswered {
		t.Errorf("a session the node did not answer for classified as %v, want waveUnanswered", got)
	}
	if got := outcomeOf(elsewhere, restarted); got != waveGone {
		t.Errorf("a session anchored on another node classified as %v, want waveGone", got)
	}
}

// A node restarting during its own restoration is not a remote case: it is what an
// under-provisioned or crash-looping node does, and restoration adds load exactly when it is least
// able to take it. Everything the run in progress is working from describes an incarnation that is
// already gone.
func TestASecondRestartSupersedesTheRestorationInProgress(t *testing.T) {
	nodeID := *context.NewNodeID("10.30.0.9")
	nodeIP := nodeID.ResolveNodeIdToIp().String()

	first := &restorationRun{}
	restorationsInProgress.Store(nodeIP, first)
	defer restorationsInProgress.Delete(nodeIP)

	if first.isSuperseded() {
		t.Fatalf("precondition: a fresh run must not be superseded")
	}

	RestoreSessionsOnUPF(nodeID, time.Now())

	if !first.isSuperseded() {
		t.Errorf("the restoration in progress was not superseded by a second restart; it would go on " +
			"installing sessions derived from an incarnation the node has already discarded, and " +
			"finish by reporting a restoration that did not happen")
	}
}

// The replacement must actually take over, or a third restart would supersede a run that is no
// longer the current one and leave the second running against stale state.
func TestTheSupersedingRunReplacesTheOneItAbandoned(t *testing.T) {
	nodeID := *context.NewNodeID("10.30.0.10")
	nodeIP := nodeID.ResolveNodeIdToIp().String()

	first := &restorationRun{}
	restorationsInProgress.Store(nodeIP, first)
	defer restorationsInProgress.Delete(nodeIP)

	RestoreSessionsOnUPF(nodeID, time.Now())

	current, ok := restorationsInProgress.Load(nodeIP)
	if !ok {
		t.Fatalf("no restoration recorded for the node after a second restart")
	}
	if current == any(first) {
		t.Errorf("the abandoned run is still recorded as the current one")
	}
}

// The bound exists because every session anchored on the node needs re-installing at the same
// moment and the node has just started. Issuing them as fast as they can be generated points the
// whole population at a cold node, and one that falls over under that load restarts again.
func TestOutstandingRequestsNeverExceedTheBound(t *testing.T) {
	restoreQuickly(t)
	nodeIP := "10.30.0.20"
	nodeID := *context.NewNodeID(nodeIP)
	associatedUpfAt(t, nodeIP)

	const population = 40
	sessions := make([]*context.SMContext, 0, population)
	for i := range population {
		sessions = append(sessions, sessionOn(t, fmt.Sprintf("imsi-2089300000005%02d", i), int32(i+1), nodeIP))
	}

	// Stand in for the UPF: answer each issued establishment shortly after it is sent, so the run
	// progresses through its waves the way it would against a live node.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			for _, smContext := range sessions {
				smContext.SMLock.Lock()
				if c, ok := smContext.PFCPContext[nodeIP]; ok && c.RemoteSEID == 0 {
					c.RemoteSEID = 4242
				}
				smContext.SMLock.Unlock()
			}
			time.Sleep(time.Millisecond)
		}
	}()

	// Sample how many are outstanding while the run proceeds.
	peak := int32(0)
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		for {
			select {
			case <-done:
				return
			default:
			}
			outstanding := int32(outstandingIn(sessions, nodeIP))
			for {
				current := atomic.LoadInt32(&peak)
				if outstanding <= current || atomic.CompareAndSwapInt32(&peak, current, outstanding) {
					break
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()

	restoreSessions(nodeID, nodeIP, &restorationRun{})

	if got := int(atomic.LoadInt32(&peak)); got > maxRestorationsInFlight {
		t.Errorf("%d requests were outstanding at once, bound is %d; a population of %d was pointed at a "+
			"node that had just restarted", got, maxRestorationsInFlight, population)
	}
}

// A node refusing everything must produce a bounded attempt, not a loop that keeps a cold node
// under load until it falls over again.
func TestARefusingNodeStopsTheRunRatherThanLoopingOverThePopulation(t *testing.T) {
	restoreQuickly(t)
	nodeIP := "10.30.0.21"
	nodeID := *context.NewNodeID(nodeIP)
	associatedUpfAt(t, nodeIP)

	// The population is large enough that stopping and not stopping are far apart in time: 200
	// sessions is 25 waves if the run works through them all, against the 3 it should take. A
	// smaller population puts the two within noise of each other, and the test then passes whether
	// or not the run actually stops.
	const population = 200
	for i := range population {
		sessionOn(t, fmt.Sprintf("imsi-208930000006%03d", i), int32(i+1), nodeIP)
	}

	start := time.Now()
	restoreSessions(nodeID, nodeIP, &restorationRun{}) // nothing answers
	elapsed := time.Since(start)

	waves := (population + maxRestorationsInFlight - 1) / maxRestorationsInFlight
	budget := time.Duration(maxConsecutiveFailedWaves+2) * restorationSettleTimeout
	if elapsed > budget {
		t.Errorf("the run took %v against a node answering nothing, over a budget of %v; it should stop "+
			"after %d unanswered wave(s) rather than working through all %d",
			elapsed, budget, maxConsecutiveFailedWaves, waves)
	}
}

// The pacing timings are shortened for the whole package, in init.
//
// Not per test and not under sync.Once: a restoration runs on its own goroutine and outlives the
// test that started it, so any write after the first test begins races with a run still reading
// them. init runs before any test and before any such goroutine exists, which removes the race
// rather than narrowing it. This package already has a TestMain, so that seat is taken.
func init() {
	restorationSettleTimeout = 60 * time.Millisecond
	restorationPollInterval = 2 * time.Millisecond
	associationWaitTimeout = 200 * time.Millisecond
	enumerationWindow = 200 * time.Millisecond
}

func restoreQuickly(t *testing.T) {
	t.Helper() // timings are set in init; the call is kept so each test says it depends on them
}

// A restoration works from the set of sessions that existed when the restart was observed. The run
// that supersedes it must take its own snapshot: a session established between the two restarts
// belongs to the incarnation now current, and one enumerated by the abandoned run may since have
// gone. Reusing the earlier list would repair the wrong population.
func TestTheSupersedingRunTakesItsOwnSnapshot(t *testing.T) {
	restoreQuickly(t)
	nodeIP := "10.30.0.30"
	nodeID := *context.NewNodeID(nodeIP)
	associatedUpfAt(t, nodeIP)
	restorationsInProgress.Delete(nodeIP)
	defer restorationsInProgress.Delete(nodeIP)

	before := sessionOn(t, "imsi-208930000000701", 1, nodeIP)

	// A run is already under way for the earlier incarnation.
	abandoned := &restorationRun{}
	restorationsInProgress.Store(nodeIP, abandoned)

	// The node restarts again, and a session appears that the abandoned run never saw.
	after := sessionOn(t, "imsi-208930000000702", 2, nodeIP)
	after.PFCPContext[nodeIP].RemoteSEID = 7777

	RestoreSessionsOnUPF(nodeID, time.Now())

	if !abandoned.isSuperseded() {
		t.Fatalf("precondition: the run in progress should have been superseded")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		after.SMLock.Lock()
		picked := after.PFCPContext[nodeIP].RemoteSEID == 0
		after.SMLock.Unlock()
		if picked {
			return // the superseding run enumerated it, so it took a fresh snapshot
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("a session that appeared after the abandoned run started was never re-issued; the " +
		"superseding run reused the earlier snapshot and left it on an incarnation that is gone")
	_ = before
}

// A session that has been released must not still read as active, or the control plane reports a
// working service that does not exist -- the state this whole change exists to end.
func TestAReleasedSessionDoesNotStillReadAsActive(t *testing.T) {
	smContext := sessionOn(t, "imsi-208930000000703", 3, restarted)
	if smContext.SMContextState == context.SmStateRelease {
		t.Fatalf("precondition: the session should start active")
	}

	if err := releaseOneSession(smContext); err == nil {
		t.Logf("release completed without error")
	}

	if smContext.SMContextState != context.SmStateRelease {
		t.Errorf("state is %v after release, want %v; a session reported as active while carrying "+
			"nothing is undiagnosable from the control plane", smContext.SMContextState, context.SmStateRelease)
	}
}

// associatedUpfAt registers a UPF for the node in the associated state, which restoration requires
// before it will issue anything: a session establishment sent while the association is down is
// rejected, and a rejection is indistinguishable from a session the UPF will not accept.
func associatedUpfAt(t *testing.T, nodeIP string) {
	t.Helper()
	upf := context.NewUPF(context.NewNodeID(nodeIP), nil)
	upf.UPFStatus = context.AssociatedSetUpSuccess
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: time.Now()}
}

// A node that is slow but willing must make the run take longer, not make it issue more at once.
// The bound exists so a restarted UPF is not handed its whole population in one burst; a node that
// answers slowly is exactly the case where a run that widened instead of waiting would do the most
// damage, since the sessions already outstanding are the ones it is struggling with.
func TestASlowNodeReducesThroughputRatherThanRaisingConcurrency(t *testing.T) {
	restoreQuickly(t)
	nodeIP := "10.30.0.21"
	nodeID := *context.NewNodeID(nodeIP)
	associatedUpfAt(t, nodeIP)

	// Three full waves, and an answer delay well inside the settle timeout so the node reads as slow
	// rather than as refusing -- a refusing node is a different behaviour, tested separately.
	const population = 24
	const answerDelay = 25 * time.Millisecond
	sessions := make([]*context.SMContext, 0, population)
	for i := range population {
		sessions = append(sessions, sessionOn(t, fmt.Sprintf("imsi-2089300000006%02d", i), int32(i+1), nodeIP))
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		firstSeen := make(map[*context.SMContext]time.Time)
		for {
			select {
			case <-done:
				return
			default:
			}
			for _, smContext := range sessions {
				smContext.SMLock.Lock()
				if c, ok := smContext.PFCPContext[nodeIP]; ok && c.RemoteSEID == 0 {
					seen, ok := firstSeen[smContext]
					if !ok {
						firstSeen[smContext] = time.Now()
					} else if time.Since(seen) >= answerDelay {
						c.RemoteSEID = 4242
						delete(firstSeen, smContext)
					}
				}
				smContext.SMLock.Unlock()
			}
			time.Sleep(time.Millisecond)
		}
	}()

	peak := int32(0)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			outstanding := int32(outstandingIn(sessions, nodeIP))
			for {
				current := atomic.LoadInt32(&peak)
				if outstanding <= current || atomic.CompareAndSwapInt32(&peak, current, outstanding) {
					break
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()

	start := time.Now()
	restoreSessions(nodeID, nodeIP, &restorationRun{})
	elapsed := time.Since(start)

	if got := int(atomic.LoadInt32(&peak)); got > maxRestorationsInFlight {
		t.Errorf("a slow node drew %d outstanding requests, bound is %d; the run widened instead of "+
			"waiting, which is the opposite of what the bound is for", got, maxRestorationsInFlight)
	}
	// The waves cannot overlap, so the run cannot finish faster than the node answers. Checked at two
	// waves rather than three to leave room for scheduling, while still being far more than a run
	// that issued everything at once would take.
	if floor := 2 * answerDelay; elapsed < floor {
		t.Errorf("the run finished in %v against a node taking %v per wave; it cannot have waited for "+
			"the waves it issued (expected at least %v)", elapsed, answerDelay, floor)
	}
}

// A sweep that finds every session locked reports a fault. When this run displaced another, that is
// not a fault -- the displaced run abandons at its next checkpoint but can still hold a session's
// lock until then -- and reporting it as one sent a real diagnosis down the wrong path.
func TestARunRecordsThatItDisplacedAnother(t *testing.T) {
	nodeID := *context.NewNodeID("10.30.0.11")
	nodeIP := nodeID.ResolveNodeIdToIp().String()

	restorationsInProgress.Store(nodeIP, &restorationRun{})
	defer restorationsInProgress.Delete(nodeIP)

	RestoreSessionsOnUPF(nodeID, time.Now())

	current, ok := restorationsInProgress.Load(nodeIP)
	if !ok {
		t.Fatalf("no restoration recorded for the node after a second restart")
	}
	run, ok := current.(*restorationRun)
	if !ok {
		t.Fatalf("what was recorded for the node is not a restoration run")
	}
	if !run.displacedAPriorRun {
		t.Errorf("a run that displaced another did not record it; a locked-out sweep will be reported " +
			"as a fault when it is two runs handing over")
	}
}

// The converse: a first restart has displaced nothing, so a sweep that finds everything locked there
// really is unexplained and must keep saying so.
func TestAFirstRunRecordsThatItDisplacedNothing(t *testing.T) {
	nodeID := *context.NewNodeID("10.30.0.12")
	nodeIP := nodeID.ResolveNodeIdToIp().String()
	defer restorationsInProgress.Delete(nodeIP)

	RestoreSessionsOnUPF(nodeID, time.Now())

	current, ok := restorationsInProgress.Load(nodeIP)
	if !ok {
		return // the run finished and removed itself; it displaced nothing either way
	}
	if run, ok := current.(*restorationRun); ok && run.displacedAPriorRun {
		t.Errorf("a first restoration recorded that it displaced another")
	}
}

// The wave loop must not be stoppable by a session's lock. SMLock is held across network calls
// elsewhere in this codebase, so a blocking acquire here is an unbounded wait: on a cluster it hung
// a run at 50 sessions, which never logged completion and left the population unrestored.
func TestAWaveIsNotBlockedByASessionWhoseLockIsHeld(t *testing.T) {
	nodeIP := "10.30.0.30"
	held := sessionOn(t, "imsi-208930000000070", 1, nodeIP)
	free := sessionOn(t, "imsi-208930000000071", 2, nodeIP)

	held.SMLock.Lock()
	defer held.SMLock.Unlock()

	returned := make(chan waveOutcome, 1)
	go func() { returned <- outcomeOf(held, nodeIP) }()

	select {
	case got := <-returned:
		if got == waveUnanswered {
			t.Errorf("a session whose lock could not be taken was reported unanswered; it would be " +
				"released as unrestorable on evidence nobody looked at")
		}
		if got != waveUnknown {
			t.Errorf("classified as %v, want waveUnknown -- nothing can be known about a session whose "+
				"lock is held", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("classifying a session whose lock was held blocked; the wave loop cannot finish")
	}
	if got := outcomeOf(free, nodeIP); got == waveUnknown {
		t.Errorf("a session whose lock was free could not be classified")
	}
}

// One restart, seen on two exchanges, must produce one restoration. Both exchanges are meant to
// reach this function -- the spec requires every path that can observe a restart to act on it -- so
// the duplicate has to be recognised here rather than prevented by silencing a path.
func TestTheSameRestartSeenTwiceStartsOneRestoration(t *testing.T) {
	nodeID := *context.NewNodeID("10.30.0.40")
	nodeIP := nodeID.ResolveNodeIdToIp().String()
	defer restorationsInProgress.Delete(nodeIP)

	recovery := time.Now()
	first := &restorationRun{recovery: recovery}
	restorationsInProgress.Store(nodeIP, first)

	RestoreSessionsOnUPF(nodeID, recovery)

	current, ok := restorationsInProgress.Load(nodeIP)
	if !ok {
		t.Fatalf("no restoration recorded for the node")
	}
	if current != any(first) {
		t.Errorf("the run in progress was replaced by a second one for the same restart; the two " +
			"displace each other and at scale neither finishes")
	}
	if first.isSuperseded() {
		t.Errorf("the run repairing this restart was abandoned on seeing the same restart again")
	}
}

// A node that really has restarted again must still displace the run in progress, which is working
// from an incarnation that no longer exists.
func TestADifferentRestartStillSupersedes(t *testing.T) {
	nodeID := *context.NewNodeID("10.30.0.41")
	nodeIP := nodeID.ResolveNodeIdToIp().String()
	defer restorationsInProgress.Delete(nodeIP)

	first := &restorationRun{recovery: time.Now().Add(-time.Minute)}
	restorationsInProgress.Store(nodeIP, first)

	RestoreSessionsOnUPF(nodeID, time.Now())

	if !first.isSuperseded() {
		t.Errorf("a genuine second restart did not abandon the run repairing the first; it would " +
			"re-install rules against an incarnation that has already discarded them")
	}
	current, _ := restorationsInProgress.Load(nodeIP)
	if current == any(first) {
		t.Errorf("the abandoned run is still recorded as the current one")
	}
}

// "Nothing anchored here" and "nothing here could be looked at" are opposite outcomes, and only one
// of them is good news. On a cluster at 20 sessions the sweep found every session locked, logged an
// error saying so, and then logged that there was nothing to restore and set the unrestored gauge to
// zero -- two adjacent lines telling opposite stories, with the metric agreeing with the wrong one.
// A population that could not be examined is exactly as dead as before.
func TestASweepThatCouldNotLookAtAnySessionDoesNotReportNothingToRestore(t *testing.T) {
	restoreQuickly(t)
	nodeIP := "10.30.0.50"
	nodeID := *context.NewNodeID(nodeIP)
	associatedUpfAt(t, nodeIP)

	locked := sessionOn(t, "imsi-208930000000080", 1, nodeIP)
	locked.SMLock.Lock()
	defer locked.SMLock.Unlock()

	_, unexaminable, _ := enumerateWithRetry(nodeID, nodeIP, &restorationRun{})

	if len(unexaminable) == 0 {
		t.Fatalf("the sweep reported nothing unexaminable while a session's lock was held; the caller " +
			"cannot then tell an empty node from one it could not examine")
	}
	if attributableTo(nodeIP, unexaminable) != 0 {
		t.Errorf("a session never seen anchored here was attributed to this node; a UPF with nothing on " +
			"it would report sessions it does not have")
	}
	rememberAnchored(nodeIP, []*context.SMContext{locked})
	if attributableTo(nodeIP, unexaminable) != 1 {
		t.Errorf("a session last seen anchored here was not attributed to it, so a population stranded " +
			"behind held locks would be reported as absent")
	}
}

// The converse must keep working: a node with nothing on it really has nothing to restore, and must
// not be reported as a population that could not be examined.
func TestASweepOfAnEmptyNodeReportsNothingLocked(t *testing.T) {
	restoreQuickly(t)
	nodeIP := "10.30.0.51"
	nodeID := *context.NewNodeID(nodeIP)
	associatedUpfAt(t, nodeIP)

	anchored, unexaminable, _ := enumerateWithRetry(nodeID, nodeIP, &restorationRun{})

	if len(anchored) != 0 || len(unexaminable) != 0 {
		t.Errorf("an empty node reported %d anchored and %d unexaminable; it should report neither",
			len(anchored), len(unexaminable))
	}
}

// Restoration sends establishments and waits on the remote identifier, not on the response channel,
// so the responses it causes are never taken. The channel holds one value, and
// HandlePfcpSessionEstablishmentResponse sends into it while holding SMLock -- so the second
// restoration of a session finds it full, the handler's send blocks forever, and the session's lock
// is never released again. On a cluster that left 20 of 20 sessions permanently unrestorable.
func TestReissueLeavesRoomForTheResponseItWillCause(t *testing.T) {
	nodeIP := "10.30.0.60"
	smContext := sessionOn(t, "imsi-208930000000090", 1, nodeIP)

	// Stand in for the response to a previous restoration, which nothing consumed.
	smContext.SBIPFCPCommunicationChan <- context.SessionEstablishSuccess

	reissue(smContext, nodeIP)

	// The handler sends without selecting, so the only thing that keeps it from blocking is room in
	// the buffer. A non-blocking send standing in for it must therefore succeed.
	select {
	case smContext.SBIPFCPCommunicationChan <- context.SessionEstablishSuccess:
	default:
		t.Errorf("no room for the response this establishment will cause; the handler sends while " +
			"holding SMLock, so it would block there forever and the session could never be restored again")
	}
}

// A wave in which nothing could be examined must not read as a wave that succeeded. The check used
// to skip sessions whose lock it could not take and then treat the empty result as "all answered",
// so a batch that was entirely busy was counted as restored without anything having been looked at.
func TestAWaveWhereNothingCanBeExaminedReportsNoneRestored(t *testing.T) {
	restoreQuickly(t)
	nodeIP := "10.30.0.70"
	a := sessionOn(t, "imsi-208930000000100", 1, nodeIP)
	b := sessionOn(t, "imsi-208930000000101", 2, nodeIP)
	a.SMLock.Lock()
	b.SMLock.Lock()
	defer a.SMLock.Unlock()
	defer b.SMLock.Unlock()

	settled := settleWave([]*context.SMContext{a, b}, nodeIP)

	if settled.answered != 0 {
		t.Errorf("%d session(s) counted as restored, but neither could be examined", settled.answered)
	}
	if settled.unknown != 2 {
		t.Errorf("%d session(s) reported as unexaminable, want 2", settled.unknown)
	}
	if len(settled.unanswered) != 0 {
		t.Errorf("%d session(s) would be released, on evidence nobody could gather", len(settled.unanswered))
	}
}

// The set a wave returns for release can only contain sessions the wave was given. The wave loop
// passes it only what reissue actually sent, so a session that was skipped -- busy, purged, without
// a tunnel -- cannot be torn down on the strength of a silence about a request never made.
func TestAWaveNeverReturnsASessionItWasNotGiven(t *testing.T) {
	restoreQuickly(t)
	nodeIP := "10.30.0.71"
	sent := sessionOn(t, "imsi-208930000000102", 1, nodeIP)
	sent.PFCPContext[nodeIP].RemoteSEID = 0
	skipped := sessionOn(t, "imsi-208930000000103", 2, nodeIP)
	skipped.PFCPContext[nodeIP].RemoteSEID = 0

	settled := settleWave([]*context.SMContext{sent}, nodeIP)

	for _, s := range settled.unanswered {
		if s == skipped {
			t.Fatalf("a session the wave was never given came back in the release set")
		}
	}
	if len(settled.unanswered) != 1 || settled.unanswered[0] != sent {
		t.Errorf("expected exactly the session that was sent, got %d", len(settled.unanswered))
	}
}

// A session that has moved off this node in the meantime is neither restored nor unrestorable. It
// used to be indistinguishable from one the node had answered, which inflated the restored count.
func TestASessionThatLeftTheNodeIsNotCountedAsRestored(t *testing.T) {
	restoreQuickly(t)
	nodeIP := "10.30.0.72"
	gone := sessionOn(t, "imsi-208930000000104", 1, "10.30.0.99")

	settled := settleWave([]*context.SMContext{gone}, nodeIP)

	if settled.answered != 0 {
		t.Errorf("a session anchored elsewhere was counted as restored on %s", nodeIP)
	}
	if settled.gone != 1 {
		t.Errorf("gone=%d, want 1", settled.gone)
	}
}

// releaseOneSession recovers from panics, which means a lock leaked on a panicking path is invisible
// -- the release merely reports an error, and every later sweep silently finds that session
// unexaminable for the rest of the process's life. ChangeState indexes into the data path pool and
// panics on a context without the entry it expects, so this is reachable, and it happened once while
// this code was being written.
func TestAPanicWhileReleasingDoesNotLeaveTheSessionLocked(t *testing.T) {
	nodeIP := "10.30.0.80"
	smContext := sessionOn(t, "imsi-208930000000110", 1, nodeIP)

	// ChangeState only walks the data path pool when the session is or becomes active, and this pool
	// has no entry at the index it reaches for.
	smContext.SMLock.Lock()
	smContext.SMContextState = context.SmStateActive
	smContext.SMLock.Unlock()

	if err := releaseOneSession(smContext); err == nil {
		t.Errorf("the release reported success although it panicked part-way")
	}

	if !smContext.SMLock.TryLock() {
		t.Fatalf("the session's lock was not released; every later sweep would skip it as unexaminable " +
			"and it could never be restored or released again")
	}
	smContext.SMLock.Unlock()
}

// outstandingIn observes a run in progress from the outside. The wave loop itself uses settleWave,
// which distinguishes states this does not.
func outstandingIn(batch []*context.SMContext, nodeIP string) int {
	outstanding := 0
	for _, smContext := range batch {
		if outcomeOf(smContext, nodeIP) == waveUnanswered {
			outstanding++
		}
	}
	return outstanding
}
