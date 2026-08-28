// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	gocontext "context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/consumer"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/util"
)

// maxRestorationsInFlight bounds how many session establishments are outstanding against a UPF
// that has just restarted.
//
// Every session anchored on the node needs re-installing at the same moment, and the node that
// must accept them has just started. Issuing them as fast as they can be generated points the
// whole anchored population at a cold node, and a node that falls over under that load restarts
// again. The bound is on requests outstanding rather than on a delay between them, so a UPF that
// answers slowly slows the restoration down instead of receiving more of it.
var maxRestorationsInFlight = 8

// restorationSettleTimeout bounds how long one wave is waited on before the next is issued. A UPF
// that never answers must not stall the restoration indefinitely; the sessions it did not answer
// for are left for the failure path rather than blocking the rest.
var restorationSettleTimeout = 10 * time.Second

// restorationPollInterval is how often a wave is checked for completion while it settles.
var restorationPollInterval = 100 * time.Millisecond

// maxConsecutiveFailedWaves bounds how long a node that answers nothing is persisted with.
var maxConsecutiveFailedWaves = 2

// associationWaitTimeout bounds how long a restoration waits for the PFCP association to come back
// before giving up. ProbeInactiveUpfs re-associates on its own cycle, so this only has to outlast
// that.
var associationWaitTimeout = 60 * time.Second

// enumerationWindow bounds how long sweeps are repeated when every session was busy. Measured
// against the thing being waited for: a session is locked because a procedure holds it, and those
// resolve in seconds. The previous bound was 20 attempts at the poll interval -- two seconds -- and
// a cluster run at 20 sessions found every one of them locked for longer than that, so the sweep
// gave up and the whole population was left dead.
//
// Waiting longer costs nothing here. This path is only reached when nothing was found, so there is
// no session being held back by the wait.
var enumerationWindow = 30 * time.Second

// lockAcquireTimeout bounds how long restoration waits for one session's lock. Long enough to ride
// out an ordinary in-memory critical section, far short of anything that makes a network call.
var lockAcquireTimeout = 50 * time.Millisecond

func init() {
	context.OnRestart = RestoreSessionsOnUPF
}

var restorationsInProgress sync.Map // UPF node IP -> *restorationRun

// sessionsLastSeenOn remembers which sessions a completed sweep found anchored on each node.
//
// A sweep that cannot take a session's lock cannot read its PFCPContext, so it cannot tell whether
// that session belongs to this node or another one. Counting every unexaminable session against the
// node being restored makes a UPF with nothing anchored on it report sessions it does not have.
// Intersecting with what was last seen here gives a number that can be defended.
var sessionsLastSeenOn sync.Map // UPF node IP -> map[string]struct{} of SMContext refs

func rememberAnchored(nodeIP string, anchored []*context.SMContext) {
	refs := make(map[string]struct{}, len(anchored))
	for _, smContext := range anchored {
		refs[smContext.Ref] = struct{}{}
	}
	sessionsLastSeenOn.Store(nodeIP, refs)
}

// attributableTo counts how many of the sessions that could not be examined were last seen anchored
// on this node. Sessions never seen here are left out: they are somebody else's problem, and naming
// them here would be a guess.
func attributableTo(nodeIP string, unexaminable []string) int {
	value, ok := sessionsLastSeenOn.Load(nodeIP)
	if !ok {
		return 0
	}
	refs, ok := value.(map[string]struct{})
	if !ok {
		return 0
	}
	count := 0
	for _, ref := range unexaminable {
		if _, seenHere := refs[ref]; seenHere {
			count++
		}
	}
	return count
}

type restorationRun struct {
	superseded bool
	// The recovery state of the restart this run is repairing. It is what tells a second observation
	// of the same restart from a node that has restarted again.
	recovery time.Time
	// Set when this run displaced one that had not finished. The displaced run abandons at its next
	// checkpoint, but it can still be inside reissue holding a session's lock, and this run's sweep
	// will then skip that session. Recorded so the sweep can say so instead of reporting a fault.
	displacedAPriorRun bool
	mu                 sync.Mutex
}

func (r *restorationRun) supersede() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.superseded = true
}

// sameRestartAs reports whether this run is already repairing the restart that the given recovery
// state describes. Compared at second resolution, as HasRestarted compares it: that is the
// resolution the timestamp is carried at on the wire.
func (r *restorationRun) sameRestartAs(recovery time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.recovery.IsZero() && r.recovery.Unix() == recovery.Unix()
}

func (r *restorationRun) isSuperseded() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.superseded
}

// RestoreSessionsOnUPF re-installs, on a user-plane function that has restarted, the sessions this
// SMF still holds for it.
//
// The UPF has forgotten its rules; this SMF has not. Its record of them is therefore the
// description of what each session needs, and re-installing from that record is the whole of the
// repair. The identifiers are carried over unchanged: they mean something to a UPF only while it
// holds the rules they name, and a restarted one holds none.
//
// Runs asynchronously. Callers detect the restart while holding the UPF lock, which the send path
// also takes.
func RestoreSessionsOnUPF(nodeID context.NodeID, recovery time.Time) {
	nodeIP := nodeID.ResolveNodeIdToIp().String()

	run := &restorationRun{recovery: recovery}
	if previous, loaded := restorationsInProgress.LoadOrStore(nodeIP, run); loaded {
		prior, ok := previous.(*restorationRun)
		// One restart, observed twice. A liveness response and the re-association that follows it
		// carry the same recovery state seconds apart, and both are meant to reach this function --
		// the spec requires every exchange that can see a restart to act on it, precisely so none of
		// them is the only one wired. What must not follow is a second restoration: it displaces the
		// first, and at 49 sessions the two displaced each other until neither finished and the
		// population was left part-restored.
		//
		// Deduplicated here rather than by recording the recovery state at the first observation.
		// Recording it there silences every later exchange, including the one that would otherwise
		// notice a UPF that came back after this run had already given up waiting for it.
		if ok && prior.sameRestartAs(recovery) {
			// Nothing to store: LoadOrStore did not replace the entry when it loaded one, so the run
			// already repairing this restart is still the recorded one. Re-storing it would risk
			// clobbering a newer run that a concurrent detection had put there in the meantime.
			logger.PfcpLog.Infof("UPF[%s] restart already being restored; this is the same restart seen "+
				"on another exchange, not a second one", nodeIP)
			return
		}
		// The node restarted again while we were still repairing the last restart. Everything the
		// run in progress is working from describes an incarnation that is already gone, so it is
		// abandoned rather than completed against a node that has discarded its results.
		if ok {
			prior.supersede()
		}
		run.displacedAPriorRun = true
		restorationsInProgress.Store(nodeIP, run)
		logger.PfcpLog.Warnf("UPF[%s] restarted again during a restoration; the one in progress is abandoned", nodeIP)
	}

	go func() {
		defer restorationsInProgress.CompareAndDelete(nodeIP, run)
		restoreSessions(nodeID, nodeIP, run)
	}()
}

// enumerateWithRetry looks again when the sweep found nothing only because sessions were locked.
//
// Enumeration takes each session's lock with TryLock and skips what it cannot take, so that one
// session's procedure cannot stall a sweep of all of them. Giving up on the first attempt is too
// blunt: a session is locked briefly and often, and under back-to-back restarts every session can be
// busy at the instant the sweep runs. Measured on a cluster: three restarts in succession, and the
// second and third each reported "no sessions anchored" while both sessions were merely locked, so
// nothing was restored and service never came back.
//
// Retrying only when sessions were locked out keeps the distinction that matters. A sweep that found
// nothing because there is nothing has finished; a sweep that found nothing because everything was
// busy has not looked yet.
func enumerateWithRetry(nodeID context.NodeID, nodeIP string, run *restorationRun) (anchoredSessions []*context.SMContext, unexaminableAtTheEnd []string, stillEstablishing int) {
	deadline := time.Now().Add(enumerationWindow)
	for attempt := 0; ; attempt++ {
		anchored, unexaminable, establishing := context.SessionsAnchoredOn(nodeID)
		if len(anchored) > 0 || len(unexaminable) == 0 || !time.Now().Before(deadline) || run.isSuperseded() {
			if len(unexaminable) > 0 && len(anchored) == 0 {
				// Reported as a fault only when nothing explains it. A run that displaced another
				// is the expected case: the displaced one abandons at its next checkpoint but can
				// still hold a session's lock inside reissue until then, and calling that "none
				// could be restored" reads as a defect in the restoration rather than two runs
				// handing over.
				if run.displacedAPriorRun {
					logger.PfcpLog.Warnf("UPF[%s] found nothing on %d attempt(s) and %d session(s) could "+
						"not be examined; the restoration this one displaced has not released them yet, "+
						"so they are left to the sweep that follows", nodeIP, attempt+1, len(unexaminable))
				} else {
					logger.PfcpLog.Errorf("UPF[%s] found nothing on %d attempt(s) and %d session(s) could "+
						"not be examined; %d of those were last seen anchored here",
						nodeIP, attempt+1, len(unexaminable), attributableTo(nodeIP, unexaminable))
				}
			}
			return anchored, unexaminable, establishing
		}
		time.Sleep(restorationPollInterval)
	}
}

func restoreSessions(nodeID context.NodeID, nodeIP string, run *restorationRun) {
	if !waitForAssociation(nodeID, nodeIP, run) {
		return
	}

	anchored, unexaminable, establishing := enumerateWithRetry(nodeID, nodeIP, run)
	if len(anchored) == 0 {
		// Two different outcomes, and only one of them is good news. A node with nothing anchored on
		// it needs nothing done. A node whose every session was locked for the whole window has a
		// population that is just as dead as before, and saying "nothing to restore" about it --
		// with the gauge set to zero -- is the exact failure this change exists to remove: a record
		// that reads healthy over a service that is not. Seen on a cluster at 20 sessions, where the
		// error naming the locked sweep and the line claiming there was nothing to do were logged
		// one after the other, and the metric agreed with the wrong one.
		if stranded := attributableTo(nodeIP, unexaminable); stranded > 0 {
			logger.PfcpLog.Errorf("UPF[%s] restarted and %d session(s) last seen anchored on it could not be "+
				"examined within %s; they are left unrestored, not absent (%d session(s) were unexaminable "+
				"in total, the rest belong elsewhere)", nodeIP, stranded, enumerationWindow, len(unexaminable))
			metrics.SetUpfUnrestoredSessions(context.SMF_Self().NfInstanceID, nodeIP, stranded)
			return
		}
		if len(unexaminable) > 0 {
			// Unexaminable, but none of them was ever seen on this node. Saying nothing is anchored
			// here is the best available answer, and claiming otherwise would put another node's
			// problem under this node's label.
			logger.PfcpLog.Warnf("UPF[%s] restarted with nothing anchored on it that could be found; "+
				"%d session(s) elsewhere could not be examined", nodeIP, len(unexaminable))
		}
		if establishing > 0 {
			// Not an empty node. These are being set up right now and their own establishment owns
			// them; restoration must not touch one, but nor should it report the node as bare.
			logger.PfcpLog.Infof("UPF[%s] restarted with no established sessions to restore; %d are "+
				"still being set up and are left to the paths establishing them", nodeIP, establishing)
		} else {
			logger.PfcpLog.Infof("UPF[%s] restarted with no sessions anchored on it; nothing to restore", nodeIP)
		}
		metrics.SetUpfUnrestoredSessions(context.SMF_Self().NfInstanceID, nodeIP, 0)
		return
	}
	logger.PfcpLog.Infof("UPF[%s] restarted; restoring %d session(s)", nodeIP, len(anchored))
	rememberAnchored(nodeIP, anchored)

	// Every anchored session is currently not carrying traffic; the gauge falls as they come back,
	// so it reads as the outstanding backlog while a restoration is running and as the sessions
	// left behind once one has finished.
	metrics.SetUpfUnrestoredSessions(context.SMF_Self().NfInstanceID, nodeIP, len(anchored))

	restored, skipped, unknown, gone := 0, 0, 0, 0
	unrestored := make([]*context.SMContext, 0)
	consecutiveFailedWaves := 0
	for wave := 0; wave < len(anchored); wave += maxRestorationsInFlight {
		if run.isSuperseded() {
			logger.PfcpLog.Warnf("UPF[%s] restoration abandoned after %d of %d session(s): superseded by a later restart",
				nodeIP, restored, len(anchored))
			// Deliberately without resolving the failures collected so far. They are still anchored
			// on the node, so the run that superseded this one enumerates them again and may well
			// restore them against the incarnation that is now current. Releasing them here would
			// tear down sessions that are about to be repaired, on the evidence of a UPF that no
			// longer exists.
			return
		}

		end := min(wave+maxRestorationsInFlight, len(anchored))
		batch := anchored[wave:end]

		// Only what was actually sent is waited on. A session reissue skipped was never sent
		// anything, so the node's silence about it is not evidence of a refusal, and letting it into
		// the wave would put it on the list this run releases.
		sent := make([]*context.SMContext, 0, len(batch))
		for _, smContext := range batch {
			if reissue(smContext, nodeIP) {
				sent = append(sent, smContext)
			} else {
				skipped++
			}
		}

		settled := settleWave(sent, nodeIP)
		restored += settled.answered
		unknown += settled.unknown
		gone += settled.gone
		unrestored = append(unrestored, settled.unanswered...)

		// A node that is refusing or ignoring everything will not start answering because more is
		// sent to it. Continuing turns a recoverable restart into a loop that keeps a cold node
		// under load, so the run stops and says how far it got rather than working through a
		// population that cannot be restored.
		//
		// Judged on answers, not on the absence of them: a wave in which nothing could be examined
		// is not a wave the node refused, and counting it as one used to stop the run early.
		if len(sent) > 0 && settled.answered == 0 {
			consecutiveFailedWaves++
			if consecutiveFailedWaves >= maxConsecutiveFailedWaves {
				logger.PfcpLog.Errorf("UPF[%s] restoration stopped after %d consecutive wave(s) with no response: "+
					"%d restored, %d not restored, %d never attempted, %d could not be examined",
					nodeIP, consecutiveFailedWaves, restored, len(unrestored), skipped, unknown)
				finish(nodeIP, restored, skipped, unknown, gone, unrestored)
				return
			}
		} else {
			consecutiveFailedWaves = 0
		}
	}

	logger.PfcpLog.Infof("UPF[%s] restoration complete: %d restored, %d not restored, %d not attempted "+
		"(busy, purged, or no longer live), %d could not be examined, %d no longer on this node",
		nodeIP, restored, len(unrestored), skipped, unknown, gone)
	finish(nodeIP, restored, skipped, unknown, gone, unrestored)
}

// finish records the outcome and settles whatever the node would not accept.
//
// The counts are separate on purpose. A restoration that restored some sessions and released the
// rest must not be readable as one that simply completed -- that conflation is the shape of the
// failure this whole change exists to remove, where every available signal reported health while
// the sessions carried nothing.
//
// The unrestored gauge counts what is known to be without service: sessions the node refused, plus
// those nothing could be learned about. A session that could not be examined has not been shown to
// be healthy, and leaving it out of the count is how a restoration comes to report success over a
// population that is still dead.
func finish(nodeIP string, restored, skipped, unknown, gone int, unrestored []*context.SMContext) {
	smfID := context.SMF_Self().NfInstanceID
	metrics.AddUpfRestorationStats(smfID, nodeIP, "restored", restored)
	metrics.AddUpfRestorationStats(smfID, nodeIP, "skipped", skipped)
	metrics.AddUpfRestorationStats(smfID, nodeIP, "unexaminable", unknown)
	metrics.AddUpfRestorationStats(smfID, nodeIP, "gone", gone)
	// Counted after the releases, not before. A session that was torn down is no longer a session
	// without service -- the UE will establish a new one -- whereas one the release could not reach
	// still is, and so is one nothing could be learned about.
	stillWithoutService := unknown + resolveUnrestorable(unrestored, nodeIP)
	metrics.SetUpfUnrestoredSessions(smfID, nodeIP, stillWithoutService)
}

// reissue clears the remote session identifier for this node and re-runs the ordinary activation.
// Clearing it is what makes that path send an establishment rather than a modification, which is
// the correct message for a node that holds no session.
//
// The liveness re-check is deliberate: the snapshot bounds which sessions are candidates, and this
// decides whether each one still should be. A session released between the two must not be
// resurrected.
func reissue(smContext *context.SMContext, nodeIP string) bool {
	// Taken with a bounded attempt, not held for. Live subscriber signalling holds this lock too,
	// and a repair that queues ahead of it delays the subscriber for no benefit -- the session can
	// as easily be restored on the next sweep. This bounds how long restoration waits; sending
	// outside the lock, below, bounds how long it holds.
	if !tryLockFor(&smContext.SMLock, lockAcquireTimeout) {
		smContext.SubPfcpLog.Infof("session is busy; leaving it for the next sweep")
		return false
	}
	unlocked := false
	release := func() {
		if !unlocked {
			smContext.SMLock.Unlock()
			unlocked = true
		}
	}
	defer release()

	pfcpContext, stillAnchored := smContext.PFCPContext[nodeIP]
	if !stillAnchored {
		return false
	}
	if smContext.SMContextState == context.SmStateRelease {
		return false
	}
	// Set as the first act of replacing a session. The context is on its way out and the
	// replacement is waiting for this very lock, so restoring it would repair something that is
	// about to be discarded while delaying the session taking its place.
	if smContext.LocalPurged {
		smContext.SubPfcpLog.Infof("session has been purged and replaced; not restoring it")
		return false
	}
	// Restoration walks every session anchored on the node, including any caught part-way through
	// establishment or teardown. The activation path dereferences the tunnel, so a session without
	// one is skipped rather than allowed to panic a goroutine that is repairing an outage.
	if smContext.Tunnel == nil {
		smContext.SubPfcpLog.Warnf("session has no tunnel and cannot be restored")
		return false
	}

	// Take back the response to the last establishment this restoration issued, which nothing
	// consumed.
	//
	// SBIPFCPCommunicationChan holds one value. In the ordinary flow a request is sent by a
	// procedure that then waits on this channel, so every response is taken. Restoration sends
	// establishments and waits on the remote identifier instead, so its responses accumulate -- and
	// the second restoration of a session finds the channel full. HandlePfcpSessionEstablishmentResponse
	// sends into it *while holding SMLock*, so the send blocks forever and the session's lock is
	// never released. Every later sweep then skips that session, and it can never be restored again.
	//
	// Observed on a cluster: 20 sessions, all permanently locked, 20 goroutines parked in `chan send`
	// inside that handler, and each restart reporting "every anchored session was locked".
	//
	// Safe to take here because no legitimate waiter can be parked on this channel for this session
	// right now. The modification and release paths hold SMLock across their receive, so they cannot
	// run while this does; and the establishment path, which waits without the lock, only does so for
	// a session that has never been acknowledged -- which the enumeration excludes.
	select {
	case <-smContext.SBIPFCPCommunicationChan:
		smContext.SubPfcpLog.Debugf("discarded an unconsumed PFCP response from an earlier restoration")
	default:
	}

	pfcpContext.RemoteSEID = 0
	pfcpContext.ClearedByRestoration = true
	markRulesUncreated(smContext, nodeIP)
	nameTheUeAddressInUse(smContext, nodeIP)
	pinUplinkTunnelsToTheirExistingTeids(smContext, nodeIP)

	// Sent under the lock, as the establishment path does. SendPFCPRules reads the tunnel, the data
	// path and the PFCP context, all of which other code mutates under this lock, so releasing first
	// would trade the stall this change fixes for a race -- which the race detector duly caught when
	// it was tried. On the native datapath the send is a UDP write and the hold is microseconds.
	//
	// It is not bounded on the adapter datapath, where the same call becomes an HTTP POST. That is
	// recorded as a follow-up rather than fixed here: it needs the rules snapshotting so the send
	// can happen outside the lock, and it cannot be reached in a deployment that has the adapter
	// disabled.
	SendPFCPRules(smContext)
	return true
}

// tryLockFor acquires the lock if it can be had within d, and reports whether it did.
//
// sync.Mutex offers TryLock but no bounded wait, and neither extreme suits a repair: failing on the
// first attempt gives up while a lock is held for microseconds, and waiting without limit is what
// let restoration stall a subscriber.
func tryLockFor(mu *sync.Mutex, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if mu.TryLock() {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

// markRulesUncreated puts the session's rules for this node back to the state that means "not yet
// on the user plane", because that is now true of all of them.
//
// The establishment builder emits a rule only when its state is RULE_INITIAL, and advances it to
// RULE_CREATE once sent. After the first establishment the session's FARs and QERs therefore say
// they exist on the user plane. They did, on the incarnation that is gone. Re-sending without
// correcting that produces an establishment carrying a PDR and nothing else: the packet matches the
// rule and then has no forwarding action and no QoS rule to act under. Measured on a cluster as a
// correct PDR installed alongside "need at least 1 QER in PDR or 2 QERs in session".
//
// PDRs are re-sent today only because the builder never advances their state, which is an asymmetry
// in that code rather than a decision. Resetting all three makes the behaviour deliberate instead of
// dependent on it.
//
// Scoped to the node that restarted: rules on another user plane are still installed there, and
// telling this session they are not would re-create them on a node that already has them.
// nameTheUeAddressInUse corrects the UE address on every rule for this node, in both directions.
//
// The uplink rule matches on the tunnel, the downlink rule matches on the UE address, and both were
// built carrying the address the SMF proposed rather than the one the user plane allocated. Fixing
// only the uplink leaves downlink matching an address the UE does not have, so traffic reaches the
// subscriber's session and no reply ever comes back -- which reads exactly like the uplink still
// being broken.
func nameTheUeAddressInUse(smContext *context.SMContext, nodeIP string) {
	for _, dataPath := range smContext.Tunnel.DataPathPool {
		for node := dataPath.FirstDPNode; node != nil; node = node.Next() {
			if node.UPF == nil || node.UPF.NodeID.ResolveNodeIdToIp().String() != nodeIP {
				continue
			}
			for _, tunnel := range []*context.GTPTunnel{node.UpLinkTunnel, node.DownLinkTunnel} {
				if tunnel == nil {
					continue
				}
				for _, pdr := range tunnel.PDR {
					if pdr != nil {
						pinUeAddress(smContext, pdr)
					}
				}
			}
		}
	}
}

func markRulesUncreated(smContext *context.SMContext, nodeIP string) {
	rules := 0
	for _, dataPath := range smContext.Tunnel.DataPathPool {
		for node := dataPath.FirstDPNode; node != nil; node = node.Next() {
			if node.UPF == nil || node.UPF.NodeID.ResolveNodeIdToIp().String() != nodeIP {
				continue
			}
			for _, tunnel := range []*context.GTPTunnel{node.UpLinkTunnel, node.DownLinkTunnel} {
				if tunnel == nil {
					continue
				}
				for _, pdr := range tunnel.PDR {
					if pdr == nil {
						continue
					}
					pdr.State = context.RULE_INITIAL
					rules++
					if pdr.FAR != nil {
						pdr.FAR.State = context.RULE_INITIAL
						rules++
					}
					for _, qer := range pdr.QER {
						if qer != nil {
							qer.State = context.RULE_INITIAL
							rules++
						}
					}
				}
			}
		}
	}
	smContext.SubPfcpLog.Infof("marked %d rule(s) for UPF[%s] as not yet installed, so the "+
		"re-establishment carries all of them", rules, nodeIP)
}

// pinUplinkTunnelsToTheirExistingTeids makes the re-installed uplink PDRs name the tunnel the RAN is
// already using, rather than asking the UPF to allocate a new one.
//
// Establishment normally sets the F-TEID's CHOOSE flag and lets the UPF pick, and the SMF then tells
// the RAN which tunnel to send on. That is right the first time and wrong on a restart: the UPF picks
// a second TEID, the RAN is never told, and every uplink packet keeps arriving on the old one and
// misses the table. Observed on a cluster as pdrLookupFail counting every packet while the
// restoration reported success.
//
// A restarted UPF holds no tunnels, so the one it used before is free for it to be given back. This
// is the same reasoning as carrying the rule identifiers over: the value means something to the UPF
// only while it holds the rule that names it.
func pinUplinkTunnelsToTheirExistingTeids(smContext *context.SMContext, nodeIP string) {
	pinned, skipped := 0, 0
	for _, dataPath := range smContext.Tunnel.DataPathPool {
		for node := dataPath.FirstDPNode; node != nil; node = node.Next() {
			if node.UPF == nil || node.UPF.NodeID.ResolveNodeIdToIp().String() != nodeIP {
				continue
			}
			if node.UpLinkTunnel == nil || node.UpLinkTunnel.TEID == 0 {
				// Never established, so there is no tunnel to preserve. Not a fault.
				continue
			}
			access := accessAddressOf(node.UPF, smContext.SelectedPDUSessionType)
			if access == nil {
				// Said out loud, because the alternative is a repair that quietly does nothing. An
				// F-TEID carrying the V4 flag and no address is malformed and the UPF rejects the
				// whole establishment, so the pin is skipped instead -- and a silent skip is
				// indistinguishable, from outside, from a pin that worked.
				smContext.SubPfcpLog.Warnf("uplink tunnel NOT pinned for UPF[%s]: no N3 address "+
					"(session type %d, %d N3 interface(s)); the UPF will choose a new TEID and the RAN "+
					"will keep sending on the old one",
					nodeIP, smContext.SelectedPDUSessionType, n3InterfaceCount(node.UPF))
				skipped++
				continue
			}
			// Counted per node as well as in total. The line below names this node's TEID and
			// address, so reporting the running total beside them would attribute another node's
			// rules to this one -- and would log a pin for a node that pinned nothing, as soon as
			// any earlier node had pinned something.
			nodePinned := 0
			for _, pdr := range node.UpLinkTunnel.PDR {
				if pdr == nil || pdr.PDI.LocalFTeid == nil {
					continue
				}
				pdr.PDI.LocalFTeid = &context.FTEID{
					V4:          true,
					Teid:        node.UpLinkTunnel.TEID,
					Ipv4Address: access,
				}
				nodePinned++
			}
			pinned += nodePinned
			if nodePinned > 0 {
				smContext.SubPfcpLog.Infof("uplink tunnel pinned for UPF[%s]: TEID %#x at %s, %d rule(s)",
					nodeIP, node.UpLinkTunnel.TEID, access, nodePinned)
			}
		}
	}
	if pinned == 0 && skipped == 0 {
		smContext.SubPfcpLog.Warnf("uplink tunnel NOT pinned for UPF[%s]: no uplink rule on this node "+
			"carried a tunnel to preserve", nodeIP)
	}
}

// pinUeAddress makes the re-installed rule name the address the UE actually holds.
//
// Where the user plane allocates UE addresses, it returns its choice in the establishment response
// and the SMF records it on the session — but the rule that was built before the request still
// carries the address the SMF had proposed. That never mattered, because the node had chosen the
// address itself and installed the rule accordingly. On a restart it matters completely: the SMF
// re-sends the rule it built, the node installs it verbatim, and the rule names an address the UE
// does not have. Observed on a cluster as a restored rule for 192.168.100.1 while the live UE held
// 192.168.100.3, with every uplink packet missing the table.
//
// This is the same fault as the tunnel identifier, in a second field: a value the user plane chose,
// of which the SMF holds a stale copy that only surfaces when the rule is sent a second time.
func pinUeAddress(smContext *context.SMContext, pdr *context.PDR) {
	if pdr.PDI.UEIPAddress == nil || smContext.PDUAddress == nil || smContext.PDUAddress.Ip == nil {
		return
	}
	if !pdr.PDI.UEIPAddress.CHV4 && pdr.PDI.UEIPAddress.Ipv4Address.Equal(smContext.PDUAddress.Ip) {
		return
	}
	smContext.SubPfcpLog.Infof("re-installed rule asked the UPF to choose a UE address (CHV4=%t, "+
		"carried %v); naming the address in use instead, %s",
		pdr.PDI.UEIPAddress.CHV4, pdr.PDI.UEIPAddress.Ipv4Address, smContext.PDUAddress.Ip)

	// Clearing CHV4 is the whole of it. Setting the address while the choose flag is still set
	// changes nothing: the user plane ignores the value and allocates from its own pool, which a
	// restart has just reset, so it hands out an address the UE has never held. Observed on a
	// cluster as a restored rule for 192.168.100.1 while the UE held 192.168.100.2.
	pdr.PDI.UEIPAddress.CHV4 = false
	pdr.PDI.UEIPAddress.V4 = true
	pdr.PDI.UEIPAddress.Ipv4Address = smContext.PDUAddress.Ip
}

func n3InterfaceCount(upf *context.UPF) int {
	upf.UpfLock.RLock()
	defer upf.UpfLock.RUnlock()
	return len(upf.N3Interfaces)
}

// accessAddressOf returns the N3 address the RAN was told to send to.
//
// It resolves it the same way the N2 setup did, through UPFInterfaceInfo.IP on the first N3
// interface. Reading IPv4EndPointAddresses directly is not equivalent: an interface configured by
// FQDN carries no address there, and an earlier version of this returned nil for exactly that
// reason, then built an F-TEID with the V4 flag and no address, which the UPF rejected as missing a
// mandatory IE.
//
// Deriving it the same way as the N2 build is the point, not a convenience: the address pinned here
// has to be the one the RAN is sending to, and that is the only way to be sure of it.
func accessAddressOf(upf *context.UPF, pduSessionType uint8) net.IP {
	upf.UpfLock.RLock()
	defer upf.UpfLock.RUnlock()
	if len(upf.N3Interfaces) == 0 {
		return nil
	}
	address, err := upf.N3Interfaces[0].IP(pduSessionType)
	if err != nil {
		return nil
	}
	return address
}

// A wave is given a chance to settle before the next is issued, so the bound is on requests
// outstanding rather than on how fast a loop can run.
//
// A session in a wave ends in one of four states, and conflating any two of them has cost a defect.
// "Answered" and "not answered" are conclusions; "could not be examined" is the absence of one, and
// treating it as either a success or a refusal is how a wave came to report sessions restored that
// nobody had looked at.
type waveOutcome int

const (
	waveAnswered   waveOutcome = iota // the node accepted it: it has a remote identifier again
	waveUnanswered                    // examined, and the node has not answered
	waveUnknown                       // its lock could not be taken, so nothing is known
	waveGone                          // no longer anchored on this node; not this run's business
)

func outcomeOf(smContext *context.SMContext, nodeIP string) waveOutcome {
	// TryLock, for the same reason the enumeration uses it: SMLock is held across network calls in
	// this codebase, so a blocking acquire here is an unbounded wait inside the wave loop. It hung a
	// run at 50 sessions on a cluster.
	if !smContext.SMLock.TryLock() {
		return waveUnknown
	}
	defer smContext.SMLock.Unlock()

	pfcpContext, onThisNode := smContext.PFCPContext[nodeIP]
	switch {
	case !onThisNode:
		return waveGone
	case pfcpContext.RemoteSEID == 0:
		return waveUnanswered
	default:
		return waveAnswered
	}
}

type waveResult struct {
	answered   int
	unanswered []*context.SMContext
	unknown    int
	gone       int
}

// settleWave gives the UPF a chance to answer the establishments this wave issued, and reports what
// is actually known when the time is up.
//
// Only sessions this wave issued are passed in. A session reissue skipped was never sent anything,
// so the node's silence about it says nothing -- and it must never reach the unanswered set, which
// is what gets released.
func settleWave(issued []*context.SMContext, nodeIP string) waveResult {
	deadline := time.Now().Add(restorationSettleTimeout)
	result := waveResult{unanswered: make([]*context.SMContext, 0)}
	pending := issued

	for {
		stillPending := make([]*context.SMContext, 0, len(pending))
		for _, smContext := range pending {
			switch outcomeOf(smContext, nodeIP) {
			case waveAnswered:
				result.answered++
			case waveGone:
				result.gone++
			case waveUnanswered, waveUnknown:
				stillPending = append(stillPending, smContext)
			}
		}
		pending = stillPending
		if len(pending) == 0 || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(restorationPollInterval)
	}

	// Classify once more at the deadline so a session whose lock freed at the last moment is judged
	// on what it says rather than on the fact that it was busy earlier.
	for _, smContext := range pending {
		switch outcomeOf(smContext, nodeIP) {
		case waveAnswered:
			result.answered++
		case waveGone:
			result.gone++
		case waveUnknown:
			result.unknown++
		case waveUnanswered:
			result.unanswered = append(result.unanswered, smContext)
		}
	}
	return result
}

// resolveUnrestorable settles the sessions the UPF would not accept.
//
// The outcome that must not occur is the one that exists before this change for every session: a
// record describing a working service that does not exist. A released session is a fact the rest of
// the system can act on; a session reported as active but forwarding nothing is undiagnosable from
// the control plane, because every signal it offers says the service is running.
func resolveUnrestorable(unrestored []*context.SMContext, nodeIP string) (notReleased int) {
	if len(unrestored) == 0 {
		return 0
	}
	released := 0
	for _, smContext := range unrestored {
		smContext.SubPfcpLog.Errorf("session could not be restored on UPF[%s]; releasing it", nodeIP)
		if err := releaseOneSession(smContext); err != nil {
			smContext.SubPfcpLog.Errorf("releasing the unrestorable session failed: %v", err)
			continue
		}
		released++
	}
	logger.PfcpLog.Errorf("UPF[%s] %d session(s) could not be restored, %d released", nodeIP, len(unrestored), released)
	metrics.AddUpfRestorationStats(context.SMF_Self().NfInstanceID, nodeIP, "released", released)
	return len(unrestored) - released
}

// releaseUnrestorableSession tears down a session the restarted UPF would not accept, and tells the
// peers that hold state for it.
//
// The UE has to be told. It observed nothing when the UPF restarted — the radio is up, the cell is
// present, its mobility state did not change — so there is no procedure on its side that would
// discover the loss and no timer that expires into one. A session left in place is one the UE
// believes it can use indefinitely. Releasing it is what lets the UE establish a working one.
//
// Both peers are told even if one fails, because a session half-released is worse than either
// outcome: the PCF holding a policy association for a session the UE has been told to drop, or the
// UE still holding a session whose policy is gone.
// releaseOneSession isolates a single release, so one session cannot take the process with it.
//
// This runs on a background goroutine, over whatever sessions happen to be anchored on the node,
// while the network is already degraded. Some of them are caught part-way through establishment and
// do not yet carry the fields the release path reads. A panic here would turn a UPF restart into an
// SMF restart, which loses every session on every UPF rather than the ones on this one.
func releaseOneSession(smContext *context.SMContext) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("releasing the session panicked: %v", r)
		}
	}()
	return releaseUnrestorableSession(smContext)
}

var errSessionBusy = errors.New("session is busy")

// markReleasedAndBuild does the in-memory half of the release under SMLock: the state change and
// assembling the transfer, both of which touch fields other paths mutate under that lock.
//
// The unlock is deferred rather than written after the work. ChangeState indexes into the data path
// pool and can panic on a malformed context, and releaseOneSession recovers -- so an un-deferred
// unlock leaks the lock silently, and every later sweep then finds the session unexaminable. That
// is not hypothetical: it happened while making this very change, and the sweep tests caught it.
func markReleasedAndBuild(smContext *context.SMContext) (*models.N1N2MessageTransferRequest, error) {
	if !tryLockFor(&smContext.SMLock, lockAcquireTimeout) {
		return nil, errSessionBusy
	}
	defer smContext.SMLock.Unlock()

	smContext.ChangeState(context.SmStateRelease)
	return buildReleaseCommandForUE(smContext)
}

// deleteSmPolicy terminates the policy association with SMLock held, as the ordinary release path
// does at producer/pdu_session.go. This is a PCF call without the re-discovery loop that made the
// AMF transfer too dangerous to hold the lock for.
func deleteSmPolicy(smContext *context.SMContext) error {
	if !tryLockFor(&smContext.SMLock, lockAcquireTimeout) {
		return errSessionBusy
	}
	defer smContext.SMLock.Unlock()

	_, err := consumer.SendSMPolicyAssociationDelete(smContext, &models.ReleaseSmContextRequest{})
	return err
}

func releaseUnrestorableSession(smContext *context.SMContext) error {
	n1n2Request, buildErr := markReleasedAndBuild(smContext)

	// Cleaned up whether or not the build succeeded: a build that failed part-way has already staged
	// the payloads it got through, and the request is returned for exactly that reason.
	if n1n2Request != nil {
		defer util.CleanupMultipartTempFiles(n1n2Request)
	}
	if buildErr != nil {
		return buildErr
	}

	var firstErr error
	// The transfer is deliberately not under SMLock -- see the note inside transferReleaseCommand's
	// body. The residual is that AMF re-discovery can mutate the serving-AMF fields while this reads
	// them; accepted, because holding the lock here was measured to stop an unrelated subscriber from
	// establishing a session at all.
	if err := transferReleaseCommand(smContext, n1n2Request); err != nil {
		firstErr = err
	}

	if err := deleteSmPolicy(smContext); err != nil {
		smContext.SubPduSessLog.Errorf("terminating the SM policy association failed: %v", err)
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// buildReleaseCommandForUE assembles the transfer. The caller must hold SMLock: every field read
// here is one other paths mutate under it. The caller is also responsible for releasing the
// temporary files, which is why the cleanup is not deferred inside.
func buildReleaseCommandForUE(smContext *context.SMContext) (*models.N1N2MessageTransferRequest, error) {
	n1n2Request := models.NewN1N2MessageTransferRequest()

	n2InfoContent := models.NewN2InfoContent(models.RefToBinaryData{ContentId: "N2SmInformation"})
	n2InfoContent.SetNgapIeType(models.NGAPIETYPE_PDU_RES_REL_CMD)
	smInfo := models.NewN2SmInformation(smContext.PDUSessionID)
	smInfo.SetN2InfoContent(*n2InfoContent)
	if smContext.Snssai != nil {
		smInfo.SetSNssai(*smContext.Snssai)
	}
	n2InfoContainer := models.NewN2InfoContainer(models.N2INFORMATIONCLASS_SM)
	n2InfoContainer.SetSmInfo(*smInfo)

	n1MessageClass, err := models.NewN1MessageClassFromValue("SM")
	if err != nil {
		return n1n2Request, fmt.Errorf("create N1 message class: %w", err)
	}
	n1MsgContainer := models.NewN1MessageContainer(*n1MessageClass, *models.NewRefToBinaryData("GSM_NAS"))

	n1n2Request.SetJsonData(*models.NewN1N2MessageTransferReqData())
	jsonData := n1n2Request.GetJsonData()
	jsonData.SetPduSessionId(smContext.PDUSessionID)
	n1n2Request.SetJsonData(jsonData)

	nasBuf, err := context.BuildGSMPDUSessionReleaseCommand(smContext)
	if err != nil {
		return n1n2Request, fmt.Errorf("build PDU Session Release Command: %w", err)
	}
	nasFile, err := util.CreatePayloadTempFile(nasBuf)
	if err != nil {
		return n1n2Request, fmt.Errorf("stage the N1 payload: %w", err)
	}
	n1n2Request.SetBinaryDataN1Message(nasFile)
	jsonData = n1n2Request.GetJsonData()
	jsonData.SetN1MessageContainer(*n1MsgContainer)
	n1n2Request.SetJsonData(jsonData)

	n2Pdu, err := context.BuildPDUSessionResourceReleaseCommandTransfer(smContext)
	if err != nil {
		return n1n2Request, fmt.Errorf("build PDUSessionResourceReleaseCommandTransfer: %w", err)
	}
	n2File, err := util.CreatePayloadTempFile(n2Pdu)
	if err != nil {
		return n1n2Request, fmt.Errorf("stage the N2 payload: %w", err)
	}
	n1n2Request.SetBinaryDataN2Information(n2File)
	jsonData = n1n2Request.GetJsonData()
	jsonData.SetN2InfoContainer(*n2InfoContainer)
	n1n2Request.SetJsonData(jsonData)

	// Deliberately NOT under SMLock, unlike the QoS transfer in callback.go.
	//
	// That one holds the lock across its transfer so AMF re-discovery's mutation of the serving-AMF
	// fields cannot race other users of the context, and for request-scoped code that is right: the
	// call is bounded by the caller's timeout and it blocks only the subscriber it is serving.
	//
	// This is a background sweep over whatever sessions happen to be anchored on a restarted node,
	// and the same lock is what a replacing session needs in order to purge the context it is
	// replacing. Holding it across an AMF call with re-discovery and retries therefore stops an
	// unrelated subscriber from establishing a session at all. Measured on a cluster while the AMF
	// was answering 404: the purge logged and then hung, and the UE retransmitted until T3580 for
	// minutes. A best-effort repair must not be able to do that.
	return n1n2Request, nil
}

// transferReleaseCommand sends what was built, without SMLock.
func transferReleaseCommand(smContext *context.SMContext, n1n2Request *models.N1N2MessageTransferRequest) error {
	rspData, err := consumer.SendN1N2TransferWithRediscovery(gocontext.Background(), smContext, n1n2Request)
	if err != nil {
		return fmt.Errorf("N1N2 transfer: %w", err)
	}
	if rspData.GetCause() == models.N1N2MESSAGETRANSFERCAUSE_N1_MSG_NOT_TRANSFERRED {
		return fmt.Errorf("N1N2 transfer refused: %v", rspData.GetCause())
	}
	return nil
}

// waitForAssociation holds the restoration back until the PFCP association with the restarted UPF
// has been re-established.
//
// A restart is noticed on the heartbeat path before the association is back: that path marks the
// UPF NotAssociated precisely so ProbeInactiveUpfs will re-associate it. Session establishments
// issued in that gap are rejected -- observed on a cluster as PFCP cause 72 -- and, worse, a
// rejection is indistinguishable from a session the UPF will not accept, so restoration would
// release sessions that were only asked too early.
//
// Returns false if the association does not come back in time, or if a later restart has
// superseded this run, in which case there is nothing useful left to do here.
func waitForAssociation(nodeID context.NodeID, nodeIP string, run *restorationRun) bool {
	deadline := time.Now().Add(associationWaitTimeout)
	for {
		if run.isSuperseded() {
			return false
		}
		upf := context.RetrieveUPFNodeByNodeID(nodeID)
		if upf == nil {
			logger.PfcpLog.Errorf("UPF[%s] is no longer known; abandoning the restoration", nodeIP)
			return false
		}
		upf.UpfLock.RLock()
		associated := upf.UPFStatus == context.AssociatedSetUpSuccess
		upf.UpfLock.RUnlock()
		if associated {
			return true
		}
		if !time.Now().Before(deadline) {
			logger.PfcpLog.Errorf("UPF[%s] did not re-associate within %s; sessions are left un-restored "+
				"rather than established into a node that cannot accept them", nodeIP, associationWaitTimeout)
			return false
		}
		time.Sleep(restorationPollInterval)
	}
}
