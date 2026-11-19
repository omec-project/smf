// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"fmt"
	"sync"
	"time"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/util/li/x1"
)

// maxUndecidableRounds bounds how many rounds of the registry's name refresh a restart whose node
// could not be matched is retried for before the node's sessions are released. Only rounds that
// start after the restoration was withheld count, so at the refresh interval the sessions on that
// node carry nothing for two to three minutes.
var maxUndecidableRounds = 3

// restartMatch is what settling the record for a restarted node concluded.
type restartMatch int

const (
	// restartAtPOI: the node is a configured point of interception and its claims were discarded.
	restartAtPOI restartMatch = iota
	// restartNotAtPOI: the node is not one, so there was nothing to discard.
	restartNotAtPOI
	// restartUndecidable: this element cannot tell whether the node is one.
	restartUndecidable
)

// RestartHooks are the SMF's session restoration and the two things the gate needs beside it,
// supplied by the service wiring because this package may not import the producer.
type RestartHooks struct {
	// Restore re-installs the sessions anchored on a restarted node. It starts its own work.
	Restore func(smfctx.NodeID, time.Time)
	// Abandon stops a restoration in progress for the node at the given address that is repairing
	// a restart other than the one given.
	Abandon func(nodeIP string, recovery time.Time)
	// Release releases the sessions anchored on the node at the given address instead of restoring
	// them, and reports whether it could identify them at all. It starts its own work.
	//
	// Both take the node's last known address from the gate rather than resolving it, because
	// they run under the node's restart lock — which a restart path holding UpfLock may be
	// waiting for — and because the name may not resolve now while its sessions are still keyed
	// by the address it had.
	Release func(node smfctx.NodeID, nodeIP string, recovery time.Time) bool
}

// GateRestoration wraps the SMF's restart hook so that the record of what a restarted point of
// interception held is settled before any of its sessions is re-installed.
//
// The order — the discard, then the restoration — is the whole of what stops a restored session
// covered by a content task from forwarding at a restarted point of interception while the stale
// claims still say it is tasked: `plan` would find the triple claimed, install nothing, and this
// element would report the interception as running. As neighbouring statements at each place a
// restart is detected, the order would be a matter of each call site. Wrapping the hook makes it
// a property of the only way restoration can be reached, so a new detection path cannot leave
// the discard out.
//
// A node that is not a point of interception, and an element whose interception is not running,
// restore exactly as without this. A node that cannot be matched or ruled out is not restored
// while that lasts: the restoration is withheld, any restoration still running for an earlier
// restart of that node is stopped, and settling is retried after each name refresh for
// maxUndecidableRounds. Then the node's sessions are released instead, so the subscriber
// re-establishes rather than holding a session that carries nothing. Restoring it would let
// traffic flow at a point of interception that may still be recorded as tasked.
//
// The returned hook runs on the caller's goroutine, which holds UpfLock. It resolves the node's
// address, which every call site did under that lock before, and then waits for the node's
// restart lock, whose holders do no lookups of their own: the retry resolves before taking it,
// and the hooks are handed an address. Restore resolves the node again itself, which after the
// gate's own lookup is an answer from the cache. The work of restoring or releasing runs on
// goroutines the hooks start.
func GateRestoration(hooks RestartHooks) func(smfctx.NodeID, time.Time) {
	return func(node smfctx.NodeID, recovery time.Time) {
		sub := active.Load()
		if sub == nil || sub.triggers == nil {
			hooks.Restore(node, recovery)
			return
		}
		r := sub.triggers
		addr := node.ResolveNodeIdToIp().String()
		mu := r.restartLock(node)
		mu.Lock()
		defer mu.Unlock()

		r.noteAddress(node, addr)
		match := sub.discardRestarted(upfSession{node: node, addr: addr})
		if match != restartUndecidable || r.isSettled(node, recovery) {
			// Settled now, or the same restart seen again on another exchange after it was settled:
			// either way nothing here describes the node's current incarnation but this, so a
			// restoration still withheld for an earlier restart of it is dropped.
			r.settle(node, recovery)
			hooks.Restore(node, recovery)
			return
		}
		sub.withhold(node, recovery, hooks)
	}
}

// withhold holds back the restoration of a node whose record could not be settled, and retries
// settling it on the registry's own goroutine. The caller holds the node's restart lock.
func (s *subsystem) withhold(node smfctx.NodeID, recovery time.Time, hooks RestartHooks) {
	w, started := s.triggers.beginWithheld(node, recovery)
	if !started {
		// The same restart, observed on another exchange; it is already being retried.
		return
	}
	// A restoration still running for an earlier restart of this node is re-installing sessions
	// onto the incarnation that has just restarted, with this restart's claims still standing.
	// It was recorded under the address the node had then.
	if nodeIP := s.triggers.lastAddress(node); nodeIP != "" {
		hooks.Abandon(nodeIP, recovery)
	}

	// Taken here, before the hook returns, so a refresh that starts after this is one the retry
	// counts however late it is scheduled.
	round := s.triggers.nextRefresh()
	if !s.triggers.goOwned(func() { s.retryWithheld(w, node, round, hooks) }) {
		// The registry has been stopped, so interception is not running and there is nothing to
		// hold the restoration back for.
		s.triggers.endWithheld(node, w)
		hooks.Restore(node, recovery)
		return
	}
	// Told to the LIPF only, naming no warrant. An operator-visible line would show that
	// interception is configured here; the operator sees the restoration's own lines when it goes
	// ahead, or the release path's if it does not.
	if s.reporter != nil {
		s.reporter.NotifyAsync(x1.NEIssueReconcileFailed,
			"a user-plane node restarted and this element cannot yet establish whether it is a triggered "+
				"point of interception; restoring its sessions is withheld until it can")
	}
}

// retryWithheld settles a withheld restart again after each name refresh, starting with round.
// Settled, the node is restored; still undecidable after maxUndecidableRounds, its sessions are
// released. Every act is taken under the node's restart lock and only while w is still the
// current withheld restoration, so a retry that has been overtaken by a newer restart neither
// discards the claims that restart's sessions have since installed nor restores over it.
func (s *subsystem) retryWithheld(w *withheldRestart, node smfctx.NodeID, round <-chan struct{}, hooks RestartHooks) {
	r := s.triggers
	mu := r.restartLock(node)

	for range maxUndecidableRounds {
		select {
		case <-round:
		case <-w.abandoned:
			return
		case <-r.stop:
			// Interception is ending, so there is nothing left to hold the restoration back for.
			mu.Lock()
			if r.endWithheld(node, w) {
				hooks.Restore(node, w.recovery)
			}
			mu.Unlock()
			return
		}
		// The next round is taken before settling, for the same reason as the first.
		round = r.nextRefresh()
		// Resolved before the lock: a lookup that fails is the usual reason this node is
		// undecidable, and it is not to be waited on while holding up the node's other restarts.
		addr := node.ResolveNodeIdToIp().String()

		mu.Lock()
		if !r.isWithheld(node, w) {
			mu.Unlock()
			return
		}
		r.noteAddress(node, addr)
		if s.discardRestarted(upfSession{node: node, addr: addr}) != restartUndecidable {
			r.endWithheld(node, w)
			r.settle(node, w.recovery)
			hooks.Restore(node, w.recovery)
			mu.Unlock()
			return
		}
		mu.Unlock()
	}

	mu.Lock()
	defer mu.Unlock()
	if !r.endWithheld(node, w) {
		return
	}
	released := hooks.Release(node, r.lastAddress(node), w.recovery)
	if s.reporter == nil {
		return
	}
	if released {
		s.reporter.NotifyAsync(x1.NEIssueReconcileFailed,
			"a user-plane node restarted and this element could not establish whether it is a triggered "+
				"point of interception; its sessions are being released rather than restored")
		return
	}
	s.reporter.NotifyAsync(x1.NEIssueReconcileFailed,
		"a user-plane node restarted and this element could not establish whether it is a triggered "+
			"point of interception, nor resolve the node's address; its sessions have been neither "+
			"restored nor released")
}

// withheldRestart is one restoration held back by GateRestoration.
type withheldRestart struct {
	recovery  time.Time
	abandoned chan struct{}
	once      sync.Once
}

func (w *withheldRestart) abandon() {
	w.once.Do(func() { close(w.abandoned) })
}

// withheldKey identifies a node by what it is configured as, not by its address: an address that
// could not be resolved is one of the reasons a restoration is withheld.
func withheldKey(node smfctx.NodeID) string {
	return fmt.Sprintf("%d/%x", node.NodeIdType, node.NodeIdValue)
}

// restartLock returns the lock that orders everything done about one node's restarts. One per
// node for the life of the registry, so the map is bounded by the number of user-plane nodes.
func (r *triggerRegistry) restartLock(node smfctx.NodeID) *sync.Mutex {
	r.withheldMu.Lock()
	defer r.withheldMu.Unlock()

	if r.restartLocks == nil {
		r.restartLocks = make(map[string]*sync.Mutex)
	}
	key := withheldKey(node)
	mu, ok := r.restartLocks[key]
	if !ok {
		mu = &sync.Mutex{}
		r.restartLocks[key] = mu
	}

	return mu
}

// beginWithheld records a withheld restoration for node. It reports false for a restart already
// withheld — the same recovery state, compared at the second resolution it is carried at — and
// abandons one for an earlier restart, which describes an incarnation that no longer exists.
func (r *triggerRegistry) beginWithheld(node smfctx.NodeID, recovery time.Time) (*withheldRestart, bool) {
	r.withheldMu.Lock()
	defer r.withheldMu.Unlock()

	if r.withheld == nil {
		r.withheld = make(map[string]*withheldRestart)
	}
	key := withheldKey(node)
	if prior, ok := r.withheld[key]; ok {
		if prior.recovery.Unix() == recovery.Unix() {
			return nil, false
		}
		prior.abandon()
	}
	w := &withheldRestart{recovery: recovery, abandoned: make(chan struct{})}
	r.withheld[key] = w

	return w, true
}

// isWithheld reports whether w is still the current withheld restoration for node.
func (r *triggerRegistry) isWithheld(node smfctx.NodeID, w *withheldRestart) bool {
	r.withheldMu.Lock()
	defer r.withheldMu.Unlock()

	return r.withheld[withheldKey(node)] == w
}

// endWithheld removes w and reports whether it was still the current one for node, which is what
// entitles its retry to act.
func (r *triggerRegistry) endWithheld(node smfctx.NodeID, w *withheldRestart) bool {
	r.withheldMu.Lock()
	defer r.withheldMu.Unlock()

	key := withheldKey(node)
	if r.withheld[key] != w {
		return false
	}
	delete(r.withheld, key)

	return true
}

// settle records that node's restart at recovery has been settled, and abandons a restoration
// still withheld for it.
func (r *triggerRegistry) settle(node smfctx.NodeID, recovery time.Time) {
	r.withheldMu.Lock()
	defer r.withheldMu.Unlock()

	key := withheldKey(node)
	if w, ok := r.withheld[key]; ok {
		w.abandon()
		delete(r.withheld, key)
	}
	if r.settled == nil {
		r.settled = make(map[string]time.Time)
	}
	r.settled[key] = recovery
}

// noteAddress records addr as node's last known address, if it is one.
func (r *triggerRegistry) noteAddress(node smfctx.NodeID, addr string) {
	if !knownAddress(addr) {
		return
	}
	r.withheldMu.Lock()
	defer r.withheldMu.Unlock()

	if r.addresses == nil {
		r.addresses = make(map[string]string)
	}
	r.addresses[withheldKey(node)] = addr
}

// lastAddress is node's last known address, or "" if none has been seen.
func (r *triggerRegistry) lastAddress(node smfctx.NodeID) string {
	r.withheldMu.Lock()
	defer r.withheldMu.Unlock()

	return r.addresses[withheldKey(node)]
}

// isSettled reports whether node's restart at recovery has already been settled. A liveness
// response leaves the held recovery state alone, so the re-association that follows reports the
// same restart again, and by then a name lookup that answered the first time may not.
func (r *triggerRegistry) isSettled(node smfctx.NodeID, recovery time.Time) bool {
	r.withheldMu.Lock()
	defer r.withheldMu.Unlock()

	at, ok := r.settled[withheldKey(node)]

	return ok && at.Unix() == recovery.Unix()
}

// goOwned runs f on a goroutine this registry counts, so Stop waits for it. It reports false,
// starting nothing, once the registry has been stopped.
func (r *triggerRegistry) goOwned(f func()) bool {
	r.serialMu.Lock()
	if r.stopped {
		r.serialMu.Unlock()
		return false
	}
	r.wg.Add(1)
	r.serialMu.Unlock()

	go func() {
		defer r.wg.Done()
		f()
	}()

	return true
}
