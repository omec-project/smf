// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"net"
	"runtime/debug"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
)

// AbandonRestorationOnUPF stops a restoration in progress for the node at nodeIP that is
// repairing a restart other than the one at recovery.
//
// A restoration is otherwise superseded only by the next one RestoreSessionsOnUPF starts. When the
// next restart's restoration is held back instead, the run for the previous restart goes on
// re-installing sessions onto an incarnation it knows nothing about.
//
// The address is the caller's, not resolved here: it is the one the run was recorded under, and
// the node's name may not resolve now.
func AbandonRestorationOnUPF(nodeIP string, recovery time.Time) {
	value, ok := restorationsInProgress.Load(nodeIP)
	if !ok {
		return
	}
	if run, ok := value.(*restorationRun); ok && !run.sameRestartAs(recovery) {
		run.supersede()
	}
}

// ReleaseSessionsOnUPF releases every session anchored on a restarted UPF instead of restoring it,
// and reports whether it could identify them.
//
// It is for a restoration that was held back and cannot go ahead. Leaving the sessions in place is
// not an option: once the restart is recorded nothing need detect it again, and the UE observed
// nothing and will go on using a session that carries nothing. Releasing them is what lets each
// UE establish a working one, through the same path RestoreSessionsOnUPF uses for sessions the
// node would not accept.
//
// It takes part in the same one-run-per-node bookkeeping as the restoration, so a restoration for a
// later restart stops it, and it stops a restoration for an earlier one.
//
// Sessions are found by the address they were anchored under, which the caller supplies: the
// node's name may not resolve now, and its last known address is the one its sessions are keyed
// by. With no address at all there is nothing to find, and that is reported rather than counted
// as a release of nothing. Runs asynchronously, as RestoreSessionsOnUPF does.
func ReleaseSessionsOnUPF(nodeID context.NodeID, nodeIP string, recovery time.Time) bool {
	if ip := net.ParseIP(nodeIP); ip == nil || ip.IsUnspecified() {
		logger.PfcpLog.Errorf("UPF[%s] restarted and no address is known for it; the sessions anchored "+
			"on it can be neither restored nor released", nodeID.NodeIdValue)
		return false
	}

	run := &restorationRun{recovery: recovery}
	if previous, loaded := restorationsInProgress.LoadOrStore(nodeIP, run); loaded {
		if prior, ok := previous.(*restorationRun); ok {
			prior.supersede()
		}
		run.displacedAPriorRun = true
		restorationsInProgress.Store(nodeIP, run)
	}

	restorationGoroutines.Add(1)
	go func() {
		defer restorationGoroutines.Done()
		defer restorationsInProgress.CompareAndDelete(nodeIP, run)
		defer func() {
			if r := recover(); r != nil {
				logger.PfcpLog.Errorf("UPF[%s] release of unrestored sessions panicked and was abandoned: %v\n%s",
					nodeIP, r, debug.Stack())
			}
		}()
		// Enumerated by the address, which is all SessionsAnchoredOn reads the node for.
		releaseAnchored(*context.NewNodeID(nodeIP), nodeIP, run)
	}()

	return true
}

func releaseAnchored(nodeID context.NodeID, nodeIP string, run *restorationRun) {
	anchored, unexaminable, _ := enumerateWithRetry(nodeID, nodeIP, run)
	smfID := context.SMF_Self().NfInstanceID
	if len(anchored) == 0 {
		logger.PfcpLog.Infof("UPF[%s] restarted with no sessions anchored on it; nothing to release", nodeIP)
		metrics.SetUpfUnrestoredSessions(smfID, nodeIP, attributableTo(nodeIP, unexaminable))
		return
	}
	logger.PfcpLog.Errorf("UPF[%s] restarted and its %d session(s) are being released rather than restored",
		nodeIP, len(anchored))

	released, notReleased, gone := 0, 0, 0
	for i, smContext := range anchored {
		// Stopped by a restoration for a later restart, which enumerates these sessions again
		// against the incarnation that is current; the gauge is that run's to set.
		if run.isSuperseded() {
			logger.PfcpLog.Warnf("UPF[%s] release abandoned after %d of %d session(s): superseded by a later restart",
				nodeIP, i, len(anchored))
			metrics.AddUpfRestorationStats(smfID, nodeIP, "released", released)
			return
		}
		smContext.SubPfcpLog.Errorf("session could not be restored on UPF[%s]; releasing it", nodeIP)
		if err := releaseOneSession(smContext); errors.Is(err, errSessionGone) {
			// Released, or replaced by its subscriber, since it was enumerated: not a session left
			// without service, so not counted as one.
			smContext.SubPfcpLog.Infof("session was released or replaced meanwhile; not releasing it again")
			gone++
			continue
		} else if err != nil {
			smContext.SubPfcpLog.Errorf("releasing the unrestorable session failed: %v", err)
			notReleased++
			continue
		}
		released++
	}
	if gone > 0 {
		logger.PfcpLog.Infof("UPF[%s] %d session(s) were released or replaced meanwhile", nodeIP, gone)
	}
	metrics.AddUpfRestorationStats(smfID, nodeIP, "released", released)
	metrics.SetUpfUnrestoredSessions(smfID, nodeIP, notReleased+attributableTo(nodeIP, unexaminable))
}
