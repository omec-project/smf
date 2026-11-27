// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"
	"time"

	"github.com/omec-project/smf/context"
)

// A release that replaces a withheld restoration takes the sessions the restarted node lost, and
// only those: a session anchored elsewhere is working and must be left alone.
func TestReleasingARestartedNodeReleasesOnlyTheSessionsAnchoredThere(t *testing.T) {
	const lost, elsewhere = "10.30.1.1", "10.30.1.2"
	onLost := sessionOn(t, "imsi-208930000000901", 1, lost)
	onElsewhere := sessionOn(t, "imsi-208930000000902", 1, elsewhere)

	if !ReleaseSessionsOnUPF(*context.NewNodeID(lost), lost, time.Unix(1_790_000_100, 0)) {
		t.Fatal("a node with a known address was reported as one whose sessions cannot be identified")
	}
	waitForBackgroundRestorations(t)

	if onLost.SMContextState != context.SmStateRelease {
		t.Errorf("the session on the restarted node is %v, want %v: left in place it carries nothing "+
			"and nothing will detect the restart again", onLost.SMContextState, context.SmStateRelease)
	}
	if onElsewhere.SMContextState == context.SmStateRelease {
		t.Errorf("a session on a node that did not restart was released")
	}
}

// Sessions are found by the address they were anchored under. Without one there is nothing to
// find, and saying the sessions were released would be a record reading healthy over sessions
// that carry nothing.
func TestAReleaseForANodeWithNoAddressSaysSo(t *testing.T) {
	unresolvable := context.NodeID{NodeIdType: 0xff, NodeIdValue: []byte("no-such-upf")}

	for _, nodeIP := range []string{"", "0.0.0.0", "::", "<nil>"} {
		if ReleaseSessionsOnUPF(unresolvable, nodeIP, time.Unix(1_790_000_200, 0)) {
			t.Errorf("a node with address %q was reported as releasable", nodeIP)
		}
	}
}

// A node whose name no longer resolves still has sessions keyed by the address it had, and the
// release finds them by that address rather than by resolving the name again.
func TestAReleaseFindsTheSessionsOfANodeWhoseNameNoLongerResolves(t *testing.T) {
	const lastKnown = "10.30.1.5"
	onIt := sessionOn(t, "imsi-208930000000905", 1, lastKnown)
	unresolvable := context.NodeID{NodeIdType: 0xff, NodeIdValue: []byte("upf-gone-quiet")}

	if !ReleaseSessionsOnUPF(unresolvable, lastKnown, time.Unix(1_790_000_500, 0)) {
		t.Fatal("a node with a known last address was reported as one whose sessions cannot be identified")
	}
	waitForBackgroundRestorations(t)

	if onIt.SMContextState != context.SmStateRelease {
		t.Errorf("the session keyed by the node's last address is %v, want %v", onIt.SMContextState, context.SmStateRelease)
	}
}

// The release takes part in the one-run-per-node bookkeeping: it stops a restoration for an earlier
// restart, which would otherwise go on re-installing sessions it is releasing.
func TestAReleaseSupersedesTheRestorationOfAnEarlierRestart(t *testing.T) {
	nodeID := *context.NewNodeID("10.30.1.3")
	nodeIP := nodeID.ResolveNodeIdToIp().String()
	earlier := &restorationRun{recovery: time.Unix(1_790_000_300, 0)}
	restorationsInProgress.Store(nodeIP, earlier)
	defer restorationsInProgress.Delete(nodeIP)

	ReleaseSessionsOnUPF(nodeID, nodeIP, time.Unix(1_790_000_360, 0))
	waitForBackgroundRestorations(t)

	if !earlier.isSuperseded() {
		t.Error("the restoration for the earlier restart was left running beside the release")
	}
}

// Abandoning is for a restoration repairing a *different* restart. The one repairing the restart
// that is being withheld is not stopped by being seen again.
func TestAbandoningStopsOnlyARestorationForAnotherRestart(t *testing.T) {
	nodeID := *context.NewNodeID("10.30.1.4")
	nodeIP := nodeID.ResolveNodeIdToIp().String()
	recovery := time.Unix(1_790_000_400, 0)
	run := &restorationRun{recovery: recovery}
	restorationsInProgress.Store(nodeIP, run)
	defer restorationsInProgress.Delete(nodeIP)

	AbandonRestorationOnUPF(nodeIP, recovery)
	if run.isSuperseded() {
		t.Fatal("the restoration for the very restart being withheld was abandoned")
	}
	AbandonRestorationOnUPF(nodeIP, recovery.Add(time.Minute))
	if !run.isSuperseded() {
		t.Error("a restoration for an earlier restart was not abandoned when a later one was withheld")
	}
}

// A session released or replaced after the release enumerated it is not one left without service.
// Counting it as a failed release would have the gauge report a session the node no longer has.
func TestAReleaseDoesNotCountASessionGoneMeanwhileAsWithoutService(t *testing.T) {
	restoreQuickly(t)
	const nodeIP = "10.30.1.9"
	nodeID := *context.NewNodeID(nodeIP)
	associatedUpfAt(t, nodeIP)

	// Replaced by its subscriber between the enumeration and the release: purged, still pooled.
	gone := sessionOn(t, "imsi-208930000000909", 1, nodeIP)
	t.Cleanup(func() { context.RemoveSMContext(gone.Ref) })
	gone.LocalPurged.Store(true)

	releaseAnchored(nodeID, nodeIP, &restorationRun{recovery: time.Now()})

	if got := unrestoredOn(t, nodeIP); got != 0 {
		t.Errorf("the node reports %v sessions without service, want 0: the only session was released "+
			"or replaced before this release reached it", got)
	}
}
