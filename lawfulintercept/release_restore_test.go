// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"testing"
	"time"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/util/li/types"
)

// TestARestoredReleaseIsReportableAgainAndRetasksNothing is the effect the producer's
// branch test could only assert as a function call.
//
// The subject is what RestoreInterception *does*, and the previous round got the answer
// wrong in its comment rather than in its code. It called triggerCC and its doc said the
// triggers were re-installed. Every reachable caller runs after releaseTunnel has nilled
// sc.Tunnel, so sessionUPFs returns nothing and triggerCC returns before planning
// anything: the call was unreachable on every branch while the comment asserted it had
// run, and the producer test stubbed the whole function and counted it, so nothing
// anywhere established which of the two halves was real.
//
// One half is real. LiReleaseReported goes back to false, so the release that eventually
// happens is reported rather than suppressed as a duplicate of one that never occurred —
// without it the agency's record of the session ends at a failed attempt, permanently.
func TestARestoredReleaseIsReportableAgainAndRetasksNothing(t *testing.T) {
	poi := newFakePOI(t)
	sub := triggerSubsystem(t, poi)

	// A warrant this element would task on, so a re-install would have something to
	// install: without it the test would pass because there was nothing to do.
	task := types.InterceptTask{
		XID:      testXIDPrimary,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}
	if !sub.store.Activate(task) {
		t.Fatal("Activate failed")
	}

	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	// The session as the restore branches actually hold it: released, its tunnel nilled
	// by releaseTunnel, its release already reported. This is the shape production
	// reaches, not a convenient one.
	sc := pooledSession(t, testSUPI, 1)
	sc.Tunnel = nil
	sc.LiReleaseReported = true

	RestoreInterception(sc)

	if sc.LiReleaseReported {
		t.Error("the release stayed reported after the release did not happen: the release that " +
			"eventually occurs is suppressed as a duplicate of one that never occurred, and the " +
			"agency's record of this session ends at a failed attempt")
	}

	// And nothing was sent. The withdrawal the POI has already acknowledged stands:
	// what would re-establish this session's content interception is its user-plane
	// state coming back, which no path here provides.
	if n := poi.countMessages("ActivateTaskRequest"); n != 0 {
		t.Errorf("%d triggers were installed for a session with no tunnel: the criterion is a "+
			"PFCP session that has been deleted, so it matches no packet while this element "+
			"believes interception is running", n)
	}
}

// TestRestoreInterceptionPerformsNoX1Work is the guard against the re-install coming
// back, stated as the contract rather than as a property of one session shape.
//
// A session *with* a tunnel is not a state any restore branch reaches — releaseTunnel
// has run by then — so this is not a claim about production. It is the assertion that
// makes the removal durable: whatever the session looks like, restoring a release that
// did not happen restores the report state and talks to no point of interception. Fail
// it and someone has re-added a trigger keyed to a deleted PFCP session.
func TestRestoreInterceptionPerformsNoX1Work(t *testing.T) {
	poi := newFakePOI(t)
	sub := triggerSubsystem(t, poi)

	task := types.InterceptTask{
		XID:      testXIDPrimary,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}
	if !sub.store.Activate(task) {
		t.Fatal("Activate failed")
	}

	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	sc := pooledSession(t, testSUPI, 1)
	node := smfctx.NewDataPathNode()
	node.UPF = &smfctx.UPF{NodeID: upfNode(trigNodeA)}
	node.UpLinkTunnel.PDR["default"] = &smfctx.PDR{
		FAR: &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}},
	}
	sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
		1: &smfctx.DataPath{FirstDPNode: node, IsDefaultPath: true},
	}}
	sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{
		node.UPF.NodeID.ResolveNodeIdToIp().String(): {
			PDRs:       map[uint16]*smfctx.PDR{},
			NodeID:     node.UPF.NodeID,
			RemoteSEID: 0x2632898145f4d191,
		},
	}
	sc.LiReleaseReported = true

	RestoreInterception(sc)

	// The X1 exchange would run on its own goroutine, so a bare count immediately after
	// would pass whatever happened. Wait for it not to happen.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if n := poi.countMessages("ActivateTaskRequest"); n != 0 {
			t.Fatalf("RestoreInterception sent %d activations: it restores a release report, "+
				"not an interception — re-installing from a release path produces a trigger "+
				"whose detection criterion names a PFCP session that no longer exists", n)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if sc.LiReleaseReported {
		t.Error("the release stayed reported")
	}
}
