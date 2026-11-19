// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
)

// hangingPOI accepts the connection and never answers, so a keepalive to it costs the
// requester's full timeout. That is what an unreachable-but-routable UPF looks like, and
// it is the case a serial round pays for once per endpoint.
func hangingPOI(t *testing.T) string {
	t.Helper()

	held := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-held:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(held)
		srv.Close()
	})

	return srv.URL
}

// TestAnUnreachableEndpointDoesNotDelayAHealthyOnesKeepalive is the sending half of the
// fail-safe property, and the half this element controls.
//
// A fail-safe window says how long silence must last before it means absence, and the
// POI's minTriggerKeepalive floor protects that window from the operator's side. It
// protects nothing if the sending side cannot keep the cadence: signalled one after
// another, each bounded only by a peer timeout, a round takes as long as the sum of its
// failures. A healthy point of interception sharing a triggering function with enough
// unreachable ones is then signalled at intervals its own window was chosen to read as
// absence — so it purges live tasking and reports that its triggering function went
// silent, which is true of the interval and false of the cause.
//
// **Asserted on the interval, not the call count.** A serial round signals every
// endpoint too; it just does it too late, so a count assertion passes against the defect.
func TestAnUnreachableEndpointDoesNotDelayAHealthyOnesKeepalive(t *testing.T) {
	// It waits out the requester's 10s timeout, and touches no package state, so it waits
	// alongside the other tests that do rather than after them.
	t.Parallel()

	poi := newFakePOI(t)

	// One endpoint that answers, and several that never do.
	triggers := []UPFTrigger{{NodeID: trigNodeA, X1URL: poi.srv.URL, NEID: testUPFNEID1}}
	for i := range 4 {
		triggers = append(triggers, UPFTrigger{
			NodeID: "10.0.2." + string(rune('1'+i)),
			X1URL:  hangingPOI(t),
			NEID:   "upf-dead-" + string(rune('a'+i)),
		})
	}

	reg := mustRegistry(Config{NEID: testNEID, MDF3: testMDF3Addr, UPFTriggers: triggers})

	// Keepalives are owed for tasking this element can name *at an endpoint it has
	// reconciled with*, which is the state a running element reaches at startup. Both
	// halves are set here, or the round has nothing to send and this measures nothing.
	for _, tr := range triggers {
		reg.endpoints[tr.NodeID].markReconciled()
	}
	for i, tr := range triggers {
		reg.installed[triggerKey(types.XID("W1"), "session-ref-1", tr.NodeID)] = installedTrigger{
			xid: types.XID(x1.NewUUID()), seid: uint64(0x2632898145f4d191 + i), correlation: 7,
		}
	}

	start := time.Now()
	reg.keepaliveRound()
	elapsed := time.Since(start)

	// Four unreachable endpoints at 10s each is 40s serially. The bound is far below
	// that and far above one timeout plus scheduling noise.
	if elapsed > 20*time.Second {
		t.Errorf("a keepalive round took %s with four unreachable endpoints; a healthy point of "+
			"interception is being signalled at intervals its own fail-safe reads as absence, "+
			"and will purge live tasking this element is still answering for", elapsed)
	}

	if n := poi.countMessages("KeepaliveRequest"); n == 0 {
		t.Error("the reachable point of interception was not signalled at all; this test would " +
			"assert nothing about when it was")
	}
}

// TestARestartedPointOfInterceptionIsReTasked is the bookkeeping half of a UPF restart.
//
// A triggered POI holds its tasking in memory, so a restart takes all of it. This
// element's record survives, and every claim in it now describes tasking that does not
// exist — so plan finds each triple already claimed and installs nothing. The restarted
// UPF holds no tasking, produces no content, and discards the copies it is told to make
// as untasked, while this element reports the interception as running.
func TestARestartedPointOfInterceptionIsReTasked(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	awaitMessages(t, poi, "ActivateTaskRequest", 1)

	// A second attempt installs nothing, which is correct while the POI still holds it.
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Fatalf("re-planning an already-installed trigger sent %d activations, want 1", n)
	}

	// The UPF restarts.
	if forgotten := s.triggers.ForgetPOI(trigNodeA); forgotten != 1 {
		t.Fatalf("ForgetPOI discarded %d claims, want 1", forgotten)
	}

	// And the next establishment or scan re-tasks it.
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	awaitMessages(t, poi, "ActivateTaskRequest", 2)
}

// TestAForgottenEndpointStopsEarningKeepalives is the liveness half, and it follows from
// the same discard rather than needing a mechanism of its own.
//
// keepaliveDue owes a signal for tasking this element can name. Keeping a restarted POI
// alive on the strength of tasking that no longer exists is what disables its own
// fail-safe — the last mechanism able to reclaim an orphan.
func TestAForgottenEndpointStopsEarningKeepalives(t *testing.T) {
	poi := newFakePOI(t)
	reg := mustRegistry(Config{
		NEID: testNEID, MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{{NodeID: trigNodeA, X1URL: poi.srv.URL, NEID: testUPFNEID1}},
	})

	reg.endpoints[trigNodeA].markReconciled()
	reg.installed[triggerKey(types.XID("W1"), "session-ref-1", trigNodeA)] = installedTrigger{
		xid: types.XID(x1.NewUUID()), seid: 0x2632898145f4d191, correlation: 7,
	}

	reg.keepaliveRound()
	if poi.countMessages("KeepaliveRequest") == 0 {
		t.Fatal("an endpoint holding this element's tasking was not signalled")
	}

	before := poi.countMessages("KeepaliveRequest")
	reg.ForgetPOI(trigNodeA)
	reg.keepaliveRound()

	if after := poi.countMessages("KeepaliveRequest"); after != before {
		t.Errorf("a point of interception this element holds no tasking for was signalled %d more "+
			"times; its own fail-safe is being held off on the strength of tasking that is gone",
			after-before)
	}
}

var _ = sync.WaitGroup{}
