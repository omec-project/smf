// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/omec-project/smf/context"
)

func anchor(t *testing.T, supi string, psi int32, nodeIPs ...string) *context.SMContext {
	t.Helper()
	smContext := context.NewSMContext(supi, psi)
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	for i, ip := range nodeIPs {
		smContext.PFCPContext[ip] = &context.PFCPSessionContext{
			NodeID:     *context.NewNodeID(ip),
			LocalSEID:  uint64(1000 + i),
			RemoteSEID: uint64(2000 + i),
		}
	}
	return smContext
}

// Enumeration has to be by node, because a restart is scoped to one node and re-installing a
// session onto a UPF that never lost anything would replace working forwarding state.
func TestSessionsAnchoredOnReturnsOnlyThatNodesSessions(t *testing.T) {
	here := anchor(t, "imsi-208930000000001", 1, "10.20.0.1")
	elsewhere := anchor(t, "imsi-208930000000002", 2, "10.20.0.2")
	both := anchor(t, "imsi-208930000000003", 3, "10.20.0.1", "10.20.0.2")

	found, _, _ := context.SessionsAnchoredOn(*context.NewNodeID("10.20.0.1"))

	seen := map[*context.SMContext]bool{}
	for _, s := range found {
		seen[s] = true
	}
	if !seen[here] {
		t.Errorf("the session anchored on 10.20.0.1 was not returned")
	}
	if !seen[both] {
		t.Errorf("the session anchored on both nodes was not returned for 10.20.0.1")
	}
	if seen[elsewhere] {
		t.Errorf("a session anchored only on 10.20.0.2 was returned for 10.20.0.1; restoring it would " +
			"re-install rules on a node that never restarted")
	}
}

// A node nothing is anchored on must produce an empty result rather than everything.
func TestSessionsAnchoredOnAnUnknownNodeIsEmpty(t *testing.T) {
	anchor(t, "imsi-208930000000004", 4, "10.20.0.3")

	if found, _, _ := context.SessionsAnchoredOn(*context.NewNodeID("10.20.0.99")); len(found) != 0 {
		t.Errorf("expected no sessions for a node holding none, got %d", len(found))
	}
}

// Enumeration ranges the live session pool while sessions are being created, because there is no
// index from a node to the sessions anchored on it. It must tolerate the pool changing under it
// rather than requiring it to be still, and it must not race with the establishment that adds a
// session's PFCP context.
//
// Release churn is not exercised here: ChangeState publishes through infrastructure a unit test does
// not have. The race that matters for enumeration is against establishment, which is what adds the
// entry this reads.
func TestSessionsAnchoredOnToleratesConcurrentEstablishment(t *testing.T) {
	node := *context.NewNodeID("10.20.0.40")

	// Bounded on both sides. Sessions are never removed from the pool, so unbounded churn makes each
	// enumeration range an ever-larger set and the test becomes quadratic rather than informative.
	const writers, perWriter, sweeps = 3, 60, 40

	var churn sync.WaitGroup
	for w := range writers {
		churn.Add(1)
		go func(w int) {
			defer churn.Done()
			for i := range perWriter {
				anchor(t, fmt.Sprintf("imsi-2089300%02d%05d", w, 8000+i), int32(i%15+1), "10.20.0.40")
			}
		}(w)
	}

	for range sweeps {
		for _, s := range mustAnchored(node) {
			if s == nil {
				t.Errorf("enumeration returned a nil session")
				break
			}
		}
	}
	churn.Wait()

	// Everything the writers created is anchored on the node, so the final sweep must see them all.
	if got := len(mustAnchored(node)); got < writers*perWriter {
		t.Errorf("after the churn settled, enumeration found %d session(s), want at least %d",
			got, writers*perWriter)
	}
}

// A UE that establishes the same PDU session again without the old one being released leaves the
// first context in the pool describing a session nothing will use. Restoring it after a user-plane
// restart programs the recovered node with a rule for a UE address that is gone, and spends the
// restoration on a session that cannot carry traffic — while the live one goes unrestored. Observed
// exactly that on a cluster.
func TestSessionsAnchoredOnSkipsASupersededSession(t *testing.T) {
	node := *context.NewNodeID("10.20.0.50")
	const supi, psi = "imsi-208930000009001", int32(1)

	superseded := anchor(t, supi, psi, "10.20.0.50")
	current := anchor(t, supi, psi, "10.20.0.50") // same subscriber and session: repoints the ref

	found, _, _ := context.SessionsAnchoredOn(node)

	seen := map[*context.SMContext]bool{}
	for _, s := range found {
		seen[s] = true
	}
	if seen[superseded] {
		t.Errorf("a superseded session was returned; restoring it installs a rule for a UE address " +
			"that is gone and consumes the restoration the live session needed")
	}
	if !seen[current] {
		t.Errorf("the current session was not returned, so the live session would go unrestored")
	}
}

func mustAnchored(node context.NodeID) []*context.SMContext {
	anchored, _, _ := context.SessionsAnchoredOn(node)
	return anchored
}

// A session whose establishment is still outstanding must be left alone. Restoring it overwrites
// the establishment in flight: on a cluster this pinned the UE address to the SMF's placeholder
// before the UPF had chosen one, and the subscriber came up outside the address pool with no
// downlink.
func TestSessionsAnchoredOnSkipsASessionTheNodeHasNotAcknowledged(t *testing.T) {
	node := *context.NewNodeID("10.20.0.50")
	establishing := anchor(t, "imsi-208930000000050", 5, "10.20.0.50")
	establishing.SMLock.Lock()
	establishing.PFCPContext["10.20.0.50"].RemoteSEID = 0
	establishing.SMLock.Unlock()

	for _, s := range mustAnchored(node) {
		if s == establishing {
			t.Errorf("a session the node never acknowledged was offered for restoration; " +
				"re-installing its rules overwrites the establishment still in flight")
		}
	}
}

// The zero written by restoration itself must not read as "never established", or a node that
// restarts twice in quick succession leaves every session it was repairing behind on the second
// sweep -- exactly the sessions that most need repairing.
func TestSessionsAnchoredOnStillReturnsASessionRestorationCleared(t *testing.T) {
	node := *context.NewNodeID("10.20.0.51")
	interrupted := anchor(t, "imsi-208930000000051", 6, "10.20.0.51")
	interrupted.SMLock.Lock()
	interrupted.PFCPContext["10.20.0.51"].RemoteSEID = 0
	interrupted.PFCPContext["10.20.0.51"].ClearedByRestoration = true
	interrupted.SMLock.Unlock()

	found := false
	for _, s := range mustAnchored(node) {
		if s == interrupted {
			found = true
		}
	}
	if !found {
		t.Errorf("a session whose remote identifier a previous restoration cleared was not offered " +
			"to the restart that superseded it; it would be left unrepaired")
	}
}
