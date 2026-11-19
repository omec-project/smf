// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"strings"
	"testing"
	"time"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
)

// namedTriggerSubsystem is triggerSubsystem with the UPF configured under a **name**, which
// is what the chart and the blueprint default to (`nodeId: upf`) and what a deployment
// therefore runs.
//
// That is the whole subject here. Trigger keys carry the configured string, and the restart
// notification passed a resolved address, so ForgetPOI's string equality matched nothing and
// the notification did nothing at all. The existing test configures an IP literal — the one
// spelling in which the two forms coincide — so it passed against the defect.
func namedTriggerSubsystem(t *testing.T, poi *fakePOI, node, addr string) *subsystem {
	t.Helper()

	cfg := Config{
		NEID: testNEID,
		MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{
			{NodeID: node, X1URL: poi.srv.URL, NEID: testUPFNEID1},
		},
	}
	s := &subsystem{neID: testNEID, triggers: mustRegistry(cfg), store: store.New()}
	waitForScans(t, s)

	// The name resolves to the address the session path carries, which is what makes the
	// two configurations describe one UPF.
	resolvingTo(s.triggers, map[string]string{node: addr})

	return s
}

// TestARestartAtANamedNodeIsRecognised: the notification has to identify the point of
// interception the way the registry does.
//
// `li.upfTriggers[].nodeId` is the configured string and the trigger keys are built from it;
// the caller holds a `smfctx.NodeID` whose resolved form is an address. Handed the address,
// the discard would match no key: every claim would survive, so `plan` would find each triple
// already claimed and install nothing — the restarted UPF holding no tasking and discarding the
// copies it was told to make, while this element reported the interception as running.
//
// With a pre-resolved string the registry keeps its claims and the second establishment sends
// no activation, which is what this test fails on.
func TestARestartAtANamedNodeIsRecognised(t *testing.T) {
	poi := newFakePOI(t)
	s := namedTriggerSubsystem(t, poi, "upf", trigNodeA)

	active.Store(s)
	t.Cleanup(func() { active.Store(nil) })

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	// The session names its serving UPF by address, as sessionUPFs builds it: the session
	// path and the LI block are independent configuration and need not agree.
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	awaitMessages(t, poi, "ActivateTaskRequest", 1)

	// The UPF restarts, discovered on whichever PFCP path noticed. The node identity is what
	// the PFCP handlers hold.
	POIRestarted(*smfctx.NewNodeID(trigNodeA))

	// And the next establishment re-tasks it.
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	awaitMessages(t, poi, "ActivateTaskRequest", 2)
}

// TestARestartIsRecognisedThroughTheAddressFallbackToo keeps the other arm of the matching
// rule covered. A UPF configured by address and a session naming it by address match by
// identity; a UPF configured by name and a session carrying an address match through the
// resolved index. Both arms exist because the two configurations are independent, and a
// change that fixed one by breaking the other would pass a test of the first alone.
func TestARestartIsRecognisedThroughTheAddressFallbackToo(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi) // configured by address, as the existing tests do

	active.Store(s)
	t.Cleanup(func() { active.Store(nil) })

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	awaitMessages(t, poi, "ActivateTaskRequest", 1)

	POIRestarted(*smfctx.NewNodeID(trigNodeA))

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	awaitMessages(t, poi, "ActivateTaskRequest", 2)
}

// TestARestartAtAnUnconfiguredNodeDiscardsNothing is the guard on the matching rule itself.
// An unresolvable or unconfigured node must never match, because a claim discarded for the
// wrong POI re-installs one element's tasking at another's — the defect matchEndpoint's own
// documentation exists to prevent, arrived at from the restart path.
func TestARestartAtAnUnconfiguredNodeDiscardsNothing(t *testing.T) {
	poi := newFakePOI(t)
	s := namedTriggerSubsystem(t, poi, "upf", trigNodeA)

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	awaitMessages(t, poi, "ActivateTaskRequest", 1)

	held := len(s.triggers.installed)
	n, match := s.triggers.forgetRestartedPOI(upfSession{
		node: upfNode(trigNodeElsewhere), addr: trigNodeElsewhere,
	})
	if n != 0 {
		t.Errorf("a restart at a node this element does not task discarded %d claims", n)
	}
	// Ruled out, not undecidable: every configured name has resolved and none is this node, so
	// nothing about it may hold that node's restoration back.
	if match != restartNotAtPOI {
		t.Errorf("a restart at a node this element can rule out was classified %d, want restartNotAtPOI", match)
	}
	if now := len(s.triggers.installed); now != held {
		t.Errorf("claims went from %d to %d for a restart at another node", held, now)
	}
}

// TestARecognisedRestartIsReported is the part of the requirement nothing exercised: an
// operator learns that interception this element believed was running has been discarded and
// must be re-installed. NE-level and countable, naming no warrant — which interceptions were
// lost is the ADMF's to work out from its own provisioning, and this element cannot name them
// without disclosing tasking on a channel that must not carry it.
func TestARecognisedRestartIsReported(t *testing.T) {
	poi := newFakePOI(t)
	s := namedTriggerSubsystem(t, poi, "upf", trigNodeA)

	admf := newADMFStub(t)
	s.reporter = x1.NewReporter(admf.srv.URL, testADMFID, testNEID, admf.clientTLS())

	active.Store(s)
	t.Cleanup(func() { active.Store(nil) })

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	awaitMessages(t, poi, "ActivateTaskRequest", 1)

	POIRestarted(*smfctx.NewNodeID(trigNodeA))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(admf.received(), "\n"), "reconcileFailed") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Errorf("a recognised restart was reported to nobody: interception this element believed was "+
		"running has been discarded and must be re-installed, which only the ADMF can act on.\n%s",
		strings.Join(admf.received(), "\n"))
}
