// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/Npcf_SMPolicyControl"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/transaction"
)

// liRelease records what each release branch did to the session's interception state.
type liRelease struct {
	released, untasked, restored, rejected int
	rejectedIDs                            []int32
}

func captureRelease(t *testing.T) *liRelease {
	t.Helper()

	c := &liRelease{}
	release, untrigger := liReportRelease, liUntriggerCC
	restore, reject := liRestoreInterception, liReportReleaseReject
	liReportRelease = func(*smf_context.SMContext) { c.released++ }
	liUntriggerCC = func(*smf_context.SMContext) { c.untasked++ }
	liRestoreInterception = func(*smf_context.SMContext) { c.restored++ }
	liReportReleaseReject = func(_ *smf_context.SMContext, pduSessionID int32, _ uint8) {
		c.rejected++
		c.rejectedIDs = append(c.rejectedIDs, pduSessionID)
	}
	t.Cleanup(func() {
		liReportRelease, liUntriggerCC = release, untrigger
		liRestoreInterception, liReportReleaseReject = restore, reject
	})

	return c
}

// releasableSession is a session with a tunnel, so releaseTunnel has something to
// release and the handler reaches the branch that decides what the outcome was.
func releasableSession(t *testing.T) *smf_context.SMContext {
	t.Helper()

	sc := teardownSession(t)
	t.Cleanup(func() { smf_context.RemoveSMContext(sc.Ref) })

	// Releasing a tunnel asks each node for its UPF id, which reads the element's
	// user-plane table. An empty one is enough: the lookup then fails, the deletion
	// request is skipped and logged, and releaseTunnel still reports the tunnel
	// released — which is the state this test needs, since it supplies the deletion's
	// outcome itself.
	if smf_context.SMF_Self().UserPlaneInformation == nil {
		smf_context.SMF_Self().UserPlaneInformation = &smf_context.UserPlaneInformation{
			UPFsIPtoID: map[string]string{},
		}
		t.Cleanup(func() { smf_context.SMF_Self().UserPlaneInformation = nil })
	}

	// The state change to SmStateActive on the failure branches reports session metrics
	// keyed by the UE's address, so a session without one panics there. Marked as
	// allocated by the user plane, which is a real deployment choice and the one that
	// keeps the address out of an SMF-side pool: releasing it is then a no-op, where
	// an SMF-allocated address would be handed back to an allocator these tests do not
	// build.
	sc.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP("10.250.0.9"), UpfProvided: true}

	// A policy client pointing nowhere. The release path deletes the SM policy
	// association before it touches PFCP, and a nil client panics there — so without
	// this the handler never reaches the branch under test. It resolves to nothing and
	// the failure is logged and carried on from, which is the behaviour this test wants
	// anyway: what is asserted is what happens after the PFCP deletion does not.
	cfg := Npcf_SMPolicyControl.NewConfiguration()
	sc.SMPolicyClient = Npcf_SMPolicyControl.NewAPIClient(cfg)

	node := smf_context.NewDataPathNode()
	node.UPF = &smf_context.UPF{NodeID: *smf_context.NewNodeID("10.0.1.5"), Port: 8805}
	node.UpLinkTunnel.PDR["default"] = &smf_context.PDR{FAR: &smf_context.FAR{}}
	sc.Tunnel = &smf_context.UPTunnel{DataPathPool: smf_context.DataPathPool{
		1: &smf_context.DataPath{FirstDPNode: node, IsDefaultPath: true},
	}}
	// The PFCP context the deactivation removes the session's PDRs from. Deactivating
	// a tunnel whose UPF has no entry here dereferences nothing and panics, so this is
	// part of what an established session means rather than test decoration.
	sc.PFCPContext = map[string]*smf_context.PFCPSessionContext{
		node.UPF.NodeID.ResolveNodeIdToIp().String(): {
			PDRs:       map[uint16]*smf_context.PDR{},
			NodeID:     node.UPF.NodeID,
			RemoteSEID: 0x2632898145f4d191,
		},
	}

	return sc
}

// TestAReleaseThatTimesOutRestoresTheSessionsInterceptionState is the release-path half
// of "a record reports the transition it names", asserted at the level this package can:
// **which of its branches call the hook.**
//
// That is the whole of its subject, and the distinction is worth stating because the
// previous round's version of this test read as more than it was. The hooks are
// stubbed here — they have to be, since `active` is private to lawfulintercept and Init
// needs mTLS material and a TCP bind this package has no business standing up — so a
// count establishes that this branch reaches the hook and nothing about what the hook
// then does. What it does is asserted in lawfulintercept's own
// TestARestoredReleaseIsReportableAgainAndRetasksNothing, and the two halves of that
// answer were not the same: the release-report restore is real, and the trigger
// re-install the previous comment claimed was unreachable code.
//
// The SMF reports the release and withdraws the session's triggers before PFCP deletion
// — which is the right order: releaseTunnel may nil sc.Tunnel, withdrawal needs the
// serving-UPF list that hangs off it, and stopping interception before or as the session
// goes is the fail-closed direction. What was wrong is that on the branches where the
// deletion times out or fails, the session is restored to service and nothing put the
// release-report state back: LiReleaseReported stayed set, so the release that eventually
// happened was suppressed as a duplicate of one that never occurred, and the agency's
// record of the session ended at the failed attempt.
//
// The timeout branch also emitted no unsuccessful-procedure record, where its two
// siblings did: the mediation function saw a release record and then silence, and which
// failure had occurred is exactly the distinction it cannot make.
func TestAReleaseThatTimesOutRestoresTheSessionsInterceptionState(t *testing.T) {
	calls := captureRelease(t)
	sc := releasableSession(t)

	txn := &transaction.Transaction{
		Req:  models.ReleaseSmContextRequest{},
		Ctxt: sc,
	}

	done := make(chan error, 1)
	go func() { done <- HandlePDUSessionSMContextRelease(txn) }()

	// The deletion never lands.
	select {
	case sc.SBIPFCPCommunicationChan <- smf_context.SessionReleaseTimeout:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never waited on the PFCP deletion outcome")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandlePDUSessionSMContextRelease: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not return after the deletion timed out")
	}

	if calls.released != 1 || calls.untasked != 1 {
		t.Fatalf("the release path reported %d and untasked %d; this test asserts nothing "+
			"unless the teardown it is meant to undo actually ran", calls.released, calls.untasked)
	}
	if calls.restored != 1 {
		t.Errorf("the session was restored to service %d times and its interception state %d: "+
			"the release that eventually happens is then suppressed as a duplicate of one that "+
			"never occurred, and the agency's record of this session ends at a failed attempt",
			1, calls.restored)
	}
	if calls.rejected != 1 {
		t.Errorf("the timeout branch emitted %d unsuccessful-procedure records, want 1 — its two "+
			"sibling branches emit one, so what the mediation function sees depends on which "+
			"failure occurred, which is the distinction it cannot make", calls.rejected)
	}
	if len(calls.rejectedIDs) == 1 && calls.rejectedIDs[0] != sc.PDUSessionID {
		t.Errorf("the unsuccessful-procedure record names PDU session %d, want %d: the release "+
			"that timed out is this session's own", calls.rejectedIDs[0], sc.PDUSessionID)
	}
}
