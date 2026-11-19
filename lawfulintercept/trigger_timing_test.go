// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
)

// unansweringADMF accepts the report and never answers it, which is the state a task
// issue is most likely to be reported under: the LIPF being unreachable is itself one
// of the things that goes wrong at the same time as everything else.
type unansweringADMF struct {
	url     string
	arrived atomic.Int32
}

func (a *unansweringADMF) count() int { return int(a.arrived.Load()) }

func newUnansweringADMF(t *testing.T) *unansweringADMF {
	t.Helper()

	a := &unansweringADMF{}
	held := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		a.arrived.Add(1)
		select {
		case <-held:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(held)
		srv.Close()
	})
	a.url = srv.URL

	return a
}

// sessionServedBy builds a session whose serving UPF is at addr, which is what
// triggerCC matches against the configured triggering endpoints.
func sessionServedBy(supi, addr string) *smfctx.SMContext {
	node := smfctx.NewDataPathNode()
	node.UPF = &smfctx.UPF{NodeID: upfNode(addr)}
	node.UpLinkTunnel.PDR["default"] = &smfctx.PDR{FAR: &smfctx.FAR{}}

	sc := &smfctx.SMContext{
		Supi: supi,
		Ref:  "session-ref-timing",
		Tunnel: &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
			1: &smfctx.DataPath{FirstDPNode: node, IsDefaultPath: true},
		}},
	}
	// The correlation identifier is the anchor's PFCP session, and plan refuses to do
	// anything without one — a session whose anchor is not up yet is not a fault. So a
	// test that omits it exercises none of this, which is how the first draft of this
	// test passed against the very defect it was written for.
	sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{
		node.UPF.NodeID.ResolveNodeIdToIp().String(): {RemoteSEID: 0x2632898145f4d191},
	}

	return sc
}

// TestATaskedEstablishmentIsNotSlowedByAnUnreachableLIPF is the undetectability form
// of the rule, and it is the one that matters: a tasked subscriber whose session takes
// measurably longer to establish than an untasked one's is distinguishable by the
// subject, which is the leak this whole capability exists to prevent.
//
// triggerCC runs on HandlePfcpSessionEstablishmentResponse's path with sc.SMLock held.
// The reports it issues for a warrant it cannot install — no triggering endpoint for a
// UPF serving the target — go over X1, and ReportTaskIssue is deliberately unthrottled
// because each task's failure is its own fact. Issued synchronously, every affected
// warrant would cost the establishment a full client timeout, under the session's own
// lock, and only for the subscribers who were being intercepted.
//
// Three warrants, so a synchronous report costs three timeouts rather than one: this
// asserts against a stall that scales with the tasking, which is the shape that makes
// it a measurement of the warrant rather than of the network.
func TestATaskedEstablishmentIsNotSlowedByAnUnreachableLIPF(t *testing.T) {
	const (
		supi     = testSUPI
		servedBy = trigNodeElsewhere // not the address triggerSubsystem configures an endpoint for
	)

	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	admf := newUnansweringADMF(t)
	s.taskReporter = x1.NewReporter(admf.url, "admfID", testNEID, nil)

	st := store.New()
	for _, xid := range []types.XID{
		testXIDPrimary,
		testXIDSecondary,
		testXIDTertiary,
	} {
		if !st.Activate(types.InterceptTask{
			XID:      xid,
			Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
			Products: []types.ProductType{types.ProductCC},
			State:    types.TaskActive,
		}) {
			t.Fatalf("activating %s", xid)
		}
	}
	s.store = st

	tasked := sessionServedBy(supi, servedBy)
	tasked.Tunnel.DataPathPool[1].FirstDPNode.UPF.NodeID = upfNode(servedBy)

	untasked := sessionServedBy("imsi-262010000000000", servedBy)

	// The untasked session is the control: it is what the subject's peers experience,
	// and the tasked one must not be distinguishable from it.
	start := time.Now()
	s.triggerCC(untasked)
	control := time.Since(start)

	start = time.Now()
	s.triggerCC(tasked)
	target := time.Since(start)

	// A synchronous report would put three unthrottled 10s timeouts on this path. The
	// bound is deliberately far below one of them and far above any scheduling noise.
	if target > time.Second {
		t.Errorf("a tasked subscriber's establishment waited %s on the LI plane (untasked: %s); "+
			"the difference is observable to the subject", target, control)
	}

	// And the reports were actually issued, off the path. Without this the timing
	// assertion above passes against a session that produced no warrants, no UPFs and
	// no reports at all — which is what it did until this line was added.
	reported := func() int {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if n := admf.count(); n > 0 {
				return n
			}
			time.Sleep(5 * time.Millisecond)
		}

		return 0
	}()
	if reported == 0 {
		t.Fatal("no task issue was reported at all, so this asserts nothing about where they are reported from")
	}
}
