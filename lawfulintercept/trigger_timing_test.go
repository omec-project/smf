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

// chanTaskReporter hands each task report to the test as it is made. The reports are made
// off the caller's goroutine, which recordingTaskReporter cannot be read across.
type chanTaskReporter chan taskReport

func (c chanTaskReporter) NotifyTask(xid, reportType, details string) {
	c <- taskReport{xid, reportType, details}
}

// TestCCWithoutAnyTriggeringEndpointIsReported: an li block with no `upfTriggers` builds no
// trigger registry, and content interception it accepts can reach no CC-POI. Each CC warrant
// covering a live session is reported to the LIPF as having no triggering endpoint, as it is
// for a UPF the list leaves out, where triggerCC used to return without a word. An IRI-only
// warrant asks for no content and is not reported, and neither is a session whose anchor is
// not up yet.
func TestCCWithoutAnyTriggeringEndpointIsReported(t *testing.T) {
	reports := make(chanTaskReporter, 4)
	s := &subsystem{neID: testNEID, store: store.New(), taskReporter: reports}
	for xid, product := range map[types.XID]types.ProductType{
		testXIDPrimary:   types.ProductCC,
		testXIDSecondary: types.ProductIRI,
	} {
		if !s.store.Activate(types.InterceptTask{
			XID:      xid,
			Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
			Products: []types.ProductType{product},
			State:    types.TaskActive,
		}) {
			t.Fatalf("activating %s", xid)
		}
	}
	quiet := func(what string) {
		t.Helper()
		select {
		case r := <-reports:
			t.Errorf("%s: reported %+v", what, r)
		case <-time.After(200 * time.Millisecond):
		}
	}

	comingUp := sessionServedBy(testSUPI, trigNodeA)
	comingUp.PFCPContext = nil
	s.triggerCC(comingUp)
	quiet("a session whose anchor is not up yet")

	// The anchor not up yet while another of the session's UPFs is: that UPF is a serving UPF,
	// so only the anchor's missing SEID keeps the session from being reported as a fault.
	anchorPending := sessionServedBy(testSUPI, trigNodeA)
	other := smfctx.NewDataPathNode()
	other.UPF = &smfctx.UPF{NodeID: upfNode(trigNodeElsewhere)}
	anchorPending.PFCPContext = map[string]*smfctx.PFCPSessionContext{
		other.UPF.NodeID.ResolveNodeIdToIp().String(): {RemoteSEID: 0x2632898145f4d192},
	}
	anchorPending.Tunnel.DataPathPool[2] = &smfctx.DataPath{FirstDPNode: other}
	if len(sessionUPFs(anchorPending)) == 0 {
		t.Fatal("the session's other UPF is not a serving UPF, so the case below tests nothing")
	}
	s.triggerCC(anchorPending)
	quiet("a session whose anchor is not up yet, served by another UPF that is")

	s.triggerCC(sessionServedBy(testSUPI, trigNodeA))
	select {
	case r := <-reports:
		want := taskReport{
			string(testXIDPrimary), x1.TaskReportTerminatingFault,
			"no triggering endpoint configured for a UPF serving the target",
		}
		if r != want {
			t.Errorf("reported %+v, want %+v", r, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a CC warrant on a live session with no triggering endpoint at all was not reported")
	}
	quiet("after the CC warrant's report")
}

// TestAWarrantChangedWhileTheUPFsAreFoundIsNotTriggered: the X1 hooks change the store and then
// take the warrant's claims from the registry. A withdrawal, or a ModifyTask that moves the
// warrant off this subscriber, landing after triggerCCAt has read the session's warrants and
// before the claim, found no claim to take; the trigger was then claimed and installed for a
// warrant the store no longer holds for this session, and stillHolds vouched for it, so nothing
// withdrew it. The serving UPFs are looked up between the two, which is where the change is made.
func TestAWarrantChangedWhileTheUPFsAreFoundIsNotTriggered(t *testing.T) {
	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
	}
	retargeted := warrant
	retargeted.Targets = []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543211"}}

	for _, tc := range []struct {
		name   string
		change func(s *subsystem)
	}{
		{"withdrawn", func(s *subsystem) {
			s.store.Deactivate(warrant.XID)
			s.applyTaskChange(&warrant, nil)
		}},
		{"moved to another subscriber", func(s *subsystem) {
			s.store.Activate(retargeted)
			s.applyTaskChange(&warrant, &retargeted)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			poi := newFakePOI(t)
			s := triggerSubsystem(t, poi)
			if !s.store.Activate(warrant) {
				t.Fatal("activating the warrant")
			}
			sc := sessionServedBy(testSUPI, trigNodeA)

			looked := false
			s.triggerCCAt(sc, func(sc *smfctx.SMContext) []upfSession {
				looked = true
				tc.change(s)

				return sessionUPFs(sc)
			})
			if !looked {
				t.Fatal("triggerCCAt never looked up the serving UPFs, so the change was never made between the read and the claim")
			}
			s.scans.Wait()

			s.triggers.mu.Lock()
			installed, pending := len(s.triggers.installed), len(s.triggers.pending)
			s.triggers.mu.Unlock()
			if installed != 0 || pending != 0 {
				t.Errorf("after the change the registry holds %d claims and %d pending withdrawals, want none: "+
					"a trigger claimed for a warrant this session no longer has is installed with nothing to withdraw it",
					installed, pending)
			}
		})
	}
}
