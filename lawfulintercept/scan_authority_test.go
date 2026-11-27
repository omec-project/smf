// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/nas/v2/nasMessage"
	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x2x3"
)

// withdrawingSender is a delivery client that withdraws the warrant as soon as the
// first record is handed to it, and records where each record went.
//
// The withdrawal is driven from the sender rather than from a timer because the
// property is about what happens *during* a scan, and a scan over a handful of
// sessions is over in microseconds. Racing a goroutine at it would assert nothing.
type withdrawingSender struct {
	mu    sync.Mutex
	sent  int
	addrs []string

	onFirst func()
	addr    string
}

func (w *withdrawingSender) Send(_ *x2x3.PDU) error {
	w.mu.Lock()
	w.sent++
	w.addrs = append(w.addrs, w.addr)
	first := w.sent == 1
	onFirst := w.onFirst
	w.mu.Unlock()

	if first && onFirst != nil {
		onFirst()
	}

	return nil
}

func (w *withdrawingSender) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.sent
}

func (w *withdrawingSender) destinations() []string {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([]string(nil), w.addrs...)
}

// scanFixture is a subsystem whose scan can be observed: several targeted sessions in
// the pool, and a sender that reports what the scan delivered.
func scanFixture(t *testing.T, task types.InterceptTask, sessions int) (*subsystem, *store.Store, *withdrawingSender) {
	t.Helper()

	st := store.New()
	if !st.Activate(task) {
		t.Fatal("Activate failed")
	}

	snd := &withdrawingSender{}
	sub := &subsystem{
		store: st,
		senderFor: func(addr string) sender {
			snd.mu.Lock()
			snd.addr = addr
			snd.mu.Unlock()

			return snd
		},
		mdf2: testDestinationAddr,
		neID: testNEID,
		ids:  x2x3.NewIdentity(testNEID, smfInterceptionPoint),
	}
	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })
	waitForScans(t, sub)

	for i := range sessions {
		sc := pooledSession(t, testSUPI, int32(i+1))
		// The two things the record and the scan each refuse to proceed without: an
		// endpoint address, because a record asserting the session has none would be
		// untrue, and a PFCP session, because its SEID is the correlation the mediation
		// function joins content to. Omitting either makes the scan silently deliver
		// nothing — which is how the first draft of this test asserted nothing at all.
		// An established IP session has an endpoint address, and the record reports it, so
		// the fixture gives the session one — marked as allocated by the user plane, which is
		// a real deployment choice and the one that keeps the address out of an SMF-side pool these tests
		// do not build. Clearing it from a cleanup instead would be a write to a session
		// the scan's goroutine may still be reading, which -race reports as the test's
		// own race rather than the element's.
		sc.PDUAddress = &smfctx.UeIpAddr{Ip: net.ParseIP("10.250.0.9"), UpfProvided: true}

		// And a PDU session type, the third mandatory member. Without the two above the
		// record is silently not delivered; without this one it is refused by li/iri,
		// because pDUSessionType is mandatory in this record and its enumeration has no
		// zero — so a session left at the Go zero value would produce a record a
		// conformant mediation function discards.
		//
		// A session that has an address has completed establishment, and establishment is
		// where the type is chosen: HandlePDUSessionEstablishmentRequest refuses the
		// request outright while SelectedPDUSessionType is still 0. So an address without
		// a type is a session the SMF cannot produce, and the fixture was describing one.
		sc.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4

		// And a DNN: the record's dNN is a mandatory string, and li/iri refuses an empty one
		// because it names nothing. Every established session has one.
		sc.Dnn = "internet"

		// A default data path with a serving UPF, because the correlation the record
		// carries is that UPF's PFCP session id, and a session without one is deferred
		// by the scan as still establishing rather than reported.
		node := smfctx.NewDataPathNode()
		node.UPF = &smfctx.UPF{NodeID: upfNode(trigNodeA)}
		// ApplyAction.Forw, because forEachForwardingFAR — which is what applies and
		// clears duplication — only visits forwarding FARs. A FAR without it is
		// invisible to every part of this path.
		node.UpLinkTunnel.PDR["default"] = &smfctx.PDR{
			FAR: &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}},
		}
		sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
			1: &smfctx.DataPath{FirstDPNode: node, IsDefaultPath: true},
		}}
		sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{
			node.UPF.NodeID.ResolveNodeIdToIp().String(): {RemoteSEID: uint64(0x2632898145f4d190 + i)},
		}
	}

	return sub, st, snd
}

// TestAWithdrawalDuringAScanStopsTheRemainingRecords is the authority half of
// "product is delivered only under authority the element currently holds".
//
// The scan runs off the X1 goroutine because another rule requires it to — a
// provisioning answer must not scale with the subscriber population — and that is
// exactly what makes its duration unbounded by anything the provisioning function can
// see. So "the warrant was valid when this scan began" and "the warrant is valid now"
// are two different statements, and only the second licenses a record. The failure is
// the kind an agency cannot audit: the withdrawal is acknowledged, the ADMF records the
// interception as ended, and records keep arriving.
func TestAWithdrawalDuringAScanStopsTheRemainingRecords(t *testing.T) {
	task := types.InterceptTask{
		XID:      testXIDPrimary,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}

	sub, st, snd := scanFixture(t, task, 5)
	snd.onFirst = func() { st.Deactivate(task.XID) }

	sub.reportStartOfInterception(task, nil)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && snd.count() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // let any further records land

	if n := snd.count(); n == 0 {
		t.Fatal("the scan delivered nothing at all; this asserts nothing about withdrawal")
	} else if n > 1 {
		t.Errorf("%d records were delivered for a warrant withdrawn after the first; "+
			"the withdrawal was acknowledged and product kept arriving", n)
	}
}

// TestAScanDeliversToTheDestinationsTheTaskNowNames is the same property for a
// modification rather than a withdrawal: a scan holding a captured task delivers the
// rest of its records to endpoints the ADMF has already replaced, which for an agency
// that has retired one is product going somewhere it should not.
func TestAScanDeliversToTheDestinationsTheTaskNowNames(t *testing.T) {
	const (
		before = testDestinationAddr
		after  = "10.0.60.123:42069"
	)

	task := types.InterceptTask{
		XID:      testXIDPrimary,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
		Deliveries: []types.DeliveryEndpoint{
			{Type: types.DeliveryX2, Address: before},
		},
	}

	sub, st, snd := scanFixture(t, task, 5)
	snd.onFirst = func() {
		moved := task
		moved.Deliveries = []types.DeliveryEndpoint{{Type: types.DeliveryX2, Address: after}}
		st.Activate(moved)
	}

	sub.reportStartOfInterception(task, nil)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && snd.count() < 2 {
		time.Sleep(time.Millisecond)
	}

	addrs := snd.destinations()
	if len(addrs) < 2 {
		t.Fatalf("the scan delivered %d records; it needs at least two to say anything "+
			"about what happened after the modification", len(addrs))
	}
	for i, addr := range addrs[1:] {
		if addr != after {
			t.Errorf("record %d went to %s after the task's destinations were replaced with %s",
				i+2, addr, after)
		}
	}
}

// TestAModificationThatAddsIRIBeginsIt: a modification that adds a product passes the
// early return, and its control.
//
// modifyInterception decides "nothing about this interception has moved" by comparing
// the targets and each product. Comparing the target identifiers and the CC flag alone,
// adding IRI to a task that already has CC changes neither, so it would return before
// reportStartOfInterception and the target's already-established sessions would produce
// no start-of-interception record at all — interception of a second product beginning,
// at a moment the ADMF chose, with the only record that would say so skipped.
//
// The control matters as much as the case: changing the targets takes the other branch,
// so a test that only exercised that would pass against the narrower comparison and
// report the feature as covered.
func TestAModificationThatAddsIRIBeginsIt(t *testing.T) {
	targets := []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}}

	for _, tc := range []struct {
		name       string
		prev, next types.InterceptTask
	}{
		{
			name: "a product added, targets unchanged",
			prev: types.InterceptTask{
				XID: testXIDPrimary, Targets: targets,
				Products: []types.ProductType{types.ProductCC}, State: types.TaskActive,
			},
			next: types.InterceptTask{
				XID: testXIDPrimary, Targets: targets,
				Products: []types.ProductType{types.ProductCC, types.ProductIRI}, State: types.TaskActive,
			},
		},
		{
			// The control: this branch always emitted, which is why the gap read as
			// coverage from the outside.
			name: "targets changed",
			prev: types.InterceptTask{
				XID:      testXIDPrimary,
				Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262010000000000"}},
				Products: []types.ProductType{types.ProductCC, types.ProductIRI}, State: types.TaskActive,
			},
			next: types.InterceptTask{
				XID: testXIDPrimary, Targets: targets,
				Products: []types.ProductType{types.ProductCC, types.ProductIRI}, State: types.TaskActive,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sub, _, snd := scanFixture(t, tc.next, 1)

			sub.modifyInterception(tc.prev, tc.next)

			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) && snd.count() == 0 {
				time.Sleep(time.Millisecond)
			}
			if snd.count() == 0 {
				t.Error("no start-of-interception record for the target's live session: " +
					"interception of this product began and nothing said so")
			}
		})
	}
}

// TestAWithdrawalStopsDuplicationEvenThoughTheTaskIsGone: the per-session revalidation
// must not apply to a deactivation scan.
//
// A deactivation scan exists to take duplication down, and it runs *because* the task
// was removed from the store — removal is what triggers the callback. Applying the
// "product is delivered only under authority the element currently holds" check to it
// therefore finds the task gone and returns before clearing anything: the datapath keeps
// duplicating for a warrant that no longer exists, which is interception outliving its
// authority — the failure the rule is about, reached by applying the rule to the path
// that enforces it.
//
// **Driven through reportDeactivation, not through scanSessions.** A test that called the
// scan directly and passed the flag itself would stay green with the production call site
// passing the wrong value: it would assert that a function does what its argument says,
// one layer below the decision that matters. Every other scan test exercises activation
// and modification, where the task *is* in the store, so only this one reaches the case.
func TestAWithdrawalStopsDuplicationEvenThoughTheTaskIsGone(t *testing.T) {
	task := types.InterceptTask{
		XID:      testXIDPrimary,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}

	sub, st, _ := scanFixture(t, task, 1)

	// The session is being duplicated, as a tasked one is. Each FAR is kept beside
	// the session that owns it, because sc.SMLock is what serialises this test's reads
	// against the scan's writes — scanSessions takes it per session, so a bare *FAR
	// list would leave the assertion below with no lock to take. Reading the field
	// unlocked is what reddened `go test ./lawfulintercept/... -race`.
	type duplicatedFAR struct {
		sc  *smfctx.SMContext
		far *smfctx.FAR
	}
	var duplicating []duplicatedFAR
	smfctx.RangeSMContexts(func(sc *smfctx.SMContext) bool {
		sc.SMLock.Lock()
		forEachForwardingFAR(sc, func(far *smfctx.FAR) {
			setDuplication(far, true)
			duplicating = append(duplicating, duplicatedFAR{sc: sc, far: far})
		})
		sc.SMLock.Unlock()

		return true
	})
	if len(duplicating) == 0 {
		t.Fatal("no forwarding FAR to duplicate on; this test would assert nothing")
	}

	// Exactly the state the callback runs in: the store no longer holds the task,
	// because its removal is what caused this.
	if !st.Deactivate(task.XID) {
		t.Fatal("Deactivate failed")
	}

	sub.reportDeactivation(task)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stillOn := 0
		for _, d := range duplicating {
			d.sc.SMLock.Lock()
			if d.far.ApplyAction.Dupl {
				stillOn++
			}
			d.sc.SMLock.Unlock()
		}
		if stillOn == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Error("duplication is still set on a withdrawn warrant's session: the datapath goes on " +
		"copying a subject's traffic under authority that has been taken away, and the only " +
		"thing that would have stopped it returned early because the task was already gone")
}
