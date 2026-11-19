// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
)

// namedUPF and retaskUPF are triggering endpoints configured by name, as the chart and the
// blueprint configure them; the tests below decide whether the name has resolved.
const (
	namedUPF  = "upf"
	retaskUPF = "upf-retask"
)

// gateSubsystem is a running subsystem whose triggering endpoints are the given configured node
// identities, with every name lookup failing until a test says otherwise.
func gateSubsystem(t *testing.T, nodes ...string) *subsystem {
	t.Helper()

	poi := newFakePOI(t)
	cfg := Config{NEID: testNEID, MDF3: testMDF3Addr}
	for i, node := range nodes {
		cfg.UPFTriggers = append(cfg.UPFTriggers, UPFTrigger{
			NodeID: node, X1URL: poi.srv.URL, NEID: testUPFNEID1 + string(rune('a'+i)),
		})
	}
	s := &subsystem{neID: testNEID, triggers: mustRegistry(cfg), store: store.New()}
	waitForScans(t, s)
	resolvingTo(s.triggers, map[string]string{})

	active.Store(s)
	t.Cleanup(func() { active.Store(nil) })

	return s
}

// claim records an installed trigger at the endpoint configured as key, as a session
// establishment would have.
func claim(s *subsystem, key string) {
	s.triggers.mu.Lock()
	defer s.triggers.mu.Unlock()

	s.triggers.installed[triggerKey(types.XID(testXIDPrimary), "session-ref-1", key)] = installedTrigger{
		xid: types.XID(x1.NewUUID()), seid: 0x2632898145f4d191, correlation: 7,
	}
}

func claimsAt(s *subsystem, key string) int {
	s.triggers.mu.Lock()
	defer s.triggers.mu.Unlock()

	n := 0
	for k := range s.triggers.installed {
		if _, _, node, ok := parseTriggerKey(k); ok && node == key {
			n++
		}
	}

	return n
}

// hooks stands in for the SMF's session restoration and the release that replaces it. A restoration
// records how many claims were still standing at the endpoint keyed claimKey when it was started,
// which is the whole of what the ordering is about.
type hooks struct {
	s        *subsystem
	claimKey string

	// cannotRelease makes release report that it could not identify the node's sessions.
	cannotRelease bool

	mu         sync.Mutex
	restored   []time.Time
	claims     []int
	released   []time.Time
	releasedAt []string
	abandoned  []time.Time
	abandonAt  []string
	done       chan struct{}
}

func newHooks(s *subsystem, claimKey string) *hooks {
	return &hooks{s: s, claimKey: claimKey, done: make(chan struct{}, 16)}
}

func (h *hooks) restore(_ smfctx.NodeID, recovery time.Time) {
	n := claimsAt(h.s, h.claimKey)
	h.mu.Lock()
	h.restored = append(h.restored, recovery)
	h.claims = append(h.claims, n)
	h.mu.Unlock()
	h.done <- struct{}{}
}

func (h *hooks) release(_ smfctx.NodeID, nodeIP string, recovery time.Time) bool {
	h.mu.Lock()
	h.released = append(h.released, recovery)
	h.releasedAt = append(h.releasedAt, nodeIP)
	h.mu.Unlock()
	h.done <- struct{}{}

	return !h.cannotRelease
}

func (h *hooks) abandon(nodeIP string, recovery time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.abandoned = append(h.abandoned, recovery)
	h.abandonAt = append(h.abandonAt, nodeIP)
}

func (h *hooks) gate() func(smfctx.NodeID, time.Time) {
	return GateRestoration(RestartHooks{Restore: h.restore, Abandon: h.abandon, Release: h.release})
}

func (h *hooks) await(t *testing.T, what string) {
	t.Helper()

	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never happened", what)
	}
}

func (h *hooks) quiet(t *testing.T, what string) {
	t.Helper()

	select {
	case <-h.done:
		t.Fatalf("%s happened", what)
	case <-time.After(200 * time.Millisecond):
	}
}

func (h *hooks) snapshot() (restored []time.Time, claims []int, released []time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]time.Time(nil), h.restored...), append([]int(nil), h.claims...), append([]time.Time(nil), h.released...)
}

// refreshRound runs one round of the registry's name refresh once a withheld restoration is
// waiting for it. A round that ran before the retry was waiting would not be one it counts, so
// the test waits for the waiter rather than racing it.
func refreshRound(t *testing.T, s *subsystem, table map[string]string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		s.triggers.mu.Lock()
		waiting := s.triggers.refreshed != nil
		s.triggers.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no withheld restoration is waiting for a refresh round")
		}
		time.Sleep(5 * time.Millisecond)
	}
	resolvingTo(s.triggers, table)
}

func recoveryAt(offset time.Duration) time.Time {
	return time.Now().Add(offset).Truncate(time.Second)
}

// TestTheClaimsAreGoneBeforeTheRestorationStarts is the requirement itself. A restored session
// covered by a content task must not forward at a restarted point of interception while the
// claims describing that point still stand: `plan` would find the triple claimed and install
// nothing, and this element would report an interception the restarted node is not performing.
//
// The restoration is reached the only way it can be — through the hook — and it must find the
// claims already gone, whatever order the five restart-detection sites call things in.
func TestTheClaimsAreGoneBeforeTheRestorationStarts(t *testing.T) {
	s := gateSubsystem(t, trigNodeB)
	claim(s, trigNodeB)
	h := newHooks(s, trigNodeB)

	h.gate()(upfNode(trigNodeB), recoveryAt(0))
	h.await(t, "the restoration")

	restored, claims, released := h.snapshot()
	if len(restored) != 1 || claims[0] != 0 {
		t.Fatalf("the restoration started with %v claim(s) still standing at the restarted point of "+
			"interception (restorations %d): a restored session covered by a task would find its "+
			"triple claimed and be left untasked", claims, len(restored))
	}
	if len(released) != 0 {
		t.Errorf("a settled restart released its sessions")
	}
}

// TestARestartAtANodeThatIsNotAPOIRestoresAtOnce: the gate must cost nothing to a node this
// element does not task. Every configured endpoint is an address, so the node is ruled out.
func TestARestartAtANodeThatIsNotAPOIRestoresAtOnce(t *testing.T) {
	s := gateSubsystem(t, trigNodeB)
	claim(s, trigNodeB)
	h := newHooks(s, trigNodeB)

	h.gate()(upfNode(trigNodeElsewhere), recoveryAt(0))
	h.await(t, "the restoration of a node that is not a point of interception")

	if n := claimsAt(s, trigNodeB); n != 1 {
		t.Errorf("a restart at another node discarded the claims at %s (%d left)", trigNodeB, n)
	}
}

// TestWithInterceptionNotRunningTheRestorationPassesThrough: an element whose interception is
// not running restores exactly as it would without the gate.
func TestWithInterceptionNotRunningTheRestorationPassesThrough(t *testing.T) {
	active.Store(nil)
	h := newHooks(nil, "")
	h.s = &subsystem{} // claimsAt is not consulted for a nil registry; keep it non-nil for the hook
	h.s.triggers = &triggerRegistry{installed: map[string]installedTrigger{}}

	h.gate()(upfNode(trigNodeA), recoveryAt(0))
	h.await(t, "the restoration with interception not running")
}

// TestAnUndecidableRestartIsWithheldUntilItCanBeSettled is the case the statement order could
// not express. The endpoint is configured by name and the name has not resolved, so the
// restarted node — known by its address — can be neither matched to it nor ruled out. Discarding
// nothing and restoring, which is what happened, lets the restored session forward with the
// stale claims standing. It is held back instead, and goes ahead once the name resolves.
func TestAnUndecidableRestartIsWithheldUntilItCanBeSettled(t *testing.T) {
	s := gateSubsystem(t, namedUPF)
	admf := newADMFStub(t)
	s.reporter = x1.NewReporter(admf.srv.URL, testADMFID, testNEID, admf.clientTLS())
	claim(s, namedUPF)
	h := newHooks(s, namedUPF)

	recovery := recoveryAt(0)
	h.gate()(upfNode(trigNodeA), recovery)
	h.quiet(t, "the restoration of a node that could not be matched or ruled out")

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(strings.Join(admf.received(), "\n"), "reconcileFailed") {
		if time.Now().After(deadline) {
			t.Fatalf("withholding a restoration was reported to nobody:\n%s", strings.Join(admf.received(), "\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}

	refreshRound(t, s, map[string]string{namedUPF: trigNodeA})
	h.await(t, "the restoration once the name resolved")

	restored, claims, released := h.snapshot()
	if len(restored) != 1 || claims[0] != 0 || !restored[0].Equal(recovery) {
		t.Fatalf("restorations %v with claims %v standing, want one for %v with none", restored, claims, recovery)
	}
	if len(released) != 0 {
		t.Errorf("a restart that was settled released its sessions as well")
	}
}

// TestAnUndecidableRestartThatStaysSoIsReleased: withholding is not a delay if nothing ends it.
// The restart has been recorded, so nothing will detect it again, and a session neither restored
// nor released carries nothing for as long as the UE keeps it. At the bound the sessions are
// released, so each UE re-establishes.
func TestAnUndecidableRestartThatStaysSoIsReleased(t *testing.T) {
	previous := maxUndecidableRounds
	maxUndecidableRounds = 2
	t.Cleanup(func() { maxUndecidableRounds = previous })

	s := gateSubsystem(t, namedUPF)
	claim(s, namedUPF)
	h := newHooks(s, namedUPF)

	recovery := recoveryAt(0)
	h.gate()(upfNode(trigNodeA), recovery)
	refreshRound(t, s, map[string]string{})
	h.quiet(t, "an outcome after one of two rounds")
	refreshRound(t, s, map[string]string{})
	h.await(t, "the release")

	restored, _, released := h.snapshot()
	if len(restored) != 0 {
		t.Errorf("a restart that was never settled was restored")
	}
	if len(released) != 1 || !released[0].Equal(recovery) {
		t.Errorf("releases %v, want one for %v", released, recovery)
	}
}

// TestAnotherNodeIsNotHeldBackByAnUndecidableOne: withholding is per node. A node matched by
// identity is settled whatever else is unresolved.
func TestAnotherNodeIsNotHeldBackByAnUndecidableOne(t *testing.T) {
	s := gateSubsystem(t, namedUPF, trigNodeB)
	claim(s, trigNodeB)
	h := newHooks(s, trigNodeB)

	h.gate()(upfNode(trigNodeA), recoveryAt(0)) // undecidable: namedUPF has not resolved
	h.gate()(upfNode(trigNodeB), recoveryAt(0))
	h.await(t, "the restoration of the node that could be settled")

	restored, claims, _ := h.snapshot()
	if len(restored) != 1 || claims[0] != 0 {
		t.Errorf("restorations %d with claims %v standing, want one with none", len(restored), claims)
	}
}

// TestTheSameRestartIsWithheldOnceAndANewerOneReplacesIt: a liveness response and the
// re-association that follows carry the same recovery state, and both reach the hook. One
// restart is withheld once. A newer restart describes the incarnation that is current, so the
// older one's retry must not act on its behalf.
func TestTheSameRestartIsWithheldOnceAndANewerOneReplacesIt(t *testing.T) {
	s := gateSubsystem(t, namedUPF)
	claim(s, namedUPF)
	h := newHooks(s, namedUPF)
	gate := h.gate()

	first, second := recoveryAt(-time.Minute), recoveryAt(0)
	gate(upfNode(trigNodeA), first)
	gate(upfNode(trigNodeA), first)
	s.triggers.withheldMu.Lock()
	held := len(s.triggers.withheld)
	s.triggers.withheldMu.Unlock()
	if held != 1 {
		t.Fatalf("one restart seen twice left %d withheld restorations, want 1", held)
	}

	gate(upfNode(trigNodeA), second)
	refreshRound(t, s, map[string]string{namedUPF: trigNodeA})
	h.await(t, "the restoration")
	h.quiet(t, "a second restoration")

	restored, _, released := h.snapshot()
	if len(restored) != 1 || !restored[0].Equal(second) || len(released) != 0 {
		t.Errorf("restored %v, released %v; want one restoration, for the newer restart %v", restored, released, second)
	}
}

// TestTheDiscardDoesNotWaitOnAnEndpointsX1Exchange: the gate runs with UpfLock held, and
// ensureDestinations holds an endpoint's lock across CreateDestination, an X1 round trip with a
// 10 s timeout. The discard must not wait on that lock, or one slow point of interception stalls
// every PFCP send.
func TestTheDiscardDoesNotWaitOnAnEndpointsX1Exchange(t *testing.T) {
	s := gateSubsystem(t, trigNodeB)
	claim(s, trigNodeB)
	h := newHooks(s, trigNodeB)

	endpoint := s.triggers.endpoints[trigNodeB]
	endpoint.mu.Lock() // as ensureDestinations does, mid-CreateDestination
	defer endpoint.mu.Unlock()

	go h.gate()(upfNode(trigNodeB), recoveryAt(0))
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the discard for a restarted node waited on an endpoint's in-flight X1 exchange")
	}
}

// TestARestartSettledWhileAnEarlierOneIsWithheldReplacesIt: the newer restart describes the
// incarnation that is current. Its restoration goes ahead, and the retry for the earlier one must
// neither restore over it nor, once the name resolves, discard the claims its restored sessions
// have installed since — that would leave them untasked at the point of interception.
func TestARestartSettledWhileAnEarlierOneIsWithheldReplacesIt(t *testing.T) {
	s := gateSubsystem(t, namedUPF)
	claim(s, namedUPF)
	h := newHooks(s, namedUPF)
	gate := h.gate()

	first, second := recoveryAt(-time.Minute), recoveryAt(0)
	gate(upfNode(trigNodeA), first) // withheld: namedUPF has not resolved

	// The name resolves through some other round the retry has not reached yet, and the node
	// restarts again; this time it is settled at once.
	s.triggers.mu.Lock()
	s.triggers.resolved[namedUPF] = trigNodeA
	s.triggers.mu.Unlock()
	gate(upfNode(trigNodeA), second)
	h.await(t, "the restoration for the newer restart")

	// That restoration's sessions are tasked again, and the earlier retry's round arrives.
	claim(s, namedUPF)
	resolvingTo(s.triggers, map[string]string{namedUPF: trigNodeA})
	h.quiet(t, "an action by the superseded retry")

	if n := claimsAt(s, namedUPF); n != 1 {
		t.Errorf("the claims installed after the newer restart were discarded by the older one's retry (%d left)", n)
	}
	restored, _, released := h.snapshot()
	if len(restored) != 1 || !restored[0].Equal(second) || len(released) != 0 {
		t.Errorf("restored %v, released %v; want one restoration, for %v", restored, released, second)
	}
}

// TestWithholdingStopsTheRestorationOfAnEarlierRestart: the SMF supersedes a restoration in
// progress only when the next one starts. A withheld restart starts none, so without this the run
// for the previous restart goes on re-installing sessions onto the restarted node with this
// restart's claims still standing.
func TestWithholdingStopsTheRestorationOfAnEarlierRestart(t *testing.T) {
	s := gateSubsystem(t, namedUPF)
	h := newHooks(s, namedUPF)

	// A node known by a name that resolved to trigNodeA when it was last seen, and resolves to
	// nothing now. The earlier restoration was recorded under that address.
	node := smfctx.NodeID{NodeIdType: 0xff, NodeIdValue: []byte("upf-gone-quiet")}
	s.triggers.noteAddress(node, trigNodeA)
	recovery := recoveryAt(0)
	h.gate()(node, recovery)

	h.mu.Lock()
	abandoned, at := append([]time.Time(nil), h.abandoned...), append([]string(nil), h.abandonAt...)
	h.mu.Unlock()
	if len(abandoned) != 1 || !abandoned[0].Equal(recovery) || at[0] != trigNodeA {
		t.Errorf("withholding asked for restorations other than %v's to be abandoned at %v, %v; want one, at %s",
			recovery, at, abandoned, trigNodeA)
	}
}

// TestTheGateRemembersTheAddressANodeWasSeenAt: the address a release or an abandon is keyed by
// is the one the gate saw the node at, since its name may not resolve by then.
func TestTheGateRemembersTheAddressANodeWasSeenAt(t *testing.T) {
	s := gateSubsystem(t, trigNodeB)
	h := newHooks(s, trigNodeB)

	h.gate()(upfNode(trigNodeB), recoveryAt(0))
	h.await(t, "the restoration")

	if got := s.triggers.lastAddress(upfNode(trigNodeB)); got != trigNodeB {
		t.Errorf("the gate remembered %q for the node, want %s", got, trigNodeB)
	}
}

// TestTheRetryCountsOnlyARoundThatStartsAfterTheWithhold: a refresh already running when the
// restoration is withheld may have looked the name up before the restart, so its answer is not
// one the retry can act on, and counting it would shorten the bound.
func TestTheRetryCountsOnlyARoundThatStartsAfterTheWithhold(t *testing.T) {
	s := gateSubsystem(t, namedUPF)
	claim(s, namedUPF)
	h := newHooks(s, namedUPF)

	// A round in flight: its lookup is under way and will answer with the address.
	looking, answer := make(chan struct{}), make(chan struct{})
	s.triggers.mu.Lock()
	s.triggers.lookup = func(context.Context, string) (string, error) {
		close(looking)
		<-answer
		return trigNodeA, nil
	}
	s.triggers.mu.Unlock()
	inFlight := make(chan struct{})
	go func() {
		defer close(inFlight)
		s.triggers.refreshResolved()
	}()
	<-looking

	h.gate()(upfNode(trigNodeA), recoveryAt(0))
	close(answer)
	<-inFlight
	h.quiet(t, "an outcome on the strength of a round that started before the withhold")

	refreshRound(t, s, map[string]string{namedUPF: trigNodeA})
	h.await(t, "the restoration after a round that started after the withhold")
}

// TestAReleaseUsesTheAddressTheNodeLastHad: a node's sessions are keyed by the address it had.
// When its name stops resolving that is still the address to release them by, and the one an
// earlier restoration was recorded under.
func TestAReleaseUsesTheAddressTheNodeLastHad(t *testing.T) {
	previous := maxUndecidableRounds
	maxUndecidableRounds = 1
	t.Cleanup(func() { maxUndecidableRounds = previous })

	s := gateSubsystem(t, namedUPF)
	h := newHooks(s, namedUPF)
	s.triggers.noteAddress(upfNode(trigNodeA), trigNodeA)

	h.gate()(upfNode(trigNodeA), recoveryAt(0))
	refreshRound(t, s, map[string]string{})
	h.await(t, "the release")

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.releasedAt) != 1 || h.releasedAt[0] != trigNodeA {
		t.Errorf("released at %v, want the node's last known address %s", h.releasedAt, trigNodeA)
	}
}

// TestARestartAlreadySettledIsNotWithheldWhenSeenAgain: a liveness response leaves the held
// recovery state alone, so the re-association that follows reports the same restart again. If a
// name that answered the first time does not answer now, that restart is still settled; withholding
// it would release sessions its restoration has just put back.
func TestARestartAlreadySettledIsNotWithheldWhenSeenAgain(t *testing.T) {
	s := gateSubsystem(t, namedUPF)
	resolvingTo(s.triggers, map[string]string{namedUPF: trigNodeA})
	h := newHooks(s, namedUPF)
	gate := h.gate()

	recovery := recoveryAt(0)
	gate(upfNode(trigNodeA), recovery)
	h.await(t, "the restoration")

	s.triggers.mu.Lock()
	delete(s.triggers.resolved, namedUPF)
	s.triggers.mu.Unlock()
	gate(upfNode(trigNodeA), recovery)
	h.await(t, "the restoration on the second observation")

	s.triggers.withheldMu.Lock()
	held := len(s.triggers.withheld)
	s.triggers.withheldMu.Unlock()
	if held != 0 {
		t.Errorf("a restart that was already settled was withheld when seen again")
	}
}

// TestANodeWhoseAddressIsUnknownCannotBeRuledOut is the other cause of an undecidable record:
// every configured name has resolved, but the restarted node's own address has not, so there is
// nothing to compare them with.
func TestANodeWhoseAddressIsUnknownCannotBeRuledOut(t *testing.T) {
	s := gateSubsystem(t, namedUPF)
	resolvingTo(s.triggers, map[string]string{namedUPF: trigNodeA})

	_, match := s.triggers.forgetRestartedPOI(upfSession{node: upfNode("10.0.9.10"), addr: "0.0.0.0"})
	if match != restartUndecidable {
		t.Errorf("a node with no known address was classified %d, want restartUndecidable", match)
	}
	if _, match := s.triggers.forgetRestartedPOI(upfSession{node: upfNode("10.0.9.10"), addr: "10.0.9.10"}); match != restartNotAtPOI {
		t.Errorf("the same node with its address known was classified %d, want restartNotAtPOI", match)
	}
}

// TestAReleaseThatFindsNothingIsNotReportedAsOne: sessions are found by the node's address, so a
// node whose address cannot be resolved has none that can be released. Telling the LIPF they
// were released would be a record reading healthy over sessions that carry nothing.
func TestAReleaseThatFindsNothingIsNotReportedAsOne(t *testing.T) {
	previous := maxUndecidableRounds
	maxUndecidableRounds = 1
	t.Cleanup(func() { maxUndecidableRounds = previous })

	s := gateSubsystem(t, namedUPF)
	h := newHooks(s, namedUPF)
	h.cannotRelease = true

	h.gate()(upfNode(trigNodeA), recoveryAt(0))
	// Attached after the withholding notice, which shares the outcome notice's issue type: the
	// reporter sends one report per type per 30 s, and this test is about the second.
	admf := newADMFStub(t)
	s.reporter = x1.NewReporter(admf.srv.URL, testADMFID, testNEID, admf.clientTLS())
	refreshRound(t, s, map[string]string{})
	h.await(t, "the release")

	deadline := time.Now().Add(5 * time.Second)
	for {
		got := strings.Join(admf.received(), "\n")
		if strings.Contains(got, "neither restored nor released") {
			if strings.Contains(got, "being released") {
				t.Errorf("a release that could not identify the sessions was also reported as one:\n%s", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("a release that could not identify the sessions was not reported as such:\n%s", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestARestoredSessionCoveredByATaskIsTaskedAgain is the existing re-tasking requirement reached
// through the gate: once the restart is settled and the session restored, its establishment
// installs the trigger again instead of finding the triple already claimed.
func TestARestoredSessionCoveredByATaskIsTaskedAgain(t *testing.T) {
	poi := newFakePOI(t)
	s := namedTriggerSubsystem(t, poi, retaskUPF, trigNodeA)
	active.Store(s)
	t.Cleanup(func() { active.Store(nil) })

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	awaitMessages(t, poi, "ActivateTaskRequest", 1)

	h := newHooks(s, retaskUPF)
	h.gate()(upfNode(trigNodeA), recoveryAt(0))
	h.await(t, "the restoration")

	// The restored session's establishment is answered through the ordinary path.
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	awaitMessages(t, poi, "ActivateTaskRequest", 2)
}

// TestARestoredSessionNoTaskCoversIsRestoredWithoutTasking: the gate costs a session no task covers
// nothing beyond the discard, and its restoration installs nothing at the point of interception.
func TestARestoredSessionNoTaskCoversIsRestoredWithoutTasking(t *testing.T) {
	poi := newFakePOI(t)
	s := namedTriggerSubsystem(t, poi, retaskUPF, trigNodeC)
	active.Store(s)
	t.Cleanup(func() { active.Store(nil) })

	h := newHooks(s, retaskUPF)
	h.gate()(upfNode(trigNodeC), recoveryAt(0))
	h.await(t, "the restoration of a node holding no tasking")

	upfs := []upfSession{{node: upfNode(trigNodeC), addr: trigNodeC, seid: 0x2632898145f4d192}}
	s.installFor("session-ref-untasked", nil, upfs, 8)
	time.Sleep(200 * time.Millisecond)
	if n := poi.countMessages("ActivateTaskRequest"); n != 0 {
		t.Errorf("restoring a session no task covers sent %d ActivateTask(s)", n)
	}
}
