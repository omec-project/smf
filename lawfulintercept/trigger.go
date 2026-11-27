// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
)

// The SMF is the CC Triggering Function. Marking a session's FARs for duplication
// tells the UPF *to* copy packets; it does not tell it whose warrant the copies
// belong to, and a mediation function attributes product by XID alone. TS 33.128
// clause 6.2.3.3 closes that gap with LI_T3: the CC-TF tasks the CC-POI in the UPF
// over ETSI TS 103 221-1, acting in the "ADMF" role, and supplies the warrant XID
// (as ProductID), the correlation identifier it uses on that session's own xIRI,
// the packet detection criteria, and the X3 destination.
//
// Duplication and tasking therefore travel over different interfaces
// and are applied at slightly different moments — see triggerCC on the window
// between them.

// UPFTrigger names one UPF's LI_T3 triggering endpoint. The trigger must reach the
// UPF *serving the session*, and a session may be served by several, so these are
// configured per UPF and resolved by the N4 node address.
type UPFTrigger struct {
	// NodeID identifies the UPF's N4 node. It may be given exactly as the slice
	// topology names it, in which case it matches by identity and no name
	// resolution happens at all; or as any name or address that resolves to the
	// same node, which is matched by resolving both at the moment of use. A DNS
	// name is preferred over a deploy-time ClusterIP. See matchEndpoint.
	NodeID string
	// X1URL is that UPF's LI_T3 endpoint, e.g. https://upf-1:8443/X1/NE.
	X1URL string
	// NEID is the identifier the UPF answers to on X1, which its certificate is
	// bound to. It cannot be derived from the URL, which is why these are listed
	// explicitly rather than built from the N4 address and a port.
	NEID string
}

// upfEndpoint is the CC-TF's client for one UPF, plus the delivery destinations it
// has provisioned there.
type upfEndpoint struct {
	req *x1.Requester
	// node is the configured NodeID, parsed. Held so a session's serving UPF can be
	// matched by identity before anything is resolved (matchEndpoint).
	node smfctx.NodeID

	mu sync.Mutex
	// dids maps an X3 endpoint address to the destination identifier this CC-TF
	// allocated for it and provisioned at this POI. An entry exists only once
	// CreateDestination has succeeded, since a trigger referencing an unprovisioned
	// DID resolves to no destination at the POI (TS 33.128 table 6.2.3-6:
	// destinations are configured "prior to first use").
	//
	// One per address rather than one per UPF, which is what makes a task's own
	// destinations reachable: a warrant names where its content goes, and an element
	// that provisioned a single endpoint could only ever deliver every warrant's
	// content to that one. One per *address* rather than one per task, too — two
	// warrants naming one endpoint share its DID, because the POI deduplicates
	// delivery by address and reports faults by identifier, and a second identifier
	// for one endpoint would report one failure twice.
	dids map[string]string
	// reconciled records that this POI has once told us what it holds. Until it
	// has, this triggering function cannot name that tasking and therefore could
	// never withdraw it — so it owes the POI no liveness signal, and the POI's own
	// fail-safe is left free to act. See keepaliveDue.
	//
	// Atomic rather than under mu, because mu is held across X1 round trips
	// (ensureDestinations holds it over CreateDestination) and ForgetPOI clears this while
	// holding the registry lock, under a caller holding UpfLock. Through mu, a restart's
	// discard could wait on one POI's X1 timeout with every PFCP send blocked behind it.
	reconciled atomic.Bool
	// forgotten counts the ForgetPOI calls that discarded this element's account of the POI, so
	// a reconciliation can tell whether one landed while it was asking. Guarded by the
	// registry's mu, which ForgetPOI holds.
	forgotten uint64
	// reconciling guards against starting a second reconciliation for this endpoint while
	// one is already retrying. See beginReconcile.
	reconciling bool
}

// markReconciled records that this POI has given an authoritative account of its
// tasking.
//
// It does not stay true for the life of the process. A restart of *this* process is not the
// only thing that invalidates the account: ForgetPOI discards this element's claims for a POI
// on a liveness timeout too, and after that this process can no longer name what that POI
// holds. See forgetReconciled.
func (e *upfEndpoint) markReconciled() {
	e.reconciled.Store(true)
}

// forgetReconciled records that this element's account of what a POI holds is no longer good.
//
// **It must be paired with reconciling again, and that is not optional.** keepaliveDue answers
// false for an unreconciled endpoint, so this alone stops the liveness signal — which is right
// while the element holds nothing it can name there, and wrong the moment a new session installs
// a trigger at that POI. The element would then hold live tasking it never signals for, and the
// POI's own fail-safe would purge it along with the orphans. Re-reconciliation is what closes
// that window; the silence is only safe because it is temporary.
func (e *upfEndpoint) forgetReconciled() {
	e.reconciled.Store(false)
}

// beginReconcile claims the right to reconcile this endpoint, so that a reconciliation asked for
// on every keepalive round starts at most one goroutine per endpoint. reconcileEndpoint retries
// until it has an answer, which can be minutes; without this, a POI that is down would accumulate
// one retrying goroutine per round for as long as it stayed down.
func (e *upfEndpoint) beginReconcile() bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.reconciling {
		return false
	}

	e.reconciling = true

	return true
}

func (e *upfEndpoint) endReconcile() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reconciling = false
}

func (e *upfEndpoint) isReconciled() bool {
	return e.reconciled.Load()
}

// triggerRegistry holds the CC-TF's per-UPF endpoints and the trigger tasks it has
// installed.
type triggerRegistry struct {
	mdf3 string
	// endpoints is keyed by the NodeID *as configured*, never by an address derived
	// from it: the configured string is stable for the life of the process, so a
	// trigger installed at a UPF is still found under the same key when it is
	// withdrawn, even if that UPF's address changed in between. Written once during
	// construction and read-only afterwards, so it needs no lock.
	endpoints map[string]*upfEndpoint
	// resolved maps a configured node's key to the address it currently resolves to,
	// refreshed on this registry's own goroutine so that matching performs no I/O.
	// An entry is absent only for a name that has never resolved. Guarded by mu.
	resolved map[string]string
	// order is endpoints' keys, sorted, so matching iterates deterministically. Two
	// configured nodes can resolve to one address — transiently, while a Service is
	// being recreated, or permanently in a mistaken configuration — and choosing
	// between them by Go's map order would send a session's triggers to a different
	// UPF from one establishment to the next. The CC-POI avoids the same
	// nondeterminism in warrant selection; it is worse here, because the trigger
	// carries the X3 destination.
	order []string

	// reportUnattributable tells the LIPF that a POI's answer could not be bound to
	// the request that produced it. Injected rather than reached through the
	// subsystem because the keepalive goroutine starts inside the constructor,
	// before the subsystem holds the registry — a field assigned afterwards would be
	// written while that goroutine was already reading it.
	reportUnattributable func(error)
	// reportCadenceMissed tells the LIPF that a keepalive round overran the interval it
	// is supposed to keep, so a point of interception may be about to purge live tasking
	// this element is still answering for.
	//
	// It exists because that condition is invisible from the other side: a POI cannot
	// tell a triggering function that has gone away from one that is merely late, and
	// will report the first. nil when no ADMF is configured.
	reportCadenceMissed func(time.Duration)
	// reportTaskHealth carries a POI's own account of the tasks it holds back to the
	// subsystem, once per keepalive round.
	//
	// **A condition that can only be observed once is not a condition this element can
	// report.** The POI's account is the only way a triggering function learns that a trigger
	// it installed has stopped running — a failed provisioning, an unresolved fault, a
	// datapath that refused the duplication rule. Read only once per POI per process, during
	// start-up reconciliation, it would be read *before this process has installed anything*:
	// every trigger it goes on to install would be outside that window for the life of the
	// process, and the one condition `triggerFaulty` exists for would be the one condition it
	// could not see.
	//
	// Asked on the keepalive round because that round already contacts every endpoint this
	// element owes a signal to, and owes one exactly when it holds tasking there — which is
	// exactly when a task's health is worth asking about.
	reportTaskHealth func(nodeID string, reported []x1.TaskResponseDetails, asked uint64)
	// reconcile re-establishes what one POI holds. Held as a callback for the same reason
	// reportTaskHealth is: the registry keeps the endpoints and the cadence, the subsystem
	// owns what reconciliation means.
	reconcile func(nodeID string, e *upfEndpoint)
	// unhealthy is what a POI last said about a trigger this element installed, keyed by the
	// trigger's own XID: one warrant has a trigger per session and serving UPF, so a warrant-keyed
	// record would let a healthy sibling's report erase an unhealthy one. A warrant is faulty while
	// any trigger it currently holds is in here; taskFaults reads only installed triggers, and an
	// entry is dropped when its trigger is released or withdrawn.
	//
	// Refreshed on the keepalive cadence rather than by asking when the question arrives: an
	// X1 status request answered by dialling every POI would put a round trip per endpoint on
	// the request goroutine, which is the cost this element's own worker exists to keep off it.
	// The cadence is the same one the fail-safe windows are chosen against, so the answer is at
	// most one round old.
	unhealthy map[types.XID]triggerHealth

	// sleep and now are the withdrawal retry loop's clock, held here so a test can
	// drive a backoff measured in minutes without spending it. Nil means the real
	// one — see sleepFor and timeNow, which is what lets a registry be built as a
	// literal.
	sleep func(time.Duration)
	now   func() time.Time
	// lookup resolves a configured node's name, for the same reason: what a name
	// resolves to belongs to the deployment, and a test that had to arrange real DNS
	// to assert on matching would be testing the resolver. Nil means the real one.
	//
	// Guarded by mu, unlike sleep and now, because the goroutine that reads it is
	// this registry's own refresh loop rather than the caller's.
	lookup func(ctx context.Context, host string) (string, error)
	// refreshed is closed by the next refresh round to start after its creation, once that round
	// has stored its answers; nextRefresh creates it on demand. It is how a restart whose node
	// could not be matched waits for the condition that made it undecidable to change. Guarded
	// by mu.
	refreshed chan struct{}

	// withheldMu guards the four maps below, all keyed by withheldKey. See GateRestoration.
	// It is a leaf lock: nothing else is taken while it is held.
	withheldMu sync.Mutex
	// withheld holds the restorations held back because the node that restarted could not be
	// matched to, or ruled out as, a configured point of interception.
	withheld map[string]*withheldRestart
	// settled is the recovery state of each node's last restart whose record was settled.
	settled map[string]time.Time
	// restartLocks order everything done about one node's restarts: settling its record,
	// withholding, restoring and releasing it.
	restartLocks map[string]*sync.Mutex
	// addresses is each node's last known address. A restoration and a node's sessions are keyed
	// by the address the node had, which may not resolve when the node restarts.
	addresses map[string]string

	// stop, stopOnce and wg are the registry's lifecycle. Its background work — the
	// address refresh, the keepalive cadence, and the per-warrant propagations it
	// dispatches — is started by Start and ended by Stop, not by the constructor.
	//
	// Two reasons, one in production and one in test. In production, construction
	// happens before the X1 listener is bound and before this subsystem is committed
	// to running; an initialisation that fails after this point must leave nothing
	// behind — not a resolver and a keepalive loop running for the life of the
	// process, one set per attempt. In test, a registry built to exercise
	// planning or matching should start no background work at all, and a goroutine
	// outliving its test fails the next one.
	//
	// stop is nil on a registry built as a literal, which several tests do; a nil
	// channel never fires in a select, so those loops are simply not stoppable, and
	// Stop tolerates it rather than closing nil.
	stop     chan struct{}
	stopOnce sync.Once
	// wg counts everything this registry owns — the two loops and each per-warrant
	// propagation runner — so Stop can wait for all of it.
	wg sync.WaitGroup

	// serialMu guards the per-warrant dispatch queues. A separate lock from mu
	// because dispatch happens with the registry already planned and must not be
	// ordered against registry reads.
	serialMu sync.Mutex
	// stopped refuses new dispatch after Stop, which is also what makes wg.Add safe
	// against the wg.Wait inside Stop.
	stopped bool
	// queued and draining are one FIFO queue of outbound propagations per warrant,
	// and whether a runner is currently draining it.
	//
	// **Ordering is the correctness property here, not fairness.** Two ModifyTasks
	// for one warrant dispatched on bare goroutines complete in either order, and both
	// succeed — so a POI can end up labelling content with a delivery identifier the
	// ADMF has already superseded, with both exchanges acknowledged and nothing
	// anywhere recording that the element applied them backwards. Installs need no
	// ordering (plan skips a claimed triple, so two cannot overwrite each other) and
	// withdrawals own their own retry loop keyed by the pending entry; it is the
	// relabel that is last-writer-wins.
	queued   map[types.XID][]func()
	draining map[types.XID]bool

	mu sync.Mutex
	// installed maps a (warrant, session, UPF) triple to the trigger this CC-TF
	// installed for it. The trigger's XID is the CC-TF's own — the warrant's travels
	// in ProductID — and must stay stable from activation to deactivation, so it is
	// remembered rather than recomputed.
	installed map[string]installedTrigger
	// pending holds triggers this CC-TF has decided to withdraw and the POI has not
	// yet acknowledged. Between the two maps the registry answers "what might still
	// be installed", which is the question every other mechanism here actually asks:
	// withdrawn and *believed* withdrawn are not the same state, and treating them
	// as one is what left content interception running with nothing tracking it.
	//
	// Keyed by pendingKey — the trigger key *and* the XID — because the two maps
	// are not in step. A warrant deactivated and re-activated while its POI is
	// unreachable claims the same (warrant, session, UPF) key again, under a new
	// XID, while the old one is still being withdrawn; keying on the trigger key
	// alone would have the second withdrawal displace the first's entry and the
	// first's acknowledgement then clear the second's.
	pending map[string]*pendingWithdrawal
	// restartedAt is the recovery timestamp of the last restart recorded for each configured
	// point of interception, keyed by its configured NodeID. plan claims nothing for a session
	// that node acknowledged before it: see plan.
	restartedAt map[string]time.Time
	// discarded holds, by pendingKey, the claims ForgetPOI dropped at a POI whose account has
	// not been taken since: every one, since a key re-claimed and dropped again names a second
	// trigger. The POI may still hold them, so a withdrawal of their warrant or session
	// withdraws them too (see take). A reconciliation that takes the account drops them: what
	// the POI still holds of them is an orphan in that account.
	discarded map[string]discardedClaim
	// activating holds the XIDs claimed by plan whose ActivateTask has not been answered yet.
	// A POI can apply a withdrawal sent meanwhile before the activation, so its answer that the
	// task does not exist says nothing about whether the POI holds it afterwards: see deactivate.
	// The value is zero while the activation is in flight, and for one that went unanswered the
	// end of unansweredActivationWindow.
	activating map[types.XID]time.Time
	// seq orders activations against the accounts the keepalive round asks for. See noteTaskHealth.
	seq uint64
}

// installedTrigger is what this CC-TF put at a POI for one (warrant, session, UPF)
// triple.
//
// It carries the detection criterion and the correlation value as well as the XID,
// because a ModifyTask has to restate them: TS 33.128 table 6.2.3-6 makes both
// mandatory on an LI_T3 trigger, so a modification that changes only how the
// warrant's product is labelled would otherwise have to invent them or tear the
// trigger down and rebuild it — interrupting content the warrant still authorises in
// order to change a label. A registry whose subject is "what might still be
// installed" is the right place to know what it installed.
type installedTrigger struct {
	xid types.XID
	// warrant is the XID of the warrant this trigger serves, which is *not* xid: the
	// trigger's XID is this CC-TF's own, and the warrant's travels in ProductID.
	//
	// Held because it is the only thing that can turn a POI's answer into a report the LIPF
	// can act on. A POI reports a task under the XID this element gave it, and the LIPF never
	// issued that identifier — so a fault report naming it would name a warrant the LIPF
	// cannot look up, which is worse than naming none. The composite key carries the warrant
	// too, but recovering it by splitting a key on a separator is a decoding step that would
	// silently produce the wrong answer the day a key gains a component.
	warrant types.XID
	// seid is the PFCP session the trigger detects on, and correlation the value the
	// POI stamps on the content it produces. Both are the session's rather than the
	// warrant's, which is why they are held per trigger and not per task.
	seid        uint64
	correlation uint64
	// activatedSeq is the registry sequence number at which the POI accepted the trigger's
	// activation, zero until it has. See noteTaskHealth.
	activatedSeq uint64
}

// discardedClaim is one claim ForgetPOI dropped: its trigger key and the XID installed under it.
type discardedClaim struct {
	key string
	xid types.XID
}

// pendingWithdrawal is one trigger whose removal has been attempted and not
// acknowledged. It stays until the POI says the task is gone.
type pendingWithdrawal struct {
	xid    types.XID
	nodeID string
	// since is when the withdrawal was decided, not when it was last attempted:
	// what matters to an operator is how long authority has been withdrawn while
	// content may still be flowing.
	since time.Time
	// failureReported and stuckReported keep each condition to one report. A
	// withdrawal that retries for an hour is one fault, not seven hundred.
	failureReported bool
	stuckReported   bool
}

// withdrawal is one entry of the pending set, handed to the retry loop. Its key is
// the pending one, so an acknowledgement clears exactly what it acknowledged and
// nothing that has since been claimed under the same trigger key.
type withdrawal struct {
	key    string
	nodeID string
	xid    types.XID
}

// pendingKey names one trigger's withdrawal: the trigger key it was installed
// under, and the XID that was installed. Nothing parses it — it need only be
// unique, and the two together are.
func pendingKey(key string, xid types.XID) string { return key + "|" + string(xid) }

// liKeepaliveInterval is how often each triggered POI is told this triggering
// function is still here.
//
// It must be comfortably shorter than the POI's own fail-safe window, since that
// window is what protects against a triggering function that has died: too slow
// and healthy tasking lapses, too fast and it costs a needless request. The POI's
// timeout is its own configuration, so this is deliberately well inside any
// sensible value rather than derived from it.
const liKeepaliveInterval = 60 * time.Second

const (
	// withdrawalRetryInitial is how long the first retry of an unacknowledged
	// withdrawal waits. It doubles up to liKeepaliveInterval and then stays there:
	// a POI is either answering or it is not, and retrying faster than this
	// triggering function's own liveness signal buys nothing.
	withdrawalRetryInitial = 5 * time.Second
	// withdrawalStuckAfter is how long a withdrawal may go unacknowledged before it
	// stops being "the last attempt failed" and becomes "authority was removed some
	// time ago and content is probably still being intercepted". An operator cannot
	// act on a condition that looks the same a second and an hour after it arose.
	withdrawalStuckAfter = 5 * time.Minute
)

// newTriggerRegistry builds the CC-TF's endpoints from configuration. A UPF with
// no configured triggering endpoint cannot be tasked, so CC for a session it
// serves is reported as a fault rather than silently skipped.
func newTriggerRegistry(
	cfg Config,
	clientTLS *tls.Config,
	onUnattributable func(error),
	onCadenceMissed func(time.Duration),
) (*triggerRegistry, error) {
	reg := &triggerRegistry{
		mdf3:                 cfg.MDF3,
		stop:                 make(chan struct{}),
		queued:               make(map[types.XID][]func()),
		draining:             make(map[types.XID]bool),
		endpoints:            make(map[string]*upfEndpoint, len(cfg.UPFTriggers)),
		resolved:             make(map[string]string, len(cfg.UPFTriggers)),
		installed:            make(map[string]installedTrigger),
		pending:              make(map[string]*pendingWithdrawal),
		unhealthy:            make(map[types.XID]triggerHealth),
		reportUnattributable: onUnattributable,
		reportCadenceMissed:  onCadenceMissed,
	}
	// The element identifiers already claimed, so two endpoints cannot share one.
	claimedNEIDs := make(map[string]string, len(cfg.UPFTriggers))

	for _, t := range cfg.UPFTriggers {
		// Key by the NodeID exactly as configured, and resolve nothing here. Keying
		// by the address the NodeID resolves to at this moment would make a derived,
		// mutable value permanent: a UPF that later changed address would never be
		// found again, and a name that did not resolve at the instant the SMF started
		// would be keyed "0.0.0.0" for the life of the process. Either way every CC
		// warrant for that UPF would report "no triggering endpoint" until the SMF
		// was restarted. Matching happens per use, in matchEndpoint.
		if _, dup := reg.endpoints[t.NodeID]; dup {
			// Letting the second entry replace the first would present a two-UPF
			// configuration as a one-UPF registry, and the displaced UPF's content
			// would never be attributable.
			return nil, fmt.Errorf("upfTriggers names the same node twice: %q", t.NodeID)
		}
		// **Two points of interception may not share an element identifier**, and this
		// is the only place the collision is visible: neither UPF can see it, because
		// each is numbering its own product correctly.
		//
		// Every UPF serving one session is deliberately given the *same* delivery
		// identifier and correlation value — that is what joins one warrant's content
		// to its signalling and to the other UPF's content. TS 103 221-2 clause 5.3.9
		// then counts sequence numbers within a context formed from those two plus the
		// network function and interception point identifiers, both of which follow
		// from ne_id. So ne_id is the only thing separating two UPFs' sequence
		// contexts, and two that share it number one context from zero independently.
		//
		// The mediation function receives a single sequence with duplicated numbers and
		// apparent gaps, for a warrant whose product is otherwise entirely correct — and
		// gaps are how loss is made visible on this interface, so the collision forges
		// the signal an agency uses to decide whether it has everything. Under ULCL,
		// where a branching point and a session anchor both serve one session, this is
		// the ordinary multi-UPF case rather than an exotic one.
		if first, dup := claimedNEIDs[t.NEID]; dup {
			return nil, fmt.Errorf(
				"upfTriggers gives %q and %q the same neId %q: two points of interception sharing an "+
					"element identifier number one delivery context independently, which reaches the "+
					"mediation function as duplicated sequence numbers and apparent loss",
				first, t.NodeID, t.NEID)
		}
		claimedNEIDs[t.NEID] = t.NodeID
		reg.endpoints[t.NodeID] = &upfEndpoint{
			node: *smfctx.NewNodeID(t.NodeID),
			req:  x1.NewRequester(t.X1URL, cfg.NEID, t.NEID, clientTLS),
			// Destinations are allocated per X3 endpoint on first use, not one per
			// UPF up front: which endpoints this POI needs is a property of the
			// warrants that arrive, not of the configuration.
			dids: make(map[string]string),
		}
		reg.order = append(reg.order, t.NodeID)
	}
	slices.Sort(reg.order)

	// The address-typed nodes are seeded here, synchronously, because resolving them
	// is not I/O — the value is the answer — and doing it now means the common
	// configuration matches from the first session onward with nothing to wait for.
	//
	// The name-typed ones are left to the loop, which resolves before its first tick.
	// Blocking this constructor on DNS would put a name lookup on the element's
	// startup path, which is the kind of thing this design keeps off it; the cost
	// is that a deployment whose LI block names its UPFs differently from the slice
	// topology has a window of one lookup in which such a session reports a warrant
	// with no triggering endpoint and the next one succeeds. Where the two agree —
	// which is the documented arrangement — matching is by identity and no name is
	// resolved at all.
	reg.seedResolvedLiterals()

	// The loops are NOT started here. See the lifecycle fields: a registry is built
	// before the caller knows whether the subsystem will run at all, and an
	// initialisation that fails after this point has to leave nothing behind. Start
	// is called once the subsystem is committed.

	return reg, nil
}

// Start begins the registry's background work: the address index refresh and the
// keepalive cadence to every triggered point of interception.
//
// Called once, by the initialisation that has decided this subsystem is running.
// Everything it starts is counted in wg, so Stop can prove it has ended.
func (r *triggerRegistry) Start() {
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		r.resolveLoop()
	}()
	go func() {
		defer r.wg.Done()
		r.keepalive()
	}()
}

// Stop ends the registry's background work and waits for it.
//
// It refuses further per-warrant dispatch first — which is also what makes the
// wg.Add in dispatchForWarrant safe against the wg.Wait here — then releases the
// loops and waits for everything in flight. A propagation already running is
// bounded by the X1 requester's own timeout, so this returns.
//
// Idempotent, and safe on a registry whose loops were never started.
func (r *triggerRegistry) Stop() {
	r.serialMu.Lock()
	r.stopped = true
	r.serialMu.Unlock()

	if r.stop != nil {
		r.stopOnce.Do(func() { close(r.stop) })
	}
	r.wg.Wait()
}

// dispatchForWarrant runs job off the caller's goroutine — the caller is the X1
// request goroutine, and these are synchronous HTTPS round trips — and in dispatch
// order against every other job dispatched for the same warrant.
//
// One runner per warrant with work outstanding, so warrants do not serialise
// against each other. See the queued/draining fields for why the ordering is a
// correctness property.
func (r *triggerRegistry) dispatchForWarrant(warrant types.XID, job func()) {
	r.serialMu.Lock()
	if r.stopped {
		// The subsystem is going away. A propagation that cannot be ordered against
		// the ones already queued is worse than one not sent: the POI keeps the label
		// it has, which is a task-level fault the LIPF is told about by the caller.
		r.serialMu.Unlock()

		return
	}
	if r.queued == nil {
		r.queued = make(map[types.XID][]func())
	}
	if r.draining == nil {
		r.draining = make(map[types.XID]bool)
	}
	r.queued[warrant] = append(r.queued[warrant], job)
	if r.draining[warrant] {
		r.serialMu.Unlock()

		return
	}
	r.draining[warrant] = true
	r.wg.Add(1)
	r.serialMu.Unlock()

	go func() {
		defer r.wg.Done()
		r.drainWarrant(warrant)
	}()
}

// drainWarrant runs one warrant's queued propagations in order until none is left.
// A job dispatched while this is running joins the queue rather than starting a
// second runner, which is what keeps the order.
func (r *triggerRegistry) drainWarrant(warrant types.XID) {
	for {
		r.serialMu.Lock()
		queue := r.queued[warrant]
		if len(queue) == 0 {
			delete(r.queued, warrant)
			delete(r.draining, warrant)
			r.serialMu.Unlock()

			return
		}
		job := queue[0]
		r.queued[warrant] = queue[1:]
		r.serialMu.Unlock()

		job()
	}
}

// matchEndpoint finds the triggering endpoint for the UPF serving a session.
//
// Identity is tried first and costs nothing: when `li.upfTriggers` names the node
// the way the slice topology names it, the two NodeIDs are equal and no name is
// ever resolved. That is the SMF's own conclusion for the sibling comparison in
// nodeInLinks (#613) — membership is identity, not reachability.
//
// Resolution remains as the fallback because these two values come from
// *independent* configuration — the LI block and the slice topology — and need not
// agree: a DNS name in the LI block has to match a session whose N4 node is an IP,
// which is the case that made resolution necessary in the first place. So identity
// alone cannot replace it, and address matching alone was what broke.
//
// What matters is *when* this resolves, not whether: at the point of use
// rather than once at construction. That is what makes a recreated Service, or a
// name that was not yet resolvable at startup, recover on its own instead of
// requiring an SMF restart. It is also cheap here — the trigger path runs a few
// times per session, an IP literal short-circuits without touching DNS, and a name
// reads the SMF's DNS cache that a 60-second refresh keeps current.
//
// An unresolvable node NEVER matches. Failed resolution yields net.IPv4zero, so
// comparing it would make every unresolvable name equal to every other — precisely
// the defect #613 fixed for gNB names, which here would task one UPF's CC-POI with
// another UPF's warrant. Returning "no match" instead means the warrant is reported
// to the LIPF as having no triggering endpoint, which is true and actionable.
// It performs no I/O. Both sides of the comparison are already resolved by the time
// it runs: the session's address was resolved by sessionUPFs to key the PFCP
// context, and the configured names are resolved on this registry's own goroutine
// (see refreshResolved). That is what took a name lookup off the session lock. The
// caller holds r.mu.
func (r *triggerRegistry) matchEndpoint(session upfSession) (string, *upfEndpoint, bool) {
	for _, key := range r.order {
		if ep := r.endpoints[key]; ep.node.Equal(session.node) {
			return key, ep, true
		}
	}

	// An address this element could not establish never matches, which is the same
	// rule as before by a different route: comparing an unresolved node would make
	// every unresolvable name equal to every other, and task one UPF's CC-POI with
	// another UPF's warrant.
	if session.addr == "" || session.addr == net.IPv4zero.String() {
		return "", nil, false
	}
	for _, key := range r.order {
		if r.resolved[key] == session.addr {
			return key, r.endpoints[key], true
		}
	}

	return "", nil, false
}

// endpointRefreshInterval is how often the configured triggering nodes' names are
// re-resolved. It matches the cadence the SMF's own DNS cache refreshes at, since
// what both are tracking is a Service address that changes when a Service is
// recreated.
const endpointRefreshInterval = 60 * time.Second

// endpointResolveTimeout bounds one name lookup. The value matters less than its
// existence: the lookup this replaces used context.Background() and could block for
// as long as the resolver chose, on a subscriber's signalling path.
const endpointResolveTimeout = 2 * time.Second

// lookupHost resolves a name to one address, or reports that it could not.
//
// It is this package's own rather than the SMF's shared helper, for two reasons that
// happen to point the same way. The shared one logs — "host [X] not found in smf dns
// cache", then "host [X] dns resolved" — which for a name that appears only in LI
// configuration puts an LI-only hostname into the general operator log, and
// undetectability forbids that. And it reads a process-wide map with no
// synchronisation, which is a defect of its own (tracked separately); resolving here
// does not fix that, and does stop LI adding callers to it.
func lookupHost(ctx context.Context, host string) (string, error) {
	var res net.Resolver

	addrs, err := res.LookupHost(ctx, host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("li: %q resolved to no address", host)
	}
	// Normalised through net.IP so the string compares equal to the one sessionUPFs
	// derives from the session's own NodeID, which is that type's String().
	ip := net.ParseIP(addrs[0])
	if ip == nil {
		return "", fmt.Errorf("li: %q resolved to %q, which is not an address", host, addrs[0])
	}

	return ip.String(), nil
}

// refreshResolved re-resolves every configured triggering node and stores the
// answers, so matchEndpoint can compare addresses without performing a lookup.
//
// The lookups happen outside r.mu — they are the slow part, and holding the registry
// lock across them would move the stall from the session lock to the registry's,
// which every other trigger operation waits on.
//
// A name that fails to resolve keeps its previous answer rather than losing it. A
// transient resolver failure is not evidence that a UPF has moved, and dropping the
// entry would stop content interception for every session that UPF serves until the
// resolver recovered. Where there was no previous answer there is nothing to keep,
// and the endpoint simply does not match — which is reported to the LIPF as a
// warrant with no triggering endpoint, and is true.
func (r *triggerRegistry) refreshResolved() {
	// The resolver is read under the lock and used outside it. Reading it under the
	// lock is what makes it safe for a test to substitute one while this loop is
	// already running; using it outside is the point of the whole function, since the
	// lookups are the slow part and holding the registry lock across them would move
	// the stall from the session lock to the registry's.
	//
	// A waiter registered before this round starts is released when it ends; one registered
	// while it runs waits for the next, because this round's lookups may predate its question.
	r.mu.Lock()
	lookup := r.lookup
	done := r.refreshed
	r.refreshed = nil
	r.mu.Unlock()

	if lookup == nil {
		lookup = lookupHost
	}

	fresh := make(map[string]string, len(r.order))

	for _, key := range r.order {
		node := r.endpoints[key].node
		if node.NodeIdType != smfctx.NodeIdTypeFqdn {
			// An address, not a name: the value *is* the answer. This branch of the
			// shared resolver neither logs nor performs I/O, so it is safe to use.
			fresh[key] = node.ResolveNodeIdToIp().String()

			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), endpointResolveTimeout)
		addr, err := lookup(ctx, string(node.NodeIdValue))
		cancel()

		if err == nil {
			fresh[key] = addr
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for key, addr := range fresh {
		r.resolved[key] = addr
	}
	if done != nil {
		close(done)
	}
}

// nextRefresh returns a channel that is closed when a refresh round that starts after this call
// has stored its answers.
func (r *triggerRegistry) nextRefresh() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.refreshed == nil {
		r.refreshed = make(chan struct{})
	}

	return r.refreshed
}

// resolveLoop keeps the address index current. Like the keepalive loop it runs for
// the life of the process, because an endpoint's address can change at any point in
// it — a recreated Service is the case this exists for.
func (r *triggerRegistry) resolveLoop() {
	// Before the first tick, not a minute after it: the constructor deliberately does
	// not block on DNS, so this is what closes the window it leaves.
	r.refreshResolved()

	ticker := time.NewTicker(endpointRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.refreshResolved()
		}
	}
}

// seedResolvedLiterals records the address of every configured node that *is* an
// address. No I/O and no logging: for these two node types the shared resolver
// returns the stored value unchanged.
func (r *triggerRegistry) seedResolvedLiterals() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, key := range r.order {
		if node := r.endpoints[key].node; node.NodeIdType != smfctx.NodeIdTypeFqdn {
			r.resolved[key] = node.ResolveNodeIdToIp().String()
		}
	}
}

// keepalive tells each triggered POI this triggering function is still present —
// which is what lets a POI safely purge tasking when it is not. Failures are
// ignored here: a POI that cannot be reached will lapse its own tasking, which is
// the outcome intended, and the trigger path reports the fault when it next tries
// to task it.
func (r *triggerRegistry) keepalive() {
	ticker := time.NewTicker(liKeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.keepaliveRound()
		}
	}
}

// keepaliveRound signals every POI that owes one. Separated from the ticker so the
// behaviour can be driven directly rather than waited for.
//
// **The endpoints are signalled concurrently, and that is a correctness property rather
// than a performance one.** Signalled in line, a round takes as long as the sum of its
// failures: each Keepalive is bounded only by the requester's 10s timeout, on a 60s
// ticker, so around fifteen unreachable UPFs push a round past the POI's own 150s
// fail-safe window. A *healthy* point of interception then goes unsignalled for longer
// than its window allows, purges the tasking it holds, and reports that its triggering
// function went silent — which is true of the interval and false of the cause. An
// operator is sent to investigate a healthy element while the warrant that mattered has
// already stopped producing.
//
// That is the exact fault minTriggerKeepalive exists to prevent, reached by a route the
// floor cannot see: the floor protects the window from the operator's side, and this
// protects the cadence from the sending side. The two are halves of one property, and
// this is the half the element controls. Fanned out, a round costs one peer timeout
// however many endpoints are configured or unreachable.
func (r *triggerRegistry) keepaliveRound() {
	r.mu.Lock()
	due := make(map[string]*upfEndpoint, len(r.endpoints))
	for nodeID, endpoint := range r.endpoints {
		due[nodeID] = endpoint
	}
	r.mu.Unlock()

	var wg sync.WaitGroup

	started := time.Now()

	for nodeID, endpoint := range due {
		// An endpoint whose account this element has lost — a restart, or a liveness timeout
		// that made ForgetPOI discard its claims — is reconciled again rather than left
		// silent. Until it answers, keepaliveDue keeps this element quiet toward it, which is
		// what lets the POI's own fail-safe reclaim tasking nobody here can name.
		if !endpoint.isReconciled() && r.reconcile != nil {
			go r.reconcile(nodeID, endpoint)

			continue
		}

		if !r.keepaliveDue(nodeID, endpoint) {
			continue
		}

		wg.Add(1)
		go func(nodeID string, endpoint *upfEndpoint) {
			defer wg.Done()

			// Best-effort: a missed keepalive is transient, and a POI that has really
			// gone away trips its own fail-safe; nothing here to act on per tick.
			//
			// A response that could not be *bound* to the request is a different fault
			// and is not best-effort. A keepalive answered by an endpoint naming another
			// element means this triggering function believes a POI is alive on the
			// strength of an answer from something else — the same silent condition the
			// tasking paths report, on the one exchange whose whole purpose is to say the
			// peer is still there. reportUnattributable filters for exactly that and
			// ignores every transient failure, so handing it the error keeps the
			// best-effort behaviour this loop was written for.
			if err := endpoint.req.Keepalive(); err != nil && r.reportUnattributable != nil {
				r.reportUnattributable(err)
			}

			// And what the POI says about the tasks it holds, on the same round and the same
			// goroutine. Best-effort in the same sense: a POI that cannot answer is either
			// transiently unreachable, which the keepalive above already accounts for, or gone,
			// which its own fail-safe handles. What must not happen is this element never
			// asking, which is the state it was in.
			if r.reportTaskHealth == nil {
				return
			}

			asked := r.askSeq()
			if reported, err := endpoint.req.ReportedTasks(); err == nil {
				r.reportTaskHealth(nodeID, reported, asked)
			}
		}(nodeID, endpoint)
	}

	wg.Wait()

	// And where the cadence still cannot be kept, say so rather than leaving it to be
	// inferred from a purge at the other end. From the POI's side an overrun is
	// indistinguishable from a triggering function that has gone away — it will purge
	// and report exactly that — so the element that can tell the difference is this one.
	if elapsed := time.Since(started); elapsed > liKeepaliveInterval && r.reportCadenceMissed != nil {
		r.reportCadenceMissed(elapsed)
	}
}

// keepaliveDue reports whether this triggering function owes a POI the signal that
// it is still here. It owes it for tasking it can name, and for nothing else.
//
// Keeping every *configured* endpoint alive disables the POI's fail-safe by
// construction: the fail-safe is the last mechanism able to reclaim tasking a
// triggering function has forgotten, and a POI holding a forgotten trigger was
// being told, once a minute, that the function responsible for it was alive and
// well. So an endpoint this process holds nothing at falls silent and the POI
// reclaims whatever it still holds; an endpoint that has not yet answered what it
// holds falls silent too, because after a restart this process cannot name that
// tasking and so could never withdraw it.
//
// Both directions fail toward interception stopping, which is the direction a
// fail-safe must fail in. What this cannot do is reclaim one orphan at an endpoint
// that also holds live tasking: the fail-safe is per-connection, so the live task's
// keepalives preserve the orphan with it. Durable withdrawal is the remedy for
// that; this only makes the backstop reachable at all.
func (r *triggerRegistry) keepaliveDue(nodeID string, e *upfEndpoint) bool {
	return e.isReconciled() && r.tasksAt(nodeID)
}

// tasksAt reports whether this triggering function believes the POI at nodeID
// holds anything it installed. Pending counts: a withdrawal in flight is tasking
// this function is still answerable for, and going silent under it would ask the
// POI's fail-safe to finish a job this process has not given up on.
func (r *triggerRegistry) tasksAt(nodeID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for key := range r.installed {
		if _, _, node, ok := parseTriggerKey(key); ok && node == nodeID {
			return true
		}
	}
	for _, p := range r.pending {
		if p.nodeID == nodeID {
			return true
		}
	}

	return false
}

// reconcileTriggers withdraws tasking a POI still holds from a previous life of
// this process.
//
// This is the case the keepalive fail-safe cannot cover. That fail-safe protects
// against a triggering function that is *gone*; one that has *restarted* is
// present, resumes keepalives within the minute, and so leaves behind triggers
// belonging to warrants the new process knows nothing about — and therefore can
// never withdraw, not even when the warrant is revoked.
//
// Withdrawing everything found is safe because of the authorisation model, not by
// assumption: a POI accepts tasking from exactly one triggering function
// (x1.WithADMF at the POI), so whatever it holds came from this one. **If a POI is
// ever allowed more than one triggering function, this needs provenance instead.**
//
// Started at startup, one goroutine per POI: it is network I/O, nothing else waits
// on it, and a POI that is slow or down must not hold up reconciliation of the
// others — theirs is what lets them be kept alive again.
func (s *subsystem) reconcileTriggers() {
	if s.triggers == nil {
		return
	}

	for _, nodeID := range s.triggers.order {
		go s.reconcileEndpoint(nodeID, s.triggers.endpoints[nodeID])
	}
}

// reconcileEndpoint establishes what one POI holds and withdraws what no live
// warrant corresponds to, retrying until it has an authoritative answer.
//
// One attempt is not reconciliation. A POI unreachable at startup and reachable a
// minute later — the ordinary shape of a whole-cluster restart — would, after one
// attempt, be abandoned with a fault report and never revisited, while this process
// resumed keepalives to it regardless: the POI would then be kept alive, for the
// life of the process, by a triggering function that could not name a single thing
// it held. Retrying is what makes that state temporary, and the keepalive gating
// (keepaliveDue) is what makes it safe while it lasts.
func (s *subsystem) reconcileEndpoint(nodeID string, endpoint *upfEndpoint) {
	// At most one per endpoint: this is called from start-up and from every keepalive round,
	// and it retries until it has an answer.
	if !endpoint.beginReconcile() {
		return
	}

	defer endpoint.endReconcile()

	var reported []x1.TaskResponseDetails
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			s.triggers.sleepFor(withdrawalBackoff(attempt - 1))
		}

		forgotten := s.triggers.forgetCount(endpoint)

		var err error
		reported, err = endpoint.req.ReportedTasks()
		if err == nil {
			// From here this process knows what this POI holds, so it may resume telling it
			// that it is here. Before this point its silence is what lets the POI's own
			// fail-safe reclaim tasking nobody can name.
			//
			// Unless ForgetPOI discarded claims at this POI after the account was asked for. A
			// trigger installed after the POI answered and dropped by that ForgetPOI is in
			// neither the account nor the registry, and only another account finds it.
			if s.triggers.markReconciledSince(nodeID, forgotten) {
				break
			}

			continue
		}
		// The POI may simply not be up yet — on a whole-cluster restart it very
		// likely is not. Worth telling the LIPF, because tasking may have been left
		// behind that this process cannot withdraw until this succeeds. Reported as
		// an element-level issue, not a task one: a task report has to name an XID,
		// and which warrants they were is precisely what was lost. Once, not per
		// attempt — the retry is this element's business, the condition is the LIPF's.
		if attempt == 0 && s.reporter != nil {
			s.reporter.Notify(x1.NEIssueReconcileFailed,
				"could not establish what content tasking a UPF still holds after restart; retrying")
		}
	}

	// This account is judged like any other. At start-up it almost never says anything —
	// this process has installed nothing yet, so it holds nothing to be answerable for —
	// which is precisely why the same judgement must run on the keepalive round.
	s.noteTaskHealth(nodeID, reported, 0)

	var orphans []withdrawal
	for _, task := range reported {
		xid := types.XID(task.TaskDetails.XID)
		if xid == "" {
			continue
		}

		// Skip anything this process is answerable for. Reconciliation runs
		// concurrently with ordinary triggering, so a session establishing right
		// now would otherwise have its brand-new trigger withdrawn by the cleanup —
		// and one being withdrawn right now would be withdrawn twice, by two
		// parties neither of which can read the other's answer.
		// Anything this process is answerable for is not stale. Its health is judged by
		// noteTaskHealth, which runs for this account and for every later one.
		if held, _, _ := s.triggers.holdsFor(xid); held {
			continue
		}

		// Nothing here knows about this one, which after a restart means all of it.
		// Withdrawing is the only way it ever stops — and it goes through the same
		// pending-removal state as any other withdrawal, because a withdrawal
		// reconciliation fires and forgets leaves exactly the tasking reconciliation
		// exists to remove.
		orphans = append(orphans, s.triggers.takeOrphan(nodeID, xid))
	}

	// Synchronously, on this endpoint's own goroutine: a POI that will not
	// acknowledge holds up nothing but its own reconciliation.
	s.deactivate(orphans)

	// And then what the current warrants call for at this POI is installed again. After the
	// withdrawal, so what it installs is not withdrawn as an orphan.
	s.retriggerAt(nodeID)
}

// retriggerAt installs the triggers the current CC warrants call for on the live sessions
// served by the POI configured as nodeID.
//
// ForgetPOI drops this element's claims at a POI that stopped answering, and reconciliation
// then withdraws whatever that POI still holds, because nothing here can name it any more. When
// the POI did not restart, its sessions are live and their FARs still duplicate, and nothing else
// installs their triggers again: establishment installs them for a new session, and a scan only
// on a warrant change. Content interception at that POI would stop with nothing reported.
//
// Claims make it idempotent. plan skips a (warrant, session, POI) already claimed, so a trigger
// that was never discarded, or that an establishment has installed again, is not installed twice.
// At start-up no warrant is usually held yet, and nothing is installed; usually, because
// reconciliation retries until the POI answers, and a warrant can be provisioned meanwhile.
//
// It walks every live session and takes each one's lock, once per reconciliation of each POI and
// outside the scans' bound. So it returns before the walk when no task asks for CC, which is the
// case at start-up and on an element holding no content warrant.
//
// Only at nodeID. A session the node's current incarnation did not acknowledge is skipped: after
// a restart, a session that restoration has not re-established yet still carries the SEID the
// previous incarnation assigned, so a trigger planned on it would match nothing, and its claim
// would make the re-establishment skip the trigger it should install. The same holds at the
// session's other UPFs, whose incarnations this reconciliation says nothing about, so their
// triggers are left to their own establishment and reconciliation.
func (s *subsystem) retriggerAt(nodeID string) {
	if !s.ccTaskHeld() {
		return
	}

	smfctx.RangeSMContexts(func(sc *smfctx.SMContext) bool {
		sc.SMLock.Lock()
		defer sc.SMLock.Unlock()

		// The same skip the activation scan makes: a session that has ended belongs to its
		// teardown, which withdraws its triggers.
		if sc.SMContextState == smfctx.SmStateRelease || sc.LocalPurged.Load() || sc.SupersededByAnother() {
			return true
		}
		s.triggerCCAt(sc, func(sc *smfctx.SMContext) []upfSession {
			return s.servedByCurrentIncarnation(sc, nodeID)
		})

		return true
	})
}

// ccTaskHeld reports whether the store holds any task asking for CC, asked as the activation
// scan asks it of one task.
func (s *subsystem) ccTaskHeld() bool {
	for _, t := range s.store.Snapshot() {
		if t.WantsProduct(types.ProductCC) {
			return true
		}
	}

	return false
}

// servedByCurrentIncarnation returns the UPF configured as nodeID serving sc, when it serves sc
// on a PFCP session that the node's current incarnation acknowledged, and nothing otherwise.
// Caller holds sc.SMLock, and not r.mu: the node's held recovery timestamp is read under
// UpfLock, which a restart path holds while it waits for r.mu.
func (s *subsystem) servedByCurrentIncarnation(sc *smfctx.SMContext, nodeID string) []upfSession {
	if sc.Tunnel == nil {
		return nil
	}
	for _, dp := range sc.Tunnel.DataPathPool {
		for node := dp.FirstDPNode; node != nil; node = node.Next() {
			if node.UPF == nil {
				continue
			}
			// Keyed and matched as sessionUPFs keys and plan matches.
			addr := node.UPF.NodeID.ResolveNodeIdToIp().String()
			pfcpCtx := sc.PFCPContext[addr]
			if pfcpCtx == nil || pfcpCtx.RemoteSEID == 0 {
				continue
			}
			s.triggers.mu.Lock()
			key, _, ok := s.triggers.matchEndpoint(upfSession{node: node.UPF.NodeID, addr: addr})
			s.triggers.mu.Unlock()
			// A zero acknowledgement names no incarnation: a session restored from a document
			// stored without one carries it, and so does a node held at no timestamp yet, so
			// zero equalling zero says nothing about the SEID.
			acknowledgedAt := pfcpCtx.AcknowledgedAtRecovery
			if ok && key == nodeID && !acknowledgedAt.IsZero() && acknowledgedAt.Unix() == node.UPF.HeldRecovery().Unix() {
				return []upfSession{{
					node: node.UPF.NodeID, addr: addr, seid: pfcpCtx.RemoteSEID, acknowledgedAt: acknowledgedAt,
				}}
			}
		}
	}

	return nil
}

// noteTaskHealth reports every trigger this element holds that the POI says is not running.
//
// The POI's account is the only way a triggering function learns that a trigger it installed has
// stopped: a failed provisioning, an unresolved fault, a datapath that refused the duplication
// rule. Content interception has then stopped while the warrant is live, which is precisely what a
// CC triggering function exists to notice.
//
// **Against the warrant, which is what makes it actionable.** Reported at element scope this said
// that something among the content interceptions this element triggers had stopped, and a LIPF
// holding several warrants could not tell which — a condition nobody could act on.
//
// Non-terminating: the POI holds the task and this element holds the trigger, so what has stopped
// is the product rather than the tasking, and a terminating report would tell the LIPF to
// re-provision an element whose provisioning is intact.
//
// A trigger already on its way out is exempt: it is meant to stop. Describe() renders the POI's own
// account and is documented never to include a target identifier, which is what lets it be
// forwarded.
//
// A trigger missing from the account is one the POI no longer holds: its fail-safe purged it, or
// it restarted unseen. asked is the registry sequence number taken before the account was asked
// for, and only triggers whose activation was answered before it are judged, so one the POI
// applied after composing its account is not missing. Zero judges none. A missing trigger makes
// this element's account of the POI untrue, so it is discarded as for a POI that stopped
// answering: the next keepalive round reconciles the POI and re-installs the triggers of its live
// sessions.
func (s *subsystem) noteTaskHealth(nodeID string, reported []x1.TaskResponseDetails, asked uint64) {
	if s.triggers == nil {
		return
	}

	if asked != 0 && s.triggers.forgetIfPurged(nodeID, reported, asked) > 0 && s.reporter != nil {
		s.reporter.NotifyAsync(x1.NEIssueReconcileFailed,
			"a triggered point of interception no longer holds content triggers this element installed "+
				"there; its tasking has been discarded, and is re-installed for its live sessions once it "+
				"has reported what it holds")
	}

	for _, task := range reported {
		xid := types.XID(task.TaskDetails.XID)
		if xid == "" {
			continue
		}

		held, withdrawing, warrant := s.triggers.holdsFor(xid)
		if !held || withdrawing {
			continue
		}

		if task.TaskStatus.Healthy() {
			s.triggers.noteHealthy(xid)

			continue
		}

		// Recorded as state, which is what both the X1 server's task-fault watcher and an
		// interrogation read: the watcher reports the fault to the LIPF when it appears and
		// retracts it once the POI reports the trigger running again (TS 103 221-1 clause
		// 6.5.2.1), and the ADMF can ask whether it still holds in between.
		s.triggers.noteUnhealthy(xid, warrant, task.TaskStatus.Describe())
	}
}

// triggerHealth is what a POI last said about one installed trigger that is not running.
type triggerHealth struct {
	warrant types.XID
	why     string
}

// noteUnhealthy and noteHealthy record what a POI last said about one trigger, so the condition
// can be answered when the ADMF asks and reported by the task-fault watcher.
func (r *triggerRegistry) noteUnhealthy(trigger, warrant types.XID, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.unhealthy[trigger] = triggerHealth{warrant: warrant, why: why}
}

func (r *triggerRegistry) noteHealthy(trigger types.XID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.unhealthy, trigger)
}

// unhealthyFor returns, sorted, what the POIs last said about every trigger this warrant
// currently holds that is not running. A trigger no longer installed contributes nothing: its
// report ended with it.
func (r *triggerRegistry) unhealthyFor(warrant types.XID) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var reasons []string
	for _, installed := range r.installed {
		if installed.warrant != warrant {
			continue
		}
		if h, ok := r.unhealthy[installed.xid]; ok {
			reasons = append(reasons, h.why)
		}
	}
	slices.Sort(reasons)

	return reasons
}

// taskFaults answers what is currently wrong with one warrant's content interception, for the X1
// status a provisioning function can ask for and for the task-fault watcher, which reports a fault
// when it appears and retracts it when it ends.
//
// The IRI-POI role contributes nothing here: a quiet subscriber is indistinguishable from one this
// element has stopped watching, and a destination's failure belongs to the destination rather than
// to each warrant pointing at it. The CC triggering role does: a trigger a POI reports as not
// running is task-scoped, re-observable on the keepalive round, and means this warrant's content
// interception has stopped while the warrant is live. So does a modification this element could
// not apply to a session the warrant covers, until a later one applies.
func (s *subsystem) taskFaults(xid types.XID) []x1.X1Error {
	var reasons []string
	if s.triggers != nil {
		for _, why := range s.triggers.unhealthyFor(xid) {
			reasons = append(reasons, "a point of interception reports a content trigger this "+
				"element installed for this warrant as not running: "+why)
		}
	}
	reasons = append(reasons, s.failedModificationsFor(xid)...)

	if len(reasons) == 0 {
		return nil
	}

	return []x1.X1Error{x1.TaskFault(x1.TaskIssueTriggerNotRunning, strings.Join(reasons, "; "))}
}

// upfSession is one UPF serving a session, with the detection criterion for that
// UPF's share of it.
type upfSession struct {
	// node is the serving UPF's N4 NodeID as the session carries it, passed on
	// unresolved so matchEndpoint can compare identities before addresses.
	node smfctx.NodeID
	// addr is that node's address, as sessionUPFs has *already* resolved it to key
	// the session's PFCP context. Carried rather than re-derived, because deriving
	// it again is a name lookup — and matchEndpoint ran on the PDU-session
	// establishment path of the subscriber being intercepted, holding that session's
	// lock and the registry's, with no timeout on the lookup. Every other exchange
	// on this path is deliberately off-goroutine for exactly that reason; this one
	// was not, and a name lookup is network I/O however small its answer.
	addr string
	// seid is the F-SEID the UPF assigned to this session — the value it tags onto
	// every packet it duplicates, and therefore the criterion that lets it match a
	// copy to this trigger. It is per UPF, unlike the correlation identifier.
	seid uint64
	// acknowledgedAt is the recovery timestamp of the node's incarnation that acknowledged the
	// PFCP session, zero where none is known.
	acknowledgedAt time.Time
}

// sessionUPFs returns the UPFs serving sc, each with the SEID it assigned. Caller
// holds sc.SMLock (it reads sc.Tunnel and sc.PFCPContext).
func sessionUPFs(sc *smfctx.SMContext) []upfSession {
	if sc.Tunnel == nil {
		return nil
	}

	var out []upfSession
	seen := make(map[string]bool)

	for _, dp := range sc.Tunnel.DataPathPool {
		for node := dp.FirstDPNode; node != nil; node = node.Next() {
			if node.UPF == nil {
				continue
			}
			// The PFCP context is keyed by the resolved address because that is how the
			// SMF keys it everywhere (context/sm_context.go), so this lookup — and the
			// dedupe that goes with it — has to use the same form. Only the value
			// handed onward is the unresolved NodeID: matching a UPF to its triggering
			// endpoint is this package's business, and doing it on an address frozen
			// anywhere is the defect this avoids.
			key := node.UPF.NodeID.ResolveNodeIdToIp().String()
			if seen[key] {
				continue
			}
			pfcpCtx, ok := sc.PFCPContext[key]
			if !ok || pfcpCtx == nil || pfcpCtx.RemoteSEID == 0 {
				// The PFCP session is not established on this UPF yet, so it has no
				// SEID to match on. Nothing to trigger — the establishment response
				// for that UPF will bring us back here.
				continue
			}
			seen[key] = true
			// key is that address, already resolved for the PFCP context lookup above.
			// Passing it on is what keeps matchEndpoint from resolving the same name a
			// second time, on this goroutine, under this session's lock.
			out = append(out, upfSession{
				node: node.UPF.NodeID, addr: key, seid: pfcpCtx.RemoteSEID,
				acknowledgedAt: pfcpCtx.AcknowledgedAtRecovery,
			})
		}
	}
	return out
}

// TriggerCC installs the LI_T3 triggers for sc at every UPF serving it, for each
// active task that wants CC. Call it once the UPF has answered the PFCP Session
// Establishment Request — the trigger's detection criterion is the SEID that
// response assigns, exactly as ReportEstablishment needs it for the correlation
// identifier. No-op and silent when LI is inactive or sc is untasked.
// Caller holds sc.SMLock.
func TriggerCC(sc *smfctx.SMContext) {
	if sub := active.Load(); sub != nil && sc != nil {
		sub.triggerCC(sc)
	}
}

// POIRestarted tells the CC Triggering Function that a triggered point of interception
// has stopped answering, so the tasking this element believes it holds there is discarded. The
// endpoint's reconciliation that follows re-installs it for the POI's live sessions (see
// retriggerAt), and establishments install it for new ones. Silent no-op unless LI is configured.
//
// **It takes the node identity, not a pre-resolved string**, because the
// registry has to be allowed to apply its own matching rule. Trigger keys carry
// `li.upfTriggers[].nodeId` exactly as configured — which the chart and the blueprint default
// to `upf`, a name — while every caller here holds a `smfctx.NodeID` whose resolved form is
// an address. Handed the address, ForgetPOI's string equality would match nothing and this
// notification would do nothing at all: the registry would keep every claim for the
// restarted POI, so `plan` would find each triple already claimed and install nothing, while
// the POI held no tasking and discarded the copies it was told to make. A test configured
// with an IP literal cannot see this: it is the one spelling in which the two forms coincide.
//
// So the identity and its resolved address travel in the shape sessionUPFs already builds,
// and matchEndpoint resolves them to a configured key — identity first, then the refreshed address index —
// which is the same rule the trigger path uses. ForgetPOI stays as the key-level primitive.
//
// **A detected restart does not come through here.** It reaches the same discard through
// GateRestoration, which wraps the SMF's session restoration so the discard is settled before
// any session is re-installed. This is for the paths on which a UPF stops answering, where
// nothing is restored. If it comes back having restarted, its re-association reports a new
// recovery timestamp and is gated in turn; if it comes back with the timestamp it had, nothing
// is restored, and the discard here is what lets reconciliation and its next establishments
// re-install tasking.
func POIRestarted(node smfctx.NodeID) {
	if sub := active.Load(); sub != nil {
		// Resolved here, not by the caller, so an element without LI does no lookup.
		sub.discardRestarted(upfSession{node: node, addr: node.ResolveNodeIdToIp().String()}, time.Time{})
	}
}

// discardRestarted discards the claims held for the point of interception serving session's
// node, reports a discard that dropped anything, and says what it concluded about the node.
// recovery is the restarted node's recovery timestamp, zero for a node that stopped answering.
func (s *subsystem) discardRestarted(session upfSession, recovery time.Time) restartMatch {
	if s.triggers == nil {
		return restartNotAtPOI
	}
	n, match := s.triggers.forgetRestartedPOI(session, recovery)
	if n > 0 && s.reporter != nil {
		// NE-level and countable, naming no warrant: which interceptions were lost is
		// the ADMF's to work out from its own provisioning, and this element cannot
		// name them without disclosing tasking on a channel that must not carry it.
		s.reporter.NotifyAsync(x1.NEIssueReconcileFailed,
			"a triggered point of interception restarted or stopped answering; the tasking this element "+
				"believed it held there has been discarded, and is re-installed for its live sessions once "+
				"it has reported what it holds, and for re-established sessions as they are established")
	}

	return match
}

// UntriggerCC removes the LI_T3 triggers installed for sc. Call it when the
// session is released (TS 33.128 clause 6.2.3.3.1). Caller holds sc.SMLock.
func UntriggerCC(sc *smfctx.SMContext) {
	if sub := active.Load(); sub != nil && sc != nil {
		sub.untriggerCC(sc)
	}
}

// RestoreInterception makes a session's release reportable again, for a release that
// did not happen. Caller holds sc.SMLock.
//
// The SMF reports the release and withdraws the session's triggers *before* PFCP
// deletion, and that order is right rather than wrong: stopping interception before or
// as the session goes is the fail-closed direction, and withdrawal needs the
// serving-UPF list that hangs off sc.Tunnel. On the branches where the deletion times
// out or fails and the session is restored to service, the *report* state must be put
// back — otherwise the release that eventually happens is suppressed as a duplicate of
// one that never occurred, and the agency's record of the session ends at a failed
// attempt, permanently. That is what this restores: the eventual release stays
// reportable, because a record reports the transition it names.
//
// **It does not re-install the triggers, and it cannot.** Every reachable caller runs
// after releaseTunnel has set sc.Tunnel = nil (producer/pdu_session.go), and a session
// with no tunnel has no serving UPFs, so sessionUPFs would return nothing and triggerCC
// would return before planning anything.
//
// Snapshotting the UPF list before releaseTunnel and re-triggering afterwards is not
// the fix. It would install a trigger keyed to a PFCP session that has been deleted,
// into a session that cannot forward — a trigger matching no packet, held by a
// triggering function that believes interception is running. That is the state this
// whole capability exists to prevent, arrived at by trying to prevent it.
//
// So the durable withdrawal stands: this element has withdrawn the triggers, the POI
// has acknowledged, and content interception for this session is over until something
// re-establishes it. What would re-establish it is the session's own user-plane state
// coming back, which no path here provides and which is a larger problem than this one.
// **Do not re-raise the re-install here**: it is absent because it cannot work from a
// session with no tunnel, not because it was overlooked.
//
// The UPF may still forward the session's traffic, so each content warrant covering the
// session is reported to the LIPF as producing no content for it, once per session unless the
// LIPF did not take the report.
func RestoreInterception(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	sc.LiReleaseReported = false
	sub.reportUntriggerable(sc)
}

// reportUntriggerable reports each content warrant covering sc, a session whose triggers were
// withdrawn and which has no tunnel to install them on again. Nothing is reported without a
// registry: there were no triggers to withdraw, and plan's fault for that was reported already.
//
// Once per warrant and session: a release that fails again, on this or another failure branch,
// describes the same loss. A report the LIPF did not take is not counted, so the next failure
// sends it again. A non-terminating fault, because the warrant's provisioning and its
// interception of the target's other sessions are intact; no clear follows, as the condition
// ends only with the session. The reports go off this goroutine, as triggerCCAt's do. Caller
// holds sc.SMLock.
func (s *subsystem) reportUntriggerable(sc *smfctx.SMContext) {
	if s.triggers == nil {
		return
	}
	var tasks []types.InterceptTask
	for _, t := range s.ccTasks(sc) {
		if sc.LiContentLostReported[string(t.XID)] {
			continue
		}
		if sc.LiContentLostReported == nil {
			sc.LiContentLostReported = make(map[string]bool)
		}
		sc.LiContentLostReported[string(t.XID)] = true
		tasks = append(tasks, t)
	}
	if len(tasks) == 0 {
		return
	}
	go func() {
		for _, t := range tasks {
			err := s.sendTaskIssueAs(t.XID, x1.TaskReportNonTerminatingFault, "a session release failed after "+
				"the session's content triggers were withdrawn; the session may still carry traffic and its "+
				"content is not intercepted")
			if err != nil {
				sc.SMLock.Lock()
				delete(sc.LiContentLostReported, string(t.XID))
				sc.SMLock.Unlock()
			}
		}
	}()
}

// triggerCC tasks each serving UPF's CC-POI for each CC warrant covering sc.
//
// The X1 exchange runs in a goroutine: it is a synchronous HTTPS round trip, and
// the caller holds sc.SMLock on the PDU-session signalling path, where a slow or
// unreachable peer must never block.
//
// That leaves a brief window at establishment in which the UPF is already
// duplicating (the DUPL FAR rode out with the establishment *request*) but is not
// yet tasked (the trigger needs the SEID from the *response*). Content in that
// window is dropped and reported by the CC-POI rather than delivered with an
// unattributable XID — the fail-closed choice, and the reason the window is
// acceptable rather than merely tolerated. It cannot be closed by reordering:
// the criterion the POI matches on does not exist until the response arrives.
//
// Caller holds sc.SMLock.
func (s *subsystem) triggerCC(sc *smfctx.SMContext) {
	s.triggerCCAt(sc, sessionUPFs)
}

// triggerCCAt is triggerCC for the serving UPFs upfsOf returns, which is asked only once a CC
// warrant covers sc. Caller holds sc.SMLock.
func (s *subsystem) triggerCCAt(sc *smfctx.SMContext, upfsOf func(*smfctx.SMContext) []upfSession) {
	tasks := s.ccTasks(sc)
	if len(tasks) == 0 {
		return
	}

	upfs := upfsOf(sc)
	if len(upfs) == 0 {
		return
	}

	// With no `li.upfTriggers` there is no registry, and every UPF serving the session is one
	// this element has no triggering endpoint for. That is the fault plan reports for a UPF the
	// list leaves out, and it is reported the same way: once per warrant on each call (plan
	// dedupes only within one), only once the anchor's session exists, and off this goroutine.
	// The task was accepted and the session's FARs duplicate, so a silent return would leave
	// the LIPF believing the interception runs.
	if s.triggers == nil {
		if sessionCorrelation(sc) == 0 {
			return
		}
		go func() {
			for _, t := range tasks {
				s.reportTaskIssue(t.XID, "no triggering endpoint configured for a UPF serving the target")
			}
		}()

		return
	}

	// The correlation identifier is the session's, not the UPF's: it is the value
	// this SMF puts on the session's xIRI, so every UPF serving the session must
	// stamp the same one for the MDF to join content to signalling.
	// Only the detection criterion is per UPF.
	//
	// plan reads the warrants again, under the registry's lock, rather than taking the list
	// above: a DeactivateTask or a ModifyTask that lands between the two removes the warrant
	// from the store and then looks in the registry for its claims, before this one exists.
	// Planned from the earlier read, the trigger would be installed for a warrant already
	// withdrawn, or for a session it no longer covers, and stillHolds would vouch for it.
	planned, unreachable, undeliverable := s.triggers.plan(
		sc.Ref, func() []types.InterceptTask { return s.ccTasks(sc) }, upfs, sessionCorrelation(sc))

	if len(planned) == 0 && len(unreachable) == 0 && len(undeliverable) == 0 {
		return
	}

	// Everything that talks to a peer goes off this goroutine, the reports included.
	//
	// This runs on HandlePfcpSessionEstablishmentResponse's path with sc.SMLock held,
	// for the very subscriber being intercepted. ReportTaskIssue is a synchronous mTLS
	// POST bounded only by its own 10s timeout, and — unlike an NE-level report — it is
	// deliberately *not* throttled, because each task's failure is its own fact. Sent
	// in line, every affected warrant would cost the establishment a full timeout while
	// an ADMF was unreachable, under the session's own lock: a tasked subscriber's
	// session setup measurably slower than an untasked one's, which is the
	// target-observable timing difference this element must never produce.
	go func() {
		// A UPF we have no triggering endpoint for is carrying a tasked session's
		// traffic and cannot be told whose warrant it serves. The interception is
		// authorised and will produce nothing, which only the LIPF can resolve.
		for _, warrant := range unreachable {
			s.reportTaskIssue(warrant, "no triggering endpoint configured for a UPF serving the target")
		}

		// And a warrant whose content has nowhere to go at all: it named no destination
		// and there is no configured MDF3, or the destinations it named give no X3
		// endpoint (see x3Destinations). Reported separately from the above because the
		// remedy is a different one — provision the destination, or configure the MDF3.
		for _, warrant := range undeliverable {
			s.reportTaskIssue(warrant, "no X3 delivery destination could be resolved for this task")
		}

		s.installTriggers(planned)
	}()
}

// ccTasks returns the warrants covering sc that order content. Caller holds sc.SMLock.
func (s *subsystem) ccTasks(sc *smfctx.SMContext) []types.InterceptTask {
	var tasks []types.InterceptTask
	for _, t := range s.matchingTasks(sc) {
		if t.WantsProduct(types.ProductCC) {
			tasks = append(tasks, t)
		}
	}

	return tasks
}

// x1ErrXIDExists is TS 103 221-1 table 6.7-3's "XID already exists on NE": the POI holds
// a different task under the XID an ActivateTask named.
const x1ErrXIDExists = 2010

// installTriggers performs the X1 exchanges off the signalling path. Every
// trigger it is given has already been claimed in the registry by triggerCC, so
// the withdrawal path can see it even before it exists at the POI.
func (s *subsystem) installTriggers(planned []plannedTrigger) {
	for _, p := range planned {
		dids, err := s.ensureDestinations(p.endpoint, p.addresses)
		if err != nil {
			// Released rather than withdrawn, and the asymmetry with the activation
			// below is the point: no ActivateTask has been sent, so whatever happened
			// to the CreateDestination, this POI holds no trigger of ours. There is
			// nothing to withdraw.
			s.triggers.activationAnswered(p.key, p.trigger.XID, false)
			s.triggers.release(p.key)
			s.reportTaskIssue(p.warrant, "X3 delivery destination could not be provisioned at the UPF")
			// The first X1 exchange of the sequence, so an answer this element
			// cannot bind surfaces here before it ever reaches the activation.
			s.reportUnattributable(err)

			continue
		}
		p.trigger.DIDs = dids

		err = p.endpoint.req.ActivateTask(p.trigger)
		var refused *x1.RequestError
		// unanswered records that an attempt went unanswered, after which the POI may
		// hold the trigger whatever a later attempt says.
		unanswered := false
		switch {
		case err == nil:
		case errors.As(err, &refused) && refused.Code != x1ErrXIDExists:
			// A refusal may mean the POI has lost the destinations we provisioned —
			// it restarts independently of us, and its destination registry does not
			// survive that. Re-provision and try once more before concluding the
			// interception cannot be arranged: the alternative is content dropped
			// at the POI for as long as this process happens to live. A refused task
			// is not held, so the retry's new destinations cannot collide with it.
			p.endpoint.forgetDestination()

			if again, retryErr := s.ensureDestinations(p.endpoint, p.addresses); retryErr == nil {
				p.trigger.DIDs = again
				err = p.endpoint.req.ActivateTask(p.trigger)
			}
		case !errors.As(err, &refused):
			// No answer: the POI may hold the trigger. Resend it unchanged rather than with
			// re-provisioned destinations, which would be a different task under an XID the
			// POI may hold, refused with 2010 (TS 103 221-1 table 6.2.1.1-2). The util x1
			// server this UPF runs acknowledges a replay of the identical task it holds; one
			// that never received it activates it.
			unanswered = true
			err = p.endpoint.req.ActivateTask(p.trigger)

			// A refusal of the replay other than 2010 says the POI holds no task under this
			// XID — holding the identical task it would have acknowledged, holding a different
			// one it would have answered 2010 — so the first attempt was not applied. That is
			// the restarted POI the branch above re-provisions for, and it is handled the same
			// way. Only a re-provisioned attempt that again goes unanswered leaves the task
			// possibly held.
			if errors.As(err, &refused) && refused.Code != x1ErrXIDExists {
				unanswered = false
				p.endpoint.forgetDestination()

				if again, retryErr := s.ensureDestinations(p.endpoint, p.addresses); retryErr == nil {
					p.trigger.DIDs = again
					err = p.endpoint.req.ActivateTask(p.trigger)
					unanswered = err != nil && !errors.As(err, &refused)
				}
			}
		}
		// From here a withdrawal of this trigger is sent after the POI answered its activation, so a
		// 2020 to it means the POI does not hold it. Unless the last attempt went unanswered, or was
		// refused with 2010 after one that went unanswered: the POI may apply the unanswered one yet.
		// An acknowledged attempt means the POI holds the trigger, and a replay refused with another
		// code means the unanswered attempt before it was not applied, so both close it.
		if err != nil && (unanswered || !errors.As(err, &refused)) {
			s.triggers.activationUnanswered(p.trigger.XID)
		} else {
			s.triggers.activationAnswered(p.key, p.trigger.XID, err == nil)
		}

		if err != nil {
			// What happens to the bookkeeping turns on whether the POI *said* it
			// holds nothing, or said nothing at all.
			//
			// A stated refusal is a negative answer: the POI received the request,
			// understood it, and declined. Nothing is installed, so the claim is
			// dropped and a later establishment or modification retries.
			//
			// Anything else — a timeout, a lost response, an answer this element
			// cannot bind to its request — is not an answer. The POI may well hold
			// the trigger. Dropping the claim then leaves it installed and untracked:
			// absent from both maps, so a warrant's withdrawal finds nothing, a
			// session's release finds nothing, and reconciliation runs only at
			// startup. The POI goes on duplicating the subject's content, correctly
			// labelled and indistinguishable downstream, past the point where the
			// warrant is revoked. So it is withdrawn instead, durably, and the POI's
			// own "XID not held" answer completes that withdrawal at once in the case
			// where it never received the activation at all.
			//
			// 2010, "XID already exists on NE", is not a refusal to hold anything: the
			// POI holds a different task under this XID, so it is withdrawn like a
			// non-answer rather than released. So is a refusal of a re-provisioned
			// attempt whose own predecessor went unanswered: that attempt may have been
			// applied.
			if errors.As(err, &refused) && refused.Code != x1ErrXIDExists && !unanswered {
				s.triggers.release(p.key)
			} else if w, owned := s.triggers.takeFailedActivation(p.key, p.trigger.XID); owned {
				// On its own goroutine: the retry loop runs until the POI
				// acknowledges, and the triggers behind this one in the batch must
				// not wait for it.
				go s.deactivate([]withdrawal{w})
			}

			// Either way the LIPF is told this warrant is producing no content.
			s.reportTaskIssue(p.warrant, "the UPF refused or failed the content-interception trigger")
			// And, where the cause was an answer this element could not bind to its
			// request, say so separately. The task issue above is the same whether
			// the POI refused the warrant or this element disbelieved its answer,
			// and those need opposite actions — the first is a POI to look at, the
			// second a configuration mismatch here.
			s.reportUnattributable(err)

			continue
		}

		// The session may have been released, or the warrant withdrawn, in the time
		// this trigger took to install. That withdrawal ran against a registry entry
		// whose trigger did not yet exist at the POI, so whatever it sent was refused
		// and the trigger is now in place with nothing tracking it: reconciliation
		// runs only at startup, and the POI's fail-safe only fires once this SMF
		// stops answering it, so nothing would ever take it down. Withdraw it here.
		if !s.triggers.stillHolds(p.key, p.trigger.XID) {
			// **Durably, not best-effort.** This was one DeactivateTask whose failure
			// left the trigger installed and untracked, on the reasoning that the POI's
			// fail-safe is the last resort — and the requirement beside this one records
			// why that fail-safe cannot help here: the element's *other* tasking at this
			// POI keeps the keepalive relationship alive, so the POI never concludes its
			// triggering function has gone and never purges. The single attempt was
			// relying on a mechanism this project has documented as unable to reclaim
			// exactly this orphan.
			//
			// So it goes into the same pending-removal state every other withdrawal
			// uses, and the retrying deactivate path owns it until the POI says the task
			// is gone. takeOrphan is the shape: this trigger's claim is no longer in the
			// registry under its key — that is what stillHolds just reported — so the
			// pending entry gets a synthetic key, as reconciliation's orphans do.
			//
			// Exactly one party withdraws, as before: stillHolds reports true while a
			// withdrawal of this XID is pending, so a session release that raced this
			// activation is already owned by its own retry loop and this branch does not
			// run. What reaches here is the trigger that is in neither map — released
			// without a withdrawal, or displaced by a newer claim under the same key —
			// which is precisely the orphan nothing else can name.
			_, _, nodeID, ok := parseTriggerKey(p.key)
			if !ok {
				// Unaddressable, so no withdrawal can be sent anywhere. Every key this
				// element builds parses; reported rather than looped on forever.
				s.reportTaskIssue(p.warrant,
					"a content trigger installed after its own withdrawal cannot be addressed for removal")

				continue
			}
			// On its own goroutine: the retry loop runs until the POI acknowledges, and
			// the triggers behind this one in the batch must not wait for it.
			go s.deactivate([]withdrawal{s.triggers.takeOrphan(nodeID, p.trigger.XID)})
		}
	}
}

// untriggerCC removes every trigger installed for sc, across warrants and UPFs.
//
// The UPFs are taken from this CC-TF's own bookkeeping rather than from the
// session, because by release time the session's PFCP state may already be gone —
// and a trigger we failed to find here is one the UPF keeps holding. Caller holds
// sc.SMLock (it reads sc.Ref).
func (s *subsystem) untriggerCC(sc *smfctx.SMContext) {
	if s.triggers == nil {
		return
	}

	pending := s.triggers.takeForSession(sc.Ref)
	if len(pending) == 0 {
		return
	}

	go s.deactivate(pending)
}

// deactivate withdraws pending triggers at the UPF each was installed at, and
// keeps trying until every one of them is acknowledged.
//
// Its two callers arrive with opposite premises, and it holds the second's, which
// is the stricter. untriggerCC releases a session that is *gone*: the
// trigger's detection criterion is that session's SEID, so it can no longer match
// a packet and a POI that keeps the trigger produces nothing from it.
// untriggerWarrant withdraws *authority* from sessions that remain: the criterion
// still matches every packet the subject sends, so a POI that keeps that trigger
// keeps delivering the subject's content to the MDF under a warrant that no longer
// exists — well-formed, correctly attributed, and unauthorised. Nothing downstream
// can tell, which is why best-effort is not available here and the entry stays in
// the registry until the POI says the task is gone.
//
// Runs on its own goroutine (both callers start it with go): the retry loop
// outlives the X1 request that began it, by design.
func (s *subsystem) deactivate(pending []withdrawal) {
	for attempt := 0; len(pending) > 0; attempt++ {
		if attempt > 0 {
			s.triggers.sleepFor(withdrawalBackoff(attempt - 1))
		}

		var remaining []withdrawal
		for _, w := range pending {
			endpoint, ok := s.triggers.endpoints[w.nodeID]
			if !ok {
				// The endpoint is keyed by the NodeID as configured and configuration is
				// read once, so this cannot happen for a trigger this process installed.
				// If it ever does, no request can be addressed anywhere, and retrying an
				// unaddressable withdrawal forever would be a loop with no exit.
				s.triggers.forgetPending(w.key)

				continue
			}

			// Read before the request is sent: a 2020 is an answer about the POI after
			// whatever it applied first, and an activation not yet answered may be applied
			// after this withdrawal. Then the POI is asked again once that one has been.
			activating := s.triggers.activationOpen(w.xid)
			err := endpoint.req.DeactivateTask(w.xid)
			if activating && withdrawalComplete(err) {
				remaining = append(remaining, w)

				continue
			}
			if err != nil && !withdrawalComplete(err) {
				remaining = append(remaining, w)
				s.reportWithdrawalFailure(w.key, err)

				continue
			}
			s.triggers.forgetPending(w.key)
		}
		pending = remaining
	}
}

// unansweredActivationWindow is how long after an ActivateTask went unanswered the POI may still
// apply it. The util x1 server applies a request once it has read the body and taken an admission
// slot, whether or not the requester has given up: its listener reads a request for up to 30 s,
// and a request waits up to 2 s for a slot. A minute covers both with room for the processing.
const unansweredActivationWindow = 60 * time.Second

// activationOpen reports whether xid's ActivateTask may still be sent, is unanswered, or went
// unanswered within unansweredActivationWindow.
func (r *triggerRegistry) activationOpen(xid types.XID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	until, ok := r.activating[xid]
	if !ok {
		return false
	}
	if until.IsZero() || r.timeNow().Before(until) {
		return true
	}
	delete(r.activating, xid)

	return false
}

// activationUnanswered records that xid's ActivateTask went unanswered, so the POI may apply it for
// unansweredActivationWindow yet.
func (r *triggerRegistry) activationUnanswered(xid types.XID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.activating == nil {
		r.activating = make(map[types.XID]time.Time)
	}
	r.activating[xid] = r.timeNow().Add(unansweredActivationWindow)
}

// activationAnswered records that xid's ActivateTask, claimed under key, has been answered, or will
// not be sent, and when the POI accepted it if applied.
func (r *triggerRegistry) activationAnswered(key string, xid types.XID, applied bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.activating, xid)
	r.seq++
	if installed, ok := r.installed[key]; ok && applied && installed.xid == xid {
		installed.activatedSeq = r.seq
		r.installed[key] = installed
	}
}

// askSeq returns the sequence number to judge an account asked for now by.
func (r *triggerRegistry) askSeq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.seq++

	return r.seq
}

// forgetIfPurged discards this element's account of the POI at nodeID, as ForgetPOI does, when
// that POI's reported tasks leave out a trigger whose activation it accepted before asked, and
// returns how many claims were dropped.
func (r *triggerRegistry) forgetIfPurged(nodeID string, reported []x1.TaskResponseDetails, asked uint64) int {
	held := make(map[types.XID]bool, len(reported))
	for _, task := range reported {
		held[types.XID(task.TaskDetails.XID)] = true
	}

	r.mu.Lock()
	purged := false
	for key, installed := range r.installed {
		_, _, keyNode, ok := parseTriggerKey(key)
		if ok && keyNode == nodeID && installed.activatedSeq != 0 && installed.activatedSeq < asked &&
			!held[installed.xid] {
			purged = true

			break
		}
	}
	r.mu.Unlock()

	if !purged {
		return 0
	}

	return r.ForgetPOI(nodeID)
}

// x1CodeNoSuchTask is TS 103 221-1 table 6.7-3 code 2020, "XID does not exist on
// NE". Named here rather than imported because x1 keeps its copy unexported for
// the server side; the two must stay in step.
const x1CodeNoSuchTask = 2020

// withdrawalComplete reports whether an error from DeactivateTask means the
// tasking is already gone — which is what the withdrawal was for.
//
// Only 2020 qualifies, and only here. The POI is required to answer it for an XID
// it does not hold, and the situations that produce it are the ordinary ones: the
// POI restarted, or its keepalive fail-safe purged tasking this element could no
// longer name. Read as a failure, it makes the retry loop run hardest exactly
// when the withdrawal has most certainly succeeded, and the loop has no exit —
// the POI's answer cannot change.
//
// What that costs is both of the things the pending state exists to protect.
// taskingWithdrawalStuck says content is probably still being intercepted without
// authority; raised over tasking the POI has confirmed absent, it sends an
// operator after an interception that is not running, and an alarm that cries
// wolf is not one anybody acts on when it is real. Meanwhile the entry that can
// never clear keeps keepaliveDue true, and those keepalives are precisely what
// stops that POI's fail-safe from reclaiming any orphaned tasking it does hold.
// So the misreading manufactures the alarm for unauthorised interception and
// disables the mechanism that would end a real case of it, at once.
//
// The classification stays on this side rather than moving into the x1 client
// because 2020 only means "already done" for a withdrawal. Answering the same
// code to an activation means what it says, and folding it into the transport
// would make tasking against a vanished task look like it worked.
func withdrawalComplete(err error) bool {
	var reqErr *x1.RequestError

	return errors.As(err, &reqErr) && reqErr.Code == x1CodeNoSuchTask
}

// reportWithdrawalFailure tells the LIPF that a withdrawal did not land, and
// separately that one has now been outstanding long enough to mean something
// worse. Both are element-level conditions: they name no XID, because what an
// operator must know is that this element cannot end an interception it has been
// told to end, and a channel carrying that must not also carry whose it was.
//
// It also says *which side* the failure is on, and that is not cosmetic. A
// withdrawal whose answer this element refuses is not a POI problem: the POI may
// be answering perfectly well and being disbelieved, because the identity it
// states is not the one this SMF addressed, or its version is one this element
// does not speak. Reported only as taskingWithdrawalFailed, that presents as a POI
// at fault and sends an operator to look in the wrong place — and it is precisely
// the failure that does not resolve itself, because the pending entry never
// clears, the retries never stop, and the keepalives a pending entry earns keep
// the POI's own fail-safe from reclaiming the tasking either. Both remedies are
// held open by the same condition, so naming it is what makes it actionable.
func (s *subsystem) reportWithdrawalFailure(key string, cause error) {
	first, stuck := s.triggers.noteFailure(key)
	if s.reporter == nil {
		return
	}

	s.reportUnattributable(cause)

	if first {
		s.reporter.Notify(x1.NEIssueTaskingWithdrawalFailed,
			"a UPF did not acknowledge the withdrawal of a content trigger; retrying")
	}
	if stuck {
		s.reporter.Notify(x1.NEIssueTaskingWithdrawalStuck,
			"a content trigger has been unacknowledged since its withdrawal was ordered, "+
				"long enough that content interception is probably continuing without authority")
	}
}

// forgetDestination drops the belief that this POI still holds our destinations, so
// the next trigger re-provisions them. A POI restart is a routine event and takes its
// whole destination registry with it, so all of them go and not just the one whose
// trigger happened to fail.
func (e *upfEndpoint) forgetDestination() {
	e.mu.Lock()
	defer e.mu.Unlock()
	clear(e.dids)
}

// ensureDestinations provisions the X3 endpoints a task names at this UPF, and
// returns the destination identifiers to put on its trigger.
//
// Provisioned once per address per POI, and the DID is remembered: two warrants
// naming one endpoint share it. The POI deduplicates delivery by address, so a
// second identifier for the same endpoint would buy nothing and would split that
// endpoint's fault reporting across two identifiers the ADMF would have to
// reassemble.
//
// A DID is recorded only once CreateDestination has succeeded. Recording it first
// would leave the trigger naming a destination the POI does not hold, which
// RequireResolvableDIDs at the POI refuses — correctly, and pointlessly, since this
// element could have known.
func (s *subsystem) ensureDestinations(endpoint *upfEndpoint, addresses []string) ([]string, error) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()

	dids := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		did, held := endpoint.dids[addr]
		if held {
			dids = append(dids, did)

			continue
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, err
		}

		did = x1.NewUUID()
		if err := endpoint.req.CreateDestination(x1.Destination{
			DID:          did,
			DeliveryType: "X3Only",
			Address:      host,
			Port:         uint16(p),
		}); err != nil {
			return nil, err
		}

		endpoint.dids[addr] = did
		dids = append(dids, did)
	}

	return dids, nil
}

// reportUnattributable tells the LIPF that this element received an X1 answer it
// could not bind to the request that produced it, naming the envelope field that
// disagreed and nothing else.
//
// It is called beside a task-level report rather than instead of one: on this path
// the element does know which warrant it was installing, so the task issue is
// true and useful. What it cannot convey is *which side* the fault is on, and that
// is what this adds. A response that cannot be attributed is an element-level
// condition however much context the caller happens to hold.
func (s *subsystem) reportUnattributable(cause error) {
	var unattributable *x1.ResponseError
	if s.reporter == nil || !errors.As(cause, &unattributable) {
		return
	}
	s.reporter.Notify(x1.NEIssueX1ResponseUnattributable,
		"a POI's answer could not be bound to the request that produced it ("+
			unattributable.Field+"); the POI may be answering correctly and being refused here")
}

// reportTaskIssue tells the LIPF that an authorised interception is not producing
// the content it authorises (TS 33.128 clause 5.2.6). It names the warrant, never
// the target, and never reaches a general log.
func (s *subsystem) reportTaskIssue(warrant types.XID, details string) {
	s.reportTaskIssueAs(warrant, x1.TaskReportTerminatingFault, details)
}

// reportTaskIssueAs is reportTaskIssue with the severity stated by the caller.
//
// The two exist separately because the distinction is the LIPF's to act on: a trigger that
// could not be installed has stopped the interception outright, and one a POI reports as not
// running has stopped its product while the tasking on both sides remains in place. Sending the
// second as a terminating fault would ask a LIPF to re-provision an element with nothing wrong
// with its provisioning.
//
// An empty warrant reports nothing rather than reporting under an empty XID, which the schema
// would refuse and which would in any case name no warrant.
func (s *subsystem) reportTaskIssueAs(warrant types.XID, reportType, details string) {
	if s.taskReporter == nil || warrant == "" {
		return
	}
	s.taskReporter.NotifyTask(string(warrant), reportType, details)
}

// taskIssueSender is a taskIssueReporter that says whether the LIPF took the report, as the x1
// Reporter does.
type taskIssueSender interface {
	ReportTaskIssue(xid, reportType, details string) error
}

// sendTaskIssueAs is reportTaskIssueAs for a caller that needs to know the report was delivered.
// A reporter that cannot say is taken at its word, and with none configured there is nobody to
// tell, so both count as delivered.
func (s *subsystem) sendTaskIssueAs(warrant types.XID, reportType, details string) error {
	if s.taskReporter == nil || warrant == "" {
		return nil
	}
	if sender, ok := s.taskReporter.(taskIssueSender); ok {
		return sender.ReportTaskIssue(string(warrant), reportType, details)
	}
	s.taskReporter.NotifyTask(string(warrant), reportType, details)

	return nil
}

// triggerKey identifies one installed trigger: a warrant, a session, and the UPF
// it was installed at. A session served by several UPFs needs one trigger each.
func triggerKey(warrant types.XID, ref, nodeID string) string {
	return string(warrant) + "|" + ref + "|" + nodeID
}

// plannedTrigger is one trigger this CC-TF has claimed and is about to install.
type plannedTrigger struct {
	endpoint *upfEndpoint
	key      string
	// warrant is the XID of the warrant this trigger serves — what a task issue
	// names, as opposed to trigger.XID, which is this CC-TF's own.
	warrant types.XID
	// addresses are the X3 endpoints this warrant's content goes to. They are
	// carried rather than the DIDs because turning one into the other means
	// provisioning it at the POI, which is a network exchange and belongs on the
	// install goroutine — plan runs under the session lock. trigger.DIDs is filled
	// in there.
	addresses []string
	trigger   x1.Trigger
}

// x3Destinations is where this task's content goes.
//
// The task's own destinations first, which is what TS 33.128 requires and what the
// IRI path does (see x2Destinations, which this mirrors deliberately: the two
// answer the same question for the two interfaces).
//
// **The configured MDF3 serves a task that named no destination, not one whose
// destinations produced no X3 endpoint.** The two were the same test — an empty resolved
// list — and they are different facts: a task that named nothing is a gap the
// provisioning function left, and one that named only X2 destinations is an assertion
// this element cannot honour by substituting an endpoint of its own. On an element
// serving several agencies the substitution sends a warrant's content to whichever
// address local configuration happens to name. x1 refuses that task with 3040 before
// it is stored, so the branch below is a backstop, kept for the reason x2Destinations
// keeps its own.
//
// Until the task's own destinations were consulted at all, the configured endpoint served
// *every* task, so two agencies' content arrived at whichever address configuration
// happened to name. This is the last of that defect, and it is the same one the IRI path
// had.
func (r *triggerRegistry) x3Destinations(t types.InterceptTask) []string {
	if addrs := t.DeliveryAddresses(types.DeliveryX3); len(addrs) > 0 {
		return addrs
	}
	if len(t.DIDs) > 0 {
		return nil
	}
	if r.mdf3 == "" {
		return nil
	}

	return []string{r.mdf3}
}

// plan claims a trigger XID for every (warrant, session, UPF) triple that does
// not already have one, and returns the triggers to install together with the
// warrants whose serving UPF has no configured triggering endpoint.
//
// Claiming happens here rather than in the install goroutine because the caller
// holds the session lock, and that is what orders it against untriggerCC taking
// the same session's triggers away. Claiming later let a release that ran first
// find nothing to withdraw, after which the install put a trigger at the POI that
// nothing would ever remove — tasking outliving the session it was for, which is
// exactly what must not exist.
//
// A triple that is already claimed is skipped: concurrent establishment and
// mid-session activation can both reach it, and tasking a POI twice for one
// session would have it deliver each packet twice. The detection criterion is the
// session's SEID, which does not change for the life of the PFCP session, so there
// is nothing a ModifyTask would update.
//
// A zero correlation identifier means the anchor's PFCP session does not exist
// yet, so nothing can be planned: a trigger without it is refused by x1.Trigger,
// and reporting that refusal to the LIPF would describe a session that is merely
// still coming up as an interception that has failed. The anchor's establishment
// response brings the CC-TF back here.
//
// undeliverable carries the warrants whose content has nowhere to go — the task
// names no destination and no MDF3 is configured, or the destinations it names give
// no X3 endpoint (see x3Destinations). It is reported separately from unreachable because the two are
// different faults with different remedies: one is a UPF this element cannot task,
// the other a destination it cannot find.
//
// The warrants are read by currentTasks under the registry's lock, so they are the ones the
// store holds when the claims are made. The X1 hooks change the store first and then take a
// warrant's claims under the same lock: a change that lands before the read is seen by it, and
// one that lands after finds the claims made here.
func (r *triggerRegistry) plan(
	ref string, currentTasks func() []types.InterceptTask, upfs []upfSession, correlation uint64,
) (planned []plannedTrigger, unreachable, undeliverable []types.XID) {
	if correlation == 0 {
		return nil, nil, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	tasks := currentTasks()

	// A warrant is reported unreachable once, however many of the session's UPFs this
	// element has no endpoint for. The fault is about the warrant — it is authorised
	// and some of its content cannot be attributed — and it is one fault whether one
	// UPF or three are missing an entry; a per-UPF report multiplied one condition into
	// as many unthrottled POSTs as the session had unmatched endpoints (two UPFs and
	// three warrants produced six), all of them naming the same remedy at the LIPF.
	reportedUnreachable := make(map[types.XID]bool, len(tasks))

	for _, u := range upfs {
		nodeKey, endpoint, ok := r.matchEndpoint(u)
		if !ok {
			for _, t := range tasks {
				if reportedUnreachable[t.XID] {
					continue
				}
				reportedUnreachable[t.XID] = true
				unreachable = append(unreachable, t.XID)
			}

			continue
		}

		// A session the node acknowledged before its last recorded restart carries the SEID the
		// previous incarnation assigned, which the restarted node does not hold. Its restoration
		// re-establishes it, and the answer, acknowledged by the current incarnation, brings it
		// back here. Claimed now, the trigger would detect on nothing, and the claim would make
		// that answer skip the trigger it should install. One acknowledged by a later incarnation
		// than the recorded one is current: a restart whose node could not be matched is recorded
		// only once it can be, and the node may answer new sessions meanwhile.
		if at, restarted := r.restartedAt[nodeKey]; restarted && u.acknowledgedAt.Unix() < at.Unix() {
			continue
		}

		for _, t := range tasks {
			// Where this warrant's content goes. Resolved per task rather than per
			// element: the destinations are the task's, and an element substituting its
			// own is how two agencies' content came to arrive at one endpoint.
			addresses := r.x3Destinations(t)
			if len(addresses) == 0 {
				undeliverable = append(undeliverable, t.XID)

				continue
			}

			// Keyed by the matched *configured* node, not by whatever it currently
			// resolves to, so withdrawal finds this trigger even if the UPF's address
			// moves while the session is live.
			key := triggerKey(t.XID, ref, nodeKey)
			if _, held := r.installed[key]; held {
				continue
			}

			xid := types.XID(x1.NewUUID())
			r.installed[key] = installedTrigger{
				xid: xid, warrant: t.XID, seid: u.seid, correlation: correlation,
			}
			if r.activating == nil {
				r.activating = make(map[types.XID]time.Time)
			}
			r.activating[xid] = time.Time{}
			planned = append(planned, plannedTrigger{
				endpoint:  endpoint,
				key:       key,
				warrant:   t.XID,
				addresses: addresses,
				trigger: x1.Trigger{
					XID: xid,
					// The label the POI will put on its xCC, and it must be the one this
					// element puts on its own xIRI for the same warrant — the ADMF's
					// productID where it provisioned one, per TS 103 221-1 clause 6.2.1.2.
					// The task XID is the wrong value whenever the two differ: an MDF
					// attributes on this field alone, so signalling labelled one way and
					// content the other are two unrelated intercepts to it, with nothing
					// in either stream to show they were meant to join. Both sides stay
					// well-formed and separately deliverable, which is why nothing reports
					// it. Above, t.XID is correct — the registry keys tasking by the
					// warrant this element was tasked with, not by how product is labelled.
					ProductID:     t.DeliveryXID(),
					CorrelationID: correlation,
					SEID:          u.seid,
					// DIDs are filled by installTriggers, once the addresses above
					// have been provisioned at this POI. Provisioning is a network
					// exchange and this runs under the session lock.
				},
			})
		}
	}

	return planned, unreachable, undeliverable
}

// stillHolds reports whether this registry is still answerable for the trigger
// claimed under key — either because it is installed, or because a withdrawal of
// it is pending. False means nobody is tracking it, and the caller must take it
// down itself.
//
// A pending entry counts as held on purpose: the retry loop already owns that
// trigger, and a second party withdrawing the same XID concurrently is two
// requests where the POI's answer to one is indistinguishable from its answer to
// the other.
func (r *triggerRegistry) stillHolds(key string, xid types.XID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.installed[key].xid == xid {
		return true
	}
	_, pending := r.pending[pendingKey(key, xid)]

	return pending
}

// holds reports whether this process is answerable for the given trigger, and
// whether it is on its way out. The registry is keyed by (warrant, session, UPF),
// so this is a scan — it runs once per reconciliation, over a set the size of the
// live interceptions.
//
// withdrawing separates "ours and running" from "ours and being withdrawn":
// reconciliation must leave both alone, but only the first is a trigger whose
// health at the POI is worth reporting.
func (r *triggerRegistry) holds(xid types.XID) (held, withdrawing bool) {
	held, withdrawing, _ = r.holdsFor(xid)

	return held, withdrawing
}

// holdsFor is holds, and also which warrant the trigger serves.
//
// The warrant is empty for a trigger on its way out: a pending withdrawal is keyed by the
// trigger's XID and the entry does not carry the warrant, and it does not need to — a trigger
// that is meant to stop is exempt from being reported as faulty for having stopped.
func (r *triggerRegistry) holdsFor(xid types.XID) (held, withdrawing bool, warrant types.XID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, installed := range r.installed {
		if installed.xid == xid {
			return true, false, installed.warrant
		}
	}
	for _, p := range r.pending {
		if p.xid == xid {
			return true, true, ""
		}
	}

	return false, false, ""
}

// release forgets a trigger that could not be installed, so a later attempt
// retries rather than assuming it is in place.
func (r *triggerRegistry) release(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.unhealthy, r.installed[key].xid)
	delete(r.installed, key)
}

// takeForSession moves every trigger installed for one session into the
// pending-removal state, ready to be withdrawn.
func (r *triggerRegistry) takeForSession(ref string) []withdrawal {
	return r.take(func(warrant, session, _ string) bool { return session == ref })
}

// takeForWarrant moves every trigger installed for one warrant, wherever it was
// installed, into the pending-removal state. Used when a warrant is deactivated
// while its sessions are still live.
func (r *triggerRegistry) takeForWarrant(warrant types.XID) []withdrawal {
	// The warrant is going, so what a POI last said about its triggers is no longer an answer
	// this element should give about anything. Left behind it would be both a stale fault and an
	// entry nothing ever removes.
	r.noteHealthy(warrant)

	return r.takeForWarrantExcept(warrant, nil)
}

// takeForWarrantExcept is takeForWarrant for a warrant whose task has been
// modified rather than removed: the triggers for sessions in keep stay installed,
// because the modified task still covers them and their interception is not
// meant to be interrupted.
func (r *triggerRegistry) takeForWarrantExcept(warrant types.XID, keep map[string]bool) []withdrawal {
	return r.take(func(w, session, _ string) bool {
		return w == string(warrant) && !keep[session]
	})
}

// forgetRestartedPOI discards the claims held for the POI serving one node, matched the way
// every other trigger path matches it.
//
// It exists because the caller knows a node and its address and the registry is keyed by a
// configured string, and only the registry can turn one into the other. Doing it here rather
// than at the call site is also what keeps the *one* matching rule in one place: an
// unresolvable node never matches, which is right — a claim discarded for the wrong POI would
// re-install one element's tasking at another's, which is the defect matchEndpoint's own
// documentation exists to prevent.
//
// It also says which of three things is true, because a node that matched nothing is two
// different cases. Either this element can rule the node out — it is not a configured point of
// interception, and there was nothing to discard — or it cannot tell, because the address
// either side would be compared by is not known yet. Only the second may hold anything back.
//
// A non-zero recovery is recorded for the matched POI before its claims are dropped, so a plan
// that runs after the drop claims nothing for a session the previous incarnation acknowledged,
// and a claim made before the record is among those dropped.
//
// The lock is taken twice deliberately. matchEndpoint documents needing r.mu and ForgetPOI
// takes it itself; nothing between the two can invalidate the key, because endpoints and
// order are written once at construction.
func (r *triggerRegistry) forgetRestartedPOI(session upfSession, recovery time.Time) (int, restartMatch) {
	r.mu.Lock()
	key, _, ok := r.matchEndpoint(session)
	ruledOut := !ok && r.canRuleOut(session)
	if ok && !recovery.IsZero() {
		if r.restartedAt == nil {
			r.restartedAt = make(map[string]time.Time)
		}
		// The newest restart only: a retry settling an earlier one may run after it.
		if at, held := r.restartedAt[key]; !held || recovery.After(at) {
			r.restartedAt[key] = recovery
		}
	}
	r.mu.Unlock()

	switch {
	case ok:
		return r.ForgetPOI(key), restartAtPOI
	case ruledOut:
		return 0, restartNotAtPOI
	default:
		return 0, restartUndecidable
	}
}

// knownAddress reports whether addr is an address a node can be compared by: what ResolveNodeIdToIp
// returns for a node it could not resolve is the unspecified address, and a nil IP prints as
// "<nil>".
func knownAddress(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && !ip.IsUnspecified()
}

// canRuleOut reports whether a node matchEndpoint did not match is known not to be a configured
// point of interception. It is not when the comparison matchEndpoint falls back to could not be
// made: the node's own address is unknown, or a configured name has not resolved yet and so
// might be that node. The caller holds r.mu.
func (r *triggerRegistry) canRuleOut(session upfSession) bool {
	if len(r.order) == 0 {
		return true
	}
	if !knownAddress(session.addr) {
		return false
	}
	for _, key := range r.order {
		if r.resolved[key] == "" {
			return false
		}
	}

	return true
}

// ForgetPOI discards this element's record of what a triggered point of interception
// holds, because that point of interception has restarted and holds none of it.
//
// A triggered POI keeps its tasking in memory, so a restart takes all of it. This
// element's record of what it installed survives, and every claim in that record now
// describes tasking that does not exist. The planning path then finds each triple
// already claimed and installs nothing — so the restarted POI holds no tasking, produces
// no content, and discards the copies it is told to make as untasked, while this element
// goes on reporting the interception as running. Nothing else corrects it: claims are
// released by a withdrawal, and there is nothing left to withdraw.
//
// It is the mirror of the rule that a triggering function which cannot say what a POI
// holds must stay silent and let the fail-safe act. There this element restarted; here
// the POI did, and the conclusion is the same for the same reason — a claim that cannot
// be true must not be treated as one.
//
// Dropping the claims also makes the liveness signal correct again, and that falls out
// rather than needing its own step: keepaliveDue owes a signal for tasking this element
// can name, so an endpoint it now names none for stops being kept alive. That is the
// right answer — keeping a restarted POI alive on the strength of tasking that no longer
// exists is what disables its own fail-safe.
//
// **What this does not do is restore the subscriber's sessions.** That is the SMF's session
// restoration, which GateRestoration starts for a detected restart only once this has run.
// What is in scope is that the interception bookkeeping is not the reason re-tasking cannot
// happen: after this, an establishment at the restarted POI — a restored one included, since
// it is answered through the ordinary response handler — or a scan installs the trigger
// instead of skipping it as already claimed.
func (r *triggerRegistry) ForgetPOI(nodeID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	// This element's account of what that POI holds is exactly what has just become
	// untrustworthy, so it is no longer reconciled. The claims below are dropped without being
	// withdrawn — right when the POI really restarted and holds nothing, and wrong when it is
	// merely unreachable and holds everything — and reconciling again is how the second case
	// is discovered instead of assumed.
	if e, ok := r.endpoints[nodeID]; ok {
		e.forgotten++
		e.forgetReconciled()
	}

	forgotten := 0
	for key := range r.installed {
		_, _, keyNode, ok := parseTriggerKey(key)
		if !ok || keyNode != nodeID {
			continue
		}
		// Deleted outright rather than moved to pending: a pending withdrawal is a
		// trigger this element is still trying to remove *from a POI that holds it*,
		// and retrying against one that restarted would report a fault about tasking
		// that is already gone. Kept as discarded, so a POI that merely stopped
		// answering is told when the trigger's warrant or session goes before it is
		// reconciled.
		if r.discarded == nil {
			r.discarded = make(map[string]discardedClaim)
		}
		xid := r.installed[key].xid
		r.discarded[pendingKey(key, xid)] = discardedClaim{key: key, xid: xid}
		delete(r.unhealthy, xid)
		delete(r.installed, key)
		forgotten++
	}

	return forgotten
}

// forgetCount returns how many times ForgetPOI has discarded this element's account of e.
func (r *triggerRegistry) forgetCount(e *upfEndpoint) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	return e.forgotten
}

// markReconciledSince marks the endpoint configured as nodeID reconciled, drops the claims
// ForgetPOI discarded there, and reports true, unless ForgetPOI has discarded this element's
// account of it since forgetCount returned forgotten. Under the lock ForgetPOI holds, so a
// ForgetPOI is either counted here or clears the mark after it.
func (r *triggerRegistry) markReconciledSince(nodeID string, forgotten uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	e := r.endpoints[nodeID]
	if e.forgotten != forgotten {
		return false
	}
	e.markReconciled()
	for pkey, discarded := range r.discarded {
		if _, _, keyNode, ok := parseTriggerKey(discarded.key); ok && keyNode == nodeID {
			delete(r.discarded, pkey)
			delete(r.unhealthy, discarded.xid)
		}
	}

	return true
}

// take moves every installed trigger whose key matches into pending, and returns
// them.
//
// It does not delete. Deciding to withdraw a trigger is not the same as having
// withdrawn it, and the registry that forgets on the decision has no way to retry
// and no way to know it should: the POI keeps the trigger, keeps duplicating, and
// every participant believes the interception ended. Only an acknowledged
// DeactivateTask deletes (see forgetPending).
//
// Returned sorted by key so a caller's retry order — and a test's — is the same
// every time.
func (r *triggerRegistry) take(match func(warrant, session, nodeID string) bool) []withdrawal {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []withdrawal
	for key, installed := range r.installed {
		warrant, session, nodeID, ok := parseTriggerKey(key)
		if !ok || !match(warrant, session, nodeID) {
			continue
		}
		pkey := pendingKey(key, installed.xid)
		out = append(out, withdrawal{key: pkey, nodeID: nodeID, xid: installed.xid})
		delete(r.installed, key)
		delete(r.unhealthy, installed.xid)
		r.pending[pkey] = &pendingWithdrawal{xid: installed.xid, nodeID: nodeID, since: r.timeNow()}
	}
	// And the claims ForgetPOI discarded, which the POI may still hold. One it does not hold is
	// answered 2020, which completes the withdrawal.
	for pkey, discarded := range r.discarded {
		warrant, session, nodeID, ok := parseTriggerKey(discarded.key)
		if !ok || !match(warrant, session, nodeID) {
			continue
		}
		delete(r.discarded, pkey)
		delete(r.unhealthy, discarded.xid)
		if _, owned := r.pending[pkey]; owned {
			continue
		}
		out = append(out, withdrawal{key: pkey, nodeID: nodeID, xid: discarded.xid})
		r.pending[pkey] = &pendingWithdrawal{xid: discarded.xid, nodeID: nodeID, since: r.timeNow()}
	}
	slices.SortFunc(out, func(a, b withdrawal) int { return strings.Compare(a.key, b.key) })

	return out
}

// takeFailedActivation moves a trigger whose activation did not clearly fail into
// the pending-removal state, and reports whether the caller now owns withdrawing it.
//
// It exists because a failed ActivateTask is not evidence the POI holds nothing.
// Only a refusal the POI *states* is that; a timeout, a lost response or an answer
// this element cannot bind says nothing at all, and the POI may have applied the
// task and answered. Releasing on that outcome leaves a trigger installed that this
// process can no longer name — absent from both maps, so a warrant's withdrawal and
// a session's release each find nothing, and reconciliation only runs at startup.
// The POI then keeps duplicating a subject's content under a warrant that may since
// have been revoked, which is the failure the withdrawal path already exists to
// prevent, reached from the activation side.
//
// Three states are possible when this runs, and each has one right answer:
//
//   - a withdrawal of this exact trigger is already pending — untriggerCC ran while
//     the activation was in flight — and the retry loop already owns it. False: two
//     parties withdrawing one XID is two requests whose answers are
//     indistinguishable.
//   - this trigger is still the claim under its key. Take it.
//   - the key has been re-claimed under a newer XID, so ours is tracked by nothing.
//     Take it anyway, without disturbing the newer claim — that is precisely the
//     orphan this exists to prevent.
func (r *triggerRegistry) takeFailedActivation(key string, xid types.XID) (withdrawal, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pkey := pendingKey(key, xid)
	if _, owned := r.pending[pkey]; owned {
		return withdrawal{}, false
	}

	// Only if it is still ours: a newer claim under this key belongs to a later
	// trigger and deleting it would strand that one instead.
	if r.installed[key].xid == xid {
		delete(r.installed, key)
	}
	delete(r.unhealthy, xid)

	_, _, nodeID, ok := parseTriggerKey(key)
	if !ok {
		// Unaddressable, so no withdrawal can be sent anywhere and a pending entry
		// would never clear. Every key this element builds parses; if one ever does
		// not, leaving it out is better than a retry loop with no exit.
		return withdrawal{}, false
	}

	r.pending[pkey] = &pendingWithdrawal{xid: xid, nodeID: nodeID, since: r.timeNow()}

	return withdrawal{key: pkey, nodeID: nodeID, xid: xid}, true
}

// takeOrphan puts a trigger this process never installed — one reconciliation
// found at a POI, left by a previous life — into the same pending-removal state as
// any other withdrawal.
//
// Its key is synthetic: an orphan has no warrant and no session this process can
// name, which is exactly what made it an orphan. Nothing parses a pending key, so
// it need only be unique, and the XID it is built from already is.
func (r *triggerRegistry) takeOrphan(nodeID string, xid types.XID) withdrawal {
	key := pendingKey("orphan|"+nodeID, xid)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending[key] = &pendingWithdrawal{xid: xid, nodeID: nodeID, since: r.timeNow()}

	return withdrawal{key: key, nodeID: nodeID, xid: xid}
}

// forgetPending drops a pending withdrawal the POI has acknowledged — the one
// event that ends this registry's responsibility for a trigger.
func (r *triggerRegistry) forgetPending(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.pending[key]; ok {
		delete(r.unhealthy, p.xid)
		delete(r.activating, p.xid)
	}
	delete(r.pending, key)
}

// noteFailure records that a withdrawal attempt failed and reports which
// conditions this attempt newly raises. Each is raised once per pending entry: the
// LIPF needs to hear that a withdrawal failed, and separately that one has been
// outstanding long enough that content is likely still being intercepted without
// authority, but it needs to hear each of them once.
func (r *triggerRegistry) noteFailure(key string) (first, stuck bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.pending[key]
	if !ok {
		return false, false
	}
	if !p.failureReported {
		p.failureReported = true
		first = true
	}
	if !p.stuckReported && r.timeNow().Sub(p.since) >= withdrawalStuckAfter {
		p.stuckReported = true
		stuck = true
	}

	return first, stuck
}

// pendingCount is how many withdrawals are outstanding — the registry's own
// measure of interception it has decided to end and cannot prove has ended.
func (r *triggerRegistry) pendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.pending)
}

// timeNow and sleepFor are the registry's clock. They tolerate a nil hook so a
// registry can be built as a literal without every caller wiring a clock it does
// not care about.
func (r *triggerRegistry) timeNow() time.Time {
	if r.now != nil {
		return r.now()
	}

	return time.Now()
}

func (r *triggerRegistry) sleepFor(d time.Duration) {
	if r.sleep != nil {
		r.sleep(d)

		return
	}
	time.Sleep(d)
}

// withdrawalBackoff is the delay before retry number attempt: 5s doubling to the
// keepalive interval, then steady. Bounded in effort, unbounded in intent — a
// retry that gives up is the defect this exists to fix, arriving later.
func withdrawalBackoff(attempt int) time.Duration {
	d := withdrawalRetryInitial
	for i := 0; i < attempt && d < liKeepaliveInterval; i++ {
		d *= 2
	}
	if d > liKeepaliveInterval {
		return liKeepaliveInterval
	}

	return d
}

// parseTriggerKey splits a key back into its warrant, session and UPF parts. A
// node address contains no "|", so splitting into exactly three is unambiguous.
func parseTriggerKey(key string) (warrant, session, nodeID string, ok bool) {
	parts := strings.Split(key, "|")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// retriggerWarrant reconciles the triggers held for a warrant against the sessions
// its modified task still covers. This is the X1 modification path: the warrant
// remains, so what changes is which of its sessions are tasked for content — and
// a session tasked before and after keeps the trigger it has.
//
// The set of sessions to keep is computed first and the registry is then read
// once, so no trigger installed for the new task can be withdrawn by the old
// task's teardown: under one XID the two are the same key, and they are settled in
// one pass rather than by two events racing.
//
// **It stays on the caller's goroutine, and that is load-bearing.** modifyInterception
// runs this before reportStartOfInterception, whose triggerCC installs triggers for
// sessions the modified task newly covers. Moving this to a goroutine would let that
// installation land between the registry read here and takeForWarrantExcept below — and
// the new trigger's session, absent from `keep`, would then be withdrawn by the pass that
// was meant to leave it alone, which is the race the ordering above exists to prevent.
//
// It is safe to keep here because it costs no walk of the session pool: the work is
// bounded by this warrant's own triggers (see sessionsWithTriggers), so a provisioning
// function's answer does not scale with the element's subscriber population.
func (s *subsystem) retriggerWarrant(next types.InterceptTask) {
	if s.triggers == nil {
		return
	}

	var keep map[string]bool
	if next.WantsProduct(types.ProductCC) {
		// Bounded by this warrant's own triggers, not by the session population. See
		// sessionsWithTriggers for why that is the whole of what the caller can act on.
		keep = sessionsCovered(next, s.triggers.sessionsWithTriggers(next.XID))
	}

	pending := s.triggers.takeForWarrantExcept(next.XID, keep)
	if len(pending) == 0 {
		return
	}

	go s.deactivate(pending)
}

// sessionsWithTriggers returns the session references this registry holds triggers for
// under one warrant.
//
// It is what bounds the modification path, and it is bounded correctly rather than
// merely narrowed: `keep` has exactly one consumer, takeForWarrantExcept, which tests
// it while iterating this warrant's installed triggers. A session no trigger exists for
// could never be consulted, so computing an answer for it would be work whose result is
// unobservable.
//
// The alternative, walking every live session and taking every session's lock per
// modification, would run on the X1 request goroutine, so a provisioning function's answer
// would take time proportional to the element's subscriber population. Which of the triggers
// this element holds a modified task still covers is a fact about the registry, and the
// registry knows it.
//
// A session served by several UPFs holds a trigger per UPF and appears once here.
func (r *triggerRegistry) sessionsWithTriggers(warrant types.XID) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []string
	for key := range r.installed {
		w, session, _, ok := parseTriggerKey(key)
		if !ok || w != string(warrant) {
			continue
		}
		if !slices.Contains(out, session) {
			out = append(out, session)
		}
	}

	return out
}

// sessionsCovered returns which of refs the given task still targets.
//
// The registry lock is deliberately *not* held across this. plan takes the two the other
// way round — the session's lock first, then the registry's — so holding the registry's
// while acquiring a session's would invert that ordering. The caller reads the refs under
// r.mu, releases it, and only then arrives here.
//
// Each session's identity is read under its own lock, as scanSessions does.
func sessionsCovered(task types.InterceptTask, refs []string) map[string]bool {
	covered := make(map[string]bool, len(refs))
	for _, ref := range refs {
		sc := smfctx.GetSMContext(ref)
		if sc == nil {
			// Released between the registry read and now. Not covered — and withdrawing
			// the trigger of a session that has gone is what that session needs anyway.
			continue
		}

		sc.SMLock.Lock()
		hit := sessionTargets(task, sc)
		sc.SMLock.Unlock()

		if hit {
			covered[ref] = true
		}
	}

	return covered
}

// relabelWarrant carries a change in how a warrant's product is labelled, or in
// where its content goes, to the triggers already installed for it.
//
// The triggers are not torn down and reinstalled. The XID this CC-TF allocated stays,
// the session keeps being intercepted, and a `ModifyTask` carries the new values —
// which is what TS 33.128 table 6.2.3-8 provides for. Withdrawing and reactivating
// would interrupt content the warrant still authorises, to change a label.
//
// Only the fields a POI acts on are compared. A modification that leaves the delivery
// identifier, the correlation value and the destinations alone reaches no POI, because
// there is nothing for one to do differently.
//
// Best-effort per trigger, and deliberately so: a POI that cannot be reached keeps
// labelling content with the superseded identifier, which is a task-level fault the
// LIPF is told about rather than a reason to stop the interception. The alternative —
// withdrawing what cannot be relabelled — would end an interception the warrant still
// authorises because a message did not land.
func (s *subsystem) relabelWarrant(prev, next types.InterceptTask) {
	if s.triggers == nil || !next.WantsProduct(types.ProductCC) {
		return
	}
	// The task's own CorrelationID is deliberately absent from this test. relabel sends
	// installed.correlation — the session's, which is what the POI must stamp so content
	// joins to signalling — so a change to the provisioned value changed nothing at
	// either end and cost an X1 exchange to every POI to do it. The field is now refused
	// at this element anyway (x1.HonoursCorrelationID is not set here), which makes it
	// unreachable rather than merely inert.
	if prev.DeliveryXID() == next.DeliveryXID() &&
		slices.Equal(s.triggers.x3Destinations(prev), s.triggers.x3Destinations(next)) {
		return
	}

	planned := s.triggers.relabel(next, s.triggers.x3Destinations(next))
	if len(planned) == 0 {
		return
	}

	// Ordered per warrant rather than dispatched on a bare goroutine: two
	// modifications in quick succession must leave the POI holding the second one's
	// values, and on bare goroutines they complete in either order with both
	// exchanges acknowledged.
	s.triggers.dispatchForWarrant(next.XID, func() { s.modifyTriggers(planned) })
}

// modifyTriggers sends the ModifyTask for each relabelled trigger.
//
// Off the caller's goroutine as installTriggers is, and for the same reason — these
// are synchronous HTTPS round trips and the caller is the X1 request goroutine —
// but through the registry's per-warrant queue rather than a bare go, because two
// relabels of one warrant must reach the POI in the order the ADMF sent them.
func (s *subsystem) modifyTriggers(planned []plannedTrigger) {
	for _, p := range planned {
		dids, err := s.ensureDestinations(p.endpoint, p.addresses)
		if err != nil {
			s.reportTaskIssue(p.warrant, "the modified X3 delivery destination could not be provisioned at the UPF")
			s.reportUnattributable(err)

			continue
		}
		p.trigger.DIDs = dids

		if err := p.endpoint.req.ModifyTask(p.trigger); err != nil {
			// The trigger stays installed and stays tracked: it is still intercepting,
			// under the label it was given. What the LIPF needs to know is that the
			// element could not apply the modification it acknowledged.
			s.reportTaskIssue(p.warrant, "the UPF did not accept a modification to a content trigger")
			s.reportUnattributable(err)
		}
	}
}

// relabel returns the installed triggers for a warrant, rebuilt with the task's
// current labelling and destinations. It changes nothing in the registry: the trigger
// XIDs and the (warrant, session, UPF) keys are unchanged, because what moved is what
// the POI does with the trigger rather than which trigger it is.
func (r *triggerRegistry) relabel(task types.InterceptTask, addresses []string) []plannedTrigger {
	if len(addresses) == 0 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var out []plannedTrigger
	for key, installed := range r.installed {
		warrant, _, nodeID, ok := parseTriggerKey(key)
		if !ok || warrant != string(task.XID) {
			continue
		}
		endpoint, held := r.endpoints[nodeID]
		if !held {
			continue
		}
		out = append(out, plannedTrigger{
			endpoint:  endpoint,
			key:       key,
			warrant:   task.XID,
			addresses: addresses,
			trigger: x1.Trigger{
				XID: installed.xid,
				// The warrant's new label, and the session's own criterion and
				// correlation unchanged — the trigger still detects the same traffic.
				ProductID:     task.DeliveryXID(),
				CorrelationID: installed.correlation,
				SEID:          installed.seid,
			},
		})
	}
	slices.SortFunc(out, func(a, b plannedTrigger) int { return strings.Compare(a.key, b.key) })

	return out
}

// untriggerWarrant removes every trigger installed for a warrant, wherever it was
// installed. This is the X1 deactivation path: the warrant is gone, so its
// triggers must go even though the sessions remain. Unlike the FAR state, which is
// re-evaluated against the remaining task set, a trigger belongs to exactly one
// warrant.
func (s *subsystem) untriggerWarrant(warrant types.XID) {
	if s.triggers == nil {
		return
	}

	pending := s.triggers.takeForWarrant(warrant)
	if len(pending) == 0 {
		return
	}

	go s.deactivate(pending)
}
