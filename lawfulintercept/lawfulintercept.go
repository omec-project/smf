// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package lawfulintercept is the SMF's Lawful Interception IRI-POI. It receives
// interception tasks over X1 (mutual TLS), matches PDU-session events against
// tasked targets, and delivers the resulting xIRI to an MDF2 over X2. It is
// opt-in: inactive — and silent — unless the SMF is started with LI credentials,
// so an SMF that is not intercepting behaves and looks exactly as before.
package lawfulintercept

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/omec-project/openapi/v2/models"
	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/util/li/iri"
	"github.com/omec-project/util/li/mtls"
	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
	"github.com/omec-project/util/li/x2x3"
)

// Config configures the SMF LI IRI-POI. Init is only called when LI is enabled.
type Config struct {
	// BlockError, when non-nil, is why the element's `li` configuration block was refused
	// before it reached here — an unrecognised key, most likely a misspelling of one this
	// element does model.
	//
	// It is carried rather than acted on by the loader because refusing a configuration is not
	// the same as refusing to run: the network function has work of its own, and stopping it
	// over an optional subsystem is both an outage and the loudest way to disclose that this
	// element is LI-provisioned. Interception does not start on it; the SMF does.
	BlockError error

	X1Listen string // address for the X1 provisioning listener, e.g. ":8443"
	MDF2     string // X2 delivery destination (MDF2 "host:port")
	NEID     string // this network element's identifier (echoed in X1 responses)
	Cert     string // X0-pre-provisioned LI PKI: this NE's certificate
	Key      string //                            its private key
	CACert   string //                            the LI CA trust anchor

	// MDF3 is the X3 delivery destination this CC-TF provisions at each triggered
	// CC-POI (TS 33.128 table 6.2.3-6: the trigger names destinations by DID, which
	// the triggering function configures beforehand). The UPF carries no MDF3 address
	// of its own.
	MDF3 string
	// UPFTriggers lists the LI_T3 triggering endpoints of the UPFs this SMF may
	// serve sessions with. A UPF absent from this list cannot be tasked, so CC on a
	// session it serves is reported to the LIPF as a fault rather than skipped.
	UPFTriggers []UPFTrigger

	// Destinations are DID→endpoint mappings this element can resolve without their
	// having been provisioned over X1, for destinations agreed out of band.
	Destinations []Destination

	AdmfURL string // ADMF X1 endpoint for NE-initiated issue reports (empty = disabled)
	AdmfID  string // the responsible ADMF's identifier: authenticates inbound X1 peers and addresses outbound reports (empty accepts any certified ADMF)
	// KeepaliveTimeout, KeepaliveTimeP1 and KeepaliveTimeP3 are the timers of the X1
	// keepalive procedure (TS 103 221-1 clause 6.6.2) as the operator wrote them:
	// TIME_P2, TIME_P1 and TIME_P3. Empty takes the clause default (1h, 1m, 2h). The
	// procedure runs unless KeepaliveDisabled is set, because the clause enables it by
	// default; KeepaliveRetainTasking keeps it from ever deactivating tasking.
	//
	// Strings rather than durations, and parsed inside Init, because a value this
	// element cannot read has to be *reported* — and the only channel it may be
	// reported on is the one the reporter opens, which does not exist until Init runs.
	KeepaliveTimeout       string
	KeepaliveTimeP1        string
	KeepaliveTimeP3        string
	KeepaliveRetainTasking bool
	KeepaliveDisabled      bool

	// The three settings of the TS 103 221-2 clause 6.2.4 keepalive mechanism, as the
	// operator wrote them. Parsed here rather than by the caller because an unusable
	// value is reported to the ADMF over X1, and the reporter does not exist until
	// this subsystem starts.
	X2X3KeepaliveEnabled *bool
	X2X3KeepaliveTimeP1  string
	X2X3KeepaliveTimeP2  string

	// DeactivateAllTasks and RemoveAllDestinations are the two bulk operations
	// TS 103 221-1 leaves to advance agreement between the operator and the agency.
	// Nil is "no agreement in advance" and leaves the standard's defaults, which
	// li/x1 holds; see x1.BulkOptions.
	DeactivateAllTasks    *bool
	RemoveAllDestinations *bool
}

// Destination is one pre-shared delivery destination: a DID an ADMF's tasks reference,
// and where it points. It resolves exactly as a destination provisioned over X1 does; a
// provisioned entry for the same DID wins.
type Destination struct {
	DID          string
	DeliveryType string // X2Only | X3Only | X2andX3
	Address      string // host:port
}

// errNoElementIdentifier means the deployment configured interception without the
// identifier this element asserts on X1, which is also the Network Function ID every
// record it delivers has to carry (TS 33.128 table 5.3.1-2).
var errNoElementIdentifier = errors.New("li: no network element identifier configured")

// errNoX1Listen means the deployment configured interception without an address for the
// X1 listener to bind.
//
// This is not caught by the bind: Listen(ctx, "tcp", "") *succeeds*, on every interface at
// an OS-selected ephemeral port. So interception starts, reports itself healthy, and waits
// for tasking on a port nobody — the ADMF least of all — can predict. The element is
// unprovisionable and indistinguishable from one that is merely un-tasked, which is the
// worst shape this failure could take: silent, and only visible once a warrant that was
// supposed to be running turns out never to have arrived.
var errNoX1Listen = errors.New("li: no X1 listen address configured")

// smfInterceptionPoint is the Interception Point ID every xIRI from this element
// carries (ETSI TS 103 221-2 clause 5.3.8): it names the POI within the network
// function. The SMF also hosts the CC and IRI triggering functions, but a triggering
// function delivers no product, so there is one point of interception here.
const smfInterceptionPoint = "SMF-IRI-POI"

// sender delivers an xIRI/xCC PDU to an MDF. *x2x3.Client satisfies it; tests
// inject a capturing implementation to assert per-warrant delivery isolation.
type sender interface {
	Send(*x2x3.PDU) error
}

// taskIssueReporter reports a fault with one interception task to the LIPF
// (TS 33.128 clause 5.2.6). An interface, like sender above, so tests can assert
// what the LIPF would be told without standing up an ADMF.
type taskIssueReporter interface {
	NotifyTask(xid, reportType, details string)
}

type subsystem struct {
	// keepalive is the X1 keepalive procedure this element runs, or nil when the operator
	// disabled it.
	keepalive *x1.KeepaliveProcedure

	// modMu guards modAttempts, which counts how many times an LI-initiated PFCP
	// modification has been sent for one (session, UPF) without the datapath applying it.
	// It lives here rather than travelling with the request because the send site does not
	// know how many attempts preceded it — the sequence number is allocated per send.
	modMu       sync.Mutex
	modAttempts map[modKey]int
	// resends counts the re-sends modificationNotApplied has started and not finished.
	resends sync.WaitGroup
	// modFailed holds, per (session, UPF), why this element gave up on an LI modification the
	// datapath did not apply. It is task-fault state: taskFaults reports it against every warrant
	// covering the session until a later modification for that session and UPF applies, or the
	// session goes. Guarded by modMu.
	modFailed map[modKey]string

	// scans counts the activation and deactivation scan goroutines this subsystem has
	// dispatched. Nothing in production waits on it — the whole point of the scan is
	// that a provisioning answer does not — but a scan is this subsystem's work, and
	// owning it is what lets a test wait for the walk it started rather than leaving a
	// goroutine to fail the next test with a race against a session it has finished
	// with. See waitForScans.
	scans sync.WaitGroup

	store *store.Store
	// senderFor returns the delivery client for one X2 destination address. It is a
	// function rather than a single client because a task's destinations arrive over
	// X1: two warrants may name two agencies' MDF2s, and delivering both to one address
	// is cross-agency disclosure.
	senderFor func(addr string) sender
	// unreachable answers how many of the destinations this element's tasking currently
	// names cannot be reached, and how many of them it has attempted at all — the delivery
	// pool's accounting, scoped to what is in use (see destinationsInUse). A function
	// rather than the pool itself for the same reason senderFor is one: a test states a
	// delivery condition without an MDF to take away.
	unreachable func() (unreachable, inUse int)
	// unreachableAt answers the same question about one address, which is the shape a
	// destination-scoped answer needs: an element's own status says how much is wrong, a
	// destination's says whether that one is working. Same source, so the pushed report and
	// the interrogation cannot disagree — which they did, one hard-coding activeAndWorking
	// while the other reported the endpoint unreachable.
	unreachableAt func(addr string) bool
	// mdf2 is the configured X2 endpoint, used only for a task that names no
	// destination at all (see x2Destinations).
	mdf2 string
	neID string
	// ids supplies the conditional attributes that belong to this element rather than
	// to the task — its two identities and the per-context sequence numbering — shared
	// with the AMF's IRI-POI and the UPF's CC-POI through li/x2x3.
	ids      *x2x3.Identity
	reporter *x1.Reporter // nil when NE-initiated reporting is not configured
	// taskReporter reports per-task faults; nil when no ADMF is configured.
	taskReporter taskIssueReporter
	// triggers is the CC Triggering Function's state: one X1 client per UPF, plus
	// the trigger tasks installed there. Nil when no triggering endpoints are
	// configured, in which case CC duplication is still applied but the UPF is
	// never told whose warrant it serves — so it delivers nothing.
	triggers *triggerRegistry
}

// deliveryFault is what this element can answer about itself when an ADMF asks for its
// status: whether the mediation functions it delivers to are reachable right now.
//
// Only the delivery clients know this — li/x1 holds the tasking, not the sockets — so
// without it the element would answer that no observable condition holds however long it had
// been failing to deliver. That answer is true and useless, and it is ignored exactly as
// fast as an element that always reports itself faulty.
//
// It answers from what the last delivery attempt established and dials nothing, because it
// runs on the X1 request goroutine: a probe that went looking would hold up a provisioning
// function's answer.
//
// This is the element's own status, so it covers this POI's X2 delivery only. Whether the
// UPF it triggers can reach its MDF3 is that element's status to report, and it has an X1
// interface of its own to report it on.
//
// It asks only about the destinations this element's *current* tasking names — see
// destinationsInUse — so a warrant's withdrawal takes its destination out of the answer with
// it.
//
// A subsystem with no delivery accounting reports nothing rather than panicking on the X1
// request path — an element that cannot say is not an element that is broken.
func (s *subsystem) deliveryFault() *x1.X1Error {
	if s.unreachable == nil {
		return nil
	}

	return x1.MDFUnreachableProbe(s.unreachable)()
}

// destinationUnreachable is whether delivery to one address is currently failing, for the
// destination status the provisioning function can ask for.
//
// A method rather than the field itself so that an element with no delivery pool — a test, or
// an element built before the pool exists — answers "reachable" rather than panicking. That
// answer is also the one the X1 layer defaults to, so the two agree.
func (s *subsystem) destinationUnreachable(addr string) bool {
	if s.unreachableAt == nil {
		return false
	}

	return s.unreachableAt(addr)
}

// destinationsInUse is where this element's xIRI currently goes: the X2 endpoints the tasking
// it holds names, and the configured MDF2 for a task that names no destination at all.
//
// It exists because a delivery client outlives the warrant that created it. A destination
// whose last delivery failed and whose warrant was then deactivated can never be delivered to
// again, so nothing would ever clear it — the element would report itself faulty for the life
// of the process, including while holding no tasking at all. Scoping the question to what is
// in use is what keeps that probe from sticking on.
func (s *subsystem) destinationsInUse() []string {
	var addrs []string
	for _, t := range s.store.Snapshot() {
		addrs = append(addrs, s.iriDestinations(t)...)
	}

	return addrs
}

// iriDestinations is where t's xIRI goes, and nothing for a task that wants none. A task
// ordering only content is triggered at the UPF and delivers no xIRI from here, so the
// configured MDF2 is not one of its destinations even though it names none of its own.
func (s *subsystem) iriDestinations(t types.InterceptTask) []string {
	if !t.WantsProduct(types.ProductIRI) {
		return nil
	}
	return s.x2Destinations(t)
}

// x2Health is what the destination watcher samples: the X2 destinations the tasking delivers
// xIRI to, each with its reachability. It resolves through iriDestinations, the same question
// destinationsInUse asks, so the configured MDF2 serving a task that named no DID is watched,
// and an MDF2 no task delivers xIRI to is not: watched for a content-only task, an MDF2 whose
// last delivery failed would be reported unreachable for as long as that task lived, while the
// status answer said nothing was in use.
func (s *subsystem) x2Health(unreachableAt func(addr string) bool) []x1.DestinationHealth {
	return x1.DestinationHealthOf(s.store.Snapshot(), types.DeliveryX2, s.iriDestinations, unreachableAt)
}

// active holds the running subsystem, or nil when LI is not configured.
var active atomic.Pointer[subsystem]

// newX1Server builds this element's X1 provisioning endpoint from its configuration.
//
// Separate from Init so that what an operator's configuration does to the X1 server can be
// asserted against the server this element actually runs, rather than against a second
// copy of the same wiring written in a test — which is where a configured policy quietly
// stops being applied.
func newX1Server(st *store.Store, cfg Config, sub *subsystem) *x1.Server {
	// OnTaskChange scans already-established sessions when a warrant is (de)tasked
	// or modified mid-session: emit the "start with established PDU session" xIRI
	// and (de)activate CC duplication on live sessions.
	// WithADMF holds X1 peers to the responsible ADMF's identity: a certificate
	// from the LI CA authenticates a peer, but only this identifier may task us
	// (TS 103 221-1 clause 8.2.4 + error 1040).
	// A peer that fails that check is refused, and — since this plane deliberately
	// logs nothing — would otherwise be refused in complete silence. The ADMF is the
	// only party entitled to hear that someone is trying to task its network
	// elements under an identity that is not theirs.
	opts := []x1.Option{
		x1.WithADMF(cfg.AdmfID),
		// The keepalive procedure's reports travel on the element's fault channel: the 9050
		// fault when the ADMF goes quiet, its clearing, and the 10000 alert after a purge.
		x1.KeepaliveReporter(sub.reporter),
		x1.WithConfiguredDestinations(configuredDestinations(cfg.Destinations, sub.reporter)...),
		// The conditions this POI can observe about itself, which li/x1 cannot: see
		// subsystem.deliveryFault.
		x1.WithFaultProbes(sub.deliveryFault),
		// And the same fact at destination scope, for GetDestinationDetails. Without it the
		// element answers activeAndWorking for an endpoint it is simultaneously reporting
		// as unreachable over ReportDestinationIssue — two statements about one fact, and
		// the ADMF trusts the one it asked for.
		x1.WithDestinationReachability(sub.destinationUnreachable),
		// **What this element answers about one task, and what it deliberately does not.**
		//
		// A task-scoped fault has to be a condition that stops *this* warrant's interception and
		// that this element can re-observe when asked. Two of the states this element can see
		// are the wrong shape for that, and they stay unreported per task:
		//
		//   - A subject who is not attached, or is attached and doing nothing, produces no
		//     records — and is indistinguishable from one this element has stopped watching. A
		//     fault reported for that would fire for every warrant on a quiet subscriber, and a
		//     fault channel that fires when nothing is wrong is one an ADMF learns to ignore.
		//   - Delivery failing is real and is already reported, at the two scopes that can say
		//     something true about it: the element's own status, and the destination's. A task
		//     names destinations rather than owning them, so attributing an endpoint's failure
		//     to one of the warrants pointing at it would report the same fault once per
		//     warrant and imply each was separately broken.
		//
		// **The CC triggering role is different, and is answered.** A point of interception
		// reporting that the trigger this element installed is not running is task-scoped,
		// re-observable, and means this warrant's content interception has stopped while the
		// warrant is live. Asked only once per process, at start-up, before anything was
		// installed, the condition could exist with nothing able to see it. Asking on the
		// keepalive round is what makes it a state, and taskFaults is what answers it.
		x1.WithTaskFaults(sub.taskFaults),
		x1.OnTaskChange(sub.applyTaskChange),
		// Refuse a warrant this element could never act on. It resolves subjects by
		// subscriber identity alone (see targetsOf), so a warrant naming only a UE
		// address, a tunnel endpoint or a port matches nothing here at every moment —
		// and acknowledging it tells the ADMF an interception is running that cannot
		// be. Producing nothing is also what a tasked subject who does nothing
		// produces, so the agency has no way to tell the two apart and waits.
		//
		// Refused only when *none* of the named identifiers is resolvable here: a
		// warrant naming a SUPI and a UE address is one this element can partly serve,
		// and declining it would refuse interception it is capable of performing.
		x1.CanApply(sub.canApplyHere),
		x1.OnAuthFailure(func(code int) {
			if sub.reporter == nil {
				return
			}
			// Off this goroutine: OnAuthFailure documents that it runs synchronously on
			// the X1 request goroutine and must not block, and Notify is a synchronous
			// HTTPS round trip to the ADMF. Reporting an authentication failure by
			// holding the provisioning interface open for the duration of a POST to a
			// peer that may itself be unreachable turns a refused request into a stalled
			// X1 channel — and makes the element's response time depend on whether the
			// ADMF is up, which is observable to whoever is probing it.
			//
			// The dispatch is bounded in effect rather than in count, and it is
			// NotifyAsync that makes that true, not a bare `go`.
			// The throttle is consulted on this goroutine before anything is spawned,
			// so under a flood of refusals each of these costs a mutex; spawning first
			// would have been a goroutine per refusal, which is the shape that made the
			// same fix wrong at the UPF, where the equivalent sites are driven by packet
			// rate rather than by request rate. One form, so the three elements cannot
			// reason about this hazard three times and reach three answers.
			sub.reporter.NotifyAsync(x1.NEIssueX1AuthFailed,
				fmt.Sprintf("X1 provisioning refused: peer failed authentication (error %d)", code))
		}),
	}
	// The two bulk operations the standard settles by advance agreement rather than by
	// what the element is. Unset leaves its defaults; li/x1 owns what unset means.
	opts = append(opts, x1.BulkOptions(cfg.DeactivateAllTasks, cfg.RemoveAllDestinations)...)

	return x1.NewServer(st, cfg.NEID, opts...)
}

// taskFaultInterval is how often the task-fault watcher samples, and taskFaultStop ends it.
// Zero takes the X1 reporter's throttle interval and nil runs it for the life of the process;
// only tests set them, so a watcher started by one test does not outlive it.
var (
	taskFaultInterval time.Duration
	taskFaultStop     <-chan struct{}
)

// destinationWatchInterval and destinationWatchStop do the same for the destination watcher.
var (
	destinationWatchInterval time.Duration
	destinationWatchStop     <-chan struct{}
)

// Init starts the SMF LI IRI-POI: it loads the LI credentials, opens the X1
// listener (mutual TLS), and prepares X2 delivery to the MDF2. Call it once at
// SMF startup, only when LI is configured.
func Init(cfg Config) error {
	// Without an identifier for this network element, product would reach a mediation
	// function that cannot attribute it to the element that produced it. Interception
	// does not start; the SMF itself carries on serving sessions, because a network
	// function that crash-loops over its LI configuration tells every operator that it
	// is LI-provisioned.
	if cfg.NEID == "" {
		return errNoElementIdentifier
	}

	mat, err := mtls.Load(cfg.Cert, cfg.Key, cfg.CACert)
	if err != nil {
		return err
	}
	st := store.New()
	var reporter *x1.Reporter
	if cfg.AdmfURL != "" {
		reporter = x1.NewReporter(cfg.AdmfURL, cfg.AdmfID, cfg.NEID, mat.ClientTLS())
	}
	// The refused `li` block, now that there is somewhere to report it. Checked before any
	// value out of that block is used, because the block is exactly what could not be read:
	// the keys that did decode are not trustworthy as a set, and one of the ones that did not
	// may be a keepalive timer or the fault endpoint.
	if cfg.BlockError != nil {
		reporter.Notify(x1.NEIssueInvalidConfig,
			"this element's interception configuration carries a setting it does not "+
				"recognise, so the values it would fall back on cannot be trusted; "+
				"interception has not been started")

		return cfg.BlockError
	}
	// The listener's address, before anything binds it. An empty address is a bind that
	// succeeds on an unpredictable port rather than one that fails, so nothing downstream
	// will ever report it — see errNoX1Listen. Reported to the ADMF, because an element that
	// cannot be provisioned is precisely what the ADMF needs to hear about, and refused,
	// because starting is what makes it look healthy.
	if cfg.X1Listen == "" {
		reporter.Notify(x1.NEIssueInvalidConfig,
			"no X1 listen address is configured, so this element would accept tasking on an "+
				"unpredictable port; interception has not been started")

		return errNoX1Listen
	}
	// The keepalive timers. Interception does not start on one this element cannot read —
	// it would otherwise run a procedure other than the one agreed with the agency, and look
	// healthy while it did — but the network function does, because an element that refuses
	// to run over its LI configuration is distinguishable from one that has none by anybody
	// who can see whether it is running.
	keepalive, err := keepaliveProcedure(cfg)
	if err != nil {
		reporter.Notify(x1.NEIssueInvalidConfig,
			"the configured X1 keepalive timers are not durations this element can use, so "+
				"interception has not been started")

		return err
	}
	// Deliver X2 asynchronously: the Report* hooks run on the PDU-session
	// signalling goroutine while sc.SMLock is held, so a slow or unreachable MDF2
	// must never block them — that is an availability risk and a target-observable
	// timing side channel, so delivery is asynchronous by design.
	// Worker delivery failures surface to the ADMF over X1 (throttled, NE-level,
	// no target id), never to a general log.
	//
	// One client per destination address, created on first use: a task carries the
	// endpoints its product goes to, and TS 33.128 marks them mandatory, so this
	// element cannot know them at startup.
	// The delivery-failure hook does not report. An unreachable mediation function
	// is a condition this element can re-observe — the pool's own accounting answers
	// it — so it has an ending, and TS 103 221-1 clause 5.3 requires an ending to be
	// reported too. A site that announces with nothing that retracts eventually
	// announces something nobody retracts, so both edges belong to whoever can see
	// the transition. The hook nudges that watcher, which keeps the report as prompt
	// as reporting from the hook would be, with the decision in one place.
	// Both declared before the pool because its callbacks close over them, and both are
	// only *called* once delivery is under way — by which time each is assigned.
	var (
		watcher *x1.DestinationWatcher
		sub     *subsystem
	)
	pool, err := x2x3.NewPool(mat.ClientTLS(),
		keepaliveConfig(cfg, reporter),
		// **The error is inspected, not discarded.** ErrUnitDropped says delivery to
		// this destination is working and one product unit of it was lost: a partial
		// write on a stream framer cannot be resumed without corrupting the framing, so
		// the unit is dropped whole and the connection is remade. The library
		// deliberately stops calling that unreachability — a healthy MDF must not be
		// reported as unreachable over one truncated write — and this hook discarded the
		// error, so the loss was then reported by nothing at all while the watcher
		// sampled a destination it correctly considered reachable. Product missing from
		// an agency's record with every channel that could have said so reporting
		// normality, which is the failure direction this whole plane exists to prevent.
		//
		// Reported as the same delivery loss a full queue is: from the agency's side the
		// two are one fact — an xIRI this element produced and did not deliver.
		//
		// The nudge stays for every error, this one included: what the sender concluded
		// about reachability is its own business, and the watcher's job is to re-observe
		// it promptly rather than one sampling interval later.
		func(err error) { sub.reportDeliveryError(err, watcher) },
		// Product dropped because the queue was full is reported as it happens, and
		// this hook is the only place that can report it.
		//
		// It was nil, with a comment saying drops were covered by the worker's
		// MDF-unreachable report — which AsyncSender.Unreachable's own documentation
		// contradicts in terms. Queue saturation is deliberately excluded from
		// reachability, because a full queue at one instant is a burst the buffer
		// exists to absorb rather than a fault an ADMF can act on, and that doc says
		// so and then says the drops themselves are reported as they happen. At the
		// UPF they are (x3DeliveryLost). Here nothing reported them, so a reachable
		// but slow MDF2 lost xIRI while the destination watcher went on
		// reporting the destination healthy — product missing from an agency's
		// record with every channel that could have said so reporting normality.
		//
		// Off the offering path, which is a signalling goroutine: this fires exactly
		// when delivery is already behind, so blocking here would add the reporting
		// stall to the condition being reported.
		func() {
			reporter.NotifyAsync(x1.NEIssueX2DeliveryLost,
				"xIRI dropped from the X2 delivery queue")
		},
	)
	if err != nil {
		// NewPool refuses a nil TLS configuration and keepalive timers Validate refuses.
		// Neither reaches it today: the configuration comes from the loaded material, and
		// keepaliveConfig falls back to the defaults on timers it cannot use. Checked so
		// that a change to either refuses the start instead of failing every delivery.
		return fmt.Errorf("lawful interception: X2 delivery: %w", err)
	}
	sub = &subsystem{
		store:     st,
		senderFor: func(addr string) sender { return pool.For(addr) },
		mdf2:      cfg.MDF2,
		neID:      cfg.NEID,
		ids:       x2x3.NewIdentity(cfg.NEID, smfInterceptionPoint),
		reporter:  reporter,
	}
	// Assigned after construction because it reads the subsystem it belongs to: the pool
	// knows what each destination's last delivery established, and only the subsystem knows
	// which destinations the tasking still names.
	sub.unreachable = func() (int, int) { return pool.UnreachableAmong(sub.destinationsInUse()) }
	sub.unreachableAt = pool.UnreachableAt
	// The watcher's view of the same destinations, with the identifiers the ADMF
	// provisioned them under. A different shape from the probe's on purpose: the
	// probe answers a status request and takes counts so it *cannot* name a
	// destination, and a destination-scoped report says which. Same fact, two
	// questions.
	if reporter != nil {
		watcher = x1.NewDestinationWatcher(func() []x1.DestinationHealth {
			return sub.x2Health(pool.UnreachableAt)
		}, reporter, destinationWatchInterval)
		go watcher.Watch(destinationWatchStop)
	}
	// Assign the interface only when a reporter exists: a typed-nil would pass the
	// nil check in reportTaskIssue and then panic on use.
	if reporter != nil {
		sub.taskReporter = reporter
	}
	if len(cfg.UPFTriggers) > 0 {
		var triggers *triggerRegistry
		triggers, err = newTriggerRegistry(cfg, mat.ClientTLS(), sub.reportUnattributable,
			func(elapsed time.Duration) {
				// NE-level: which point of interception was late is not the fault. The
				// fault is that this element could not keep the cadence its POIs'
				// keepalive timers (TS 103 221-1 clause 6.6.2) are chosen against, so any
				// of them may report this element silent and deactivate live tasking.
				sub.reporter.NotifyAsync(x1.NEIssueTriggerFaulty,
					fmt.Sprintf("a keepalive round to the triggered points of interception took %s, "+
						"longer than the interval it must keep; tasking may be purged at a point of "+
						"interception this element is still answering for", elapsed.Round(time.Second)))
			})
		if err != nil {
			// A CC-TF whose triggering configuration is ambiguous cannot task the POI
			// it displaced, so content for sessions that UPF serves would be
			// duplicated and then dropped as unattributable. Refusing to start LI is
			// the fail-closed choice, and the LIPF is told because the alternative is
			// an ADMF that believes content interception is available when it is not.
			if reporter != nil {
				reporter.Notify(x1.NEIssueInvalidConfig,
					"content triggering configuration is ambiguous; no content interception is possible")
			}

			return err
		}
		sub.triggers = triggers
		// The registry keeps the endpoints and the cadence; what a task's health means, and
		// what reconciliation means, belong to the subsystem. Assigned before Start, which is
		// what starts the loops that read them.
		triggers.reportTaskHealth = sub.noteTaskHealth
		triggers.reconcile = sub.reconcileEndpoint
		// Reconciliation is NOT started here, and neither are the registry's own
		// loops. See below, after the bind.
	}
	x1srv := newX1Server(st, cfg, sub)
	// Bind the X1 listener synchronously so a bind/permission failure is reported
	// to the caller, rather than being swallowed in a goroutine while LI already
	// looks enabled (active.Store below) — otherwise no X1 tasking can be received.
	// ListenConfig.Listen rather than net.Listen so the listen carries a context
	// (the linter's noctx rule).
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", cfg.X1Listen)
	if err != nil {
		if sub.reporter != nil {
			sub.reporter.Notify(x1.NEIssueX1ListenFailed, "X1 listener bind failed")
		}
		// Everything built above that runs on its own is stopped, because this
		// initialisation is over: the caller gets an error, nothing is stored in
		// active, and a retry would otherwise accumulate a second set of loops.
		if sub.triggers != nil {
			sub.triggers.Stop()
		}

		return fmt.Errorf("lawful interception: X1 listen on %s: %w", cfg.X1Listen, err)
	}
	// NewListener supplies the properties every X1 endpoint needs and none of the
	// three network functions should be trusted to remember separately: a discarded
	// error log and per-phase timeouts, without which an unauthenticated peer can
	// hold connections open until this element can no longer be untasked.
	srv := x1.NewListener(x1srv, mat.ServerTLS())
	// Certificates come from TLSConfig, so the file arguments are empty. ServeTLS
	// blocks until the listener closes; the bind already succeeded above.
	//nolint:errcheck // serve-until-close; a bind failure already surfaced above
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	// The X1 keepalive procedure (TS 103 221-1 clause 6.6.2): report the ADMF's silence,
	// and deactivate tasking it can no longer withdraw. A nil stop channel: it runs for as
	// long as this element can hold tasking.
	sub.keepalive = keepalive
	if keepalive != nil {
		go x1srv.WatchKeepalive(*keepalive, nil)
	}
	// Both edges of the task-scoped faults this element answers from state (clause
	// 6.5.2.1): a content trigger a POI reports as not running is reported when it is
	// seen, and retracted with an all-clear once the POI reports it running again.
	if reporter != nil {
		go x1srv.WatchTaskFaults(reporter, taskFaultInterval, taskFaultStop)
	}
	active.Store(sub)
	// **Only now.** Reconciliation withdraws every trigger a POI reports that this
	// registry cannot account for, and a just-started registry accounts for none — so
	// on a start-up that does not complete it untasks every live content interception
	// at every UPF this SMF can reach. The bind above is what fails when another
	// process already holds the port, which is what a rolling restart or a duplicated
	// deployment looks like: the process most likely to abandon its start-up is the one
	// running alongside a healthy instance whose interception it would withdraw.
	//
	// A POI may still hold triggers from this process's previous life, which it has no
	// record of and could never withdraw — including after the warrant is revoked. That
	// is what reconciliation is for, and it is safe from here because this subsystem is
	// now the one running.
	if sub.triggers != nil {
		sub.triggers.Start()
		go sub.reconcileTriggers()
	}
	// The modifications no answer arrived for. Silence is not a lesser case than a refusal:
	// this element records duplication as applied when it sends, so an answer that never
	// comes leaves a task reported as intercepting against a datapath that may have
	// declined. A nil stop channel — the condition can arise for as long as this element
	// can send a modification.
	go sub.watchModifications(nil)
	// Tasking lives in memory, so this element has just discarded every warrant it
	// held. Nothing else tells the ADMF that — it goes on believing the
	// interceptions it provisioned are running — and the standard's audit path is a
	// query it has to think to make. Saying so on the way up is the one push signal
	// available.
	if reporter != nil && st.Len() == 0 {
		reporter.Notify(x1.NEIssueTaskingAbsent,
			"network function started with interception enabled and no tasking present")
	}
	return nil
}

// reportDeliveryError is the delivery pool's onError hook: what this element does with a
// failure its delivery worker reports.
//
// **The error is inspected, not discarded.** ErrUnitDropped says delivery to this
// destination is working and one product unit of it was lost — a unit the write stopped
// inside, which the library resends whole on a fresh connection and reports as dropped only
// where that resend did not land either. The library deliberately refuses to call that
// unreachability, because a healthy mediation function must not be reported unreachable over
// one truncated write; this hook discarded the error, so the loss was then reported by
// nothing at all while the watcher sampled a destination it correctly considered reachable.
// Product missing from an agency's record with every channel that could have said so
// reporting normality, which is the failure direction this whole plane exists to prevent.
//
// Reported as the same delivery loss a full queue is: from the agency's side the two are one
// fact — an xIRI this element produced and did not deliver.
//
// The nudge is for every error, this one included: what the sender concluded about
// reachability is its own business, and the watcher's job is to re-observe it promptly rather
// than one sampling interval later.
//
// A method rather than a closure inside Init so the mapping can be asserted directly. What
// produces ErrUnitDropped is the transport, and that is tested where it lives, in li/x2x3;
// what this element does with it is this function, and a test that has to arrange a
// partial write on a real socket to reach it would be testing the wrong half.
//
// The report says how many xIRIs the drop cost. A write that stops inside one unit is resent
// from that unit to the end of its batch, so a resend that does not land loses every unit in
// that tail, and the library counts them (x2x3.LostUnits). Saying "an xIRI" for what may be a
// run of them would leave the agency's gap larger than this element's own account of it.
func (s *subsystem) reportDeliveryError(err error, watcher *x1.DestinationWatcher) {
	if errors.Is(err, x2x3.ErrUnitDropped) {
		s.reporter.NotifyAsync(x1.NEIssueX2DeliveryLost, droppedXIRIs(x2x3.LostUnits(err)))
	}
	watcher.Nudge()
}

// droppedXIRIs describes a drop of n xIRIs on the way to a reachable mediation function. An
// error that carries no count (n is 0) still lost at least the unit it names, so it is not
// described as a number this element cannot back.
func droppedXIRIs(n int) string {
	switch {
	case n > 1:
		return fmt.Sprintf("%d xIRIs were partially written to a reachable mediation function and dropped", n)
	case n == 1:
		return "an xIRI was partially written to a reachable mediation function and dropped"
	default:
		return "at least one xIRI was partially written to a reachable mediation function and dropped"
	}
}

// ReportEstablishment emits an SMFPDUSessionEstablishment xIRI for sc if it
// matches an active task. No-op and silent when LI is inactive or sc is not a
// target.
//
// Call this once the UPF has answered the PFCP Session Establishment Request, not
// when the SBI create returns. The record carries the session's F-TEID and its X2
// correlation identifier is the F-SEID, and neither exists until the UPF has
// assigned them. Emitted at the SBI point, the record would carry a zero TEID and
// a zero correlation, so the one record that describes the session to the MDF
// would be the one record that cannot be joined to that session's content.
//
// Emitted at most once per session: a session spanning several UPFs draws an
// establishment response from each. It is called on the anchor's response only, so
// it is also where the session's correlation identifier is fixed. Caller holds
// sc.SMLock.
func ReportEstablishment(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}

	fixCorrelation(sc)

	if sc.LiEstablishmentReported {
		return
	}

	sc.LiEstablishmentReported = true

	sub.reportEvent(sc, smfEstablishment(sc))
}

// ReportEstablishmentReject emits an SMFUnsuccessfulProcedure xIRI when the SMF
// refuses a PDU session establishment for a tasked target. cause is the 5GSM
// cause the reject itself carries, so the record and the wire cannot disagree.
//
// A target whose sessions are being refused otherwise produces no record at all,
// and to an agency that silence is indistinguishable from a subject who never
// tried. No-op and silent when LI is inactive or sc is not a target.
func ReportEstablishmentReject(sc *smfctx.SMContext, cause uint8) {
	reportUnsuccessful(sc, iri.SMFFailedPDUSessionEstablishment, cause)
}

// ReportModificationReject emits an SMFUnsuccessfulProcedure xIRI when a PDU session
// modification fails for a tasked target.
//
// **It is the counterpart to a record this element already emits.** ReportModification is raised
// before the PFCP modification is attempted, because the state the record describes may be gone by
// the time the outcome is known — a legitimate choice, and one that obliges the element to report
// the failure that follows. Without this the agency would hold a record asserting a modification
// that never took effect, with nothing to say so. The release path handles the same shape on all
// three of its failure branches.
//
// cause is the 5GSM cause where the element decided one. The PFCP-timeout path decides none — it
// answers the AMF with a 503 and a release command rather than a 5GSM reject — so it passes the
// generic rejection rather than inventing a specific cause the element never chose.
func ReportModificationReject(sc *smfctx.SMContext, cause uint8) {
	reportUnsuccessful(sc, iri.SMFFailedPDUSessionModification, cause)
}

// ReportReleaseReject emits an SMFUnsuccessfulProcedure xIRI when the SMF refuses
// a PDU session release for a tasked target. cause is the 5GSM cause the reject
// carries, and pduSessionID the PDU session identity the refused PDU SESSION RELEASE
// REQUEST named, which the reject carries too.
//
// **The identity is the request's, not the context's.** A release can reach this
// context naming another session, and that is refused as an invalid identity: the record
// then describes a refused release of the session the UE named. Taking the identity from
// the context instead would report a refused release of a session that is still up.
func ReportReleaseReject(sc *smfctx.SMContext, pduSessionID int32, cause uint8) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	sub.reportEvent(sc, smfReleaseRejected(sc, pduSessionID, cause))
}

// smfReleaseRejected is the record ReportReleaseReject delivers. For a release naming
// another session it leaves out what belongs to this context's session rather than to
// the subscriber: its UE endpoint, DNN, access type and RAT type describe a session the
// request did not name. Table 6.2.3-5 makes all four conditional: the UE endpoint and DNN
// "if available", which for the named session they are not, and the access type and RAT
// type on what the AMF provided at that session's establishment, which for the named
// session never took place here.
func smfReleaseRejected(sc *smfctx.SMContext, pduSessionID int32, cause uint8) iri.SMFUnsuccessfulProcedure {
	rec := smfUnsuccessful(sc, iri.SMFFailedPDUSessionRelease, cause)
	rec.PDUSessionID = iri.PDUSessionID(pduSessionID)
	if pduSessionID != sc.PDUSessionID {
		rec.UEEndpoint, rec.DNN, rec.AccessType, rec.RATType = nil, "", 0, 0
	}

	return rec
}

// reportUnsuccessful is the shared body. It cannot fail the procedure it reports:
// every step is a read, deliverIRI swallows its own errors, and nothing here
// returns to the caller. That matters more here than elsewhere —
// these hooks sit on paths that are already failing, which is where error
// handling is least exercised.
func reportUnsuccessful(sc *smfctx.SMContext, procedure iri.SMFFailedProcedureType, cause uint8) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	sub.reportEvent(sc, smfUnsuccessful(sc, procedure, cause))
}

// smfUnsuccessful maps a refused procedure to a TS 33.128
// SMFUnsuccessfulProcedure record (XIRIEvent [10]).
//
// initiator is always network: the field says who is "initiating the rejection",
// and on every path SD-Core has, that is the SMF. uE would appear only on a
// PDU SESSION MODIFICATION COMMAND REJECT, which this SMF does not handle.
func smfUnsuccessful(sc *smfctx.SMContext, procedure iri.SMFFailedProcedureType, cause uint8) iri.SMFUnsuccessfulProcedure {
	return iri.SMFUnsuccessfulProcedure{
		FailedProcedureType: procedure,
		FailureCause:        iri.FiveGSMCause(cause),
		Initiator:           iri.InitiatorNetwork,
		SUPI:                supiChoice(sc),
		PEI:                 peiChoice(sc),
		GPSI:                gpsiChoice(sc),
		PDUSessionID:        iri.PDUSessionID(sc.PDUSessionID),
		UEEndpoint:          ueEndpoint(sc),
		DNN:                 iri.DNN(sc.Dnn),
		RequestType:         unsuccessfulRequestType(sc, procedure),
		AccessType:          accessType(sc),
		SUPIUnauthenticated: supiUnauthenticatedOf(sc),
		AMFID:               amfIDOf(sc),
		RATType:             ratTypeOf(sc.RatType),
	}
}

// unsuccessfulRequestType is the requestType table 6.2.3-5 sets for each refused
// procedure. Only an establishment carries a request type of its own; for the others
// the table names the value: "modification request" for a modification, and none for a
// release.
func unsuccessfulRequestType(sc *smfctx.SMContext, procedure iri.SMFFailedProcedureType) iri.FiveGSMRequestType {
	switch procedure {
	case iri.SMFFailedPDUSessionEstablishment:
		return requestType(sc)
	case iri.SMFFailedPDUSessionModification:
		return iri.SMRequestModification
	case iri.SMFFailedPDUSessionRelease:
		return 0
	default:
		return 0
	}
}

// ReportModification emits an SMFPDUSessionModification xIRI for sc if it
// matches an active task. No-op and silent otherwise.
func ReportModification(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	sub.reportEvent(sc, smfModification(sc))
}

// ReportRelease emits an SMFPDUSessionRelease xIRI for sc if it matches an
// active task. No-op and silent otherwise.
func ReportRelease(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	// A single teardown can reach both the update-initiated delete and the
	// dedicated release handler; emit the release xIRI only once.
	// Both call sites hold sc.SMLock, so this check-and-set is safe.
	if sc.LiReleaseReported {
		return
	}
	sc.LiReleaseReported = true
	sub.reportEvent(sc, smfRelease(sc))
}

// ApplyCCTrigger is the SMF Content-of-Communication Triggering Function. When
// the session's target has an active task requesting CC product, it marks the
// session's forwarding FARs for user-plane duplication (ApplyAction DUPL +
// Duplicating Parameters to the LI Function) so the serving UPF(s) tee the
// traffic to the MDF3. No-op and silent when LI is inactive.
//
// It walks the session's whole data-path pool, so duplication is applied on
// every UPF serving the target (multi-slice / UPF scaling).
//
// SCOPE: this runs from SendPFCPRules at PDU-session establishment, so it triggers
// CC for sessions established after tasking. The complementary case — a warrant
// (de)tasked while the session is already up — is handled by the X1
// OnActivate/OnDeactivate hooks (reportStartOfInterception / reportDeactivation),
// which re-evaluate CC and re-send a PFCP modification.
func ApplyCCTrigger(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil || sc.Tunnel == nil {
		return
	}
	cc := sub.ccTasked(sc)
	forEachForwardingFAR(sc, func(far *smfctx.FAR) {
		if far.ApplyAction.Dupl == cc {
			return
		}
		setDuplication(far, cc)
		// At establishment the FAR is still RULE_INITIAL and is sent as a Create
		// FAR carrying DUPL. On a re-invocation of SendPFCPRules for an already-
		// installed session (ULCL path add / HO path-switch) it is RULE_CREATE, so
		// mark it RULE_UPDATE — otherwise the modification builder's state switch
		// skips it and the DUPL flip is never sent to the UPF.
		if far.State == smfctx.RULE_CREATE {
			far.State = smfctx.RULE_UPDATE
		}
	})
}

// ApplyCCTriggerTo is ApplyCCTrigger for the FARs a modification is about to carry, and only
// those. A handler that sends part of a session's rules calls this, not ApplyCCTrigger.
//
// Re-deriving every forwarding FAR there loses a change. With a warrant just stored and its
// scan waiting for SMLock, ApplyCCTrigger sets duplication on FARs the request does not carry and
// marks them RULE_UPDATE; the request goes out without them, and the scan then finds duplication
// already as the tasking implies and sends nothing. Left alone, those FARs differ from the tasking
// when the scan arrives, and it sends them.
//
// Caller holds sc.SMLock.
func ApplyCCTriggerTo(sc *smfctx.SMContext, fars []*smfctx.FAR) {
	sub := active.Load()
	if sub == nil || sc == nil || sc.Tunnel == nil {
		return
	}
	cc := sub.ccTasked(sc)
	for _, far := range fars {
		if far == nil || !far.ApplyAction.Forw || far.ApplyAction.Dupl == cc {
			continue
		}
		setDuplication(far, cc)
		// As in ApplyCCTrigger: a FAR already installed is sent as an update.
		if far.State == smfctx.RULE_CREATE {
			far.State = smfctx.RULE_UPDATE
		}
	}
}

// ApplyCCAfterEstablishment re-derives sc's duplication state now that its PFCP
// session exists, and sends a modification if that changed anything.
//
// It closes the window scanSessions defers. A warrant can activate after
// ApplyCCTrigger has run for a session — the rules are built and sent by then —
// but before the establishment response lands. The X1 scan leaves such a session
// to the establishment path rather than mutating rules that path is still
// sending; this is the establishment path picking it up. Without it the deferral
// would be a drop, and the interception would silently never start: the one
// direction this plane must not fail in.
//
// The scan re-derives only UPFs that have answered their establishment, because the
// create path builds a UPF's request without SMLock. A UPF still establishing is
// therefore re-derived here, when it answers. A forwarding FAR still RULE_UPDATE on
// an established UPF, left by the session's own pending modification, rides along
// in the same modification.
//
// In the ordinary case nothing has changed since ApplyCCTrigger ran, applyCC
// returns false, no FAR is RULE_UPDATE, and no modification is sent. Run here
// rather than anywhere earlier because this is the first point ordered after the
// session exists, and it is already under the lock the handler holds for its
// whole body.
//
// Caller holds sc.SMLock.
func ApplyCCAfterEstablishment(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	if sub.applyCC(sc) || farUpdateOwed(sc) {
		sub.modifySession(sc)
	}
}

// farUpdateOwed reports whether any of sc's forwarding FARs is still marked
// RULE_UPDATE, that is, changed and not yet sent. Caller holds sc.SMLock.
func farUpdateOwed(sc *smfctx.SMContext) bool {
	if sc.Tunnel == nil {
		return false
	}
	owed := false
	forEachEstablishedForwardingFAR(sc, func(far *smfctx.FAR) {
		if far.State == smfctx.RULE_UPDATE {
			owed = true
		}
	})

	return owed
}

// forEachForwardingFAR invokes fn for every forwarding FAR across all of sc's
// data paths — the ones actually carrying the target's user-plane traffic, on
// every UPF serving the session. Caller holds sc.SMLock; sc.Tunnel must be non-nil.
func forEachForwardingFAR(sc *smfctx.SMContext, fn func(*smfctx.FAR)) {
	forEachForwardingFARAt(sc, "", fn)
}

// forEachForwardingFARAt is forEachForwardingFAR for the UPF whose node address is nodeIP
// only, or for every UPF when nodeIP is empty. Caller holds sc.SMLock; sc.Tunnel must be
// non-nil.
func forEachForwardingFARAt(sc *smfctx.SMContext, nodeIP string, fn func(*smfctx.FAR)) {
	for _, dp := range sc.Tunnel.DataPathPool {
		for node := dp.FirstDPNode; node != nil; node = node.Next() {
			if nodeIP != "" && (node.UPF == nil || node.GetNodeIP() != nodeIP) {
				continue
			}
			for _, tun := range []*smfctx.GTPTunnel{node.UpLinkTunnel, node.DownLinkTunnel} {
				if tun == nil {
					continue
				}
				for _, pdr := range tun.PDR {
					if pdr != nil && pdr.FAR != nil && pdr.FAR.ApplyAction.Forw {
						fn(pdr.FAR)
					}
				}
			}
		}
	}
}

// forEachEstablishedForwardingFAR is forEachForwardingFAR for the UPFs whose PFCP session
// exists, those with a remote SEID. Caller holds sc.SMLock; sc.Tunnel must be non-nil.
//
// A UPF without one may be having its establishment request built, and the create path builds
// it without SMLock (fsm's HandleStatePfcpCreatePendingEventPfcpSessCreate). A re-derivation
// that sets duplication on its FARs then can land between the builder encoding a FAR and marking
// it RULE_CREATE: the request carries the old value, and when the UPF answers its FAR already
// reads as the tasking implies and is not RULE_UPDATE, so nothing is sent and the UPF never
// duplicates. Its FARs are left to ApplyCCAfterEstablishment, which re-derives them when it
// answers, after its request was built. Nothing could be sent to it before that in any case.
func forEachEstablishedForwardingFAR(sc *smfctx.SMContext, fn func(*smfctx.FAR)) {
	for _, dp := range sc.Tunnel.DataPathPool {
		for node := dp.FirstDPNode; node != nil; node = node.Next() {
			if node.UPF == nil {
				continue
			}
			ip := node.GetNodeIP()
			if pc, ok := sc.PFCPContext[ip]; !ok || pc == nil || pc.RemoteSEID == 0 {
				continue
			}
			for _, tun := range []*smfctx.GTPTunnel{node.UpLinkTunnel, node.DownLinkTunnel} {
				if tun == nil {
					continue
				}
				for _, pdr := range tun.PDR {
					if pdr != nil && pdr.FAR != nil && pdr.FAR.ApplyAction.Forw {
						fn(pdr.FAR)
					}
				}
			}
		}
	}
}

// setDuplication turns user-plane duplication on or off for one forwarding FAR.
// When on, the copy is destined for the LI Function; the SD-Core UPF CC-POI
// frames and ships it over X3 natively, so no OuterHeaderCreation tunnel is set.
func setDuplication(far *smfctx.FAR, on bool) {
	far.ApplyAction.Dupl = on
	if on {
		far.DuplicatingParameters = &smfctx.DuplicatingParameters{
			DestinationInterface: smfctx.DestinationInterface{InterfaceValue: smfctx.DestinationInterfaceLIFunction},
		}
	} else {
		far.DuplicatingParameters = nil
	}
}

// ccTasked reports whether any active task targeting sc requests CC product.
func (s *subsystem) ccTasked(sc *smfctx.SMContext) bool {
	for _, t := range s.matchingTasks(sc) {
		if t.WantsProduct(types.ProductCC) {
			return true
		}
	}
	return false
}

// sessionModifier sends a PFCP session modification carrying sc's current FAR
// state. It is injected by the service layer (SetSessionModifier) because this
// package is imported by smf/producer and so cannot call
// producer.SendPfcpSessionModifyReq directly. While nil (e.g. in tests) the
// mid-session CC hooks still update FAR state but send nothing.
var sessionModifier func(*smfctx.SMContext) error

// SetSessionModifier installs the PFCP-modification hook used by mid-session CC
// (de)activation. Call once at start-up, before the X1 server accepts tasking.
func SetSessionModifier(fn func(*smfctx.SMContext) error) {
	sessionModifier = fn
}

// applyTaskChange is the X1 lifecycle hook (x1.OnTaskChange): one event per
// transition of this element's tasking, carrying the task as it was and as it
// becomes. prev nil is an activation, next nil a removal, both a modification.
func (s *subsystem) applyTaskChange(prev, next *types.InterceptTask) {
	switch {
	case prev == nil:
		s.reportStartOfInterception(*next, nil)
	case next == nil:
		s.reportDeactivation(*prev)
	default:
		s.modifyInterception(*prev, *next)
	}
}

// modifyInterception applies a modification as one reconciliation rather than as
// an activation followed by a deactivation.
//
// A ModifyTask keeps the XID, and everything this element keys off it is the same
// key for both sides: the trigger registry is keyed by the warrant XID, and so is
// the sequence-numbering state. Applying the new task and then tearing down the
// old one let the teardown reclaim the triggers the activation had just installed,
// and let Forget discard numbering the new task's records had already consumed.
// Neither is possible from here, because there is only one pass.
//
// **Except where the modification moved the delivery label itself.** The numbering is
// keyed by the *delivery* XID, which is the provisioned ProductID where there is one —
// so a relabel does change it, and the contexts under the superseded label are stranded:
// nothing will ever number under them again, because every record from here carries the
// new one. Released below, and only there; a modification that leaves the labelling
// alone must release nothing, since those contexts are the ones this task's own records
// are still using and re-issuing a number the mediation function has already seen is how
// loss is signalled on this interface.
func (s *subsystem) modifyInterception(prev, next types.InterceptTask) {
	// The superseded label's contexts, before anything below can number under the new
	// one. Forget rather than ForgetContext because at an IRI-POI one task is one
	// warrant, so every context under that label belonged to this task.
	if s.ids != nil && prev.DeliveryXID() != next.DeliveryXID() {
		s.ids.Forget(parseXID(prev.DeliveryXID()))
	}

	wantedCC := prev.WantsProduct(types.ProductCC)
	wantsCC := next.WantsProduct(types.ProductCC)
	// Both products, not just content. A test that compared the targets and the CC
	// flag alone would find "nothing changed" when IRI is *added* to a task that already
	// has CC — and return before reportStartOfInterception, so the target's
	// already-established sessions would produce no SMFStartOfInterceptionWithEstablishedPDUSession
	// at all. Interception of that product genuinely begins, at a moment the ADMF chose,
	// and the only record that says so is the one such a comparison skips.
	// Each product is a separate authority that can be granted on its own, so the test
	// for "nothing about this interception has moved" has to cover each of them.
	//
	// covered() already tests the product on the other side, so a previous task that
	// did not want IRI does not suppress the record once the branch is reached. The AMF's
	// applyTaskChange makes the same comparison.
	wantedIRI := prev.WantsProduct(types.ProductIRI)
	wantsIRI := next.WantsProduct(types.ProductIRI)
	// The record scope belongs in the same test, and for the same reason the products do:
	// widening it makes records due that the narrower scope excluded, for subjects the task
	// already covered — so a scope-only modification *can* produce a record and must not take
	// the early return. The AMF's predicate says the same three things.
	if slices.Equal(prev.Targets, next.Targets) && wantedCC == wantsCC && wantedIRI == wantsIRI &&
		prev.RecordScope == next.RecordScope {
		// Nothing about *which* traffic is intercepted has moved. What may still have
		// moved is how this warrant's product is labelled and where its content goes,
		// and those reach the two interfaces by different routes: this element reads
		// them from the task each time it builds a record, so X2 picks them up at once,
		// while a triggered CC-POI reads them from a trigger built once. Left alone, the
		// two diverge silently — signalling arrives at the mediation function under one
		// warrant identifier and content under another, both well-formed, both
		// separately deliverable, with nothing in either stream to show they were meant
		// to join.
		s.relabelWarrant(prev, next)

		// The numbering state is dealt with at the top of this function: released where
		// the delivery label moved, left alone where it did not.
		return
	}

	// Reconcile the triggers held for this warrant against the sessions the task
	// still covers, in one locked pass: a session tasked before and after keeps the
	// trigger it has. Withdrawing everything and reinstalling would stop and restart
	// content interception for a session whose tasking did not change.
	s.retriggerWarrant(next)

	// And the labelling, on this branch too. A ModifyTask that changes the targets *and*
	// the productID or the X3 destinations takes this path, where retriggerWarrant
	// withdraws triggers for sessions the task no longer covers and leaves the rest
	// untouched. Without relabelling, those would keep labelling their content with the
	// superseded value: signalling would arrive at the mediation function under one
	// warrant identifier and content under another, both well-formed, with nothing in
	// either stream to show they were meant to join.
	//
	// The combined case is where it is hardest to notice, because part of the
	// modification visibly took effect. Called after the reconciliation so it acts on
	// the triggers that survived it, and safe on both paths because relabelWarrant
	// opens with an exact no-change test.
	s.relabelWarrant(prev, next)

	// Duplication re-derives from the task set, which already holds next, so a
	// session reached by either scan is evaluated the same way. Only sessions the
	// old task covered need the extra visit — the new task's own scan covers its.
	if wantedCC {
		// Not under authority: this re-evaluates duplication for sessions the *previous*
		// task covered, against the task set as it now stands. It produces no records,
		// and prev is the task being replaced.
		s.scanSessions(prev, false, func(sc *smfctx.SMContext) any {
			if s.applyCC(sc) {
				s.modifySession(sc)
			}

			return nil
		})
	}

	s.reportStartOfInterception(next, &prev)
}

// reportStartOfInterception applies a task to sessions that already exist: emit
// the "start with established PDU session" xIRI (if IRI is wanted) and switch on
// CC duplication (if CC is wanted). It runs on live sessions the target already
// has; sessions established later are handled at establishment by
// ReportEstablishment / ApplyCCTrigger.
//
// already, when set, is the task this one replaces. Interception of a session that
// task already covered did not begin here, so no record says it did — the CC work
// is unaffected, since that re-derives from the task set either way.
func (s *subsystem) reportStartOfInterception(task types.InterceptTask, already *types.InterceptTask) {
	wantIRI := task.WantsProduct(types.ProductIRI)
	s.scanSessions(task, true, func(sc *smfctx.SMContext) any {
		var event any
		// uEEndpoint is mandatory in this record, and an empty list would assert
		// the session has no endpoint address. A session with no address assigned
		// is not one this record can describe, so report nothing for it rather
		// than something untrue — the CC work below is unaffected either way.
		if wantIRI && ueEndpoint(sc) != nil && !covered(already, sc) {
			event = smfStartOfInterception(sc)
		}
		if s.applyCC(sc) {
			s.modifySession(sc)
		}
		// Task the serving UPFs for this warrant too: the FARs now duplicate, but
		// without a trigger the copies carry no warrant identity.
		s.triggerCC(sc)
		return event
	})
}

// covered reports whether task already intercepted this session's IRI. Caller
// holds sc.SMLock (sessionTargets reads the session's identity fields).
func covered(task *types.InterceptTask, sc *smfctx.SMContext) bool {
	return task != nil && task.WantsProduct(types.ProductIRI) && sessionTargets(*task, sc)
}

// reportDeactivation undoes the CC duplication a removed warrant caused on the
// target's live sessions. It re-evaluates
// against the remaining task set, so duplication is only cleared once no CC task
// still targets the session (correct under overlapping multi-agency warrants).
// IRI needs no undo, so a pure-IRI deactivation is a no-op.
func (s *subsystem) reportDeactivation(task types.InterceptTask) {
	// Numbering state belongs to the tasking that created it, and a warrant covering
	// many sessions creates a sequence context per session. Done for every warrant,
	// before the CC check below returns early for a pure-IRI one — it is the IRI
	// records that were numbered.
	if s.ids != nil {
		s.ids.Forget(parseXID(task.DeliveryXID()))
	}
	if !task.WantsProduct(types.ProductCC) {
		return
	}
	// Not under authority, and this is the call that made the distinction necessary: a
	// deactivation runs *because* the task was removed, so requiring it to still be in
	// the store would leave every withdrawn warrant's duplication running.
	s.scanSessions(task, false, func(sc *smfctx.SMContext) any {
		if s.applyCC(sc) {
			s.modifySession(sc)
		}
		return nil
	})
	// Withdraw this warrant's triggers wherever they were installed. Unlike the
	// FAR state, which is re-evaluated against the remaining task set, a trigger
	// belongs to exactly one warrant and goes with it.
	s.untriggerWarrant(task.XID)
}

// scanSessions finds every live session targeted by task and processes each,
// entirely on a background goroutine — off the X1 request goroutine, so neither a
// slow PFCP round-trip nor the size of the session population delays the X1
// response. fn returns an xIRI event to deliver after the lock is released, or nil.
// The target match is done under the per-session lock because it reads the
// session's identity fields.
//
// The *match* runs on the goroutine too, not only the processing. It is a scan
// either way: it visits every live session and takes every session's lock, so on the
// caller's goroutine a provisioning function's answer would take time proportional to
// the element's subscriber population, and any one of those acquisitions could queue
// behind a PFCP handler holding that session's lock. Unlike the registry read in retriggerWarrant,
// this walk cannot be bounded — which session a target holds is not indexed anywhere,
// and finding out is the work — so what moves is the whole of it, not its cost.
//
// What must not move is the instant. It is the activation's, not the scan's, so it is
// still taken here; reading it inside the goroutine would date every
// record by when this element got round to the session.
// underAuthority says whether this scan *produces product*, and therefore whether the
// warrant has to still authorise each session at the moment it is reached.
//
// **It is not true for every scan, and getting that wrong stops a withdrawal.** An
// activation or a modification applies tasking to sessions that already exist, and its
// records are only licensed by a warrant the element currently holds — so it re-reads
// the store per session. A *deactivation* scan is the opposite operation: it exists to
// take duplication down, and it runs after the task has been removed from the store,
// because removal is what triggers it. Revalidating there finds the task gone and
// returns before clearing anything, leaving the datapath duplicating for a warrant that
// no longer exists. That is interception outliving its authority — the failure this
// whole rule is about — reached by applying the rule to the path that enforces it.
func (s *subsystem) scanSessions(task types.InterceptTask, underAuthority bool, fn func(*smfctx.SMContext) any) {
	activated := time.Now()
	s.scans.Add(1)
	go func() {
		defer s.scans.Done()

		// **Bounded, because bulk provisioning launches one of these per warrant at once.**
		// TS 103 221-1's bulk operations and an ADMF restoring tasking after a restart both
		// provision many warrants in quick succession, and each walk reads the whole session
		// pool: unbounded, N warrants cost N concurrent full walks on an element whose
		// ordinary job is establishing sessions in that pool. The bound turns that into a
		// queue.
		//
		// Taken inside the goroutine, not before it: the provisioning answer must still not
		// wait on any of this, which is the property that put the scan off the X1 goroutine.
		scanSlots <- struct{}{}
		defer func() { <-scanSlots }()

		var matched []*smfctx.SMContext
		smfctx.RangeSMContexts(func(sc *smfctx.SMContext) bool {
			sc.SMLock.Lock()
			hit := sessionTargets(task, sc)
			sc.SMLock.Unlock()
			if hit {
				matched = append(matched, sc)
			}

			return true
		})

		for i, sc := range matched {
			// nil in production. The window between one record and the next is where a
			// mid-scan ModifyTask lands, and it is a few instructions wide — so a property
			// this consequential asserted by racing an X1 request against a scan is one
			// that passes against the defect. Called before each session but the first, so
			// a test can let one record out and then retarget the warrant. See
			// TestARetargetMidScanStopsDeliveringForThePreviousSubject.
			if i > 0 && beforeScanRecord != nil {
				beforeScanRecord()
			}

			// **Re-read before each session, and act under what the store holds now.**
			// This scan is unbounded in duration by design — it is off the X1 goroutine
			// precisely so a provisioning answer does not scale with the subscriber
			// population — so "the warrant was valid when the scan started" and "the
			// warrant is valid now" are two different statements, and only the second
			// authorises a record or a duplication change. A DeactivateTask
			// acknowledged mid-scan otherwise leaves this loop delivering for a
			// withdrawn warrant, and a ModifyTask leaves it delivering to destinations
			// it has just replaced.
			//
			// Per session rather than per scan: a withdrawal landing mid-scan must stop
			// the remainder, not merely the next one.
			if underAuthority {
				current, held := s.store.Get(task.XID)
				if !held {
					return
				}
				task = current
			}

			sc.SMLock.Lock()
			// **And that the session has not ended since it was matched.** The match was taken
			// under an earlier hold of this lock. A teardown in between owns the session's
			// release record and the withdrawal of its triggers. Most teardowns also nil the
			// tunnel, which makes everything below a no-op, but a restoration's release does
			// not: the UPF restarted, so no deletion is sent and the tunnel stays. Acting on
			// it then would send a modification for a dead SEID and claim a trigger nothing
			// withdraws again. A deactivation scan loses nothing by the skip, since the
			// teardown took the duplication down.
			if sc.SMContextState == smfctx.SmStateRelease || sc.LocalPurged.Load() || sc.SupersededByAnother() {
				sc.SMLock.Unlock()

				continue
			}
			// **And that the task still names this session's subject.** The re-read above
			// establishes that the task exists, and — because everything below is derived
			// from `task` — which products it wants and where its product goes. It did not
			// establish that the task still covers *this* subject: a ModifyTask that
			// retargets a warrant mid-scan leaves the remaining sessions producing records
			// under the warrant's own identifier, delivered to the new subject's agency and
			// describing the previous one. Well-formed, correctly attributed, and about
			// somebody the warrant no longer covers.
			//
			// What revalidation establishes is a list — existence, products, destinations
			// and subject — so this sits beside the re-read rather than inside the caller's
			// closure, and a later omission from that list reads as a gap in a list.
			//
			// Only where the scan is under authority. A deactivation scan runs *because*
			// the task was removed, and its job is to take duplication down; testing the
			// subject there would leave the datapath duplicating for a warrant that no
			// longer exists, which is the failure this whole rule is about.
			if underAuthority && !sessionTargets(task, sc) {
				sc.SMLock.Unlock()

				continue
			}
			corr := correlationOf(sc)   // read under the lock (reads sc.PFCPContext)
			subjectIDs := targetsOf(sc) // likewise: reads the session's identity fields
			// A session whose PFCP session does not exist yet belongs to the
			// establishment path, and this pass leaves it alone — the same test, for
			// the same reason, that triggerRegistry.plan already applies before
			// planning a trigger.
			//
			// It is a deferral, not a drop. The establishment path re-derives
			// duplication from the current task set as it goes and again when the
			// response lands (see TriggerCC's call site), so a warrant activating
			// inside this window is applied on arrival rather than lost. What it
			// avoids is this goroutine mutating rules the establishment path is
			// part-way through building and sending: that path runs without SMLock,
			// so the two would otherwise reach the same FARs with no ordering
			// between them.
			//
			// The IRI side wants the same skip for its own reason: the correlation
			// identifier is this session's F-SEID, so a record emitted now would
			// carry a zero the mediation function cannot join to anything, and
			// ReportEstablishment emits the real one once the session exists.
			var event any
			if corr != ([8]byte{}) {
				event = fn(sc)
			}
			sc.SMLock.Unlock()
			if event != nil {
				s.deliverIRI([]types.InterceptTask{task}, corr, subjectIDs, activated, event)
			}
		}
	}()
}

// beforeScanRecord is called between the sessions an activation scan walks. Set only by
// tests; nil otherwise.
var beforeScanRecord func()

// scanSlots bounds how many scans walk the session pool at once.
//
// Four rather than one: a single slot would serialise unrelated warrants behind one walk, and
// what matters is that the cost is bounded rather than that it is one. Package-level because
// the bound is a property of this element's session pool, of which there is one.
var scanSlots = make(chan struct{}, 4)

// applyCC makes sc's forwarding FARs match whether the target is currently
// CC-tasked, marking any FAR it changes RULE_UPDATE so a PFCP modification
// re-sends it. It returns whether anything changed (a modification is due).
// Caller holds sc.SMLock.
func (s *subsystem) applyCC(sc *smfctx.SMContext) bool {
	if sc.Tunnel == nil {
		return false
	}
	want := s.ccTasked(sc)
	changed := false
	// Established UPFs only: see forEachEstablishedForwardingFAR. A UPF still establishing is
	// re-derived when it answers.
	forEachEstablishedForwardingFAR(sc, func(far *smfctx.FAR) {
		if far.ApplyAction.Dupl == want {
			return
		}
		setDuplication(far, want)
		// The same guard ApplyCCTrigger carries, and for the same reason: a FAR
		// still RULE_INITIAL has never been sent, and the establishment builder
		// emits a Create FAR only for that state. Marking it RULE_UPDATE describes
		// an amendment to a rule the UPF does not have, so the FAR is dropped from
		// the establishment request while the PDR referring to it goes out anyway.
		// The UPF then holds a detection rule pointing at a forwarding rule that
		// does not exist: the subject's traffic has no forwarding action at all and
		// the session breaks — the most conspicuous thing an interception can do to
		// a target whose service must look like everyone else's — and the
		// duplication this was called to apply is lost with it.
		//
		// This path reaches sessions the establishment path owns only in the window
		// scanSessions now defers (see there); the guard is what makes a mistake in
		// that reasoning harmless rather than service-affecting.
		if far.State == smfctx.RULE_CREATE {
			far.State = smfctx.RULE_UPDATE
		}
		changed = true
	})
	return changed
}

// modifySession fires the injected PFCP-modification hook for sc, silently (any
// failure surfaces through normal PFCP handling, never a target-revealing log).
// Caller holds sc.SMLock.
func (s *subsystem) modifySession(sc *smfctx.SMContext) {
	if sessionModifier == nil {
		return
	}
	if err := sessionModifier(sc); err != nil {
		// **A send that failed is an outcome, and is not discarded.** Normal PFCP handling
		// surfaces the failure of a modification the datapath *answers*, not of one that
		// never left: no sequence number was recorded, so no response can arrive, and
		// nothing sweeps for a modification that was never sent. The element has already
		// recorded the duplication as applied.
		//
		// Reported rather than retried, and the asymmetry with the answer path is
		// deliberate: this runs with sc.SMLock held, from the paths that derive
		// duplication, so re-sending from here would re-enter the same lock — and what
		// failed is the send itself, which a retry in the same instant would fail again.
		// The condition an operator needs is that this element is not carrying out an
		// interception it has acknowledged.
		s.reporter.NotifyAsync(x1.NEIssueDuplicationRefused,
			"a duplication change could not be sent to the user plane; content interception "+
				"may not match the tasking this element holds")
	}
}

// sessionTargets reports whether sc's identifiers satisfy every criterion task names.
// Caller holds sc.SMLock (targetsOf reads sc's identity fields).
func sessionTargets(task types.InterceptTask, sc *smfctx.SMContext) bool {
	return task.MatchedBy(targetsOf(sc))
}

// reportEvent delivers event to every task this session's identities match, as the
// session and the clock stood when the event was observed.
//
// The instant is taken here, at the hook, because the X2 Timestamp attribute is the
// time the *event* occurred (TS 33.128 table 5.3.2-2) and not the time a PDU was
// built. Caller holds sc.SMLock: matchingTasks, correlationOf and targetsOf all read
// the session's fields.
func (s *subsystem) reportEvent(sc *smfctx.SMContext, event any) {
	s.deliverIRI(s.matchingTasks(sc), correlationOf(sc), targetsOf(sc), time.Now(), event)
}

// deliverIRI encodes event once and delivers it as an X2 xIRI to every task in
// tasks that wants IRI product. It is silent on any error (encoding or
// delivery) so that interception can never be inferred from SMF behaviour.
func (s *subsystem) deliverIRI(tasks []types.InterceptTask, corr [8]byte, subjectIDs []types.TargetIdentifier, at time.Time, event any) {
	if len(tasks) == 0 {
		return
	}
	if s.ids == nil {
		// An element that cannot say which network function produced a record does not
		// deliver one. Init always supplies this, so reaching here means a subsystem was
		// assembled by hand — fail closed rather than panic, since this runs on a
		// session's own goroutine.
		return
	}
	payload, err := iri.EncodeXIRI(event)
	if err != nil {
		// **A record this element could not encode is product it produced and did not
		// deliver, so it is reported.** Besides an internal codec error, the encoder
		// refuses a record whose values violate the constraints its own definition carries. A
		// conformant mediation function would discard such a record anyway; what must not
		// happen is that neither side knows.
		//
		// NE-level and naming no target or warrant, and off this goroutine: this runs on the
		// PDU-session signalling path with the session's lock held.
		s.reporter.NotifyAsync(x1.NEIssueX2DeliveryLost,
			"a record could not be encoded and was not delivered")

		// **And against each warrant, naming the record type**, as the AMF does. The NE-level
		// report above may carry neither, which is that channel's rule, so on its own it says
		// only that *something* did not encode, throttled, which is the same signal an
		// unreachable MDF2 produces and admits the same wrong diagnosis. An agency missing a
		// record needs to know which product is absent and for which warrant, and a task report
		// is scoped to a warrant by construction.
		for _, t := range tasks {
			if !t.WantsProduct(types.ProductIRI) {
				continue
			}

			// Off this goroutine, like the element-scoped report above.
			s.reporter.NotifyTaskAsync(string(t.DeliveryXID()),
				x1.TaskReportNonTerminatingFault, x1.TaskIssueRecordNotEncoded,
				fmt.Sprintf("%s: a %T record for this warrant could not be encoded and was not "+
					"delivered; the product this element produced for it is incomplete",
					x1.TaskIssueRecordNotEncoded, event))
		}

		return
	}
	for _, t := range tasks {
		if !t.WantsProduct(types.ProductIRI) {
			continue
		}
		// A provisioned ProductID replaces the task XID in the PDU header
		// (TS 103 221-1 clause 6.2.1.2), so product is labelled with the warrant an
		// ADMF names rather than with the task carrying it.
		xid := parseXID(t.DeliveryXID())
		// The six attributes TS 33.128 table 5.3.2-2 requires, built once per task and
		// carried to every destination it named: the number belongs to the (XID,
		// Correlation ID) context, so two destinations receive one numbering.
		matched, other := t.SplitTargets(subjectIDs)
		// The number is taken here, per record *generated* for this task, and not below
		// per record delivered. That ordering is deliberate twice over: a task resolving
		// to no destination therefore consumes a number nobody receives, which is
		// harmless because nobody is receiving a stream to see a gap in (a destination
		// added mid-task sees the same effect, and is accepted for it); and moving the call
		// inside the destination loop would number each destination separately, which is
		// the per-connection numbering clause 5.3.9 forbids.
		attrs := s.ids.Attributes(xid, corr, at,
			types.XMLFragments(matched), types.XMLFragments(other))
		for _, addr := range s.x2Destinations(t) {
			client := s.senderFor(addr)
			if client == nil {
				continue
			}
			// Delivery is asynchronous (see Init): Send enqueues and returns, so this
			// signalling path never blocks on the MDF; delivery failures are reported
			// to the ADMF over X1 from the delivery worker, not here. The correlation
			// ID lets the MDF join this xIRI to the session's xCC.
			//nolint:errcheck // async enqueue; delivery failures report via the worker, not here
			_ = client.Send(&x2x3.PDU{
				Type:          x2x3.PDUTypeX2,
				PayloadFormat: x2x3.PayloadFormat3GPP33128,
				Direction:     x2x3.DirectionNotApplicable,
				XID:           xid,
				CorrelationID: corr,
				Attributes:    attrs,
				Payload:       payload,
			})
		}
	}
}

// x2Destinations is where this task's xIRI goes.
//
// The task's own destinations first, which is what TS 33.128 requires — table 6.2.3-0A,
// "ActivateTask message for SMF IRI-POI, CC-TF and IRI-TF", marks ListOfDIDs mandatory
// and says the endpoints "shall be configured using the CreateDestination message …
// prior to first use".
//
// **The configured MDF2 serves a task that named no destination, not one whose
// destinations produced no X2 endpoint.** The two were the same test — an empty resolved
// list — and they are different facts. A task that named nothing is a gap the
// provisioning function left, and the configured endpoint fills it, which is the case
// every deployment predating that requirement is in. A task that named destinations and
// yielded no X2 endpoint is an assertion this element cannot honour as stated:
// substituting the configured MDF2 sends an agency's signalling to an endpoint the
// warrant never named. On an element serving several agencies it is worse than a gap —
// the product goes to whichever endpoint local configuration happens to name, and
// li-security-isolation admits no exception for it.
//
// So the fallback keys on len(t.DIDs). Neither failure reaches here from X1 any more: x1
// refuses a task naming an identifier it cannot resolve with 2040, and one whose named
// destinations give no X2 endpoint while its deliveryType orders xIRI with 3040 (TS 103
// 221-1 clause 6.2.1.2), at activation and modification alike, and every caller asks only
// for a task that wants xIRI (iriDestinations, deliverIRI). The branch stays as the backstop: removed, the same task
// would be served by the configured MDF2, which is the disclosure rather than a gap.
func (s *subsystem) x2Destinations(t types.InterceptTask) []string {
	if addrs := t.DeliveryAddresses(types.DeliveryX2); len(addrs) > 0 {
		return addrs
	}
	if len(t.DIDs) > 0 {
		// The task named where its product goes and none of it is an X2 endpoint. This
		// element has nothing to say about where the xIRI should go instead.
		return nil
	}
	if s.mdf2 == "" {
		return nil
	}

	return []string{s.mdf2}
}

// correlationOf returns the X2 correlation identifier for sc's session (see
// sessionCorrelation) encoded big-endian — the same value and byte order the UPF
// stamps on the session's X3 xCC, so the MDF can join a session's xIRI and xCC.
// Zero before the anchor's PFCP session is established. Caller holds sc.SMLock.
func correlationOf(sc *smfctx.SMContext) [8]byte {
	var corr [8]byte
	binary.BigEndian.PutUint64(corr[:], sessionCorrelation(sc))
	return corr
}

// sessionCorrelation is the correlation identifier of sc's session: the value fixed by
// fixCorrelation, or, for a session that has none, the anchor's current F-SEID. The second
// covers a session stored by a version that did not keep the value, until its anchor next
// accepts it. Caller holds sc.SMLock.
func sessionCorrelation(sc *smfctx.SMContext) uint64 {
	if sc.LiCorrelation != 0 {
		return sc.LiCorrelation
	}

	return servingUPFSEID(sc)
}

// fixCorrelation fixes sc's correlation identifier at the anchor's F-SEID, if it is not
// fixed yet. Called when the anchor accepts the session, for every session, tasked or not.
// TS 103 221-2 clause 5.2.8 gives PDUs of one communication session one correlation value,
// and the F-SEID changes when a restarted UPF re-establishes the session and is zero while it
// does, and the session's tunnel is gone after a release. Caller holds sc.SMLock.
func fixCorrelation(sc *smfctx.SMContext) {
	if sc.LiCorrelation == 0 {
		sc.LiCorrelation = servingUPFSEID(sc)
	}
}

// servingUPFSEID returns the serving UPF's assigned F-SEID for sc's default data
// path (the SMF's RemoteSEID for that UPF's PFCP session), or 0 if not yet
// established. Uses the same default-path selector as servingUPFTEID so a
// multi-path (ULCL) session anchors deterministically on the N3 UPF.
func servingUPFSEID(sc *smfctx.SMContext) uint64 {
	if sc.Tunnel == nil {
		return 0
	}
	dp := sc.Tunnel.DataPathPool.GetDefaultPath()
	if dp == nil {
		return 0
	}
	node := dp.FirstDPNode
	if node == nil || node.UPF == nil {
		return 0
	}
	key := node.UPF.NodeID.ResolveNodeIdToIp().String()
	if pfcpCtx, ok := sc.PFCPContext[key]; ok && pfcpCtx != nil {
		return pfcpCtx.RemoteSEID
	}
	return 0
}

// matchingTasks returns the active tasks whose every criterion sc's identifiers
// satisfy, de-duplicated by task id. The store's index finds the tasks naming any of
// them; a task's criteria are conjunctive (TS 103 221-1 table 6.2.1.2-1), so each is
// then decided against all of sc's identifiers.
func (s *subsystem) matchingTasks(sc *smfctx.SMContext) []types.InterceptTask {
	ids := targetsOf(sc)
	var out []types.InterceptTask
	seen := map[types.XID]bool{}
	for _, id := range ids {
		for _, t := range s.store.Match(id) {
			if !seen[t.XID] {
				seen[t.XID] = true
				if t.MatchedBy(ids) {
					out = append(out, t)
				}
			}
		}
	}
	return out
}

// targetsOf returns sc's known 5G target identifiers, with the SMF's "type-"
// prefixes stripped to the bare value the X1 tasking uses.
func targetsOf(sc *smfctx.SMContext) []types.TargetIdentifier {
	var ids []types.TargetIdentifier
	if v := afterPrefix(sc.Supi, "imsi-", "nai-"); v != "" {
		ids = append(ids, types.TargetIdentifier{Type: types.TargetSUPI, Value: v})
	}
	if v := peiValue(sc.Pei); v != "" {
		ids = append(ids, types.TargetIdentifier{Type: types.TargetPEI, Value: v})
	}
	if v := imeiOfIMEISV(sc.Pei); v != "" {
		ids = append(ids, types.TargetIdentifier{Type: types.TargetPEI, Value: v})
	}
	if v := afterPrefix(sc.Gpsi, "msisdn-", "extid-"); v != "" {
		ids = append(ids, types.TargetIdentifier{Type: types.TargetGPSI, Value: v})
	}
	return ids
}

// ratTypeOf maps the 5GC RAT type to TS 33.128's enumeration. An unmapped value
// yields zero, which encodes as absent: reporting no RAT type is right where
// reporting the wrong one would be a claim about the access the session used.
func ratTypeOf(rat models.RatType) iri.RATType {
	switch rat {
	case models.RATTYPE_NR:
		return iri.RATNR
	case models.RATTYPE_EUTRA:
		return iri.RATEUTRA
	case models.RATTYPE_WLAN:
		return iri.RATWLAN
	case models.RATTYPE_VIRTUAL:
		return iri.RATVirtual
	case models.RATTYPE_NBIOT:
		return iri.RATNBIOT
	case models.RATTYPE_LTE_M:
		return iri.RATLTEM
	case models.RATTYPE_NR_U:
		return iri.RATNRU
	case models.RATTYPE_EUTRA_U:
		return iri.RATEUTRAU
	case models.RATTYPE_TRUSTED_N3_GA:
		return iri.RATTrustedN3GA
	case models.RATTYPE_TRUSTED_WLAN:
		return iri.RATTrustedWLAN
	// Non-terrestrial access, which this deployment serves.
	case models.RATTYPE_NR_LEO:
		return iri.RATNRLEO
	case models.RATTYPE_NR_MEO:
		return iri.RATNRMEO
	case models.RATTYPE_NR_GEO:
		return iri.RATNRGEO
	case models.RATTYPE_NR_OTHER_SAT:
		return iri.RATNROtherSat
	case models.RATTYPE_NR_REDCAP:
		return iri.RATNRRedCap
	}

	return 0
}

// servingNetworkOf maps the session's serving PLMN. An incomplete PLMN yields the
// zero value, which encodes as absent.
func servingNetworkOf(sc *smfctx.SMContext) iri.SMFServingNetwork {
	mcc, mnc := sc.ServingNetwork.GetMcc(), sc.ServingNetwork.GetMnc()
	if mcc == "" || mnc == "" {
		return iri.SMFServingNetwork{}
	}

	return iri.SMFServingNetwork{
		PLMNID: iri.PLMNID{MCC: iri.MCC(mcc), MNC: iri.MNC(mnc)},
		NID:    iri.NID(sc.ServingNetwork.GetNid()),
	}
}

// amfIDOf decomposes the serving AMF's GUAMI into TS 23.003 clause 2.10.1's three
// parts, which is what TS 33.128's aMFID is.
//
// Not from SMContext.ServingNfId: that is the AMF's NF instance UUID and carries no
// AMF identifier at all. The AMF sends its GUAMI on N11 and SetCreateData retains it.
//
// AmfId is six hex digits — region (8 bits), set (10) and pointer (6) — and anything
// else yields nil, which encodes as absent rather than as a guess about which AMF
// served the session. "000000" is a real identifier and is reported.
func amfIDOf(sc *smfctx.SMContext) *iri.AMFID {
	id := sc.Guami.AmfId
	if len(id) != 6 {
		return nil
	}
	raw, err := hex.DecodeString(id)
	if err != nil {
		return nil
	}

	return &iri.AMFID{
		AMFRegionID: iri.AMFRegionID(raw[0]),
		AMFSetID:    iri.AMFSetID(uint16(raw[1])<<2 | uint16(raw[2])>>6),
		AMFPointer:  iri.AMFPointer(raw[2] & 0x3f),
	}
}

// supiUnauthenticatedOf reports the authentication status of the SUPI the record
// carries. TS 33.128: "shall be present if a SUPI is present in the message and set
// to true if the SUPI has not been authenticated, or false if it has been".
//
// Absent means the record carries no SUPI, so the governing condition does not hold.
// It does not mean authenticated — which is why this returns a pointer, and why the
// codec had to learn to emit an OPTIONAL field equal to its type's zero value.
func supiUnauthenticatedOf(sc *smfctx.SMContext) *iri.SUPIUnauthenticatedIndication {
	if supiChoice(sc) == nil {
		return nil
	}
	v := iri.SUPIUnauthenticatedIndication(sc.UnauthenticatedSupi)

	return &v
}

// smfEstablishment maps an SMContext to a TS 33.128 SMFPDUSessionEstablishment
// record. Deferred optionals (deeper subtrees): uEEndpoint, location, and the
// long tail.
func smfEstablishment(sc *smfctx.SMContext) iri.SMFPDUSessionEstablishment {
	return iri.SMFPDUSessionEstablishment{
		SUPI:                supiChoice(sc),
		PEI:                 peiChoice(sc),
		GPSI:                gpsiChoice(sc),
		PDUSessionID:        iri.PDUSessionID(sc.PDUSessionID),
		GTPTunnelID:         servingUPFTEID(sc),
		PDUSessionType:      iri.PDUSessionType(sc.SelectedPDUSessionType),
		SNSSAI:              snssai(sc),
		UEEndpoint:          ueEndpoint(sc),
		DNN:                 iri.DNN(sc.Dnn),
		RequestType:         requestType(sc),
		AccessType:          accessType(sc),
		GTPTunnelInfo:       gtpTunnelInfo(sc),
		SUPIUnauthenticated: supiUnauthenticatedOf(sc),
		AMFID:               amfIDOf(sc),
		RATType:             ratTypeOf(sc.RatType),
		ServingNetwork:      servingNetworkOf(sc),
	}
}

// ueEndpoint is the address assigned to the subject's session — distinct from
// servingUPFTEID, which carries the serving UPF's tunnel endpoint. Reporting only
// the latter tells an agency which network element carried the traffic but not
// which address the target was using, and the second is what an investigation
// correlates against.
//
// Nil when no address has been assigned, or the assigned one is unspecified (0.0.0.0, ::), so
// no record claims an address the session does not have. Where the field is optional it is
// omitted. SMFStartOfInterceptionWithEstablishedPDUSession is the one record where it is not
// optional — the module's SEQUENCE OF has no lower bound and table 6.2.3-4 marks it 0..N, "if
// available", so an empty list would encode — but reportStartOfInterception does not report
// that record at all for such a session, since an empty list would assert it has no endpoint.
func ueEndpoint(sc *smfctx.SMContext) []any {
	if sc == nil || sc.PDUAddress == nil {
		return nil
	}
	return iri.UEEndpoint(sc.PDUAddress.Ip)
}

// ueEndpointAddress is the single-address form SMFPDUSessionModification's uEEndpoint takes:
// the module makes it the UEEndpointAddress CHOICE itself, not the SEQUENCE OF the other
// session records carry. Nil when no address has been assigned, as for ueEndpoint.
func ueEndpointAddress(sc *smfctx.SMContext) any {
	if sc == nil || sc.PDUAddress == nil {
		return nil
	}
	return iri.UEEndpointAddress(sc.PDUAddress.Ip)
}

// smfStartOfInterception maps an SMContext to a TS 33.128
// SMFStartOfInterceptionWithEstablishedPDUSession record (XIRIEvent [9]), emitted
// when a warrant is activated for a UE whose PDU session is already up. Same shape
// as the establishment record, but requestType marks the session as pre-existing.
func smfStartOfInterception(sc *smfctx.SMContext) iri.SMFStartOfInterceptionWithEstablishedPDUSession {
	return iri.SMFStartOfInterceptionWithEstablishedPDUSession{
		SUPI:                supiChoice(sc),
		PEI:                 peiChoice(sc),
		GPSI:                gpsiChoice(sc),
		PDUSessionID:        iri.PDUSessionID(sc.PDUSessionID),
		GTPTunnelID:         servingUPFTEID(sc),
		PDUSessionType:      iri.PDUSessionType(sc.SelectedPDUSessionType),
		SNSSAI:              snssai(sc),
		UEEndpoint:          ueEndpoint(sc),
		DNN:                 iri.DNN(sc.Dnn),
		RequestType:         iri.SMRequestExisting,
		AccessType:          accessType(sc),
		GTPTunnelInfo:       gtpTunnelInfo(sc),
		SUPIUnauthenticated: supiUnauthenticatedOf(sc),
		AMFID:               amfIDOf(sc),
		RATType:             ratTypeOf(sc.RatType),
		ServingNetwork:      servingNetworkOf(sc),
	}
}

// smfModification maps an SMContext to a TS 33.128 SMFPDUSessionModification
// record. Only requestType is mandatory.
func smfModification(sc *smfctx.SMContext) iri.SMFPDUSessionModification {
	return iri.SMFPDUSessionModification{
		SUPI:                supiChoice(sc),
		PEI:                 peiChoice(sc),
		GPSI:                gpsiChoice(sc),
		SNSSAI:              snssai(sc),
		RequestType:         iri.SMRequestModification,
		AccessType:          accessType(sc),
		PDUSessionID:        iri.PDUSessionID(sc.PDUSessionID),
		GTPTunnelInfo:       gtpTunnelInfo(sc),
		SUPIUnauthenticated: supiUnauthenticatedOf(sc),
		RATType:             ratTypeOf(sc.RatType),
		UEEndpoint:          ueEndpointAddress(sc),
		ServingNetwork:      servingNetworkOf(sc),
	}
}

// smfRelease maps an SMContext to a TS 33.128 SMFPDUSessionRelease record.
// Volume counters are optional and deferred (they live on the UPF's URRs).
func smfRelease(sc *smfctx.SMContext) iri.SMFPDUSessionRelease {
	return iri.SMFPDUSessionRelease{
		SUPI:         supiChoice(sc),
		PEI:          peiChoice(sc),
		GPSI:         gpsiChoice(sc),
		PDUSessionID: iri.PDUSessionID(sc.PDUSessionID),
	}
}

// gtpTunnelInfo carries the session's user plane GTP tunnels. TS 33.128 marks
// gTPTunnelInfo mandatory in the establishment, modification and
// start-of-interception records, and it is the only tunnel field the
// modification record has at all — that record carries no gTPTunnelID.
//
// It reports the same UL NG-U F-TEID as gTPTunnelID, which is what table
// 6.2.3-1C asks for: the F-TEID of the UPF endpoint of the NG-U transport
// bearer. The two fields are not redundant to a mediation function — the
// structured form is where later tunnel detail (additional NG-U bearers, the
// downlink RAN tunnel) is defined to go.
func gtpTunnelInfo(sc *smfctx.SMContext) iri.GTPTunnelInfo {
	return iri.GTPTunnelInfo{
		FiveGSGTPTunnels: iri.FiveGSGTPTunnels{ULNGUUPTunnelInformation: servingUPFTEID(sc)},
	}
}

// servingUPFTEID returns the N3 GTP-U F-TEID (uplink TEID + serving UPF IP) of
// the session's default data path, best-effort: a zero F-TEID if the tunnel is
// not yet set up. It uses the canonical default-path selector (the same one the
// PFCP establishment-response handler uses to find the N3 UPF) rather than an
// arbitrary map entry, so a multi-path (ULCL) session yields the anchoring path
// deterministically. The PDU-session establishment record carries this mandatory
// field so the MDF can correlate the user plane.
func servingUPFTEID(sc *smfctx.SMContext) iri.FTEID {
	var f iri.FTEID
	if sc.Tunnel == nil {
		return f
	}
	dp := sc.Tunnel.DataPathPool.GetDefaultPath()
	if dp == nil {
		return f
	}
	node := dp.FirstDPNode
	if node == nil || node.UpLinkTunnel == nil || node.UPF == nil {
		return f
	}
	f.TEID = iri.TEID(node.UpLinkTunnel.TEID)
	if ip := net.ParseIP(node.UPF.GetUPFIP()); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			f.IPv4Address = iri.IPv4Address(v4)
		} else if v16 := ip.To16(); v16 != nil {
			f.IPv6Address = iri.IPv6Address(v16)
		}
	}
	return f
}

// requestType maps the 5GSM request type the AMF supplied to the TS 33.128
// enumeration. These records go to a law-enforcement agency, so reporting every
// session as an initial request — which is what a hard-coded value amounted to —
// misstates whether the UE asked for a new session or resumed an existing one,
// and hides an emergency session entirely.
func requestType(sc *smfctx.SMContext) iri.FiveGSMRequestType {
	switch sc.RequestType {
	case models.REQUESTTYPE_EXISTING_PDU_SESSION:
		return iri.SMRequestExisting
	case models.REQUESTTYPE_INITIAL_EMERGENCY_REQUEST:
		return iri.SMRequestInitialEmergency
	case models.REQUESTTYPE_EXISTING_EMERGENCY_PDU_SESSION:
		return iri.SMRequestExistingEmergency
	default:
		return iri.SMRequestInitial
	}
}

// accessType maps the session's access network type to the TS 33.128
// enumeration, for the same reason: a session over non-3GPP access was reported
// as a 3GPP one.
func accessType(sc *smfctx.SMContext) iri.AccessType {
	if sc.AnType == models.ACCESSTYPE_NON_3_GPP_ACCESS {
		return iri.AccessNonThreeGPP
	}
	return iri.AccessThreeGPP
}

// snssai maps the SMContext's S-NSSAI to the iri form (SST + optional SD). A nil
// or SST-0 S-NSSAI yields the zero value, which the codec omits (the record's
// S-NSSAI is optional).
func snssai(sc *smfctx.SMContext) iri.SNSSAI {
	if sc.Snssai == nil {
		return iri.SNSSAI{}
	}
	s := iri.SNSSAI{SliceServiceType: iri.SliceServiceType(sc.Snssai.Sst)}
	if sc.Snssai.Sd != nil {
		if sd, err := hex.DecodeString(*sc.Snssai.Sd); err == nil && len(sd) == 3 {
			s.SliceDifferentiator = iri.SliceDifferentiator(sd)
		}
	}
	return s
}

// supiChoice returns sc's SUPI as the iri "supi" CHOICE arm (IMSI or NAI), or
// nil when the SMF holds no SUPI in a form we can map.
func supiChoice(sc *smfctx.SMContext) any {
	if v, ok := strings.CutPrefix(sc.Supi, "imsi-"); ok {
		return iri.IMSI(v)
	}
	if v, ok := strings.CutPrefix(sc.Supi, "nai-"); ok {
		return iri.NAI(v)
	}
	return nil
}

// peiChoice returns sc's PEI as the iri "pei" CHOICE arm (IMEI or IMEISV), or nil.
func peiChoice(sc *smfctx.SMContext) any {
	if v, ok := strings.CutPrefix(sc.Pei, "imeisv-"); ok {
		return iri.IMEISV(v)
	}
	if v, ok := strings.CutPrefix(sc.Pei, "imei-"); ok {
		return iri.IMEI(imeiWithoutCheckDigit(v))
	}
	return nil
}

// peiValue is sc's PEI in the form X1 tasking names it: the IMEISV whole, and the IMEI as
// fourteen digits.
func peiValue(pei string) string {
	if v, ok := strings.CutPrefix(pei, "imeisv-"); ok {
		return v
	}
	if v, ok := strings.CutPrefix(pei, "imei-"); ok {
		return imeiWithoutCheckDigit(v)
	}
	return ""
}

// imeiOfIMEISV is the IMEI a UE's IMEISV carries, or "" if its PEI is not an IMEISV.
//
// An IMEISV is the IMEI's Type Allocation Code and Serial Number, eight and six digits, followed
// by a two-digit Software Version Number (TS 23.003), so its first fourteen digits are the IMEI
// without its check digit: the form TS 103 221-1's peiImei names. A UE that presented an IMEISV
// is the device an IMEI warrant names, and presenting the IMEI as well is what lets that warrant
// match it. The record's PEI stays the IMEISV the UE actually presented.
func imeiOfIMEISV(pei string) string {
	v, ok := strings.CutPrefix(pei, "imeisv-")
	if !ok || len(v) != 16 {
		return ""
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return v[:14]
}

// imeiWithoutCheckDigit drops the check digit from a fifteen-digit IMEI.
//
// The SMF receives the PEI from the AMF in TS 29.571 form, "imei-" and fifteen digits, because
// NAS carries the IMEI that way: TS 24.008 clause 10.5.1.4 says "the IMEI is composed of 15
// digits", the last being the check digit TS 23.003 computes over the other fourteen. TS 33.128
// defines IMEI as NumericString (SIZE(14)) and TS 103 221-1's peiImei as fourteen digits, so
// both the record and the target identifier X1 tasking names are the TAC and serial number
// alone. A value of any other length is passed through for the encoder to refuse, rather than
// guessed at. The AMF carries the same function.
func imeiWithoutCheckDigit(v string) string {
	if len(v) == 15 {
		return v[:14]
	}
	return v
}

// gpsiChoice returns sc's GPSI as the iri "gpsi" CHOICE arm (MSISDN), or nil.
func gpsiChoice(sc *smfctx.SMContext) any {
	if v, ok := strings.CutPrefix(sc.Gpsi, "msisdn-"); ok {
		return iri.MSISDN(v)
	}
	return nil
}

// parseXID converts a task's X1 identifier to the 16-byte XID carried in the
// X2 PDU header. It delegates to types.XID.Bytes so the conversion lives in one
// place across the POIs and the triggered CC-POI in the UPF.
func parseXID(xid types.XID) [16]byte {
	return xid.Bytes()
}

// afterPrefix returns s with the first matching prefix removed, or "" if none
// match (an identifier we cannot map is treated as not present).
func afterPrefix(s string, prefixes ...string) string {
	for _, p := range prefixes {
		if v, ok := strings.CutPrefix(s, p); ok {
			return v
		}
	}
	return ""
}

// keepaliveConfig turns the operator's three settings into the clause 6.2.4
// mechanism's configuration.
//
// It encodes no defaults of its own. An unset timer is passed through as zero, which
// x2x3 resolves to the specification's own value — so there is one place where "60
// seconds" is written down, and it is beside the mechanism rather than in each of the
// three network functions that run it.
//
// An unusable setting is reported to the ADMF and then discarded in favour of the
// defaults, rather than refusing to start. The alternatives are both worse: this
// subsystem is optional to the network function, so a refusal here means lawful
// interception silently does not run, and accepting the value as written can mean a
// mechanism that disconnects every delivery connection on a timer. Reporting keeps
// the operator's mistake visible to the only party that can act on it while the
// element keeps intercepting.
func keepaliveConfig(cfg Config, reporter *x1.Reporter) x2x3.KeepaliveConfig {
	ka := x2x3.KeepaliveConfig{
		Disabled: cfg.X2X3KeepaliveEnabled != nil && !*cfg.X2X3KeepaliveEnabled,
	}

	report := func(format string, args ...any) {
		if reporter != nil {
			reporter.Notify(x1.NEIssueInvalidConfig, fmt.Sprintf(format, args...))
		}
	}

	for _, t := range []struct {
		name  string
		value string
		into  *time.Duration
	}{
		{"x2x3KeepaliveTimeP1", cfg.X2X3KeepaliveTimeP1, &ka.TimeP1},
		{"x2x3KeepaliveTimeP2", cfg.X2X3KeepaliveTimeP2, &ka.TimeP2},
	} {
		if t.value == "" {
			continue
		}
		d, err := time.ParseDuration(t.value)
		if err != nil {
			report("%s is not a duration; the specification's default is used instead", t.name)

			continue
		}
		*t.into = d
	}

	if err := ka.Validate(); err != nil {
		report("the configured X2/X3 keepalive timers are unusable and the specification's "+
			"defaults are used instead: %v", err)

		return x2x3.KeepaliveConfig{Disabled: ka.Disabled}
	}

	return ka
}

// configuredDestinations maps the pre-shared destinations from configuration onto the
// form the X1 server resolves them in, and tells the ADMF about any it cannot use.
//
// An entry that does not resolve is not a small mistake: unless the ADMF provisions that DID
// itself, a task naming it is refused with 2040 (DID does not exist on the NE), so an
// operator's typo stops the warrant it was meant for. There is no general log to say so on — this plane deliberately writes to none —
// and the count is all the ADMF needs, since the entries themselves are the operator's
// configuration and not the ADMF's business.
func configuredDestinations(dests []Destination, reporter *x1.Reporter) []x1.ConfiguredDestination {
	out := make([]x1.ConfiguredDestination, 0, len(dests))
	var rejected int
	for _, d := range dests {
		entry := x1.ConfiguredDestination{DID: d.DID, DeliveryType: d.DeliveryType, Address: d.Address}
		if entry.Valid() != nil {
			rejected++

			continue
		}
		out = append(out, entry)
	}
	if rejected > 0 {
		reporter.Notify(x1.NEIssueInvalidConfig, fmt.Sprintf(
			"%d configured delivery destination(s) are unusable and were dropped; "+
				"a task naming one will be refused", rejected))
	}

	return out
}

// resolvableTargets are the identifier kinds this element can match a subject on.
// It is targetsOf's counterpart: what that function can produce is exactly what a
// warrant must name for this element to be able to act on it.
var resolvableTargets = []types.TargetIdentifierType{
	types.TargetSUPI, types.TargetPEI, types.TargetGPSI,
}

// canApply refuses tasking this element cannot act on, before it is acknowledged.
func canApply(task types.InterceptTask) error {
	if len(task.Targets) == 0 {
		return errors.New("li: task names no target identifiers")
	}
	// Every criterion must match (TS 103 221-1 table 6.2.1.2-1), so one this element
	// never evaluates makes the task unmatchable here, and so does a combination no
	// subscriber presents; the same table has the element reject both rather than
	// acknowledge an interception that can never run.
	if !task.NamesOnlyTypes(resolvableTargets...) {
		return errors.New("li: task names an identifier this element does not resolve, and " +
			"every criterion of a task must match; it matches subjects by SUPI, PEI or GPSI")
	}
	if a, b, ok := task.ContradictoryTargets(); ok {
		return fmt.Errorf("li: task names %s and %s, which no subscriber presents together, "+
			"and every criterion of a task must match", a.Type, b.Type)
	}

	// **No product test here, deliberately.** The AMF refuses an X3Only warrant, because an
	// IRI-POI that cannot produce xCC can produce nothing at all for one. This element is
	// both an IRI-POI *and* the CC Triggering Function, so an X3Only task is real work: it
	// triggers the serving UPFs' CC-POIs and applies duplication, and it delivers no xIRI
	// because none was asked for. Refusing it would refuse content interception outright.
	return nil
}

// canApplyHere is canApply and the one test that needs this element's configuration: a task
// naming no destination has its xIRI served by the configured MDF2 (see x2Destinations), so with
// no MDF2 configured a task ordering xIRI is served by nothing. Acknowledged, it would be held and
// reported running while every record it produced was numbered and delivered nowhere, the
// condition x1 refuses with 3040 for a task whose named destinations give no X2 endpoint. MDF2
// itself stays optional: an ADMF that names a destination on every task needs none.
func (s *subsystem) canApplyHere(task types.InterceptTask) error {
	if err := canApply(task); err != nil {
		return err
	}
	if task.WantsProduct(types.ProductIRI) && len(task.DIDs) == 0 && s.mdf2 == "" {
		return errors.New("li: task orders xIRI and names no delivery destination, and this " +
			"element has no configured X2 endpoint to serve one, so every record this task " +
			"produced would be delivered to nowhere")
	}

	return nil
}

// keepaliveProcedure reads the X1 keepalive procedure an operator configured, or nil when
// they disabled it (TS 103 221-1 clause 6.6.2: "By default (with no prior agreement) they
// are enabled", so only a stated agreement turns it off).
func keepaliveProcedure(cfg Config) (*x1.KeepaliveProcedure, error) {
	if cfg.KeepaliveDisabled {
		return nil, nil //nolint:nilnil // a disabled procedure is not an error
	}

	p := x1.KeepaliveProcedure{RetainTasking: cfg.KeepaliveRetainTasking}
	for _, t := range []struct {
		name, value string
		into        *time.Duration
	}{
		{"keepaliveTimeout", cfg.KeepaliveTimeout, &p.TimeP2},
		{"keepaliveTimeP1", cfg.KeepaliveTimeP1, &p.TimeP1},
		{"keepaliveTimeP3", cfg.KeepaliveTimeP3, &p.TimeP3},
	} {
		d, err := parseKeepaliveTimer(t.name, t.value)
		if err != nil {
			return nil, err
		}
		*t.into = d
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}

	return &p, nil
}

// parseKeepaliveTimer reads one keepalive timer an operator wrote. Empty is the clause
// default, returned as zero.
//
// A value that does not parse is refused rather than read as zero: zero means "the
// default", so discarding the parse error would turn a mistyped duration into a silently
// different timer on an element that otherwise looks healthy.
//
// A non-positive duration is refused for the same reason: "0s" and "-5m" are values an
// operator wrote, and neither can mean the timer they asked for. So is one below
// x1.MinKeepaliveWindow, which the procedure cannot measure; the library refuses it too,
// for any caller that does not check.
func parseKeepaliveTimer(name, v string) (time.Duration, error) {
	if v == "" {
		return 0, nil
	}

	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("li: %s %q is not a duration", name, v)
	}
	if d <= 0 {
		return 0, fmt.Errorf("li: %s %q is not a positive duration", name, v)
	}
	if d < x1.MinKeepaliveWindow {
		return 0, fmt.Errorf("li: %s %q is shorter than the minimum keepalive timer %s", name, v, x1.MinKeepaliveWindow)
	}

	return d, nil
}
