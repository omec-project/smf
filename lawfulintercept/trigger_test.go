// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
)

// sessionOn is the session side of an endpoint match: a serving UPF identified the
// way the session path identifies it, carrying the address sessionUPFs has already
// resolved to key that session's PFCP context. Built here exactly as production
// builds it, so a test cannot accidentally assert against a shape the session path
// never produces.
func sessionOn(node string) upfSession {
	n := upfNode(node)

	return upfSession{node: n, addr: n.ResolveNodeIdToIp().String()}
}

// resolvingTo points a registry's name lookup at a fixed table, and refreshes the
// index so the answers are in place. The registry resolves names on its own
// goroutine now — which is the whole point, since resolving them on the trigger path
// put a name lookup under a targeted subscriber's session lock — so a test drives
// that resolution rather than waiting for it.
func resolvingTo(reg *triggerRegistry, table map[string]string) {
	// Under the lock: the registry's own refresh loop reads this hook, and it is
	// already running by the time a test substitutes one.
	reg.mu.Lock()
	reg.lookup = func(_ context.Context, host string) (string, error) {
		addr, ok := table[host]
		if !ok {
			return "", fmt.Errorf("test resolver: %q not found", host)
		}

		return addr, nil
	}
	reg.mu.Unlock()

	reg.refreshResolved()
}

// staticRegistry builds a registry with its address index already populated and no
// background goroutines: no refresh loop and no keepalive. It exists for the tests
// whose subject is what a lookup *does not* happen, where a live refresh loop makes
// any count ambiguous.
//
// nodes maps a configured NodeID to the address it is taken to resolve to.
func staticRegistry(nodes map[string]string) *triggerRegistry {
	reg := &triggerRegistry{
		mdf3:      testMDF3Addr,
		endpoints: make(map[string]*upfEndpoint, len(nodes)),
		resolved:  make(map[string]string, len(nodes)),
		installed: make(map[string]installedTrigger),
		pending:   make(map[string]*pendingWithdrawal),
	}
	for node, addr := range nodes {
		reg.endpoints[node] = &upfEndpoint{node: upfNode(node), dids: map[string]string{}}
		reg.resolved[node] = addr
		reg.order = append(reg.order, node)
	}
	slices.Sort(reg.order)

	return reg
}

// matchOn is matchEndpoint under the lock it documents needing.
//
// The pre-existing tests called it bare, which was harmless while it read only
// endpoints and order — both written once at construction. It now also reads the
// resolved-address index, which this registry's own refresh loop writes, so the
// contract has teeth: -race reports the read against that write, and the production
// caller (plan) has held the lock all along.
const trigNodeA = "10.0.1.5"

func matchOn(reg *triggerRegistry, session upfSession) (string, bool) {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	key, _, ok := reg.matchEndpoint(session)

	return key, ok
}

// upfNode parses a UPF's N4 node identity the way the session path carries it —
// unresolved, so a test can distinguish matching by identity from matching by
// address (see matchEndpoint).
func upfNode(s string) smfctx.NodeID { return *smfctx.NewNodeID(s) }

// wrongNE is an element identifier this SMF does not address, which is how a POI
// is made to answer correctly under a name the requester did not ask for.
const wrongNE = testUPFNEID2

// mustRegistry builds a registry from a configuration the test knows is valid.
// Construction only fails on an ambiguous configuration, which the tests that care
// about that assert on explicitly.
func mustRegistry(cfg Config) *triggerRegistry {
	reg, err := newTriggerRegistry(cfg, nil, nil, nil)
	if err != nil {
		panic(err)
	}

	return reg
}

// fakePOI is a triggered CC-POI: it records the X1 requests a CC-TF sends it and
// answers as a conformant NE would. It lets the trigger path be exercised without
// a UPF or a PKI, since what matters here is what the CC-TF sends and how it
// reacts to the answer.
type fakePOI struct {
	mu       sync.Mutex
	bodies   []string
	refuse   bool // answer every request with an error
	srv      *httptest.Server
	requests int
	// refuseUntilProvisioned models a POI that has restarted: it refuses a trigger
	// naming a destination it does not hold, and accepts once one is created again.
	refuseUntilProvisioned bool
	provisioned            bool
	// holds is the tasking this POI reports when asked, which is how a restarted
	// triggering function discovers what it left behind.
	holds []string
	// detailsFail makes the POI refuse to say what it holds, which is the failure
	// reconciliation has to survive — an X1 endpoint that is not up yet.
	detailsFail bool
	// unhealthy maps an XID to the provisioningStatus this POI reports for it.
	// Anything other than "complete" means the trigger is not actually running,
	// which the triggering function can only learn from this answer.
	unhealthy map[string]string
	// misname makes this POI answer under a different NE identifier while otherwise
	// behaving perfectly. It models the two things the response binding exists for
	// and cannot tell apart: an endpoint a misroute put in the path, and a POI whose
	// configured identity does not match the one this SMF was told to address.
	misname string
	// misnameOn restricts misname to requests whose body contains this string,
	// so a test can make one exchange of a sequence unbindable and leave the rest
	// working. Empty applies it to every answer.
	misnameOn string
	// hangOn makes this POI accept one request whose body contains this string and
	// never answer it. It is the member of the ambiguous-activation class that no
	// answer of any kind describes: the request arrives, the POI may well apply it,
	// and what ends the exchange is the requester's own clock.
	hangOn string
	// activateScript answers successive ActivateTask requests in order, overriding the other
	// settings for each: "unbindable" answers under another NE identifier (an answer this
	// element cannot bind, the no-answer class), "refuse" refuses with 3000, "ok" acknowledges.
	// It is what lets a test say "the first attempt went unanswered and the replay was
	// refused" without a setting that persists across requests.
	activateScript []string
	// refuseCode is the errorCode a refusing POI answers with. Zero means 1000, a
	// generic refusal. It matters because the code is the whole content of some
	// answers: 2020 says the XID is not held, which for a withdrawal is the
	// outcome, not a failure.
	refuseCode int
	// refuseOn refuses only the requests whose body contains it, leaving the rest of a
	// sequence working. refuse refuses everything, which cannot express "the activation
	// lands and the withdrawal that follows it does not".
	refuseOn string
	// delayOn and delay hold one class of request back before it is answered, so a
	// test can make one exchange of a sequence complete after a later one. It is
	// what distinguishes "these two requests were sent in order" from "these two
	// requests happened to finish in order", which is the whole subject of the
	// per-warrant ordering: two relabels dispatched on bare goroutines both succeed,
	// and the POI is left holding whichever finished last.
	delayOn string
	delay   func()
	// pendingOn answers the requests whose body contains it with an oK of "Acknowledged" —
	// received and not completed (TS 103 221-1 clause 5.2.2) — instead of
	// "AcknowledgedAndCompleted". The requester returns that as x1.ErrAcknowledgedPending,
	// and nothing it answers may be recorded as done.
	pendingOn string
}

// poiEnvelope builds the response envelope a conformant NE returns: the response
// type derived from the request's, and the five fields of the schema's
// X1ResponseMessage base type — the peer's echoed back, its own stated.
//
// A bare <oK> and nothing else is not a response any conformant NE sends, and the
// CC-TF refuses it as unattributable. A stub that is not conformant tests this element against a
// fiction — and what this file is about is precisely what the CC-TF does with the
// answers it gets back.
func poiEnvelope(t *testing.T, request []byte, payload string) string {
	t.Helper()

	var in struct {
		Messages []struct {
			Type            string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
			AdmfIdentifier  string `xml:"admfIdentifier"`
			NeIdentifier    string `xml:"neIdentifier"`
			Timestamp       string `xml:"messageTimestamp"`
			Version         string `xml:"version"`
			X1TransactionID string `xml:"x1TransactionId"`
		} `xml:"x1RequestMessage"`
	}
	if err := xml.Unmarshal(request, &in); err != nil {
		t.Fatalf("fake POI could not parse the request it is answering: %v", err)
	}
	if len(in.Messages) != 1 {
		t.Fatalf("fake POI received %d request messages, want 1", len(in.Messages))
	}
	m := in.Messages[0]

	local := m.Type
	if i := strings.LastIndex(local, ":"); i >= 0 {
		local = local[i+1:]
	}

	return `<?xml version="1.0"?><x1:X1Response xmlns:x1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
		`<x1:x1ResponseMessage xsi:type="x1:` + strings.TrimSuffix(local, "Request") + `Response">` +
		`<x1:admfIdentifier>` + m.AdmfIdentifier + `</x1:admfIdentifier>` +
		`<x1:neIdentifier>` + m.NeIdentifier + `</x1:neIdentifier>` +
		`<x1:messageTimestamp>` + m.Timestamp + `</x1:messageTimestamp>` +
		`<x1:version>` + m.Version + `</x1:version>` +
		`<x1:x1TransactionId>` + m.X1TransactionID + `</x1:x1TransactionId>` +
		payload +
		`</x1:x1ResponseMessage></x1:X1Response>`
}

// The steps an activateScript can hold.
const (
	scriptUnbindable = "unbindable"
	scriptRefuse     = "refuse"
	scriptOK         = "ok"
)

func newFakePOI(t *testing.T) *fakePOI {
	t.Helper()

	p := &fakePOI{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test

		p.mu.Lock()
		p.bodies = append(p.bodies, string(body))
		p.requests++
		refuse := p.refuse
		if p.refuseOn != "" && strings.Contains(string(body), p.refuseOn) {
			refuse = true
		}
		refuseCode := p.refuseCode
		if refuseCode == 0 {
			refuseCode = 1000
		}
		if p.refuseUntilProvisioned {
			switch {
			case strings.Contains(string(body), "CreateDestinationRequest"):
				p.provisioned = true
			case !p.provisioned:
				refuse = true
			}
		}
		scriptedMisname := ""
		if len(p.activateScript) > 0 && strings.Contains(string(body), "ActivateTaskRequest") {
			step := p.activateScript[0]
			p.activateScript = p.activateScript[1:]
			switch step {
			case scriptUnbindable:
				refuse, scriptedMisname = false, "some-other-upf"
			case scriptRefuse:
				refuse, refuseCode = true, 3000
			case scriptOK:
				refuse = false
			}
		}
		var delay func()
		if p.delayOn != "" && strings.Contains(string(body), p.delayOn) {
			delay = p.delay
			// One request only: what is being arranged is an out-of-order completion,
			// and holding every request back would just slow the sequence down.
			p.delayOn = ""
		}
		hang := false
		if p.hangOn != "" && strings.Contains(string(body), p.hangOn) {
			hang = true
			// Both set *before* the wait below, not after it. Exactly one request
			// hangs, and from here this POI answers nothing — so the state is already
			// in place when the requester gives up, rather than racing the retry that
			// its giving up immediately produces.
			p.hangOn = ""
			p.refuse = true
		}
		p.mu.Unlock()

		// Outside the lock: whatever the test does in here, the POI must still be able
		// to answer the requests that overtake this one.
		if delay != nil {
			delay()
		}

		if hang {
			// Never answer. The requester's own deadline is what ends this exchange,
			// and waiting on the request's context rather than on a duration of this
			// handler's own means it goes away when the client does.
			<-r.Context().Done()

			return
		}

		if strings.Contains(string(body), "GetAllDetailsRequest") {
			p.mu.Lock()
			held := append([]string(nil), p.holds...)
			fail := p.detailsFail
			p.mu.Unlock()

			if fail {
				//nolint:errcheck // test handler write
				_, _ = w.Write([]byte(poiEnvelope(t, body,
					`<x1:errorInformation><x1:errorCode>1000</x1:errorCode>`+
						`<x1:errorDescription>not ready</x1:errorDescription></x1:errorInformation>`)))

				return
			}

			p.mu.Lock()
			unhealthy := map[string]string{}
			for k, v := range p.unhealthy {
				unhealthy[k] = v
			}
			p.mu.Unlock()

			var details string
			for _, xid := range held {
				// taskStatus is a complex type in the schema; a bare string there is not
				// what a conformant POI emits.
				status := "complete"
				if s, ok := unhealthy[xid]; ok {
					status = s
				}
				details += `<x1:taskResponseDetails><x1:taskDetails><x1:xId>` + xid +
					`</x1:xId></x1:taskDetails><x1:taskStatus>` +
					`<x1:provisioningStatus>` + status + `</x1:provisioningStatus>` +
					`<x1:listOfFaults/></x1:taskStatus></x1:taskResponseDetails>`
			}

			//nolint:errcheck // test handler write
			_, _ = w.Write([]byte(poiEnvelope(t, body,
				`<x1:listOfTaskResponseDetails>`+details+`</x1:listOfTaskResponseDetails>`)))

			return
		}

		if refuse {
			//nolint:errcheck // test handler write
			_, _ = w.Write([]byte(poiEnvelope(t, body,
				`<x1:errorInformation><x1:errorCode>`+strconv.Itoa(refuseCode)+`</x1:errorCode>`+
					`<x1:errorDescription>refused</x1:errorDescription></x1:errorInformation>`)))

			return
		}

		p.mu.Lock()
		misname := p.misname
		misnameOn := p.misnameOn
		p.mu.Unlock()

		// Scoped to one message type when a test asks for it. Mis-answering
		// everything makes the *first* exchange of the sequence fail, which for a
		// trigger is the CreateDestination — a different branch entirely, and one
		// where nothing has been installed at the POI to withdraw.
		if misnameOn != "" && !strings.Contains(string(body), misnameOn) {
			misname = ""
		}
		if scriptedMisname != "" {
			misname = scriptedMisname
		}

		ok := "AcknowledgedAndCompleted"
		p.mu.Lock()
		if p.pendingOn != "" && strings.Contains(string(body), p.pendingOn) {
			ok = "Acknowledged"
		}
		p.mu.Unlock()

		answer := poiEnvelope(t, body, `<x1:oK>`+ok+`</x1:oK>`)
		if misname != "" {
			answer = strings.Replace(answer,
				`<x1:neIdentifier>upf-1</x1:neIdentifier>`,
				`<x1:neIdentifier>`+misname+`</x1:neIdentifier>`, 1)
		}

		//nolint:errcheck // test handler write
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(p.srv.Close)

	return p
}

func (p *fakePOI) sent() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]string(nil), p.bodies...)
}

// countMessages returns how many of the recorded requests carry the given
// xsi:type.
func (p *fakePOI) countMessages(msgType string) int {
	n := 0
	for _, b := range p.sent() {
		if strings.Contains(b, `xsi:type="ns1:`+msgType+`"`) {
			n++
		}
	}

	return n
}

// triggerSubsystem builds a subsystem whose only configured capability is CC
// triggering, pointed at poi.
func triggerSubsystem(t *testing.T, poi *fakePOI) *subsystem {
	t.Helper()

	cfg := Config{
		NEID: testNEID,
		MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{
			{NodeID: trigNodeA, X1URL: poi.srv.URL, NEID: testUPFNEID1},
		},
	}

	// A store, because a production subsystem always has one and the paths that
	// consult it — matchingTasks, and the scans' revalidation before each delivery —
	// are reached from the trigger paths these tests drive. A test that wants a scan
	// to run activates its task in here.
	s := &subsystem{
		neID:     testNEID,
		triggers: mustRegistry(cfg),
		store:    store.New(),
	}
	// Wired as Init wires it. Without these the keepalive round asks the POI nothing about the
	// tasks it holds and never reconciles an endpoint whose account was lost — so a test would
	// exercise a registry that production does not build.
	s.triggers.reportTaskHealth = s.noteTaskHealth
	s.triggers.reconcile = s.reconcileEndpoint
	waitForScans(t, s)

	return s
}

// waitForScans joins everything a subsystem dispatched before the test that built it
// returns: its scan goroutines, and its trigger registry's own background work.
//
// A goroutine that outlives its test does not merely leak. It reaches the sessions
// and the fake POI the finished test built, so what -race reports is a race in
// whichever test happens to be running next — a rotating victim, which is the hardest
// kind of failure to attribute. The suite has to be hermetic, not merely green.
func waitForScans(t *testing.T, s *subsystem) {
	t.Helper()

	t.Cleanup(func() {
		s.scans.Wait()
		if s.triggers != nil {
			s.triggers.Stop()
		}
	})
}

// TestInstallTriggersSendsWarrantIdentity is the core of the triggering interface: the trigger a
// CC-TF sends must carry the warrant XID, the session's correlation identifier and
// the UPF's own SEID as the detection criterion, and must be preceded by the
// destination it references.
func TestInstallTriggersSendsWarrantIdentity(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}

	s.installFor("session-ref-1",
		[]types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 14426627323429955319}},
		0x2632898145f4d191)

	if n := poi.countMessages("CreateDestinationRequest"); n != 1 {
		t.Errorf("CreateDestination sent %d times, want once before the first trigger", n)
	}

	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Fatalf("ActivateTask sent %d times, want once", n)
	}

	sent := poi.sent()
	// The destination must be provisioned before the trigger that names it
	// (TS 33.128 table 6.2.3-6).
	if !strings.Contains(sent[0], "CreateDestinationRequest") {
		t.Error("the first request was not CreateDestination")
	}

	activate := sent[len(sent)-1]
	for _, want := range []string{
		// The warrant, as ProductID — what makes the content attributable.
		`<ns1:productID>11111111-1111-4111-8111-111111111111</ns1:productID>`,
		// The session's correlation identifier, matching the xIRI's.
		`<ns1:correlationID>2752413510594253201</ns1:correlationID>`,
		// This UPF's SEID as the detection criterion.
		`<ext:SEID>14426627323429955319</ext:SEID>`,
		`<ns1:deliveryType>X3Only</ns1:deliveryType>`,
	} {
		if !strings.Contains(activate, want) {
			t.Errorf("trigger missing %s\ngot:\n%s", want, activate)
		}
	}

	// The trigger's own XID is the CC-TF's, allocated per (warrant, session, UPF) —
	// it must not be the warrant's, or the POI would label content with the trigger.
	if strings.Contains(activate, `<ns1:xId>11111111-1111-4111-8111-111111111111</ns1:xId>`) {
		t.Error("the trigger reused the warrant XID as its own task id")
	}
}

// TestInstallTriggersIsIdempotent covers the case where establishment and a
// mid-session activation both reach the same session: tasking a POI twice for one
// session would make it deliver every packet twice.
func TestInstallTriggersIsIdempotent(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), seid: 42}}

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Errorf("ActivateTask sent %d times for one session, want once", n)
	}
	// The destination is provisioned once per UPF, not once per trigger.
	if n := poi.countMessages("CreateDestinationRequest"); n != 1 {
		t.Errorf("CreateDestination sent %d times, want once per UPF", n)
	}
}

// TestInstallTriggersPerUPFAndWarrant checks the fan-out: a session on two UPFs
// needs a trigger at each, and two warrants covering it need one each — with a
// distinct trigger XID every time, but the same session correlation.
func TestInstallTriggersPerUPFAndWarrant(t *testing.T) {
	poi := newFakePOI(t)
	cfg := Config{
		NEID: testNEID,
		MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{
			{NodeID: trigNodeA, X1URL: poi.srv.URL, NEID: testUPFNEID1},
			{NodeID: trigNodeB, X1URL: poi.srv.URL, NEID: testUPFNEID2},
		},
	}
	s := &subsystem{neID: testNEID, triggers: mustRegistry(cfg)}

	warrants := []types.InterceptTask{
		{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}},
		{XID: testXIDSecondary, Products: []types.ProductType{types.ProductCC}},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), seid: 42}, {node: upfNode(trigNodeB), seid: 43}}

	s.installFor("session-ref-1", warrants, upfs, 7)

	// 2 warrants x 2 UPFs.
	if n := poi.countMessages("ActivateTaskRequest"); n != 4 {
		t.Errorf("ActivateTask sent %d times, want 4 (a warrant x UPF fan-out)", n)
	}

	if got := len(s.triggers.installed); got != 4 {
		t.Errorf("installed triggers = %d, want 4", got)
	}

	// Every trigger XID must be distinct, or one deactivation would remove another
	// agency's interception.
	seen := map[types.XID]bool{}
	for _, installed := range s.triggers.installed {
		if seen[installed.xid] {
			t.Errorf("trigger XID %q reused across triggers", installed.xid)
		}
		seen[installed.xid] = true
	}
}

// TestInstallTriggersReportsRefusal covers clause 5.2.6: when a triggered POI
// refuses, the CC-TF must tell the LIPF — the warrant is authorised but no content
// will be produced, and nothing else in the system knows.
func TestInstallTriggersReportsRefusal(t *testing.T) {
	poi := newFakePOI(t)
	poi.refuse = true

	s := triggerSubsystem(t, poi)
	rec := &recordingTaskReporter{}
	s.taskReporter = rec

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}

	s.installFor("session-ref-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

	if len(rec.reports) != 1 {
		t.Fatalf("task issues reported = %d, want 1", len(rec.reports))
	}
	if rec.reports[0].xid != string(warrant.XID) {
		t.Errorf("reported XID = %q, want the warrant %q", rec.reports[0].xid, warrant.XID)
	}
	if rec.reports[0].reportType != x1.TaskReportTerminatingFault {
		t.Errorf("reportType = %q, want %q", rec.reports[0].reportType, x1.TaskReportTerminatingFault)
	}
	// The report must not name the target.
	if strings.Contains(rec.reports[0].details, "imsi") {
		t.Errorf("task issue details name a subscriber: %q", rec.reports[0].details)
	}
}

// TestInstallTriggersRetriesAfterFailure checks that a refused trigger is not
// recorded as installed: a later establishment or activation must try again, or
// one transient failure would disable the interception for the session's life.
func TestInstallTriggersRetriesAfterFailure(t *testing.T) {
	poi := newFakePOI(t)
	poi.refuse = true

	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), seid: 42}}

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

	if len(s.triggers.installed) != 0 {
		t.Fatalf("a refused trigger was recorded as installed: %+v", s.triggers.installed)
	}

	poi.mu.Lock()
	poi.refuse = false
	poi.mu.Unlock()

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

	if len(s.triggers.installed) != 1 {
		t.Errorf("installed = %d after a successful retry, want 1", len(s.triggers.installed))
	}
}

// TestInstallTriggersReportsMissingEndpoint covers a UPF carrying a tasked
// session's traffic that this SMF has no way to task. The interception is
// authorised and will produce nothing, so it must not pass silently.
func TestInstallTriggersReportsMissingEndpoint(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	rec := &recordingTaskReporter{}
	s.taskReporter = rec

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}

	// A UPF absent from the configured triggering endpoints.
	s.installFor("session-ref-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeElsewhere), seid: 42}}, 7)

	if poi.requests != 0 {
		t.Error("a request was sent for a UPF with no configured endpoint")
	}
	if len(rec.reports) != 1 {
		t.Fatalf("task issues reported = %d, want 1", len(rec.reports))
	}
}

// TestTakeForSessionAndWarrant pins the bookkeeping the deactivation paths depend
// on. A session's triggers are withdrawn when it is released; a warrant's are
// withdrawn when it is deactivated, wherever they were installed. Taken triggers
// move to pending rather than out of the registry: the withdrawal has been decided,
// not performed.
func TestTakeForSessionAndWarrant(t *testing.T) {
	reg := &triggerRegistry{
		installed: map[string]installedTrigger{},
		pending:   map[string]*pendingWithdrawal{},
	}

	// Two warrants, two sessions, two UPFs.
	for _, w := range []types.XID{"warrant-a", "warrant-b"} {
		for _, ref := range []string{"sess-1", "sess-2"} {
			for _, node := range []string{trigNodeA, trigNodeB} {
				reg.installed[triggerKey(w, ref, node)] = installedTrigger{
					xid: types.XID(string(w) + "|" + ref + "|" + node),
				}
			}
		}
	}
	if len(reg.installed) != 8 {
		t.Fatalf("setup: installed = %d, want 8", len(reg.installed))
	}

	// Releasing one session takes both warrants' triggers at both UPFs, and nothing
	// belonging to the other session. The UPFs come from the bookkeeping, not from
	// the session, so a session whose PFCP state is already gone is still cleaned up.
	got := reg.takeForSession("sess-1")
	for _, w := range got {
		if w.nodeID != trigNodeA && w.nodeID != trigNodeB {
			t.Errorf("takeForSession named an unexpected node %q", w.nodeID)
		}
	}
	if len(got) != 4 {
		t.Errorf("takeForSession returned %d triggers, want 4 (2 warrants x 2 UPFs)", len(got))
	}
	if len(reg.installed) != 4 {
		t.Errorf("installed = %d after takeForSession, want 4 (sess-2's)", len(reg.installed))
	}
	// Nothing is withdrawn yet, so the registry is still answerable for all four.
	if len(reg.pending) != 4 {
		t.Errorf("pending = %d after takeForSession, want the 4 it took — a trigger dropped "+
			"here is one the POI keeps and nothing retries", len(reg.pending))
	}

	// Deactivating a warrant takes its remaining triggers, each naming the UPF it
	// must be deactivated at.
	byWarrant := reg.takeForWarrant("warrant-a")
	for _, w := range byWarrant {
		if w.nodeID != trigNodeA && w.nodeID != trigNodeB {
			t.Errorf("takeForWarrant named an unexpected node %q", w.nodeID)
		}
	}
	if len(byWarrant) != 2 {
		t.Errorf("takeForWarrant returned %d triggers, want warrant-a's remaining 2", len(byWarrant))
	}
	// Only warrant-b's sess-2 pair remains.
	if len(reg.installed) != 2 {
		t.Errorf("installed = %d after takeForWarrant, want 2 (warrant-b's)", len(reg.installed))
	}
	for key := range reg.installed {
		if !strings.HasPrefix(key, "warrant-b|") {
			t.Errorf("a non-warrant-b trigger survived: %q", key)
		}
	}
}

// TestInstallTriggersReprovisionsAfterRestart: a POI restarts
// independently of this triggering function and takes the destination we
// provisioned with it. Believing otherwise meant every later trigger named a
// destination the POI no longer knew, so it duplicated the subject's traffic and
// discarded every copy while we were told interception was running.
func TestInstallTriggersReprovisionsAfterRestart(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}

	// First session: destination provisioned, trigger accepted.
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

	if n := poi.countMessages("CreateDestinationRequest"); n != 1 {
		t.Fatalf("CreateDestination sent %d times, want 1", n)
	}

	// The POI restarts: it has forgotten the destination, so it now refuses a
	// trigger naming it — which is the only way we can find out.
	poi.mu.Lock()
	poi.refuseUntilProvisioned = true
	poi.mu.Unlock()

	s.installFor("session-2", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 43}}, 9)

	// We must have re-provisioned rather than given up.
	if n := poi.countMessages("CreateDestinationRequest"); n != 2 {
		t.Errorf("CreateDestination sent %d times, want a second after the refusal", n)
	}

	// And the interception must now be installed, not abandoned.
	if len(s.triggers.installed) != 2 {
		t.Errorf("installed = %d, want both sessions tasked after the retry", len(s.triggers.installed))
	}
}

// TestReconcileWithdrawsTaskingFromAPreviousLife: after a restart
// this process has no record of the triggers it installed, while the POI still
// holds them — and tasking nobody can withdraw does not stop, not even when the
// warrant is revoked. The keepalive fail-safe cannot cover it, because a restarted
// triggering function is alive.
func TestReconcileWithdrawsTaskingFromAPreviousLife(t *testing.T) {
	poi := newFakePOI(t)
	poi.mu.Lock()
	poi.holds = []string{testXIDHeld, "bbbbbbbb-2222-4222-8222-222222222222"}
	poi.mu.Unlock()

	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	s.reconcileOne()

	// Both must be withdrawn: this process installed neither.
	if n := poi.countMessages("DeactivateTaskRequest"); n != 2 {
		t.Errorf("sent %d deactivations, want 2 — stale tasking would keep running", n)
	}
}

// TestReconcileLeavesThisProcesssOwnTasking guards the race the ownership check
// exists for: reconciliation runs alongside ordinary triggering, so a session
// establishing at that moment must not have its brand-new trigger cleaned up.
func TestReconcileLeavesThisProcesssOwnTasking(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

	// The POI reports exactly what this process just installed.
	var mine []string
	for _, installed := range s.triggers.installed {
		mine = append(mine, string(installed.xid))
	}

	poi.mu.Lock()
	poi.holds = mine
	poi.mu.Unlock()

	s.reconcileOne()

	if n := poi.countMessages("DeactivateTaskRequest"); n != 0 {
		t.Errorf("sent %d deactivations for tasking this process installed itself", n)
	}
}

// recordingTaskReporter captures ReportTaskIssue calls.
type recordingTaskReporter struct {
	reports []taskReport
}

type taskReport struct {
	xid, reportType, details string
}

func (r *recordingTaskReporter) NotifyTask(xid, reportType, details string) {
	r.reports = append(r.reports, taskReport{xid, reportType, details})
}

// reconcileOne runs the reconciliation that reconcileTriggers gives each endpoint
// its own goroutine for, synchronously, so a test can assert on what it did. The
// fan-out exists so that one unreachable POI does not hold up the others; nothing
// about one endpoint's reconciliation depends on it.
func (s *subsystem) reconcileOne() {
	s.reconcileEndpoint(trigNodeA, s.triggers.endpoints[trigNodeA])
}

// installFor mirrors what triggerCC does — claim the triggers under the caller's
// lock, then install them — so a test can drive both halves synchronously. The
// two are separate in production only because the X1 exchange must not run on the
// signalling path.
func (s *subsystem) installFor(ref string, tasks []types.InterceptTask, upfs []upfSession, correlation uint64) {
	planned, unreachable, undeliverable := s.triggers.plan(ref, tasks, upfs, correlation)
	for _, warrant := range unreachable {
		s.reportTaskIssue(warrant, "no triggering endpoint configured for a UPF serving the target")
	}
	for _, warrant := range undeliverable {
		s.reportTaskIssue(warrant, "no X3 delivery destination could be resolved for this task")
	}
	s.installTriggers(planned)
}

// TestTriggerInstalledAfterReleaseIsWithdrawn: the X1 exchange runs off the
// signalling path, so a short-lived session can be released while its trigger is
// still being installed. The withdrawal then runs against a registry entry whose
// trigger does not exist at the POI yet. Withdrawing nothing would leave a trigger
// in place that reconciliation (startup only) and the POI's own fail-safe (this SMF
// is alive and sending keepalives) would both never reach.
//
// The pending-removal state is what closes it, and it closes it in either
// order: the withdrawal that arrives before the trigger exists stays pending and
// retries, so the install need only leave it alone. Exactly one party withdraws,
// which is the point — two would each read an answer meant for the other.
func TestTriggerInstalledAfterReleaseIsWithdrawn(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}

	// Claim, as triggerCC does under the session lock.
	planned, unreachable, undeliverable := s.triggers.plan("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	if len(unreachable) != 0 || len(undeliverable) != 0 || len(planned) != 1 {
		t.Fatalf("plan() = %d triggers, %d unreachable, %d undeliverable; want 1, 0, 0",
			len(planned), len(unreachable), len(undeliverable))
	}

	// The session is released before the install goroutine gets to run its X1
	// exchange — the ordering the session lock permits and this guards against.
	pending := s.triggers.takeForSession("session-ref-1")
	if len(pending) != 1 {
		t.Fatalf("takeForSession returned %d triggers, want 1", len(pending))
	}

	s.installTriggers(planned)
	s.deactivate(pending)

	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Fatalf("ActivateTaskRequest count = %d, want 1", n)
	}
	if n := poi.countMessages("DeactivateTaskRequest"); n != 1 {
		t.Errorf("DeactivateTaskRequest count = %d, want 1 — a trigger installed after "+
			"its session was released must be withdrawn, and withdrawn once", n)
	}
	if !strings.Contains(strings.Join(poi.sent(), ""), string(planned[0].trigger.XID)) {
		t.Error("the withdrawal did not name the trigger that was installed")
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after an acknowledged withdrawal, want 0", n)
	}
}

// TestTriggerNotInstalledBeforeCorrelationExists: the correlation identifier is
// the anchor's F-SEID, and until the anchor's PFCP session exists there is none.
// A trigger without it is refused by x1.Trigger, so sending one would report a
// fault to the LIPF that is not one — the anchor's establishment response brings
// the CC-TF back here.
func TestTriggerNotInstalledBeforeCorrelationExists(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	rec := &recordingTaskReporter{}
	s.taskReporter = rec

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 0)

	if n := poi.countMessages("ActivateTaskRequest"); n != 0 {
		t.Errorf("sent %d triggers with no correlation identifier, want 0", n)
	}
	if len(rec.reports) != 0 {
		t.Errorf("reported %v to the LIPF; a session whose anchor is not up yet is not a fault", rec.reports)
	}
}

// ── Matching a session's UPF to its triggering endpoint ──
//
// These four cover the CC-TF's join between two independently configured things:
// the UPF named in li.upfTriggers, and the UPF actually serving a session. Getting
// it wrong is invisible from outside the SMF — the warrant stays active, the
// datapath keeps duplicating, and the content is dropped as unattributable — so
// each of these asserts a property that produced silence rather than an error.

// TestMatchEndpointFollowsAUPFThatChangesAddress: a registry that stored the address
// its configured NodeID resolved to at construction would freeze a value that moves.
// Recreating the UPF's Service gives it a new address, the session path follows
// within the minute (the SMF refreshes its DNS cache on a ticker), and such a
// registry would not, so every CC warrant for that UPF would report "no triggering
// endpoint" until the SMF was restarted.
func TestMatchEndpointFollowsAUPFThatChangesAddress(t *testing.T) {
	const name = "upf-moving.test"

	reg := mustRegistry(Config{
		NEID: testNEID, MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{{NodeID: name, X1URL: testX1URLUPF1, NEID: testUPFNEID1}},
	})
	resolvingTo(reg, map[string]string{name: trigNodeA})

	if _, ok := matchOn(reg, sessionOn(trigNodeA)); !ok {
		t.Fatal("a session on the UPF's current address found no triggering endpoint")
	}

	// The Service is recreated with a different address, and the refresh catches up.
	resolvingTo(reg, map[string]string{name: trigNodeElsewhere})

	if _, ok := matchOn(reg, sessionOn(trigNodeElsewhere)); !ok {
		t.Error("the UPF changed address and its triggering endpoint became unreachable " +
			"for the life of the process; content interception is silently dead until an SMF restart")
	}
	if _, ok := matchOn(reg, sessionOn(trigNodeA)); ok {
		t.Error("a session on the UPF's old address still matched; the endpoint is being " +
			"selected from a stale address rather than the current one")
	}
}

// TestMatchEndpointNeverMatchesUnresolvableNodes is the one with a security
// consequence. Failed resolution yields 0.0.0.0, so matching on a resolved address
// would make every unresolvable name equal to every other — the defect nodeInLinks
// avoids for gNB names (#613). Here it would hand one UPF's CC-POI a different
// UPF's warrant, delivering content under a warrant that does not cover it.
func TestMatchEndpointNeverMatchesUnresolvableNodes(t *testing.T) {
	reg := mustRegistry(Config{
		NEID: testNEID, MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{{NodeID: "upf-a.invalid", X1URL: testX1URLUPFA, NEID: "upf-a"}},
	})
	// A resolver that answers nothing, so upf-a has no address in the index — the
	// state a name that has never resolved leaves it in.
	resolvingTo(reg, map[string]string{})

	// Both shapes an unresolved session address can take: the zero address the
	// session path yields for a name it could not resolve, and an empty one.
	for _, addr := range []string{net.IPv4zero.String(), ""} {
		if _, ok := matchOn(reg, upfSession{node: upfNode("upf-b.invalid"), addr: addr}); ok {
			t.Errorf("a session with address %q matched upf-a's triggering endpoint; "+
				"one UPF's content would be tasked under another's warrant", addr)
		}
	}
}

// TestMatchEndpointPrefersIdentityOverResolution pins the ordering. Identity is
// exact and needs no DNS, so it must be tried first: a node named the way the slice
// topology names it must match its own endpoint even when another endpoint's
// address happens to be what that name resolves to.
func TestMatchEndpointPrefersIdentityOverResolution(t *testing.T) {
	const name = "upf-named.test"
	smfctx.InsertDnsHostIp(name, net.ParseIP("10.0.2.7"))

	reg := mustRegistry(Config{
		NEID: testNEID, MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{
			{NodeID: name, X1URL: "https://upf-named:8443/X1/NE", NEID: "upf-named"},
			{NodeID: "10.0.2.7", X1URL: "https://upf-numeric:8443/X1/NE", NEID: "upf-numeric"},
		},
	})

	key, ok := matchOn(reg, sessionOn(name))
	if !ok {
		t.Fatal("a session identifying its UPF by name found no endpoint")
	}
	if key != name {
		t.Errorf("matched %q, want %q: an address match won over an exact identity match", key, name)
	}
}

// TestTriggerRegistryRejectsAmbiguousNode covers the silent half of it. Two
// entries naming one node, collapsed into a single registry entry with the second
// overwriting the first, would present a two-UPF configuration as a one-UPF registry,
// and the displaced UPF's content would never be attributable — with nothing logged
// and no fault raised.
func TestTriggerRegistryRejectsAmbiguousNode(t *testing.T) {
	_, err := newTriggerRegistry(Config{
		NEID: testNEID, MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{
			{NodeID: trigNodeA, X1URL: testX1URLUPF1, NEID: testUPFNEID1},
			{NodeID: trigNodeA, X1URL: "https://upf-2:8443/X1/NE", NEID: testUPFNEID2},
		},
	}, nil, nil, nil)
	if err == nil {
		t.Error("an ambiguous upfTriggers configuration was accepted; one UPF's endpoint " +
			"silently replaces another's and its content cannot be attributed")
	}
}

// TestMatchEndpointIsDeterministic guards the ambiguous case. Two configured nodes
// can resolve to one address — transiently while a Service is recreated, or
// permanently by mistake — and picking between them by Go's map order would send a
// session's triggers to a different UPF from one establishment to the next, each
// carrying the X3 destination with it.
func TestMatchEndpointIsDeterministic(t *testing.T) {
	reg := mustRegistry(Config{
		NEID: testNEID, MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{
			{NodeID: "upf-one.test", X1URL: "https://upf-one:8443/X1/NE", NEID: "upf-one"},
			{NodeID: "upf-two.test", X1URL: "https://upf-two:8443/X1/NE", NEID: "upf-two"},
		},
	})
	resolvingTo(reg, map[string]string{"upf-one.test": "10.0.3.3", "upf-two.test": "10.0.3.3"})

	first, ok := matchOn(reg, sessionOn("10.0.3.3"))
	if !ok {
		t.Fatal("no endpoint matched an address both configured nodes resolve to")
	}
	for range 50 {
		got, _ := matchOn(reg, sessionOn("10.0.3.3"))
		if got != first {
			t.Fatalf("matched %q then %q: the same session would be triggered at a "+
				"different UPF on re-establishment", first, got)
		}
	}
}

// TestReconcileReportsATriggerThePOISaysIsNotRunning covers the one thing a CC
// triggering function exists to notice: a trigger it installed, for a live
// warrant, that the POI is not actually running.
//
// Nothing else can report it. The POI answers to this SMF over the internal
// triggering interface, not to the ADMF, so the ADMF cannot ask it directly. Reading
// the POI's reply for XIDs and discarding everything else — the task's provisioning
// status and its unresolved faults — would leave the interception stopped while every
// party believed it was running.
//
// **The report is against the warrant.** An element-scoped report says only that
// something among the interceptions this element triggers has stopped, and a LIPF holding
// several warrants cannot act on it. `triggerFaulty` is defined for the attribution, and
// the POI's answer carries the per-task fault to attribute.
func TestReconcileReportsATriggerThePOISaysIsNotRunning(t *testing.T) {
	admf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:errcheck // test handler write
		_, _ = w.Write([]byte(`<?xml version="1.0"?><X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">` +
			`<x1ResponseMessage><oK>AcknowledgedAndCompleted</oK></x1ResponseMessage></X1Response>`))
	}))
	defer admf.Close()

	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	taskReports := &recordingTaskReporter{}
	s.taskReporter = taskReports
	s.reporter = x1.NewReporter(admf.URL, "admf", "smf", nil)

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

	var mine []string
	for _, installed := range s.triggers.installed {
		mine = append(mine, string(installed.xid))
	}
	if len(mine) == 0 {
		t.Fatal("no trigger was installed, so this test would prove nothing")
	}

	// The POI holds exactly what this process installed, and reports the first as
	// not provisioned.
	poi.mu.Lock()
	poi.holds = mine
	poi.unhealthy = map[string]string{mine[0]: testUnhealthyReason}
	poi.mu.Unlock()

	s.reconcileOne()

	// It is ours, so it must not be withdrawn — the fault is reported, not acted on
	// by tearing down a live warrant's interception.
	if n := poi.countMessages("DeactivateTaskRequest"); n != 0 {
		t.Errorf("sent %d deactivations for a faulty trigger; the warrant is live", n)
	}

	// The fault is held as state against the warrant — not the trigger: the LIPF issued the
	// warrant's XID and never saw the trigger's. The X1 server's task-fault watcher reports it
	// from there as a NonTerminatingFault, since the tasking is in place at both ends and only
	// the product has stopped, and retracts it once the POI reports the trigger running.
	faults := s.taskFaults(warrant.XID)
	if len(faults) == 0 {
		t.Fatal("the POI reported a trigger this element installed as not provisioned, and this " +
			"element holds no fault for the warrant: the warrant is live, no content is being " +
			"produced, and nothing would ever tell the LIPF")
	}
	for _, f := range faults {
		if !strings.HasPrefix(f.ErrorDescription, x1.TaskIssueTriggerNotRunning+": ") {
			t.Errorf("the fault is %q, want %s", f.ErrorDescription, x1.TaskIssueTriggerNotRunning)
		}
		if !strings.Contains(f.ErrorDescription, testUnhealthyReason) {
			t.Errorf("the fault does not say what the POI reported: %q", f.ErrorDescription)
		}
	}
	for _, trigger := range mine {
		if len(s.taskFaults(types.XID(trigger))) != 0 {
			t.Errorf("a fault is held under the trigger XID %s, which the LIPF never issued", trigger)
		}
	}
}

// installOneTrigger installs a single CC trigger for a live session and returns
// the warrant and the trigger XID the CC-TF allocated for it. The withdrawal tests
// all start from here: a warrant, a session that stays up, and a POI that holds a
// trigger.
func installOneTrigger(t *testing.T, s *subsystem) (warrant types.InterceptTask, trigger types.XID) {
	t.Helper()

	warrant = types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

	for _, installed := range s.triggers.installed {
		trigger = installed.xid
	}
	if trigger == "" {
		t.Fatal("no trigger was installed, so this test would prove nothing")
	}

	return warrant, trigger
}

// TestWithdrawnWarrantIsStillTrackedWhenThePOIRefuses: a refused withdrawal keeps
// its bookkeeping.
//
// A warrant is withdrawn while its session is live. The X1 DeactivateTask to the
// serving UPF fails. Bookkeeping deleted on the way to that attempt would leave
// nothing to retry and nothing to remember: the UPF would keep the trigger, keep the
// DUPL FAR, and keep delivering the subject's content to MDF3 under a warrant that no
// longer authorised it. No participant would be in a position to notice — the SMF
// believing it had withdrawn the trigger, the UPF never told, and the mediation
// function receiving well-formed, correctly attributed product.
func TestWithdrawnWarrantIsStillTrackedWhenThePOIRefuses(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant, trigger := installOneTrigger(t, s)

	// The POI stops answering. Its session is untouched: this is the withdrawal of
	// authority from an interception that is otherwise running perfectly.
	poi.mu.Lock()
	poi.refuse = true
	poi.mu.Unlock()

	// The X1 deactivation path, as reportDeactivation reaches it.
	pending := s.triggers.takeForWarrant(warrant.XID)
	if len(pending) != 1 {
		t.Fatalf("takeForWarrant returned %d triggers, want 1", len(pending))
	}

	held, withdrawing := s.triggers.holds(trigger)
	if !held {
		t.Fatal("the registry forgot a trigger it has not been told is gone — the UPF is " +
			"still duplicating under a withdrawn warrant and nothing will ever reclaim it")
	}
	if !withdrawing {
		t.Error("the trigger is held but not marked as being withdrawn, so reconciliation " +
			"would treat it as live tasking")
	}

	// Retry until the POI answers, on a clock the test owns. The registry stays
	// answerable for the trigger throughout — that is what makes the retry possible
	// at all.
	attempts := 0
	s.triggers.sleep = func(time.Duration) {
		attempts++
		if held, _ := s.triggers.holds(trigger); !held {
			t.Error("the registry dropped the trigger between attempts")
		}
		if attempts == 2 {
			poi.mu.Lock()
			poi.refuse = false
			poi.mu.Unlock()
		}
	}
	s.deactivate(pending)

	if held, _ := s.triggers.holds(trigger); held {
		t.Error("the registry still holds a trigger the POI acknowledged withdrawing")
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after acknowledgement, want 0", n)
	}
}

// TestWithdrawalRetriesOnBackoff pins the shape of the retry: bounded in effort so
// it cannot spin against a POI that is down, unbounded in intent so it cannot give
// up while it still believes a trigger is installed. A retry that expires is this
// change's defect arriving later.
func TestWithdrawalRetriesOnBackoff(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant, _ := installOneTrigger(t, s)

	poi.mu.Lock()
	poi.refuse = true
	poi.mu.Unlock()

	pending := s.triggers.takeForWarrant(warrant.XID)

	// The clock is the test's, so a backoff measured in minutes costs nothing. The
	// POI starts answering after the fifth failure, which is where the schedule has
	// levelled off at the keepalive interval.
	var waits []time.Duration
	s.triggers.sleep = func(d time.Duration) {
		waits = append(waits, d)
		if n := s.triggers.pendingCount(); n != 1 {
			t.Errorf("pending = %d during retry %d, want exactly the one being withdrawn", n, len(waits))
		}
		if len(waits) == 5 {
			poi.mu.Lock()
			poi.refuse = false
			poi.mu.Unlock()
		}
	}

	before := poi.countMessages("DeactivateTaskRequest")
	s.deactivate(pending)

	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second}
	if !slices.Equal(waits, want) {
		t.Errorf("backoff was %v, want %v — doubling from 5s and level at the keepalive interval", waits, want)
	}
	if n := poi.countMessages("DeactivateTaskRequest") - before; n != 6 {
		t.Errorf("sent %d withdrawals, want 6 (five refused, one acknowledged)", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d once the POI acknowledged, want 0", n)
	}
}

// TestWithdrawalFailureAndStuckAreDistinctReports: the LIPF is the only party that
// can act on a withdrawal this element cannot deliver, and it can only act if the
// two conditions reach it as two conditions. "The last attempt failed" and
// "authority was removed five minutes ago and content is probably still flowing"
// call for different responses, and an operator who sees the first repeated
// indefinitely learns nothing from the hundredth.
func TestWithdrawalFailureAndStuckAreDistinctReports(t *testing.T) {
	var mu sync.Mutex
	var reports []string
	admf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test
		mu.Lock()
		reports = append(reports, string(body))
		mu.Unlock()
		//nolint:errcheck // test handler write
		_, _ = w.Write([]byte(`<?xml version="1.0"?><X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">` +
			`<x1ResponseMessage><oK>AcknowledgedAndCompleted</oK></x1ResponseMessage></X1Response>`))
	}))
	defer admf.Close()

	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}
	s.reporter = x1.NewReporter(admf.URL, "admf", "smf", nil)

	warrant, trigger := installOneTrigger(t, s)

	poi.mu.Lock()
	poi.refuse = true
	poi.mu.Unlock()

	// A clock that advances by more than the stuck window between the second and
	// third attempt, so the test observes the transition rather than waiting for it.
	now := time.Now()
	s.triggers.now = func() time.Time { return now }
	pending := s.triggers.takeForWarrant(warrant.XID)

	rounds := 0
	s.triggers.sleep = func(time.Duration) {
		rounds++
		if rounds == 2 {
			now = now.Add(withdrawalStuckAfter + time.Second)
		}
		if rounds == 5 {
			poi.mu.Lock()
			poi.refuse = false
			poi.mu.Unlock()
		}
	}
	s.deactivate(pending)

	mu.Lock()
	defer mu.Unlock()
	failed, stuck := 0, 0
	for _, body := range reports {
		if strings.Contains(body, x1.NEIssueTaskingWithdrawalFailed) {
			failed++
		}
		if strings.Contains(body, x1.NEIssueTaskingWithdrawalStuck) {
			stuck++
		}
		// The fault channel is inside the LI domain, but which subject a warrant
		// covers is not its business, and neither is which warrant.
		if strings.Contains(body, string(trigger)) || strings.Contains(body, string(warrant.XID)) {
			t.Errorf("an NE-level withdrawal report names an identifier:\n%s", body)
		}
	}
	if failed != 1 {
		t.Errorf("taskingWithdrawalFailed reported %d times over six attempts, want 1", failed)
	}
	if stuck != 1 {
		t.Errorf("taskingWithdrawalStuck reported %d times, want 1 — it is a condition, not a tick", stuck)
	}
}

// TestReconcileLeavesAWithdrawalInFlightAlone: reconciliation and the withdrawal
// retry loop both act on tasking the POI still holds, and a trigger being
// withdrawn is visible to both. Two parties sending DeactivateTask for one XID
// each read an answer meant for the other — one sees an acknowledgement for a task
// the other has already removed and concludes the withdrawal landed. The registry
// answers "mine, and on its way out", which is what keeps reconciliation off it.
func TestReconcileLeavesAWithdrawalInFlightAlone(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant, trigger := installOneTrigger(t, s)

	// The warrant is withdrawn and the POI has not acknowledged, so the trigger is
	// pending — and the POI, asked what it holds, still reports it.
	s.triggers.takeForWarrant(warrant.XID)
	poi.mu.Lock()
	poi.holds = []string{string(trigger)}
	poi.mu.Unlock()

	before := poi.countMessages("DeactivateTaskRequest")
	s.reconcileOne()

	if n := poi.countMessages("DeactivateTaskRequest") - before; n != 0 {
		t.Errorf("reconciliation sent %d withdrawals for a trigger already being withdrawn, want 0", n)
	}
}

// TestKeepalivesFollowTaskingRatherThanConfiguration: the POI's fail-safe purge is
// the last mechanism able to reclaim tasking a triggering function can no longer
// name, and keeping every configured endpoint alive on a timer disables it by
// construction. A POI holding a forgotten trigger was being told, once a minute,
// that the function responsible for it was alive and well.
func TestKeepalivesFollowTaskingRatherThanConfiguration(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}
	endpoint := s.triggers.endpoints[trigNodeA]

	// Reconciled and holding nothing: there is nothing to keep, so the POI is left
	// to lapse whatever it still holds.
	endpoint.markReconciled()
	if s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Error("an SMF holding no content tasking keeps a POI alive, which is what makes " +
			"its fail-safe unreachable")
	}

	warrant, _ := installOneTrigger(t, s)
	if !s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Error("a POI holding this SMF's live trigger is not kept alive; its fail-safe " +
			"would purge an authorised interception")
	}

	// A withdrawal in flight still counts. Going silent under it would ask the POI's
	// fail-safe to finish a job this process has not given up on, and the fail-safe
	// takes everything at that POI with it.
	pending := s.triggers.takeForWarrant(warrant.XID)
	if !s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Error("a POI is left to lapse while a withdrawal to it is still pending")
	}

	s.deactivate(pending)
	if s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Error("keepalives continue after the last trigger was withdrawn and acknowledged")
	}
}

// TestKeepalivesWaitForReconciliation is the inversion this ordering exists for. A restarted
// SMF is *present*, so the POI's fail-safe will not act while it is being kept
// alive — and until reconciliation completes, this process cannot name what that
// POI holds and therefore could never withdraw it, not even when the warrant
// behind it is revoked. Staying silent means such tasking lapses instead of
// persisting: the failure mode inverts from "interception survives" to
// "interception stops", which is the direction a fail-safe must fail in.
func TestKeepalivesWaitForReconciliation(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}
	endpoint := s.triggers.endpoints[trigNodeA]

	// A session establishes before reconciliation has finished, so this process does
	// hold tasking at the POI — and still owes it nothing, because what it cannot
	// name is what the fail-safe is for.
	installOneTrigger(t, s)
	if s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Error("a POI is kept alive before this process has established what it holds")
	}

	s.reconcileOne()
	if !s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Error("a reconciled POI holding live tasking is not kept alive")
	}
}

// TestReconcileRetriesUntilThePOIAnswers: an endpoint unreachable at startup and
// reachable a minute later is the ordinary shape of a whole-cluster restart. One
// attempt is not reconciliation — abandoning the POI left tasking this process
// could not name, for the life of the process.
func TestReconcileRetriesUntilThePOIAnswers(t *testing.T) {
	poi := newFakePOI(t)
	poi.mu.Lock()
	poi.detailsFail = true
	poi.holds = []string{testXIDHeld}
	poi.mu.Unlock()

	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}
	endpoint := s.triggers.endpoints[trigNodeA]

	attempts := 0
	s.triggers.sleep = func(time.Duration) {
		attempts++
		if endpoint.isReconciled() {
			t.Error("the endpoint counts as reconciled while it is still refusing to say what it holds")
		}
		if attempts == 2 {
			poi.mu.Lock()
			poi.detailsFail = false
			poi.mu.Unlock()
		}
	}
	s.reconcileOne()

	if attempts != 2 {
		t.Errorf("reconciliation waited %d times, want 2 — two failures then an answer", attempts)
	}
	if !endpoint.isReconciled() {
		t.Error("the endpoint is not reconciled after the POI answered")
	}
	// And what it found is withdrawn durably, not fired and forgotten: the pending
	// state is empty because the POI acknowledged, not because nobody was watching.
	if n := poi.countMessages("DeactivateTaskRequest"); n != 1 {
		t.Errorf("sent %d withdrawals for the one orphan the POI reported, want 1", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after an acknowledged withdrawal, want 0", n)
	}
}

// TestReconcileWithdrawalIsRetriedLikeAnyOther: reconciliation's own withdrawals
// are retried too — the tasking least able to survive being forgotten, since by
// definition nothing else knows it exists.
func TestReconcileWithdrawalIsRetriedLikeAnyOther(t *testing.T) {
	poi := newFakePOI(t)
	poi.mu.Lock()
	poi.holds = []string{testXIDHeld}
	poi.refuse = true // GetAllDetails still answers; DeactivateTask does not
	poi.mu.Unlock()

	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	attempts := 0
	s.triggers.sleep = func(time.Duration) {
		attempts++
		if n := s.triggers.pendingCount(); n != 1 {
			t.Errorf("pending = %d while an orphan's withdrawal is unacknowledged, want 1", n)
		}
		if attempts == 2 {
			poi.mu.Lock()
			poi.refuse = false
			poi.mu.Unlock()
		}
	}
	s.reconcileOne()

	if n := poi.countMessages("DeactivateTaskRequest"); n != 3 {
		t.Errorf("sent %d withdrawals, want 3 (two refused, one acknowledged)", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d once the orphan was acknowledged, want 0", n)
	}
}

// TestFailSafeCannotReclaimAnOrphanBesideLiveTasking is the documented limit of the
// backstop, not a behaviour to rely on. The POI's fail-safe is per-connection: it
// purges all of an endpoint's tasking or none of it. So an orphan at an endpoint
// that also holds a live task is preserved by the keepalives that live task earns,
// and no amount of gating changes that. Durable withdrawal (the pending state) is
// the remedy; this only makes the backstop reachable in the case where the
// endpoint's last task was the one that failed to withdraw.
func TestFailSafeCannotReclaimAnOrphanBesideLiveTasking(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}
	endpoint := s.triggers.endpoints[trigNodeA]
	endpoint.markReconciled()

	// One live warrant's trigger, installed and running.
	warrant, live := installOneTrigger(t, s)

	// And an orphan the POI holds that this process is not tracking — the state a
	// forgotten withdrawal leaves behind, and the reason the pending state exists.
	orphan := testXIDOrphan
	poi.mu.Lock()
	poi.holds = []string{string(live), orphan}
	poi.mu.Unlock()

	if held, _ := s.triggers.holds(types.XID(orphan)); held {
		t.Fatal("the orphan is tracked, so this test would not describe an orphan")
	}
	// The live trigger keeps the endpoint alive, so the POI's fail-safe never fires
	// and the orphan keeps duplicating alongside it.
	if !s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Fatal("the endpoint is not kept alive despite holding a live trigger")
	}

	// Only once the live trigger is withdrawn and acknowledged does the endpoint
	// fall silent — and only then can the fail-safe reclaim the orphan.
	s.deactivate(s.triggers.takeForWarrant(warrant.XID))
	if s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Error("the endpoint is still kept alive with nothing of ours left at it, so the " +
			"orphan survives even the case this backstop does cover")
	}
}

// TestRetargetDoesNotReapTheTriggerItInstalled is the race the one-event contract
// removes. A ModifyTask keeps the XID, and this registry is keyed by the warrant
// XID, so "the old task's teardown" and "the new task's installation" address the
// same entries. Under the two-event contract the activation ran first and
// installed, asynchronously, while the deactivation that followed took everything
// the warrant held — including what had just been installed — and the interception
// the ADMF had just ordered was gone with nothing left to say so.
//
// Now the modification computes the sessions the task still covers and reads the
// registry once, so a trigger for a session that survives the retarget is never
// among what is withdrawn, whatever order the goroutines run in.
func TestRetargetDoesNotReapTheTriggerItInstalled(t *testing.T) {
	// Two hundred rounds, each on its own subsystem and fake POI: nothing package-level is
	// written, so it runs beside the tests that wait out a timeout.
	t.Parallel()

	const warrant = types.XID(testXIDPrimary)

	for range 200 {
		poi := newFakePOI(t)
		s := triggerSubsystem(t, poi)
		s.taskReporter = &recordingTaskReporter{}
		task := types.InterceptTask{XID: warrant, Products: []types.ProductType{types.ProductCC}}

		// The old target's session, tasked before the modification.
		s.installFor("session-old", []types.InterceptTask{task},
			[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

		var wg sync.WaitGroup
		wg.Add(2)
		// The new target's session being tasked, off the signalling path.
		go func() {
			defer wg.Done()
			s.installFor("session-new", []types.InterceptTask{task},
				[]upfSession{{node: upfNode(trigNodeA), seid: 43}}, 9)
		}()
		// The modification's own teardown, keeping the sessions the task still covers.
		go func() {
			defer wg.Done()
			s.deactivate(s.triggers.takeForWarrantExcept(warrant, map[string]bool{"session-new": true}))
		}()
		wg.Wait()

		key := triggerKey(warrant, "session-new", trigNodeA)
		if _, held := s.triggers.installed[key]; !held {
			t.Fatalf("the retarget reaped the trigger it had just installed for the new target; "+
				"installed = %v", s.triggers.installed)
		}
		if _, gone := s.triggers.installed[triggerKey(warrant, "session-old", trigNodeA)]; gone {
			t.Fatal("the trigger for a session the task no longer covers survived the retarget")
		}
		if n := s.triggers.pendingCount(); n != 0 {
			t.Fatalf("pending = %d after an acknowledged withdrawal, want 0", n)
		}
	}
}

// TestAReactivatedWarrantDoesNotDisplaceTheWithdrawalInFlight: the two maps are
// not in step. A warrant deactivated and re-activated while its POI is unreachable
// claims the same (warrant, session, UPF) key again under a new XID, while the old
// XID is still being withdrawn. Both are this registry's responsibility and it must
// be able to hold both — the first's acknowledgement must not clear the second's
// record, which would leave a trigger installed with nothing tracking it.
func TestAReactivatedWarrantDoesNotDisplaceTheWithdrawalInFlight(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant, first := installOneTrigger(t, s)

	// The POI stops answering, and the warrant is withdrawn.
	poi.mu.Lock()
	poi.refuse = true
	poi.mu.Unlock()
	pending := s.triggers.takeForWarrant(warrant.XID)

	// The ADMF re-activates the same warrant on the same session before the
	// withdrawal has landed. The trigger key is the same; the XID is not.
	poi.mu.Lock()
	poi.refuse = false
	poi.mu.Unlock()
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

	var second types.XID
	for _, installed := range s.triggers.installed {
		second = installed.xid
	}
	if second == "" || second == first {
		t.Fatalf("the re-activation claimed no new trigger (first %q, second %q)", first, second)
	}
	if n := s.triggers.pendingCount(); n != 1 {
		t.Fatalf("pending = %d after a re-activation over a pending withdrawal, want the 1 being withdrawn", n)
	}

	// And the re-activated warrant is withdrawn in its turn, before the first
	// withdrawal has been acknowledged. Both triggers are now this registry's
	// responsibility, under one trigger key.
	poi.mu.Lock()
	poi.refuse = true
	poi.mu.Unlock()
	again := s.triggers.takeForWarrant(warrant.XID)
	if n := s.triggers.pendingCount(); n != 2 {
		t.Fatalf("pending = %d with two withdrawals outstanding for one trigger key, want 2 — "+
			"the second displaced the first and one of them is now tracked by nobody", n)
	}

	// The first withdrawal lands. It must clear its own record and leave the
	// second's alone: the second trigger is still installed at the POI.
	poi.mu.Lock()
	poi.refuse = false
	poi.mu.Unlock()
	s.deactivate(pending)

	if held, withdrawing := s.triggers.holds(second); !held || !withdrawing {
		t.Error("the acknowledgement of the first trigger's withdrawal took the second's " +
			"record with it, leaving a trigger installed at the POI with nothing tracking it")
	}
	if n := s.triggers.pendingCount(); n != 1 {
		t.Errorf("pending = %d after one of two withdrawals was acknowledged, want the other one", n)
	}

	s.deactivate(again)
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after both withdrawals were acknowledged, want 0", n)
	}
}

// TestAKeepaliveAnsweredByTheWrongElementIsReported: the keepalive reports an
// unattributable answer, as every tasking path does.
//
// Discarding keepalive failures is right about transport — a missed keepalive is
// transient and the POI's own fail-safe covers a POI that has gone. It is wrong
// about binding. The keepalive is the exchange whose entire purpose is to say the
// peer is still there, so an answer from an element this SMF did not address means
// it believes a POI is alive on the strength of a stranger's answer: a silent
// condition, on the one exchange where nothing downstream would ever contradict it.
func TestAKeepaliveAnsweredByTheWrongElementIsReported(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	var reported []error
	s.triggers.reportUnattributable = func(err error) { reported = append(reported, err) }

	// A keepalive is owed only for a POI this function believes holds its tasking.
	installOneTrigger(t, s)
	for _, e := range s.triggers.endpoints {
		e.markReconciled()
	}

	// Answering correctly, under a name this SMF did not address.
	poi.mu.Lock()
	poi.misname = wrongNE
	poi.mu.Unlock()

	s.triggers.keepaliveRound()

	if len(reported) != 1 {
		t.Fatalf("a keepalive answered by %s produced %d reports, want 1 — this SMF holds a POI alive on an answer from something else", wrongNE, len(reported))
	}
	var unattributable *x1.ResponseError
	if !errors.As(reported[0], &unattributable) {
		t.Fatalf("reported %v, want an *x1.ResponseError naming the field that disagreed", reported[0])
	}
	if unattributable.Field != "neIdentifier" {
		t.Errorf("the report names %q; the misnaming peer is detected by neIdentifier", unattributable.Field)
	}

	// And a POI answering under its own name reports nothing, or the condition would
	// be noise on every healthy tick.
	poi.mu.Lock()
	poi.misname = ""
	poi.mu.Unlock()

	reported = nil
	s.triggers.keepaliveRound()

	if len(reported) != 0 {
		t.Errorf("a healthy keepalive produced %d reports, want 0", len(reported))
	}
}

// TestAnUnattributableAnswerKeepsTheWithdrawalPending is asserted rather than assumed.
//
// Validating responses turns silent successes on the withdrawal path into visible
// failures, and that is only safe because a withdrawal survives a failed attempt.
// So: a POI that acknowledges under the wrong NE identifier is refused, and the
// withdrawal it refused must stay pending and keep being retried rather than being
// forgotten.
func TestAnUnattributableAnswerKeepsTheWithdrawalPending(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant, _ := installOneTrigger(t, s)

	// The POI now answers perfectly well, under a name this SMF did not address.
	poi.mu.Lock()
	poi.misname = wrongNE
	poi.mu.Unlock()

	pending := s.triggers.takeForWarrant(warrant.XID)
	if len(pending) != 1 {
		t.Fatalf("took %d withdrawals, want 1", len(pending))
	}

	rounds := 0
	s.triggers.sleep = func(time.Duration) {
		rounds++
		if rounds == 3 {
			// Once the mismatch is corrected the withdrawal completes, which is what
			// makes the retry worth having rather than merely persistent.
			poi.mu.Lock()
			poi.misname = ""
			poi.mu.Unlock()
		}
	}
	s.deactivate(pending)

	if rounds < 3 {
		t.Errorf("the withdrawal was retried %d times before succeeding, want at least 3 — an answer this element refuses must not be read as an acknowledgement", rounds)
	}
	if n := len(s.triggers.pending); n != 0 {
		t.Errorf("%d withdrawals still pending after the POI's answer became attributable, want 0", n)
	}
}

// TestAWithdrawalStuckOnOurOwnRefusalIsDistinguishable is the test that decides whether an operator looks in the right place.
//
// A systematic validation mismatch is the failure mode validating responses introduces: the
// pending entry never clears, the retries never stop, and because pending entries
// keep their endpoint's keepalives flowing, the POI's own fail-safe cannot reclaim
// the tasking either. Both remedies are held open by the same condition. Reported
// only as taskingWithdrawalFailed, it presents as a POI that will not answer —
// while the POI is answering perfectly well and being disbelieved here.
func TestAWithdrawalStuckOnOurOwnRefusalIsDistinguishable(t *testing.T) {
	var mu sync.Mutex
	var reports []string
	admf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test
		mu.Lock()
		reports = append(reports, string(body))
		mu.Unlock()
		//nolint:errcheck // test handler write
		_, _ = w.Write([]byte(`<?xml version="1.0"?><X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">` +
			`<x1ResponseMessage><oK>AcknowledgedAndCompleted</oK></x1ResponseMessage></X1Response>`))
	}))
	defer admf.Close()

	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}
	s.reporter = x1.NewReporter(admf.URL, "admf", "smf", nil)

	warrant, trigger := installOneTrigger(t, s)

	poi.mu.Lock()
	poi.misname = wrongNE
	poi.mu.Unlock()

	pending := s.triggers.takeForWarrant(warrant.XID)

	rounds := 0
	s.triggers.sleep = func(time.Duration) {
		rounds++
		if rounds == 4 {
			poi.mu.Lock()
			poi.misname = ""
			poi.mu.Unlock()
		}
	}
	s.deactivate(pending)

	mu.Lock()
	defer mu.Unlock()
	var unattributable, failed int
	for _, body := range reports {
		if strings.Contains(body, x1.NEIssueX1ResponseUnattributable) {
			unattributable++
		}
		if strings.Contains(body, x1.NEIssueTaskingWithdrawalFailed) {
			failed++
		}
		// The same rule as every other NE-level report: which warrant, and whose
		// session, are not this channel's business.
		if strings.Contains(body, string(trigger)) || strings.Contains(body, string(warrant.XID)) {
			t.Errorf("an NE-level report names an identifier:\n%s", body)
		}
	}

	if unattributable == 0 {
		t.Error("a withdrawal refused by this element's own response binding was reported only as a POI failure; an operator is sent to look at a POI that is answering correctly")
	}
	if failed == 0 {
		t.Error("the withdrawal failure itself was not reported")
	}
	// The condition names the field that disagreed, which is the operator's first
	// clue and the difference between "fix your configuration" and "go and look at
	// the UPF".
	named := false
	for _, body := range reports {
		if strings.Contains(body, x1.NEIssueX1ResponseUnattributable) && strings.Contains(body, "neIdentifier") {
			named = true
		}
	}
	if !named {
		t.Error("the unattributable-answer report does not name which envelope field disagreed")
	}
}

// TestAnUnbindableActivationAnswerIsReportedAsElementLevel: the unattributable
// condition is reported on the activation path as well as the withdrawal path.
//
// A task issue alone is the same report whether the POI refused the warrant or this
// element refused to believe the POI's answer. Those need opposite actions: one is a
// POI to go and look at, the other a configuration mismatch on this side.
//
// The task issue stays. On this path the element does know which warrant it was
// installing, so naming it is true and useful; what the task issue cannot convey
// is which side of the exchange is at fault.
func TestAnUnbindableActivationAnswerIsReportedAsElementLevel(t *testing.T) {
	var mu sync.Mutex
	var reports []string
	admf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test
		mu.Lock()
		reports = append(reports, string(body))
		mu.Unlock()
		//nolint:errcheck // test handler write
		_, _ = w.Write([]byte(`<?xml version="1.0"?><X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">` +
			`<x1ResponseMessage><oK>AcknowledgedAndCompleted</oK></x1ResponseMessage></X1Response>`))
	}))
	defer admf.Close()

	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}
	s.reporter = x1.NewReporter(admf.URL, "admf", "smf", nil)

	// The POI answers perfectly well, under a name this SMF did not address.
	poi.mu.Lock()
	poi.misname = wrongNE
	poi.mu.Unlock()

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

	// The X1 exchanges happen off the signalling path, so the assertion has to wait
	// for them rather than for installFor to return.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		seen := len(reports)
		mu.Unlock()
		if seen > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	var unattributable int
	for _, body := range reports {
		if strings.Contains(body, x1.NEIssueX1ResponseUnattributable) {
			unattributable++
		}
		if strings.Contains(body, x1.NEIssueX1ResponseUnattributable) &&
			strings.Contains(body, string(warrant.XID)) {
			t.Errorf("the element-level condition names a warrant:\n%s", body)
		}
	}
	if unattributable == 0 {
		t.Error("an activation answered by the wrong element was reported only as a task issue; an operator is sent to look at a POI that is answering correctly")
	}

	// And nothing was recorded as installed on the strength of an answer that
	// could not be bound.
	if n := len(s.triggers.installed); n != 0 {
		t.Errorf("%d triggers recorded as installed, want 0", n)
	}
}

// TestTriggerCarriesDeliveryXIDNotTaskXID: the trigger's ProductID is the label
// the POI puts on its xCC, and it has to be the label this element puts on its
// own xIRI for the same warrant — the ADMF's productID wherever it provisioned
// one. Sending the task XID instead is invisible in every deployment that does
// not use the field, because DeliveryXID() is then the task XID and both values
// are the same one; it separates the two streams the moment an agency does use
// it, and separates them silently, since each stream stays well-formed and
// individually deliverable. So the warrant here provisions a productID that
// differs from its XID: a test that leaves it unset passes against the defect.
func TestTriggerCarriesDeliveryXIDNotTaskXID(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	const (
		taskXID   = testXIDPrimary
		productID = testXIDSecondary
	)
	warrant := types.InterceptTask{
		XID:       taskXID,
		ProductID: productID,
		Products:  []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}

	planned, unreachable, undeliverable := s.triggers.plan("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	if len(unreachable) != 0 || len(undeliverable) != 0 || len(planned) != 1 {
		t.Fatalf("plan() = %d triggers, %d unreachable, %d undeliverable; want 1, 0, 0",
			len(planned), len(unreachable), len(undeliverable))
	}

	// Guards the test itself: if these ever coincide, the assertions below hold
	// against the defect too and prove nothing.
	if warrant.DeliveryXID() == warrant.XID {
		t.Fatal("test setup: the productID must differ from the task XID, or this test cannot detect the defect")
	}

	if got := planned[0].trigger.ProductID; got != warrant.DeliveryXID() {
		t.Errorf("trigger ProductID = %q, want the delivery XID %q — the POI labels its "+
			"xCC with this, and an MDF attributes on that label alone", got, warrant.DeliveryXID())
	}
	if got := planned[0].trigger.ProductID; got == types.XID(taskXID) {
		t.Errorf("trigger ProductID = %q, the task XID — content would carry a different "+
			"label from this element's own signalling for the same warrant", got)
	}

	// The X2 side of the same claim: lawfulintercept.go labels an xIRI header with
	// parseXID(t.DeliveryXID()), and the UPF labels its xCC header from the
	// trigger's ProductID. Comparing the two encoded headers is what says the
	// mediation function can join the streams.
	if x2, x3 := parseXID(warrant.DeliveryXID()), parseXID(planned[0].trigger.ProductID); x2 != x3 {
		t.Errorf("X2 header XID %x != X3 header XID %x — signalling and content would be "+
			"two unrelated intercepts to the mediation function", x2, x3)
	}

	// The registry still keys tasking by the warrant this element was tasked with:
	// how product is labelled is not how a withdrawal finds what to withdraw.
	if planned[0].warrant != types.XID(taskXID) {
		t.Errorf("registry warrant = %q, want the task XID %q", planned[0].warrant, taskXID)
	}
}

// TestTriggerWithoutProductIDCarriesTheTaskXID is the other half, and the half a
// deployment actually runs today: with no productID provisioned the two values
// coincide, and the trigger must carry the task XID.
//
// Asserted rather than assumed, because every other test in this file leaves the
// field unset — so the default path is exercised constantly and checked nowhere,
// which is the shape of a regression that reaches an agency before it reaches a
// test.
func TestTriggerWithoutProductIDCarriesTheTaskXID(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	const taskXID = testXIDPrimary
	warrant := types.InterceptTask{
		XID:      taskXID,
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}

	planned, unreachable, undeliverable := s.triggers.plan("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	if len(unreachable) != 0 || len(undeliverable) != 0 || len(planned) != 1 {
		t.Fatalf("plan() = %d triggers, %d unreachable, %d undeliverable; want 1, 0, 0",
			len(planned), len(unreachable), len(undeliverable))
	}

	if got := planned[0].trigger.ProductID; got != types.XID(taskXID) {
		t.Errorf("trigger ProductID = %q, want the task XID %q", got, taskXID)
	}
	if x2, x3 := parseXID(warrant.DeliveryXID()), parseXID(planned[0].trigger.ProductID); x2 != x3 {
		t.Errorf("X2 header XID %x != X3 header XID %x", x2, x3)
	}
}

// withdrawOne installs a trigger and then withdraws it, returning the pending
// withdrawals deactivate was given. It is the shape every withdrawal test needs:
// a trigger the registry believes is installed, taken out of the registry the way
// a release does, so deactivate runs against a real entry rather than a literal.
func withdrawOne(t *testing.T, s *subsystem) []withdrawal {
	t.Helper()

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}

	planned, unreachable, undeliverable := s.triggers.plan("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	if len(unreachable) != 0 || len(undeliverable) != 0 || len(planned) != 1 {
		t.Fatalf("plan() = %d triggers, %d unreachable, %d undeliverable; want 1, 0, 0",
			len(planned), len(unreachable), len(undeliverable))
	}
	s.installTriggers(planned)

	pending := s.triggers.takeForSession("session-ref-1")
	if len(pending) != 1 {
		t.Fatalf("takeForSession returned %d withdrawals, want 1", len(pending))
	}

	return pending
}

// TestWithdrawalCompletesWhenPOIDoesNotHoldTheTask: 2020 is "XID does not exist
// on NE", and a POI is required to answer it for tasking it does not hold — after
// a restart, or after its own fail-safe purged what this element could no longer
// name. That is the withdrawal's goal reached, not a failure to reach it, and the
// retry loop must exit on it. Read as a failure it never exits: the answer cannot
// change, so the loop runs forever against a POI that is behaving correctly.
func TestWithdrawalCompletesWhenPOIDoesNotHoldTheTask(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	pending := withdrawOne(t, s)

	// The POI restarted between the install and the withdrawal: it no longer holds
	// the XID and says so.
	poi.mu.Lock()
	poi.refuse = true
	poi.refuseCode = 2020
	poi.mu.Unlock()

	s.deactivate(pending) // must return; against the defect this never terminates

	if n := poi.countMessages("DeactivateTaskRequest"); n != 1 {
		t.Errorf("DeactivateTaskRequest count = %d, want 1 — an answer of 2020 cannot "+
			"change on a retry, so retrying it is a loop with no exit", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after the POI said it does not hold the task, want 0 — "+
			"the entry that never clears is what raises taskingWithdrawalStuck against "+
			"an interception that has already stopped", n)
	}
}

// TestWithdrawalStillRetriesOtherFailures keeps the reclassification narrow: only
// 2020 means the tasking is gone. Any other refusal is a POI that still holds the
// trigger and has not agreed to drop it, which is the case the pending state and
// the retry loop exist for.
func TestWithdrawalStillRetriesOtherFailures(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	pending := withdrawOne(t, s)

	poi.mu.Lock()
	poi.refuse = true
	poi.refuseCode = 1000
	poi.mu.Unlock()

	// The backoff is the registry's, not this test's: drive it through the clock
	// hook so the retries happen at once. Sleeping for real here would assert the
	// same thing thirty-five seconds later.
	s.triggers.sleep = func(time.Duration) {
		if poi.countMessages("DeactivateTaskRequest") >= 3 {
			poi.mu.Lock()
			poi.refuse = false
			poi.mu.Unlock()
		}
	}

	s.deactivate(pending)

	if n := poi.countMessages("DeactivateTaskRequest"); n < 2 {
		t.Errorf("DeactivateTaskRequest count = %d, want at least 2 — a refusal that is "+
			"not 2020 leaves the POI holding the trigger, and must be retried", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after the POI finally acknowledged, want 0", n)
	}
}

// TestKeepaliveLapsesAfterNoSuchTaskWithdrawal: the second half of what a stuck
// pending entry costs. A triggering function keeps a POI alive while it believes
// that POI holds tasking it installed, so an entry that can never clear keeps the
// keepalives flowing — and those keepalives are exactly what stops that POI's own
// fail-safe from reclaiming orphaned tasking. Completing the withdrawal on 2020
// is what lets the endpoint go quiet and the backstop work.
func TestKeepaliveLapsesAfterNoSuchTaskWithdrawal(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	pending := withdrawOne(t, s)

	endpoint := s.triggers.endpoints[trigNodeA]
	endpoint.markReconciled()
	if !s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Fatal("test setup: the endpoint should be kept alive while a withdrawal is pending")
	}

	poi.mu.Lock()
	poi.refuse = true
	poi.refuseCode = 2020
	poi.mu.Unlock()

	s.deactivate(pending)

	if s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Error("the endpoint is still being kept alive after a completed withdrawal — " +
			"the keepalives a phantom pending entry earns are what disable the POI's fail-safe")
	}
}

// TestSessionTeardownLeavesNoTaskingBehind pins the contract the teardown paths
// depend on: taking a session's triggers out of the registry and withdrawing them
// leaves this element answerable for nothing at that POI, so it stops sending
// keepalives and the POI's own fail-safe becomes reachable again.
//
// This is what a teardown path that forgets to call UntriggerCC costs. Not the
// missing release record — that one an operator could at least notice — but a
// trigger that stays installed, keeping the keepalives flowing, which is exactly
// what stops the POI's fail-safe from reclaiming it. Interception then outlives
// the session that authorised it with every party behaving as designed.
func TestSessionTeardownLeavesNoTaskingBehind(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	pending := withdrawOne(t, s)

	endpoint := s.triggers.endpoints[trigNodeA]
	endpoint.markReconciled()
	if !s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Fatal("test setup: a session holding a trigger should keep its POI alive")
	}

	s.deactivate(pending)

	if n := len(s.triggers.installed); n != 0 {
		t.Errorf("%d triggers still installed after the session's teardown, want 0", n)
	}
	if s.triggers.keepaliveDue(trigNodeA, endpoint) {
		t.Error("the POI is still being kept alive after the session that held its " +
			"tasking was torn down — its fail-safe cannot reclaim anything while this " +
			"element keeps telling it that the function responsible is present")
	}
}

// x3Task builds a content warrant naming the given X3 endpoints, as an ADMF that
// provisioned its own destinations produces.
func x3Task(xid string, addresses ...string) types.InterceptTask {
	t := types.InterceptTask{
		XID:      types.XID(xid),
		Products: []types.ProductType{types.ProductCC},
	}
	for i, addr := range addresses {
		t.Deliveries = append(t.Deliveries, types.DeliveryEndpoint{
			Type:    types.DeliveryX3,
			Address: addr,
			DID:     fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012d", i),
		})
	}

	return t
}

// elements returns the text of every occurrence of an element, by local name, in
// every recorded request of the given type. Enough to assert what went on the wire
// without decoding the whole schema.
func (p *fakePOI) elements(msgType, local string) []string {
	re := regexp.MustCompile(`<[a-z0-9]+:` + local + `>([^<]*)</[a-z0-9]+:` + local + `>`)

	var out []string
	for _, b := range p.sent() {
		if !strings.Contains(b, `xsi:type="ns1:`+msgType+`"`) {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(b, -1) {
			out = append(out, m[1])
		}
	}

	return out
}

// TestTriggerNamesTheTasksOwnX3Destinations is the cross-agency disclosure this
// change exists to close.
//
// The CC-TF read a task's X3 destinations, carried them into the task, and then
// triggered every warrant against the one endpoint in its own configuration. With a
// single agency that is invisible. With two, both agencies' *content* — not
// metadata, the subscriber's traffic — arrived wherever `mdf3` happened to point,
// which is the disclosure the equivalent X2 fix removed and which
// li-security-isolation forbids unconditionally, for every product type and every
// delivery path.
func TestTriggerNamesTheTasksOwnX3Destinations(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	const (
		agencyA = "198.51.100.10:5000"
		agencyB = "203.0.113.20:6000"
	)

	s.installFor("session-ref-1", []types.InterceptTask{
		x3Task(testXIDPrimary, agencyA),
		x3Task(testXIDSecondary, agencyB),
	}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	// Two destinations provisioned, one per agency, and neither is the configured
	// MDF3 — which no task named.
	addresses := poi.elements("CreateDestinationRequest", "IPv4Address")
	ports := poi.elements("CreateDestinationRequest", "TCPPort")
	if len(addresses) != 2 || len(ports) != 2 {
		t.Fatalf("provisioned %d addresses and %d ports, want 2 and 2:\n%s",
			len(addresses), len(ports), strings.Join(poi.sent(), "\n"))
	}
	got := map[string]bool{
		addresses[0] + ":" + ports[0]: true,
		addresses[1] + ":" + ports[1]: true,
	}
	for _, want := range []string{agencyA, agencyB} {
		if !got[want] {
			t.Errorf("no destination provisioned for %s; provisioned %v", want, got)
		}
	}
	if got[testMDF3Addr] {
		t.Error("the configured MDF3 was provisioned for a task that named its own destination")
	}

	// And each trigger names its own agency's destination, not the other's.
	dids := poi.elements("CreateDestinationRequest", "dId")
	triggerDIDs := poi.elements("ActivateTaskRequest", "dId")
	if len(dids) != 2 || len(triggerDIDs) != 2 {
		t.Fatalf("%d destinations and %d trigger DIDs, want 2 and 2", len(dids), len(triggerDIDs))
	}
	if triggerDIDs[0] == triggerDIDs[1] {
		t.Errorf("both warrants' triggers name one destination %q — the two agencies share an endpoint",
			triggerDIDs[0])
	}

	// The pairing itself: the DID a warrant's trigger names must be the DID created
	// for that warrant's address. Asserting only that the two differ would pass with
	// the two swapped, which is the same disclosure in the other direction.
	perAddress := map[string]string{} // address -> dId, from the CreateDestination bodies
	for i, b := range poi.sent() {
		if !strings.Contains(b, `xsi:type="ns1:CreateDestinationRequest"`) {
			continue
		}
		_ = i
		a := regexp.MustCompile(`<c:IPv4Address>([^<]*)</c:IPv4Address>`).FindStringSubmatch(b)
		p := regexp.MustCompile(`<c:TCPPort>([^<]*)</c:TCPPort>`).FindStringSubmatch(b)
		d := regexp.MustCompile(`<ns1:dId>([^<]*)</ns1:dId>`).FindStringSubmatch(b)
		if a == nil || p == nil || d == nil {
			t.Fatalf("CreateDestination body is missing an address, port or dId:\n%s", b)
		}
		perAddress[a[1]+":"+p[1]] = d[1]
	}
	for _, b := range poi.sent() {
		if !strings.Contains(b, `xsi:type="ns1:ActivateTaskRequest"`) {
			continue
		}
		x := regexp.MustCompile(`<ns1:productID>([^<]*)</ns1:productID>`).FindStringSubmatch(b)
		d := regexp.MustCompile(`<ns1:dId>([^<]*)</ns1:dId>`).FindStringSubmatch(b)
		if x == nil || d == nil {
			t.Fatalf("ActivateTask body is missing a productID or dId:\n%s", b)
		}
		want := map[string]string{
			testXIDPrimary:   perAddress[agencyA],
			testXIDSecondary: perAddress[agencyB],
		}[x[1]]
		if d[1] != want {
			t.Errorf("warrant %s triggers against destination %s, want %s — its content would go to the other agency",
				x[1], d[1], want)
		}
	}
}

// TestTriggerFallsBackToTheConfiguredMDF3 keeps destination handling conformant without
// making it an outage. An ADMF is entitled to task an element that names **no** destination, which is
// what every deployment predating the destination requirement does, and the configured
// endpoint serves it — exactly as the configured MDF2 serves the equivalent IRI task, and
// without the task being refused.
//
// A task that named a destination and resolved none of it is a different fact, and the
// wrong one to serve from configuration: naming an
// endpoint the warrant did not is the element deciding where a warrant's content goes,
// and on an element serving several agencies it goes to whichever address configuration
// happens to name. See x3Destinations.
func TestTriggerFallsBackToTheConfiguredMDF3(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	reporter := &recordingTaskReporter{}
	s.taskReporter = reporter

	s.installFor("session-ref-1", []types.InterceptTask{{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
		// Named no destination at all: the gap the provisioning function left, which the
		// configured endpoint is there to fill.
	}}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	addresses := poi.elements("CreateDestinationRequest", "IPv4Address")
	ports := poi.elements("CreateDestinationRequest", "TCPPort")
	if len(addresses) != 1 || len(ports) != 1 {
		t.Fatalf("provisioned %d destinations, want 1:\n%s", len(addresses), strings.Join(poi.sent(), "\n"))
	}
	if got := addresses[0] + ":" + ports[0]; got != testMDF3Addr {
		t.Errorf("fell back to %s, want the configured MDF3", got)
	}
	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Errorf("sent %d activations, want 1 — the task was refused rather than served by the fallback", n)
	}
	for _, r := range reporter.reports {
		t.Errorf("reported a task issue for a task the fallback serves: %+v", r)
	}
}

// TestATaskWhoseDestinationsYieldNoX3EndpointIsNotServedFromConfiguration is the other
// half, and the reason the two had to be told apart.
//
// A task that named where its content goes and yielded no X3 endpoint is an assertion
// this element cannot honour. x1 refuses one with 3040 before it reaches the store, so
// this pins the backstop rather than a path X1 can drive.
// Substituting the configured MDF3 sends an agency's content to an endpoint the warrant
// never named, and on an element serving several agencies it goes to whichever address
// local configuration happens to name. So nothing is provisioned, no trigger is installed,
// and the LIPF is told the content has nowhere to go — which is the one channel that can
// say so.
func TestATaskWhoseDestinationsYieldNoX3EndpointIsNotServedFromConfiguration(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	reporter := &recordingTaskReporter{}
	s.taskReporter = reporter

	s.installFor("session-ref-1", []types.InterceptTask{{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
		// Named a destination, and it resolved — to an X2 endpoint, which carries no
		// content. Built directly: x1 refuses this task with 3040.
		DIDs: []string{testXIDOrphan},
		Deliveries: []types.DeliveryEndpoint{
			{DID: testXIDOrphan, Type: types.DeliveryX2, Address: testDestinationAddr},
		},
	}}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	if n := poi.countMessages("CreateDestinationRequest"); n != 0 {
		t.Errorf("provisioned %d destinations at the POI for a task whose content has nowhere to "+
			"go:\n%s", n, strings.Join(poi.sent(), "\n"))
	}
	if n := poi.countMessages("ActivateTaskRequest"); n != 0 {
		t.Errorf("installed %d triggers, want 0 — the POI would duplicate a subject's traffic and "+
			"deliver it to an endpoint the warrant did not name", n)
	}
	if len(reporter.reports) == 0 {
		t.Error("nothing was reported to the LIPF: an interception this element cannot deliver is " +
			"exactly the condition only the provisioning function can resolve")
	}
}

// TestTwoWarrantsToOneEndpointShareItsDestination: the POI deduplicates delivery by
// address and reports faults by identifier, so a second identifier for one endpoint
// would deliver the same content once and report one failure twice — leaving the
// ADMF to work out that its two destinations are one.
func TestTwoWarrantsToOneEndpointShareItsDestination(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	const shared = "198.51.100.10:5000"

	s.installFor("session-ref-1", []types.InterceptTask{
		x3Task(testXIDPrimary, shared),
		x3Task(testXIDSecondary, shared),
	}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	if n := poi.countMessages("CreateDestinationRequest"); n != 1 {
		t.Errorf("provisioned %d destinations for one endpoint, want 1", n)
	}
	dids := poi.elements("ActivateTaskRequest", "dId")
	if len(dids) != 2 {
		t.Fatalf("%d triggers, want 2", len(dids))
	}
	if dids[0] != dids[1] {
		t.Errorf("two warrants naming one endpoint were given two destinations, %s and %s", dids[0], dids[1])
	}
}

// TestTriggerCarriesEveryDestinationATaskNames: a task may name more than one, and
// the POI delivers to all of them. Dropping the rest would give an agency an empty
// stream while the element reported the interception as running.
func TestTriggerCarriesEveryDestinationATaskNames(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	s.installFor("session-ref-1", []types.InterceptTask{
		x3Task(testXIDPrimary, "198.51.100.10:5000", "198.51.100.11:5001"),
	}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	if n := poi.countMessages("CreateDestinationRequest"); n != 2 {
		t.Errorf("provisioned %d destinations, want 2", n)
	}
	if dids := poi.elements("ActivateTaskRequest", "dId"); len(dids) != 2 {
		t.Errorf("the trigger names %d destinations, want both the task named", len(dids))
	}
}

// TestWarrantWithNoResolvableDestinationAndNoFallbackIsReported: with no configured
// MDF3 either, this element cannot deliver the warrant's content anywhere. It
// installs no trigger — duplicating a subject's traffic so every copy can be
// discarded is collection without a purpose — and tells the LIPF, which is the only
// party that can provision the destination.
func TestWarrantWithNoResolvableDestinationAndNoFallbackIsReported(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.triggers.mdf3 = ""
	reporter := &recordingTaskReporter{}
	s.taskReporter = reporter

	s.installFor("session-ref-1", []types.InterceptTask{{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	if n := poi.countMessages("ActivateTaskRequest"); n != 0 {
		t.Errorf("installed %d triggers for a warrant whose content has nowhere to go", n)
	}
	if len(reporter.reports) != 1 {
		t.Fatalf("reported %d task issues, want 1: %+v", len(reporter.reports), reporter.reports)
	}
	if !strings.Contains(reporter.reports[0].details, "X3 delivery destination") {
		t.Errorf("task issue = %q, want it to name the unresolvable destination", reporter.reports[0].details)
	}
}

// setMisname changes the identity the POI answers under, which is how a test moves
// it between "answering unbindably" and "answering properly" mid-run.
func (p *fakePOI) setHangOn(on string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hangOn = on
}

func (p *fakePOI) setRefuse(to bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refuse = to
}

func (p *fakePOI) setMisname(to, on string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.misname = to
	p.misnameOn = on
}

// awaitMessages blocks until the POI has received at least n requests of a type.
// The withdrawal after a failed activation runs on its own goroutine, so the
// assertion has to wait for it rather than race it — and the recorded bodies only
// ever grow, which is what makes polling them sound where polling the registry's
// pending count is not (that one goes up and back down).
func awaitMessages(t *testing.T, p *fakePOI, msgType string, n int) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if p.countMessages(msgType) >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the POI received %d %s after 3s, want at least %d",
		p.countMessages(msgType), msgType, n)
}

// awaitPending blocks until the registry's pending-withdrawal count reaches want.
// The withdrawal after a failed activation runs on its own goroutine — the triggers
// behind it in a batch must not wait for a retry loop — so a test that asserted
// immediately would be asserting on a race.
// have to be rewritten the first time a test waited for one.
//
//nolint:unparam // want is what the wait is for; a helper that only waited for zero would
func awaitPending(t *testing.T, r *triggerRegistry, want int) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.pendingCount() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("pending = %d after 3s, want %d", r.pendingCount(), want)
}

// TestAmbiguousActivationIsWithdrawnNotForgotten is the defect, and the
// distinction it turns on is between a negative answer and no answer.
//
// A POI that *refuses* a trigger has said it holds nothing. A POI whose answer
// never arrives, or arrives and cannot be bound to the request, has said nothing —
// and may well have applied the task before answering. Dropping the claim on that
// outcome left the trigger installed and untracked: absent from both maps, so the
// warrant's withdrawal finds nothing, the session's release finds nothing, and
// reconciliation only runs at startup. The POI keeps duplicating the subject's
// content, correctly labelled and indistinguishable downstream, past the point
// where the warrant is revoked.
//
// The POI here answers under an identity this SMF was not told to address, which
// is the ambiguous case in its purest form: the request was received, parsed and
// applied, and only the envelope of the reply is unusable.
func TestAmbiguousActivationIsWithdrawnNotForgotten(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	// The retry clock is the test's. Correcting the POI's identity on the first
	// retry lets the withdrawal converge instead of looping past the test's end.
	s.triggers.sleep = func(time.Duration) { poi.setMisname("", "") }

	poi.setMisname("some-other-upf", "ActivateTaskRequest")

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-ref-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	// The trigger must not have been silently dropped: the registry keeps it and
	// withdraws it. Asserted on the withdrawal arriving at the POI, because that is
	// the observable that matters — an entry retained and never acted on would be
	// the same defect with an extra map entry.
	awaitMessages(t, poi, "DeactivateTaskRequest", 1)
	awaitPending(t, s.triggers, 0)

	if len(s.triggers.installed) != 0 {
		t.Errorf("registry still holds %d installed triggers after the withdrawal completed",
			len(s.triggers.installed))
	}
}

// TestRefusedActivationIsReleasedNotWithdrawn is the other side of the same guard,
// and the reason the classification cannot simply be "withdraw on any error". A POI
// that states a refusal holds nothing, so withdrawing would send a DeactivateTask
// for a task that never existed — noise on the provisioning interface, and a
// pending entry whose keepalives hold that POI's own fail-safe open.
func TestRefusedActivationIsReleasedNotWithdrawn(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	poi.mu.Lock()
	poi.refuse = true
	poi.mu.Unlock()

	s.installFor("session-ref-1", []types.InterceptTask{{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	if n := poi.countMessages("DeactivateTaskRequest"); n != 0 {
		t.Errorf("sent %d withdrawals for a trigger the POI stated it refused", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after a stated refusal, want 0", n)
	}
	if len(s.triggers.installed) != 0 {
		t.Errorf("registry holds %d triggers after a stated refusal, want 0", len(s.triggers.installed))
	}
}

// TestWithdrawalOfATriggerThePOINeverReceivedCompletesAtOnce is what makes the
// conservative branch cheap enough to be the default. Where the activation truly
// never landed, the POI answers 2020 — "XID does not exist on NE" — which this
// element already reads as a completed withdrawal. One request, no retry, and no
// fault reported for a condition that resolved itself.
func TestWithdrawalOfATriggerThePOINeverReceivedCompletesAtOnce(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	reporter := &recordingTaskReporter{}
	s.taskReporter = reporter

	retries := 0
	s.triggers.sleep = func(time.Duration) { retries++ }

	// Answers unbindably to the activation, and 2020 to everything after it: the
	// shape of a POI that never received the trigger at all.
	poi.setMisname("some-other-upf", "ActivateTaskRequest")
	s.triggers.sleep = func(time.Duration) {
		retries++
		poi.setMisname("", "")
		poi.mu.Lock()
		poi.refuse = true
		poi.refuseCode = x1CodeNoSuchTask
		poi.mu.Unlock()
	}

	s.installFor("session-ref-1", []types.InterceptTask{{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	awaitPending(t, s.triggers, 0)

	if retries > 1 {
		t.Errorf("retried the withdrawal %d times against a POI answering 2020; "+
			"that answer is the outcome, not a failure", retries)
	}
}

// TestWarrantWithdrawnAfterAnAmbiguousActivationStillReachesThePOI is the
// end-to-end shape of the defect, and the reason it is release-gating: content
// continuing after a warrant is revoked is the one direction this plane may not
// fail in. Before the fix the deactivation found nothing to withdraw, because the
// activation's failure had already dropped the only record of the trigger.
func TestWarrantWithdrawnAfterAnAmbiguousActivationStillReachesThePOI(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}
	s.triggers.sleep = func(time.Duration) { poi.setMisname("", "") }

	poi.setMisname("some-other-upf", "ActivateTaskRequest")

	const warrantXID = testXIDPrimary
	s.installFor("session-ref-1", []types.InterceptTask{{
		XID:      warrantXID,
		Products: []types.ProductType{types.ProductCC},
	}}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	awaitMessages(t, poi, "DeactivateTaskRequest", 1)
	awaitPending(t, s.triggers, 0)

	// The warrant is revoked while the session is still live. By now the trigger has
	// already been withdrawn by the activation path, so this finds nothing left —
	// which is the correct end state: the POI holds no trigger for this warrant.
	s.untriggerWarrant(types.XID(warrantXID))
	awaitPending(t, s.triggers, 0)

	// The XID withdrawn must be the one that was activated, or the POI keeps the
	// trigger and answers 2020 to a request about something else.
	activated := poi.elements("ActivateTaskRequest", "xId")
	withdrawn := poi.elements("DeactivateTaskRequest", "xId")
	if len(activated) == 0 || len(withdrawn) == 0 {
		t.Fatalf("activated %v, withdrew %v", activated, withdrawn)
	}
	if !slices.Contains(withdrawn, activated[0]) {
		t.Errorf("withdrew %v, none of which is the trigger XID %s that was activated",
			withdrawn, activated[0])
	}
}

// TestMatchEndpointPerformsNoResolution: matching performs no I/O.
//
// matchEndpoint runs on the PDU-session establishment path of the subscriber being
// intercepted — triggerCC holds that session's lock, plan holds the registry's. Resolving
// both sides of its comparison there would, on a cache miss, be a synchronous LookupHost
// with context.Background() and no timeout, and the SMF's own cache *deletes* an entry
// whenever a lookup fails, so a transient resolver outage would put every subsequent call
// on the live path. A stall there delays a targeted
// subscriber's session establishment while holding a lock every other trigger
// operation waits on — the target-observable timing difference this capability names
// as the concrete, testable form of undetectability.
//
// Asserted by making resolution fatal: any lookup at all fails the test.
func TestMatchEndpointPerformsNoResolution(t *testing.T) {
	const name = "upf-noio.test"

	// A registry without the refresh loop behind it, so the only thing that can reach
	// the resolver is matchEndpoint. Built by hand for exactly that reason: with the
	// loop running, a lookup it makes on its own goroutine is indistinguishable from
	// one made here, and the assertion would be about timing rather than about the
	// function under test.
	reg := staticRegistry(map[string]string{name: trigNodeA, trigNodeC: trigNodeC})
	reg.lookup = func(_ context.Context, host string) (string, error) {
		t.Errorf("matchEndpoint resolved %q; on this path a name lookup runs under the "+
			"session lock of the subscriber being intercepted", host)

		return "", errors.New("no resolution permitted here")
	}

	// Every shape of match: by identity, by a resolved name, by a literal, and no
	// match at all — the last being the one that would resolve the most, since it
	// exhausts the identity pass and then would resolve every configured node in turn.
	for _, session := range []upfSession{
		{node: upfNode(name), addr: trigNodeA},
		{node: upfNode(trigNodeA), addr: trigNodeA},
		{node: upfNode(trigNodeC), addr: trigNodeC},
		{node: upfNode(trigNodeElsewhere), addr: trigNodeElsewhere},
	} {
		matchOn(reg, session) //nolint:errcheck // the assertion is in the resolver hook
	}
}

// TestResolvingATriggeringEndpointIsSilent is L12, and it is an undetectability
// requirement rather than a tidiness one.
//
// The shared resolver logs "host [X] not found in smf dns cache" and "host [X] dns
// resolved" on the general operator log. For a name that appears *only* in the LI
// block — a triggering endpoint the slice topology does not mention — those lines
// put an LI-only hostname somewhere every operator can read it, which is precisely
// what undetectability forbids at network-element level.
func TestResolvingATriggeringEndpointIsSilent(t *testing.T) {
	var logged bytes.Buffer

	// Capture anything the standard logger emits, which is where a stray fmt or log
	// call would land, and assert on the LI-only name never appearing.
	restore := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(restore) })

	const name = "upf-secret.li.test"
	reg := mustRegistry(Config{
		NEID: testNEID, MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{{NodeID: name, X1URL: testX1URLUPF1, NEID: testUPFNEID1}},
	})
	resolvingTo(reg, map[string]string{name: trigNodeA})

	_, ok := matchOn(reg, sessionOn(trigNodeA))

	if !ok {
		t.Fatal("the endpoint did not match, so this test proves nothing about what it logged")
	}
	if strings.Contains(logged.String(), name) {
		t.Errorf("resolving a triggering endpoint wrote its hostname to the general log:\n%s", logged.String())
	}
}

// TestSessionUPFsCarriesTheAddressItAlreadyResolved pins the other half of matching
// without I/O: the session side must hand on the address it derived for the PFCP
// context key rather than leave matchEndpoint to derive it again. Two derivations of
// one value is one lookup too many, and the second would be on the locked path.
func TestSessionUPFsCarriesTheAddressItAlreadyResolved(t *testing.T) {
	// A bare context, not one from NewSMContext: sessionUPFs reads only Tunnel and
	// PFCPContext, and a registered context has to be released — which returns its
	// PDU address to a pool these tests do not build.
	sc := &smfctx.SMContext{}

	node := smfctx.NewDataPathNode()
	node.UPF = &smfctx.UPF{NodeID: upfNode(trigNodeA)}
	sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
		1: &smfctx.DataPath{FirstDPNode: node, IsDefaultPath: true},
	}}
	sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{
		trigNodeA: {RemoteSEID: 0x2632898145f4d191},
	}

	upfs := sessionUPFs(sc)
	if len(upfs) != 1 {
		t.Fatalf("sessionUPFs returned %d entries, want 1", len(upfs))
	}
	if upfs[0].addr != trigNodeA {
		t.Errorf("upfSession.addr = %q, want the resolved address the PFCP context is keyed by", upfs[0].addr)
	}
}

// TestProductIDChangeReachesTheInstalledTrigger.
//
// An ADMF may change the identifier a warrant's product is labelled with. This
// element reads that identifier from the task each time it builds a record, so its own
// xIRI picks the new value up at once; a triggered CC-POI reads it from a trigger built
// once. A modifyInterception that returned early whenever the target identifiers and the
// required products were unchanged — which a productID change leaves alone — would leave
// the trigger with the old label. Signalling would then arrive at the mediation function
// under one warrant identifier and content under another, both well-formed, both
// separately deliverable, with nothing in either stream to show they were meant to join.
func TestProductIDChangeReachesTheInstalledTrigger(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	const (
		warrantXID = testXIDPrimary
		oldLabel   = testXIDSecondary
		newLabel   = testXIDTertiary
	)
	targets := []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}}

	prev := types.InterceptTask{
		XID: warrantXID, ProductID: oldLabel, Targets: targets,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-ref-1", []types.InterceptTask{prev},
		[]upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}, 7)

	if got := poi.elements("ActivateTaskRequest", "productID"); len(got) != 1 || got[0] != oldLabel {
		t.Fatalf("activation carried productID %v, want [%s]", got, oldLabel)
	}

	// Only the label moves: same target, same products, so this is exactly the
	// modification an early return on targets and products would swallow.
	next := prev
	next.ProductID = newLabel
	s.modifyInterception(prev, next)

	awaitMessages(t, poi, "ModifyTaskRequest", 1)

	modified := poi.elements("ModifyTaskRequest", "productID")
	if len(modified) != 1 || modified[0] != newLabel {
		t.Fatalf("modification carried productID %v, want [%s]", modified, newLabel)
	}

	// The trigger is modified, not replaced: the same XID, so the POI keeps
	// intercepting rather than stopping and starting.
	activated := poi.elements("ActivateTaskRequest", "xId")
	remodified := poi.elements("ModifyTaskRequest", "xId")
	if len(activated) != 1 || len(remodified) != 1 || activated[0] != remodified[0] {
		t.Errorf("modification names trigger %v where the activation named %v; the trigger "+
			"was replaced rather than relabelled", remodified, activated)
	}
	if n := poi.countMessages("DeactivateTaskRequest"); n != 0 {
		t.Errorf("sent %d withdrawals to change a label; content the warrant still "+
			"authorises would be interrupted", n)
	}

	// And the criterion and correlation it was installed with are restated, because
	// TS 33.128 makes both mandatory on the trigger and a modification that dropped
	// them would be refused.
	if seids := poi.elements("ModifyTaskRequest", "SEID"); len(seids) != 1 || seids[0] != "2752413510594253201" {
		t.Errorf("modification carried SEID %v, want the session's own", seids)
	}
	if corr := poi.elements("ModifyTaskRequest", "correlationID"); len(corr) != 1 || corr[0] != "7" {
		t.Errorf("modification carried correlationID %v, want the session's own", corr)
	}
}

// TestAModificationThatChangesNoLabelSendsNothing is the other half. A ModifyTask that
// leaves the delivery identifier, the correlation value and the destinations alone has
// nothing for a POI to do differently, and sending one anyway would put a message on
// the triggering interface for every unrelated modification an ADMF makes.
func TestAModificationThatChangesNoLabelSendsNothing(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	targets := []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}}
	prev := types.InterceptTask{
		XID:      testXIDPrimary,
		Targets:  targets,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-ref-1", []types.InterceptTask{prev},
		[]upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}, 7)

	s.modifyInterception(prev, prev)

	// Nothing to wait for, so a moment to let a stray goroutine be wrong in.
	time.Sleep(50 * time.Millisecond)

	if n := poi.countMessages("ModifyTaskRequest"); n != 0 {
		t.Errorf("sent %d modifications for a task whose labelling did not change", n)
	}
}

// pooledSession puts a targeted session in the global pool, which is where
// sessionsCovered reaches sessions from.
// supi is a parameter although every current caller passes the same value: which
// subscriber a test is about belongs at the call site, and a helper that hid it would
// make the tasking and the session silently agree.
//
//nolint:unparam // see above
func pooledSession(t *testing.T, supi string, id int32) *smfctx.SMContext {
	t.Helper()

	// RemoveSMContext publishes a state change that dereferences a configuration these
	// tests otherwise never build, as establishingSession explains.
	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	sc := smfctx.NewSMContext(supi, id)
	t.Cleanup(func() { smfctx.RemoveSMContext(sc.Ref) })
	// No PDUAddress: releasing the context returns the address to a pool these tests do
	// not build, and the task matches on SUPI.
	sc.Supi = supi

	return sc
}

// TestAModificationDoesNotWalkTheSessionPool.
//
// A ModifyTask on a content task reconciles the triggers held for that warrant against
// the sessions it still covers. Computing the second set by walking *every live session*
// and taking every session's lock — on the X1 request goroutine — would make the SMF's
// answer to a provisioning function take time proportional to the element's subscriber
// population, and each acquisition could block behind a PFCP handler holding that lock.
//
// Such a set would be almost entirely discarded: `keep` is consulted only by
// takeForWarrantExcept, which tests it while iterating this warrant's installed triggers,
// so a session no trigger exists for is never looked at. The work is bounded by the
// warrant's own triggers.
//
// There are **two** places on this path that could walk the pool, and this test covers
// both. scanSessions matches its sessions one call below; that cannot be bounded (nothing
// indexes target identity to session, so finding out is the work), so it runs off the
// request goroutine entirely, as the AMF's UE-pool scan does.
//
// Asserted by holding the lock of a session that is targeted but has *no* trigger. Either
// walk would block on that lock; neither path takes it on this goroutine. Reintroducing
// either walk alone fails this test, which is what says it covers them both rather than
// resting on whichever happens to run first.
func TestAModificationDoesNotWalkTheSessionPool(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	const (
		supi       = "262019876543210"
		warrantXID = testXIDPrimary
	)
	targets := []types.TargetIdentifier{{Type: types.TargetSUPI, Value: supi}}

	// The session the warrant has a trigger for.
	triggered := pooledSession(t, "imsi-"+supi, 5)
	task := types.InterceptTask{
		XID: warrantXID, Targets: targets,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor(triggered.Ref, []types.InterceptTask{task},
		[]upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}, 7)

	// A second session the same warrant targets, with no trigger of its own — the kind
	// a pool walk would visit and the bounded read never does.
	untriggered := pooledSession(t, "imsi-"+supi, 6)
	untriggered.SMLock.Lock()
	defer untriggered.SMLock.Unlock()

	// A modification that changes the targets, so the reconciliation actually runs.
	next := task
	next.Targets = []types.TargetIdentifier{
		{Type: types.TargetSUPI, Value: supi},
		{Type: types.TargetPEI, Value: "3534250000000151"},
	}

	// Held, so the scan the modification triggers actually runs: it revalidates the
	// task against the store before each session, and a task the store does not hold
	// stops it before it can walk anything — which would make the timing below pass
	// for a reason that has nothing to do with what it asserts.
	if !s.store.Activate(next) {
		t.Fatal("Activate failed")
	}

	done := make(chan struct{})
	go func() {
		s.modifyInterception(task, next)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the modification blocked on the lock of a session it holds no trigger for: " +
			"a walk of the session pool is still on the X1 request goroutine — either the " +
			"trigger reconciliation's (bound it to the warrant's own triggers) or " +
			"scanSessions' target match (move it onto its goroutine) — so the SMF's answer " +
			"to a provisioning function scales with the number of established sessions")
	}
}

// TestSessionsWithTriggersNamesOnlyThisWarrantsSessions is the bounding read itself. It
// has to be exact in both directions: a session omitted has its trigger withdrawn by the
// pass that was meant to keep it, and a session from another warrant would keep a trigger
// that warrant's own modification should decide about.
func TestSessionsWithTriggersNamesOnlyThisWarrantsSessions(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	const (
		mine   = testXIDPrimary
		theirs = testXIDSecondary
	)
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	cc := func(xid string) types.InterceptTask {
		return types.InterceptTask{XID: types.XID(xid), Products: []types.ProductType{types.ProductCC}}
	}

	s.installFor("session-a", []types.InterceptTask{cc(mine)}, upfs, 7)
	s.installFor("session-b", []types.InterceptTask{cc(mine)}, upfs, 7)
	s.installFor("session-c", []types.InterceptTask{cc(theirs)}, upfs, 7)

	got := s.triggers.sessionsWithTriggers(types.XID(mine))
	slices.Sort(got)

	if want := []string{"session-a", "session-b"}; !slices.Equal(got, want) {
		t.Errorf("sessionsWithTriggers = %v, want %v", got, want)
	}
}

// TestAnActivationThatTimesOutIsWithdrawnNotForgotten is the literal timeout, which is
// the member of the ambiguous class the requirement names first and the one the code's
// own comment leads with — and until this test, the one member not exercised. Its
// sibling above covers an answer that arrives and cannot be bound; this covers no answer
// at all.
//
// The distinction the whole guard turns on is between a negative answer and no answer,
// and a timeout is the purest case of the second: the POI received the request, may have
// applied it, and said nothing. So releasing the bookkeeping here is what leaves a
// trigger installed at the POI that this process can no longer name — duplicating and
// delivering a subject's content past the revocation of the warrant that authorised it.
//
// Worth exercising for real rather than with a fabricated error, because the classifying
// test is `errors.As(err, &refused)` against `*x1.RequestError`: if a transport failure
// ever came back wrapped in that type, a timeout would be *silently released*, and no
// test written against a hand-made error would notice.
//
// It is arranged so the error the classification actually sees is the timeout:
//
//  1. `CreateDestination` is answered normally, so the sequence reaches the activation.
//  2. The `ActivateTask` is taken and never answered. The requester's 10s deadline
//     (li/x1/trigger.go) is what ends it — which is why this test costs those 10s, and
//     the elapsed-time assertion below is what makes them worth paying.
//  3. The identical replay that follows gets no answer this element can bind either, so
//     the trigger may be held and nothing says otherwise. (A replay *refused* other than
//     with 2010 would say it is not held, and is re-provisioned instead — see
//     TestARefusedReplayAfterAnUnansweredActivationReprovisions.)
//  4. The withdrawal is refused once, and the retry clock belongs to the test, so the
//     sleep hook restores the POI and the withdrawal converges instead of looping past
//     the end of the test.
func TestAnActivationThatTimesOutIsWithdrawnNotForgotten(t *testing.T) {
	// It waits out the requester's 10s timeout, and touches no package state, so it waits
	// alongside the other tests that do rather than after them.
	t.Parallel()

	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	poi.setHangOn("ActivateTaskRequest")
	poi.mu.Lock()
	// The first step is the hung request itself; the second is the replay.
	poi.activateScript = []string{scriptOK, scriptUnbindable}
	poi.mu.Unlock()
	s.triggers.sleep = func(time.Duration) { poi.setRefuse(false) }

	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}

	started := time.Now()
	s.installFor("session-ref-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)
	elapsed := time.Since(started)

	// It really was the requester's clock that ended the activation. Everything else in
	// this test is sub-millisecond, so an activation that failed promptly failed for
	// some other reason — a different member of the class, covered elsewhere — and this
	// test would be asserting the right outcome about the wrong cause.
	if elapsed < 5*time.Second {
		t.Fatalf("the activation failed after %s, too soon to have been the requester's "+
			"10s deadline: this test is no longer exercising a timeout", elapsed)
	}

	// Retained and acted on. Asserted on the withdrawal reaching the POI, because an
	// entry kept in a map and never sent would be the same defect with better
	// bookkeeping.
	awaitMessages(t, poi, "DeactivateTaskRequest", 1)
	awaitPending(t, s.triggers, 0)

	if len(s.triggers.installed) != 0 {
		t.Errorf("registry still holds %d installed triggers after the withdrawal completed",
			len(s.triggers.installed))
	}
}

// TestALabelChangeArrivingWithATargetChangeStillReachesTheTrigger is the combined case,
// and it is the one where the divergence is hardest to notice because part of the
// modification visibly takes effect.
//
// relabelWarrant was reached only from modifyInterception's early-return branch — the
// path taken when nothing but the labelling moved. A ModifyTask that changes the
// targets *and* the productID takes the other branch, where retriggerWarrant withdraws
// triggers for sessions the task no longer covers and leaves the rest untouched. A
// trigger that survives that reconciliation is precisely a trigger that keeps its
// original labelling: the session is still covered, so nothing reinstalls it, and its
// content keeps arriving at the mediation function under the superseded warrant
// identifier while this element's own records use the new one.
func TestALabelChangeArrivingWithATargetChangeStillReachesTheTrigger(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	const (
		warrantXID = testXIDPrimary
		oldLabel   = testXIDSecondary
		newLabel   = testXIDTertiary
		supi       = "262019876543210"
	)

	// A session in the pool rather than a synthetic reference: the reconciliation
	// resolves each ref it holds a trigger for and reads the session's identity to
	// decide whether the new task still covers it, which is the decision this test
	// depends on being made correctly.
	session := pooledSession(t, "imsi-"+supi, 5)

	prev := types.InterceptTask{
		XID: warrantXID, ProductID: oldLabel,
		Targets: []types.TargetIdentifier{
			{Type: types.TargetSUPI, Value: supi},
			{Type: types.TargetPEI, Value: "3534250000000151"},
		},
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor(session.Ref, []types.InterceptTask{prev},
		[]upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}, 7)

	if got := poi.elements("ActivateTaskRequest", "productID"); len(got) != 1 || got[0] != oldLabel {
		t.Fatalf("activation carried productID %v, want [%s]", got, oldLabel)
	}

	// Both at once: a criterion is dropped and the label changes. The session installed
	// above is covered by the narrowed task, so its trigger survives the reconciliation —
	// which is exactly the trigger that would otherwise keep the old label.
	next := prev
	next.ProductID = newLabel
	next.Targets = []types.TargetIdentifier{{Type: types.TargetSUPI, Value: supi}}
	if !s.store.Activate(next) {
		t.Fatal("Activate failed")
	}
	s.modifyInterception(prev, next)

	awaitMessages(t, poi, "ModifyTaskRequest", 1)

	modified := poi.elements("ModifyTaskRequest", "productID")
	if len(modified) != 1 || modified[0] != newLabel {
		t.Fatalf("modification carried productID %v, want [%s]; content for a session the "+
			"warrant still covers keeps the superseded label while this element's own "+
			"records carry the new one", modified, newLabel)
	}
}

// TestTwoTriggeringEndpointsMayNotShareAnElementIdentifier is a deployment guard, and
// the only place the collision is visible at all.
//
// Every UPF serving one session is deliberately given the *same* delivery identifier and
// correlation value — that is what joins one warrant's content to its signalling and to
// the other UPF's content. TS 103 221-2 clause 5.3.9 then counts sequence numbers within
// a context formed from those two plus the identifiers that follow from ne_id, so ne_id
// is the only thing separating two points of interception. Two that share it number one
// context from zero independently.
//
// Neither element can detect that: each is numbering its own product correctly. What the
// mediation function receives is a single sequence with duplicated numbers and apparent
// gaps, for a warrant whose product is otherwise entirely correct — and gaps are how loss
// is made visible on this interface, so the collision forges the signal an agency uses to
// decide whether it has everything. Under ULCL, where a branching point and a session
// anchor both serve one session, this is the ordinary multi-UPF case.
func TestTwoTriggeringEndpointsMayNotShareAnElementIdentifier(t *testing.T) {
	shared := Config{
		NEID: testNEID, MDF3: testMDF3Addr,
		UPFTriggers: []UPFTrigger{
			{NodeID: trigNodeA, X1URL: testX1URLUPFA, NEID: testUPFNEID1},
			{NodeID: trigNodeB, X1URL: "https://upf-b:8443/X1/NE", NEID: testUPFNEID1},
		},
	}
	if _, err := newTriggerRegistry(shared, nil, nil, nil); err == nil {
		t.Error("a configuration giving two points of interception one element identifier was accepted; " +
			"their sequence numbering collides at the mediation function and neither element can see it")
	} else if !strings.Contains(err.Error(), testUPFNEID1) {
		t.Errorf("the refusal does not name the identifier at fault: %v", err)
	}

	// Distinct identifiers are the ordinary multi-UPF case and must still build.
	distinct := shared
	distinct.UPFTriggers = []UPFTrigger{
		{NodeID: trigNodeA, X1URL: testX1URLUPFA, NEID: testUPFNEID1},
		{NodeID: trigNodeB, X1URL: "https://upf-b:8443/X1/NE", NEID: testUPFNEID2},
	}
	if _, err := newTriggerRegistry(distinct, nil, nil, nil); err != nil {
		t.Errorf("two properly distinguished points of interception were refused: %v", err)
	}
}

// TestTwoPointsOfInterceptionServingOneSessionShareTheWarrantAndNotTheirIdentity is the
// positive half of the identity requirement, and it is the half that says what the
// refusal is protecting.
//
// One session steered through a branching point and a session anchor is served by both at
// once — the ordinary ULCL case. Both must be tasked for the same warrant, and TS 103
// 221-2 clause 5.3.9's sequence context is formed from the delivery identifier, the
// correlation value, and the identifiers that follow from each element's own ne_id. So
// the first two are deliberately *shared* — that is what joins one warrant's content to
// its signalling and to the other point of interception's content — and only the element
// identity separates the two sequence spaces.
//
// Asserting the shared halves matters as much as refusing a duplicate ne_id: an element
// that gave each UPF its own correlation would produce two streams a mediation function
// could not join, which is the same warrant broken in the other direction.
func TestTwoPointsOfInterceptionServingOneSessionShareTheWarrantAndNotTheirIdentity(t *testing.T) {
	anchor := newFakePOI(t)
	branch := newFakePOI(t)

	s := &subsystem{
		neID:  testNEID,
		store: store.New(),
		triggers: mustRegistry(Config{
			NEID: testNEID, MDF3: testMDF3Addr,
			UPFTriggers: []UPFTrigger{
				{NodeID: trigNodeA, X1URL: anchor.srv.URL, NEID: "upf-anchor"},
				{NodeID: trigNodeB, X1URL: branch.srv.URL, NEID: "upf-branch"},
			},
		}),
	}
	s.taskReporter = &recordingTaskReporter{}

	const (
		warrantXID = testXIDPrimary
		label      = testXIDSecondary
	)

	warrant := types.InterceptTask{
		XID: warrantXID, ProductID: label,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
	}

	// One session, two serving UPFs, one correlation — the session's.
	const correlation = 7
	upfs := []upfSession{
		{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191},
		{node: upfNode(trigNodeB), addr: trigNodeB, seid: 0x51f4d1912632898a},
	}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, correlation)

	awaitMessages(t, anchor, "ActivateTaskRequest", 1)
	awaitMessages(t, branch, "ActivateTaskRequest", 1)

	// Shared: the warrant's label and the session's correlation. If these ever diverge
	// the mediation function receives two unrelated intercepts.
	for name, poi := range map[string]*fakePOI{"anchor": anchor, "branch": branch} {
		if got := poi.elements("ActivateTaskRequest", "productID"); len(got) != 1 || got[0] != label {
			t.Errorf("%s was tasked with productID %v, want the warrant's %s", name, got, label)
		}
		if got := poi.elements("ActivateTaskRequest", "correlationID"); len(got) != 1 || got[0] != "7" {
			t.Errorf("%s was tasked with correlationID %v, want the session's 7", name, got)
		}
	}

	// Distinct: the trigger XIDs, so each POI's own tasking is separately withdrawable,
	// and the element identities the registry addressed them by.
	anchorXID := anchor.elements("ActivateTaskRequest", "xId")
	branchXID := branch.elements("ActivateTaskRequest", "xId")
	if len(anchorXID) != 1 || len(branchXID) != 1 {
		t.Fatalf("trigger identifiers: anchor %v branch %v", anchorXID, branchXID)
	}
	if anchorXID[0] == branchXID[0] {
		t.Error("both points of interception were tasked under one trigger identifier; withdrawing " +
			"one would clear the registry's record of the other")
	}

	// And the detection criteria are per UPF, because each holds its own PFCP session.
	// The element is ext:SEID inside the extension's FSEID, not an ns1: one — asserted
	// on a name that exists, or this check would pass by finding nothing.
	anchorSEID := anchor.elements("ActivateTaskRequest", "SEID")
	branchSEID := branch.elements("ActivateTaskRequest", "SEID")
	if len(anchorSEID) == 0 || len(branchSEID) == 0 {
		t.Fatalf("no detection criterion was read from either trigger (anchor %v, branch %v); "+
			"this assertion would otherwise pass without comparing anything", anchorSEID, branchSEID)
	}
	if anchorSEID[0] == branchSEID[0] {
		t.Errorf("both were given the same detection criterion (%s); one of them cannot match it",
			anchorSEID[0])
	}
}

// TestAFaultyTriggerNamesOnlyItsOwnWarrant is the attribution property, which is the whole
// reason `triggerFaulty` is task-scoped rather than element-scoped.
//
// A LIPF holding several warrants at one point of interception has to know which one has
// stopped producing: the responses differ — re-provision this warrant, tell this agency, ask
// this operator — and an answer naming the wrong warrant is worse than one naming none, because
// it would have somebody act on an interception that is running.
//
// The POI answers unhealthy for one of two triggers, so a report about both would satisfy any
// presence check and fail this one.
func TestAFaultyTriggerNamesOnlyItsOwnWarrant(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	taskReports := &recordingTaskReporter{}
	s.taskReporter = taskReports

	faulty := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	working := types.InterceptTask{
		XID:      testXIDSecondary,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{faulty, working},
		[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

	// Which trigger XID serves which warrant is the registry's knowledge, and is exactly what
	// this test is about — so it is read from the registry rather than assumed from order.
	triggerFor := map[types.XID]types.XID{}
	var held []string
	for _, installed := range s.triggers.installed {
		triggerFor[installed.warrant] = installed.xid
		held = append(held, string(installed.xid))
	}
	if len(triggerFor) != 2 {
		t.Fatalf("expected a trigger per warrant, got %d: %v", len(triggerFor), triggerFor)
	}

	poi.mu.Lock()
	poi.holds = held
	poi.unhealthy = map[string]string{string(triggerFor[faulty.XID]): testUnhealthyReason}
	poi.mu.Unlock()

	s.reconcileOne()

	if n := poi.countMessages("DeactivateTaskRequest"); n != 0 {
		t.Errorf("sent %d deactivations; both warrants are live and a fault is reported, not acted "+
			"on by tearing an interception down", n)
	}

	// The faults held per warrant are what the task-fault watcher reports.
	var named []string
	for _, w := range []types.XID{faulty.XID, working.XID, triggerFor[faulty.XID], triggerFor[working.XID]} {
		if len(s.taskFaults(w)) != 0 {
			named = append(named, string(w))
		}
	}
	if len(named) != 1 || named[0] != string(faulty.XID) {
		t.Errorf("reports named %v; want exactly the faulty warrant %q. The working warrant is %q "+
			"and the trigger XIDs are %v — naming the working warrant would have somebody act on "+
			"an interception that is running, and naming a trigger XID names something the LIPF "+
			"never issued", named, faulty.XID, working.XID, held)
	}
}

// TestATriggerThatStopsRunningAfterStartupIsReported drives the path that matters.
//
// A POI's account of the tasks it holds is the only way this element learns that a trigger it
// installed has stopped running. Read only once per POI per process, during start-up
// reconciliation, it would be read *before this process has installed anything*, and every
// trigger installed afterwards would be outside the only window in which its health could be
// observed: the one condition `triggerFaulty` exists for would be the one it could not see.
//
// A test that installed the trigger and *then* ran reconciliation would pass either way, and
// production cannot do that. This one keeps the order production has — reconcile first, install
// after — and asks on the keepalive round, which is where the question gets asked.
func TestATriggerThatStopsRunningAfterStartupIsReported(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	taskReports := &recordingTaskReporter{}
	s.taskReporter = taskReports

	// Start-up reconciliation, in the state production is actually in: this process has
	// installed nothing, so the POI's account names nothing this element is answerable for.
	s.reconcileOne()

	// Only now does a session establish and a trigger get installed.
	warrant := types.InterceptTask{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

	var mine []string
	for _, installed := range s.triggers.installed {
		mine = append(mine, string(installed.xid))
	}

	if len(mine) == 0 {
		t.Fatal("no trigger was installed, so this test would prove nothing")
	}

	// Later, the POI reports it as not running — a failed provisioning, an unresolved fault, a
	// datapath that refused the duplication rule.
	poi.mu.Lock()
	poi.holds = mine
	poi.unhealthy = map[string]string{mine[0]: testUnhealthyReason}
	poi.mu.Unlock()

	// The keepalive round is what asks. It already contacts every endpoint this element owes a
	// signal to, and it owes one exactly when it holds tasking there.
	s.triggers.keepaliveRound()

	// Recorded as state against the warrant, which is what the X1 server's task-fault watcher
	// reports from — both the fault and, once the POI reports the trigger running again, its
	// all-clear (TS 103 221-1 clause 6.5.2.1) — and what an interrogation answers.
	var found bool

	for _, f := range s.taskFaults(warrant.XID) {
		if strings.HasPrefix(f.ErrorDescription, x1.TaskIssueTriggerNotRunning+": ") {
			found = true
		}
	}

	if !found {
		t.Errorf("a trigger the POI reports as not running is not answered as a fault of its "+
			"warrant, so neither the task-fault watcher nor an interrogation can report it: %+v",
			s.taskFaults(warrant.XID))
	}

	// Not pushed as well: the watcher owns both edges, and a push of its own would be an
	// onset report nothing ever retracts.
	for _, r := range taskReports.reports {
		if r.xid == string(warrant.XID) && strings.Contains(r.details, x1.TaskIssueTriggerNotRunning) {
			t.Errorf("the keepalive round pushed the fault itself: %+v", r)
		}
	}

	// And it is reported, not acted on: the warrant is live, so tearing its interception down
	// would be the wrong remedy.
	if n := poi.countMessages("DeactivateTaskRequest"); n != 0 {
		t.Errorf("sent %d deactivations for a faulty trigger; the warrant is live", n)
	}
}

// TestAPOIWhoseClaimsWereDiscardedIsReconciledAgain covers the half of the restart handling that
// was missing, and the two halves are not separable.
//
// ForgetPOI drops this element's claims for a POI without withdrawing them. That is right when the
// POI really restarted and holds nothing, and wrong when it is merely unreachable and holds
// everything — and the liveness-timeout path cannot tell the two apart. Because markReconciled was
// monotone, the element never asked again: the discarded triggers stayed at the POI for the life
// of the process, and once new sessions installed new triggers there, keepalives resumed and
// preserved the orphans along with them.
//
// Clearing `reconciled` alone would be worse, not better. keepaliveDue answers false for an
// unreconciled endpoint, so the element would fall silent toward a POI at which it may hold *live*
// tasking, and that POI's own fail-safe would purge the live triggers with the orphans. The
// silence is only safe because reconciliation ends it.
func TestAPOIWhoseClaimsWereDiscardedIsReconciledAgain(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	s.reconcileOne()

	warrant := types.InterceptTask{
		XID:      testXIDSecondary,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

	var mine []string
	for _, installed := range s.triggers.installed {
		mine = append(mine, string(installed.xid))
	}

	if len(mine) == 0 {
		t.Fatal("no trigger was installed, so this test would prove nothing")
	}

	// The N4 path drops for long enough to time out. The POI has *not* restarted — it still
	// holds everything this element installed.
	poi.mu.Lock()
	poi.holds = mine
	poi.mu.Unlock()

	if n := s.triggers.ForgetPOI(trigNodeA); n == 0 {
		t.Fatal("ForgetPOI discarded nothing, so this test would prove nothing")
	}

	endpoint := s.triggers.endpoints[trigNodeA]
	if endpoint.isReconciled() {
		t.Error("the endpoint is still marked reconciled after its claims were discarded. This " +
			"element can no longer name what that POI holds, so it must not go on asserting " +
			"that it can")
	}

	// The keepalive round is what notices and reconciles again.
	s.triggers.keepaliveRound()

	deadline := time.Now().Add(5 * time.Second)
	for !endpoint.isReconciled() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if !endpoint.isReconciled() {
		t.Fatal("the endpoint was never reconciled again, so this element stays silent toward a " +
			"POI where it may hold live tasking — and that POI's fail-safe will purge it")
	}

	// And the tasking it could no longer name is withdrawn, through the ordinary
	// pending-removal machinery rather than abandoned. Waited for: reconciliation marks
	// the endpoint reconciled before it sends the withdrawals.
	for poi.countMessages("DeactivateTaskRequest") == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := poi.countMessages("DeactivateTaskRequest"); n == 0 {
		t.Error("the orphaned trigger was never withdrawn. It was discarded from this element's " +
			"registry without being withdrawn from the POI, so it goes on duplicating under a " +
			"warrant this element can no longer name — and once new tasking arrives at that POI, " +
			"this element's keepalives preserve it")
	}
}

// liveCCSession is a target's live session at trigNodeA, acknowledged by the incarnation of
// the node acknowledgedAt names, which is the incarnation the node is held at, with a CC
// warrant covering it activated in s's store.
func liveCCSession(t *testing.T, s *subsystem, acknowledgedAt time.Time) *smfctx.SMContext {
	t.Helper()

	sc := pooledSession(t, testSUPI, 7)
	node := smfctx.NewDataPathNode()
	node.UPF = &smfctx.UPF{NodeID: upfNode(trigNodeA)}
	node.UPF.RecoveryTimeStamp.RecoveryTimeStamp = acknowledgedAt
	node.UpLinkTunnel.PDR["default"] = &smfctx.PDR{FAR: &smfctx.FAR{
		ApplyAction: smfctx.ApplyAction{Forw: true, Dupl: true},
		State:       smfctx.RULE_CREATE,
	}}
	sc.SMLock.Lock()
	sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
		1: &smfctx.DataPath{FirstDPNode: node, IsDefaultPath: true, Activated: true},
	}}
	sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{trigNodeA: {
		NodeID:                 upfNode(trigNodeA),
		RemoteSEID:             0x2632898145f4d191,
		AcknowledgedAtRecovery: acknowledgedAt,
	}}
	sc.SMLock.Unlock()

	if !s.store.Activate(types.InterceptTask{
		XID:      testXIDSecondary,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}) {
		t.Fatal("failed to activate the warrant")
	}

	return sc
}

// waitForMessages waits until poi has received n messages of msgType.
func waitForMessages(poi *fakePOI, msgType string, n int) bool {
	deadline := time.Now().Add(5 * time.Second)
	for poi.countMessages(msgType) < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	return poi.countMessages(msgType) >= n
}

// TestALiveSessionIsRetriggeredAfterItsPOIIsReconciled follows a POI whose claims were
// discarded on a liveness timeout and which did not restart. Reconciliation withdraws the
// tasking it still holds, because this element can no longer name it; the session is live and
// its FARs still duplicate, so its trigger must be installed again, after the withdrawal.
// Nothing else does it: establishment installs a trigger for a new session, and a scan runs
// only on a warrant change.
func TestALiveSessionIsRetriggeredAfterItsPOIIsReconciled(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.reconcileOne()

	sc := liveCCSession(t, s, time.Unix(1_700_000_000, 0))
	sc.SMLock.Lock()
	s.triggerCC(sc)
	sc.SMLock.Unlock()
	if !waitForMessages(poi, "ActivateTaskRequest", 1) {
		t.Fatal("the session's trigger was never installed, so this test would prove nothing")
	}

	var mine []string
	s.triggers.mu.Lock()
	for _, installed := range s.triggers.installed {
		mine = append(mine, string(installed.xid))
	}
	s.triggers.mu.Unlock()
	poi.mu.Lock()
	poi.holds = mine
	poi.mu.Unlock()

	if n := s.triggers.ForgetPOI(trigNodeA); n == 0 {
		t.Fatal("ForgetPOI discarded nothing, so this test would prove nothing")
	}
	s.triggers.keepaliveRound()

	if !waitForMessages(poi, "DeactivateTaskRequest", 1) {
		t.Fatal("the tasking the POI still held was never withdrawn")
	}
	if !waitForMessages(poi, "ActivateTaskRequest", 2) {
		t.Fatal("the live session's trigger was not installed again after reconciliation: its " +
			"FARs duplicate and the POI holds no trigger for them, so content interception " +
			"has stopped with nothing reported")
	}

	// After the withdrawal, or the withdrawal took the new trigger with it.
	lastDeactivate, lastActivate := -1, -1
	for i, body := range poi.sent() {
		switch {
		case strings.Contains(body, `xsi:type="ns1:DeactivateTaskRequest"`):
			lastDeactivate = i
		case strings.Contains(body, `xsi:type="ns1:ActivateTaskRequest"`):
			lastActivate = i
		}
	}
	if lastActivate < lastDeactivate {
		t.Error("the trigger was installed again before reconciliation withdrew the POI's tasking")
	}
	s.triggers.mu.Lock()
	_, claimed := s.triggers.installed[triggerKey(testXIDSecondary, sc.Ref, trigNodeA)]
	s.triggers.mu.Unlock()
	if !claimed {
		t.Error("the trigger installed again is not claimed, so nothing withdraws it when the session ends")
	}
}

// TestASessionAnEarlierIncarnationAcknowledgedIsNotRetriggered is the restart side of the
// above. A session that restoration has not re-established yet still carries the SEID the
// previous incarnation assigned; a trigger planned on it matches nothing, and its claim would
// make the re-establishment skip the trigger it should install.
func TestASessionAnEarlierIncarnationAcknowledgedIsNotRetriggered(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	// The node is held at a recovery timestamp later than the one the session was acknowledged
	// at: it restarted, and has been associated again since.
	sc := liveCCSession(t, s, time.Unix(1_700_000_000, 0))
	sc.SMLock.Lock()
	sc.Tunnel.DataPathPool[1].FirstDPNode.UPF.RecoveryTimeStamp.RecoveryTimeStamp = time.Unix(1_700_000_600, 0)
	sc.SMLock.Unlock()

	s.reconcileOne()

	if n := poi.countMessages("ActivateTaskRequest"); n != 0 {
		t.Errorf("%d triggers were installed for a session the node's current incarnation does not hold", n)
	}
	s.triggers.mu.Lock()
	n := len(s.triggers.installed)
	s.triggers.mu.Unlock()
	if n != 0 {
		t.Errorf("%d claims recorded for a session the node's current incarnation does not hold", n)
	}
}

// TestReconciliationWithoutAContentWarrantDoesNotWalkTheSessions: re-triggering walks every
// live session and takes each one's lock, once per reconciliation of each POI. With no task
// asking for CC there is nothing it could install, so the walk is skipped; held here is a
// session lock it would otherwise wait on.
func TestReconciliationWithoutAContentWarrantDoesNotWalkTheSessions(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	sc := pooledSession(t, testSUPI, 7)
	if !s.store.Activate(types.InterceptTask{
		XID:      testXIDSecondary,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}) {
		t.Fatal("failed to activate the warrant")
	}

	sc.SMLock.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.reconcileOne()
	}()

	select {
	case <-done:
		sc.SMLock.Unlock()
	case <-time.After(2 * time.Second):
		sc.SMLock.Unlock()
		<-done
		t.Error("reconciliation waited on a session's lock although no task asks for content, " +
			"so it walked the session pool for triggers it could not install")
	}
}

// TestASessionWithNoAcknowledgementIsNotRetriggered: a session restored from a document stored
// without the recovery timestamp its node acknowledged it at carries a zero one, and against a
// node held at no timestamp yet, zero equals zero. Neither names an incarnation, so nothing
// shows that the SEID the session carries is one the node holds.
func TestASessionWithNoAcknowledgementIsNotRetriggered(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	liveCCSession(t, s, time.Time{})

	s.reconcileOne()

	if n := poi.countMessages("ActivateTaskRequest"); n != 0 {
		t.Errorf("%d triggers were installed for a session no incarnation of the node is known to hold", n)
	}
	s.triggers.mu.Lock()
	n := len(s.triggers.installed)
	s.triggers.mu.Unlock()
	if n != 0 {
		t.Errorf("%d claims recorded for a session no incarnation of the node is known to hold", n)
	}
}

// TestARetriggerInstallsOnlyAtTheReconciledPOI covers a session served by two UPFs, of which only
// the one being reconciled holds the session under its current incarnation. The other restarted
// and has been associated again, and the session is not re-established on it yet, so the SEID the
// session carries for it is the previous incarnation's. A trigger planned there would match
// nothing, and its claim would make the re-establishment skip the trigger it should install.
func TestARetriggerInstallsOnlyAtTheReconciledPOI(t *testing.T) {
	poiA, poiB := newFakePOI(t), newFakePOI(t)
	s := &subsystem{
		neID:  testNEID,
		store: store.New(),
		triggers: mustRegistry(Config{
			NEID: testNEID, MDF3: testMDF3Addr,
			UPFTriggers: []UPFTrigger{
				{NodeID: trigNodeA, X1URL: poiA.srv.URL, NEID: testUPFNEID1},
				{NodeID: trigNodeB, X1URL: poiB.srv.URL, NEID: testUPFNEID2},
			},
		}),
	}
	s.triggers.reportTaskHealth = s.noteTaskHealth
	s.triggers.reconcile = s.reconcileEndpoint
	waitForScans(t, s)

	acknowledgedAt := time.Unix(1_700_000_000, 0)
	sc := liveCCSession(t, s, acknowledgedAt)

	// B is the session's second UPF. It restarted since it acknowledged the session, and is
	// held at its new incarnation.
	b := smfctx.NewDataPathNode()
	b.UPF = &smfctx.UPF{NodeID: upfNode(trigNodeB)}
	b.UPF.RecoveryTimeStamp.RecoveryTimeStamp = time.Unix(1_700_000_600, 0)
	sc.SMLock.Lock()
	a := sc.Tunnel.DataPathPool[1].FirstDPNode
	a.DownLinkTunnel.SrcEndPoint, b.UpLinkTunnel.SrcEndPoint = b, a
	sc.PFCPContext[trigNodeB] = &smfctx.PFCPSessionContext{
		NodeID:                 upfNode(trigNodeB),
		RemoteSEID:             0x51f4d1912632898a,
		AcknowledgedAtRecovery: acknowledgedAt,
	}
	sc.SMLock.Unlock()

	s.reconcileEndpoint(trigNodeA, s.triggers.endpoints[trigNodeA])

	if !waitForMessages(poiA, "ActivateTaskRequest", 1) {
		t.Fatal("the reconciled POI's trigger was not installed again, so this test would prove nothing")
	}

	s.triggers.mu.Lock()
	_, claimedAtB := s.triggers.installed[triggerKey(testXIDSecondary, sc.Ref, trigNodeB)]
	s.triggers.mu.Unlock()
	if claimedAtB {
		t.Error("reconciling A claimed a trigger at B on the SEID B's previous incarnation " +
			"assigned. It matches nothing, and the claim makes B's re-establishment skip the " +
			"trigger it should install")
	}

	// installTriggers would reach B after A, on the same goroutine.
	time.Sleep(200 * time.Millisecond)
	if sent := poiB.sent(); len(sent) != 0 {
		t.Errorf("reconciling A sent %d requests to B, whose incarnation it says nothing about", len(sent))
	}
}

// TestAFaultyTriggerIsAnsweredAndNotOnlyPushed covers the other obligation.
//
// `The element reports the fault conditions that currently hold` requires a condition the element
// can re-observe to be available when the ADMF *asks*, not only pushed when it happens. A fault
// reported once and then unavailable to an interrogation is one the provisioning function cannot
// confirm still holds — and this element answered "nothing is wrong" for every task it held, which
// was true of its IRI-POI role and false of its CC triggering role.
func TestAFaultyTriggerIsAnsweredAndNotOnlyPushed(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	s.reconcileOne()

	warrant := types.InterceptTask{
		XID:      testXIDTertiary,
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)

	var mine []string
	for _, installed := range s.triggers.installed {
		mine = append(mine, string(installed.xid))
	}

	if len(mine) == 0 {
		t.Fatal("no trigger was installed, so this test would prove nothing")
	}

	if got := s.taskFaults(warrant.XID); len(got) != 0 {
		t.Errorf("a healthy warrant answered with faults: %+v", got)
	}

	// The POI reports the trigger as not running.
	poi.mu.Lock()
	poi.holds = mine
	poi.unhealthy = map[string]string{mine[0]: testUnhealthyReason}
	poi.mu.Unlock()

	s.triggers.keepaliveRound()

	got := s.taskFaults(warrant.XID)
	if len(got) == 0 {
		t.Fatal("an interrogation about a warrant whose content trigger a POI reports as not " +
			"running answered that nothing is wrong. The condition was pushed and then became " +
			"unanswerable, so the ADMF cannot confirm it still holds")
	}

	// It clears when the POI says the trigger is running again — a state, not a history.
	poi.mu.Lock()
	poi.unhealthy = nil
	poi.mu.Unlock()

	s.triggers.keepaliveRound()

	if got := s.taskFaults(warrant.XID); len(got) != 0 {
		t.Errorf("the fault survived the condition clearing: %+v — a status answer that "+
			"accumulates makes an element permanently faulty, which is ignored as fast as one "+
			"that is never faulty", got)
	}

	// And a withdrawn warrant answers nothing, rather than leaving an entry nothing removes.
	poi.mu.Lock()
	poi.unhealthy = map[string]string{mine[0]: testUnhealthyReason}
	poi.mu.Unlock()

	s.triggers.keepaliveRound()
	s.triggers.takeForWarrant(warrant.XID)

	if got := s.taskFaults(warrant.XID); len(got) != 0 {
		t.Errorf("a withdrawn warrant still answers with a fault: %+v", got)
	}
}

// TestAnUnansweredActivationIsReplayedUnchanged: an activation that went unanswered may
// have been applied, so it is resent exactly as it was. A POI holding the identical task
// acknowledges the replay (TS 103 221-1 table 6.2.1.1-2 makes only a *different* task under
// a held XID an error); a resend carrying re-provisioned destinations would be that
// different task, refused with 2010 while the POI went on holding the first.
func TestAnUnansweredActivationIsReplayedUnchanged(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}
	s.triggers.sleep = func(time.Duration) { poi.setMisname("", "") }

	poi.setMisname("some-other-upf", "ns1:ActivateTaskRequest")

	s.installFor("session-ref-1", []types.InterceptTask{{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	dids := poi.elements("ActivateTaskRequest", "dId")
	if n := poi.countMessages("ActivateTaskRequest"); n != 2 {
		t.Fatalf("sent %d activations, want the original and one replay", n)
	}
	if len(dids) != 2 || dids[0] != dids[1] {
		t.Errorf("the replay named destinations %v, want the original's unchanged", dids)
	}
	if n := poi.countMessages("CreateDestinationRequest"); n != 1 {
		t.Errorf("re-provisioned destinations %d times, want once: an unanswered activation is "+
			"replayed, not rebuilt", n)
	}
	// Still unanswered, so the POI may hold it: withdrawn, not forgotten.
	awaitMessages(t, poi, "DeactivateTaskRequest", 1)
}

// TestAnActivationAnsweredXIDExistsIsWithdrawnNotReleased: 2010 says the POI holds a
// different task under this XID, which is the opposite of a refusal to hold anything.
// Releasing the claim would leave that task installed and untracked; it is withdrawn.
func TestAnActivationAnsweredXIDExistsIsWithdrawnNotReleased(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	poi.mu.Lock()
	poi.refuseOn = "ns1:ActivateTaskRequest"
	poi.refuseCode = x1ErrXIDExists
	poi.mu.Unlock()

	s.installFor("session-ref-1", []types.InterceptTask{{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	awaitMessages(t, poi, "DeactivateTaskRequest", 1)
	awaitPending(t, s.triggers, 0)
	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Errorf("sent %d activations, want one: 2010 is not a lost destination to re-provision", n)
	}
}

// twoTriggersForOneWarrant installs one warrant's triggers for two sessions at one POI and
// returns the warrant and the two trigger XIDs, read from the registry.
func twoTriggersForOneWarrant(t *testing.T, s *subsystem) (types.XID, []types.XID) {
	t.Helper()

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	s.installFor("session-1", []types.InterceptTask{warrant}, []upfSession{{node: upfNode(trigNodeA), seid: 42}}, 7)
	s.installFor("session-2", []types.InterceptTask{warrant}, []upfSession{{node: upfNode(trigNodeA), seid: 43}}, 8)

	var triggers []types.XID
	for _, installed := range s.triggers.installed {
		if installed.warrant == warrant.XID {
			triggers = append(triggers, installed.xid)
		}
	}
	if len(triggers) != 2 {
		t.Fatalf("expected two triggers for the warrant, got %v", triggers)
	}

	return warrant.XID, triggers
}

// TestAHealthySiblingDoesNotHideAStoppedTrigger: one warrant has a trigger per session, and the
// POI reports on each. Recorded against the warrant, whichever report came last decided the
// answer — a healthy sibling listed after the stopped one erased the fault, so whether it was
// ever reported depended on the POI's response order. Either order must report it.
func TestAHealthySiblingDoesNotHideAStoppedTrigger(t *testing.T) {
	for _, stoppedFirst := range []bool{true, false} {
		poi := newFakePOI(t)
		s := triggerSubsystem(t, poi)
		warrant, triggers := twoTriggersForOneWarrant(t, s)

		stopped, running := triggers[0], triggers[1]
		order := []string{string(stopped), string(running)}
		if !stoppedFirst {
			order = []string{string(running), string(stopped)}
		}

		poi.mu.Lock()
		poi.holds = order
		poi.unhealthy = map[string]string{string(stopped): testUnhealthyReason}
		poi.mu.Unlock()

		s.reconcileOne()

		if len(s.taskFaults(warrant)) != 1 {
			t.Errorf("stopped trigger listed first=%v: the warrant reports %d faults, want 1 — a "+
				"running sibling must not hide a trigger that is not", stoppedFirst, len(s.taskFaults(warrant)))
		}
	}
}

// TestATriggerFaultEndsWithItsTriggers: once every trigger of a warrant is withdrawn, nothing
// remains that is not running, so the warrant must stop reporting the fault rather than hold it
// until the warrant itself is deactivated.
func TestATriggerFaultEndsWithItsTriggers(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	warrant, triggers := twoTriggersForOneWarrant(t, s)

	poi.mu.Lock()
	poi.holds = []string{string(triggers[0]), string(triggers[1])}
	poi.unhealthy = map[string]string{string(triggers[0]): testUnhealthyReason, string(triggers[1]): testUnhealthyReason}
	poi.mu.Unlock()

	s.reconcileOne()

	if len(s.taskFaults(warrant)) != 1 {
		t.Fatalf("precondition: both triggers reported not running, want the warrant faulty")
	}

	s.triggers.takeForSession("session-1")
	s.triggers.takeForSession("session-2")

	if f := s.taskFaults(warrant); len(f) != 0 {
		t.Errorf("the warrant still reports %v after every trigger it held was withdrawn", f)
	}
}

// TestARefusedReplayAfterAnUnansweredActivationReprovisions is the restarted UPF: the first
// activation goes unanswered, the replay reaches a POI that has lost the destinations and
// refuses it. A POI holding the identical task would have acknowledged the replay, and one holding
// a different task would have answered 2010, so this refusal says the task is not held — the
// same answer the first branch re-provisions for. Withdrawing instead leaves the warrant without
// content until the session's next event.
func TestARefusedReplayAfterAnUnansweredActivationReprovisions(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	s.taskReporter = &recordingTaskReporter{}

	poi.mu.Lock()
	poi.activateScript = []string{scriptUnbindable, scriptRefuse, scriptOK}
	poi.mu.Unlock()

	s.installFor("session-ref-1", []types.InterceptTask{{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	if n := poi.countMessages("ActivateTaskRequest"); n != 3 {
		t.Fatalf("sent %d activations, want the original, the replay and one after re-provisioning", n)
	}
	if n := poi.countMessages("CreateDestinationRequest"); n != 2 {
		t.Errorf("provisioned destinations %d times, want twice: the refused replay means the POI "+
			"lost them", n)
	}
	if held, _ := s.triggers.holds(s.triggers.installed[installedKeyFor(t, s)].xid); !held {
		t.Error("the trigger is not held after the re-provisioned activation was acknowledged")
	}
	if n := poi.countMessages("DeactivateTaskRequest"); n != 0 {
		t.Errorf("sent %d withdrawals; the re-provisioned trigger is running", n)
	}
}

// installedKeyFor returns the single installed trigger key, failing the test otherwise.
func installedKeyFor(t *testing.T, s *subsystem) string {
	t.Helper()

	s.triggers.mu.Lock()
	defer s.triggers.mu.Unlock()

	if len(s.triggers.installed) != 1 {
		t.Fatalf("installed triggers: %d, want 1", len(s.triggers.installed))
	}
	for k := range s.triggers.installed {
		return k
	}

	return ""
}

func (p *fakePOI) setPendingOn(on string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pendingOn = on
}

// TestAnActivationAnsweredAcknowledgedIsNotInstalled: "Acknowledged" says the POI received
// the activation and has not completed it. The trigger is not running, so it must not be
// recorded as installed — a registry that did would answer reconciliation, withdrawals and
// relabels for a trigger the POI may never run. It is handled as an activation the POI may
// hold: replayed unchanged, then withdrawn rather than forgotten.
func TestAnActivationAnsweredAcknowledgedIsNotInstalled(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	reports := &recordingTaskReporter{}
	s.taskReporter = reports

	poi.setPendingOn("ns1:ActivateTaskRequest")

	s.installFor("session-ref-1", []types.InterceptTask{{
		XID:      testXIDPrimary,
		Products: []types.ProductType{types.ProductCC},
	}}, []upfSession{{node: upfNode(trigNodeA), seid: 0x2632898145f4d191}}, 7)

	if n := poi.countMessages("ActivateTaskRequest"); n != 2 {
		t.Errorf("sent %d activations, want the original and one replay", n)
	}
	awaitMessages(t, poi, "DeactivateTaskRequest", 1)
	awaitPending(t, s.triggers, 0)

	s.triggers.mu.Lock()
	installed := len(s.triggers.installed)
	s.triggers.mu.Unlock()
	if installed != 0 {
		t.Errorf("registry holds %d installed triggers after an activation answered only "+
			"\"Acknowledged\"; a request not completed is not a trigger running", installed)
	}
}

// TestADeactivationAnsweredAcknowledgedStaysPending: a withdrawal the POI has received and
// not completed has not landed. Clearing the pending entry on it would leave the POI holding
// a trigger this element no longer tracks and will never withdraw again.
func TestADeactivationAnsweredAcknowledgedStaysPending(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)
	pending := withdrawOne(t, s)

	poi.setPendingOn("ns1:DeactivateTaskRequest")

	s.triggers.sleep = func(time.Duration) {
		if poi.countMessages("DeactivateTaskRequest") >= 3 {
			poi.setPendingOn("")
		}
	}

	s.deactivate(pending)

	if n := poi.countMessages("DeactivateTaskRequest"); n < 4 {
		t.Errorf("DeactivateTaskRequest count = %d, want at least 4 — each \"Acknowledged\" "+
			"answer leaves the withdrawal pending, and it is resent until completed", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after the POI finally completed the withdrawal, want 0", n)
	}
}
