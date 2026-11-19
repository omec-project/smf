// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/util/li/x1"
)

// TestUnreadableKeepaliveWindowStopsInterceptionAndTellsTheADMF is why the window is read
// inside Init.
//
// Read *before* Init, there is no fault channel to report on — so the refusal would have
// to be made by returning from the network function's own start-up, and nothing could
// tell the provisioning function why. Read inside Init, the
// refusal costs interception and nothing else, and the one party who needs to know that
// this element is not intercepting is told: no interrogation reveals it, since an
// element holding no tasking answers every query successfully and looks exactly like one
// nobody has tasked.
func TestUnreadableKeepaliveWindowStopsInterceptionAndTellsTheADMF(t *testing.T) {
	cert, key, ca := liPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	err := Init(Config{
		NEID:     testNEID,
		X1Listen: testListenEphemeral,
		MDF2:     testDestinationAddr,
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: testADMFID,
		// The typo this exists for: seconds meant, no unit given.
		KeepaliveTimeout: "30",
	})
	if err == nil {
		t.Fatal("Init accepted a keepalive window it cannot read; a deployment that asked " +
			"for the fail-safe would hold tasking nothing will ever reclaim")
	}

	if sub := active.Load(); sub != nil {
		t.Error("interception was started despite the refusal")
	}

	reports := admf.received()
	if len(reports) == 0 {
		t.Fatal("nothing was reported to the ADMF; an element that is not intercepting " +
			"because it could not read its own configuration is in a state no interrogation reveals")
	}
	joined := strings.Join(reports, "\n")
	if !strings.Contains(joined, "invalidConfig") {
		t.Errorf("the report does not carry invalidConfig:\n%s", joined)
	}
	// NE-level, and naming no target or warrant — there are none, and the rule holds
	// regardless.
	if strings.Contains(joined, "30") && strings.Contains(joined, "keepaliveTimeout=") {
		t.Errorf("the report echoes the operator's value back on the LI channel:\n%s", joined)
	}
}

// TestTheKeepaliveProcedureRunsByDefault: TS 103 221-1 clause 6.6.2 enables keepalives
// "by default (with no prior agreement)", so an element configured with no keepalive
// settings runs the procedure on the clause's timers rather than holding tasking an ADMF
// that has gone away can never withdraw.
func TestTheKeepaliveProcedureRunsByDefault(t *testing.T) {
	sub := initWithKeepalive(t, Config{})

	if sub.keepalive == nil {
		t.Fatal("no keepalive procedure runs on an element whose configuration says nothing " +
			"about one; clause 6.6.2 enables it by default")
	}
	if *sub.keepalive != (x1.KeepaliveProcedure{}) {
		t.Errorf("the procedure is %+v, want the clause defaults (zero timers)", *sub.keepalive)
	}
}

// TestADisabledKeepaliveStartsNothing: an operator who agreed with the agency that there
// are no keepalives says so, and the element runs no procedure.
func TestADisabledKeepaliveStartsNothing(t *testing.T) {
	sub := initWithKeepalive(t, Config{KeepaliveDisabled: true, KeepaliveTimeout: "30s"})

	if sub.keepalive != nil {
		t.Errorf("a keepalive procedure %+v runs although the configuration disabled it", *sub.keepalive)
	}
}

// TestKeepaliveTimersAreTheOperatorsOwn: keepaliveTimeout is TIME_P2, the silence after
// which the fault is reported, and the other keys set the remaining timers.
func TestKeepaliveTimersAreTheOperatorsOwn(t *testing.T) {
	sub := initWithKeepalive(t, Config{
		KeepaliveTimeout: "30m", KeepaliveTimeP1: "2m", KeepaliveTimeP3: "4h",
		KeepaliveRetainTasking: true,
	})

	want := x1.KeepaliveProcedure{
		TimeP2: 30 * time.Minute, TimeP1: 2 * time.Minute, TimeP3: 4 * time.Hour,
		RetainTasking: true,
	}
	if sub.keepalive == nil || *sub.keepalive != want {
		t.Errorf("the procedure is %+v, want %+v", sub.keepalive, want)
	}
}

// TestAQuietADMFIsToldKeepalivesStopped: the procedure's reports travel on the fault
// channel. With the timers at their floor and no X1 request arriving, the ADMF receives the
// clause 6.6.2 fault report — which it cannot if the reporter is not wired into the server.
func TestAQuietADMFIsToldKeepalivesStopped(t *testing.T) {
	admf := newADMFStub(t)
	initWithKeepalive(t, Config{
		AdmfURL: admf.srv.URL, AdmfID: testADMFID,
		KeepaliveTimeout: "1s", KeepaliveTimeP1: "1s", KeepaliveTimeP3: "1s",
	})

	var joined string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if joined = strings.Join(admf.received(), "\n"); strings.Contains(joined, x1.NEIssueKeepalivesMissing) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(joined, x1.NEIssueKeepalivesMissing) {
		t.Errorf("no keepalive fault reached the ADMF after TIME_P2 passed in silence:\n%s", joined)
	}
}

// initWithKeepalive starts interception with cfg's keepalive and reporting settings and
// returns the subsystem it started.
func initWithKeepalive(t *testing.T, cfg Config) *subsystem {
	t.Helper()

	cert, key, ca := liPKI(t)
	t.Cleanup(func() { active.Store(nil) })

	cfg.NEID, cfg.X1Listen, cfg.MDF2 = testNEID, testListenEphemeral, testDestinationAddr
	cfg.Cert, cfg.Key, cfg.CACert = cert, key, ca
	if err := Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	sub := active.Load()
	if sub == nil {
		t.Fatal("interception did not start")
	}

	return sub
}

// TestASubFloorKeepaliveWindowStopsInterceptionRatherThanTheProcess is the second path
// on which an LI configuration mistake still cost the network function.
//
// "1ns" is a well-formed Go duration, so it passes the chart's regex — ns is a unit —
// and it is positive, so it passed this element's own test. The fail-safe window is then
// halved to produce the watchdog's tick interval, and integer division reaches zero:
// time.NewTicker panics, on a goroutine, and the SMF goes down. An element that
// terminates under an LI misconfiguration when one without interception configured does
// not is distinguishable to anybody who can see whether it is running — the class of
// leak this capability exists to prevent, arrived at from the configuration file.
//
// The policy is the one already applied to an unreadable window: interception does not
// start, the ADMF is told, and the network function serves.
func TestASubFloorKeepaliveWindowStopsInterceptionRatherThanTheProcess(t *testing.T) {
	cert, key, ca := liPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	err := Init(Config{
		NEID:     testNEID,
		X1Listen: testListenEphemeral,
		MDF2:     testDestinationAddr,
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: testADMFID,
		KeepaliveTimeout: "1ns",
	})
	if err == nil {
		t.Fatal("Init accepted a fail-safe window shorter than the watchdog can measure")
	}
	if sub := active.Load(); sub != nil {
		t.Error("interception was started despite the refusal")
	}
	if joined := strings.Join(admf.received(), "\n"); !strings.Contains(joined, "invalidConfig") {
		t.Errorf("the refusal was not reported to the ADMF:\n%s", joined)
	}
}

// TestNoX1ListenAddressStopsInterceptionAndTellsTheADMF covers the configuration mistake that
// would otherwise produce a *working* element nobody could provision.
//
// `Listen(ctx, "tcp", "")` does not fail. It binds every interface at an OS-selected ephemeral
// port, so with `x1Listen` absent — misspelled, or templated from a value that rendered
// empty — interception started, `active` was set, and the element waited for tasking on a port
// the ADMF has no way to learn. Every X1 request it should have received went to a closed port
// on the configured one instead, and from outside, an element holding no tasking is
// indistinguishable from one nobody has tasked: it answers interrogation successfully and reports
// nothing wrong. The mistake only surfaces when a warrant that was supposed to be running turns
// out never to have arrived.
//
// The policy is the one the other configuration refusals take: interception does not start, the
// ADMF is told over the channel that exists for exactly this, and the network function serves
// traffic — an element that terminates over its LI configuration is distinguishable from one that
// has none.
func TestNoX1ListenAddressStopsInterceptionAndTellsTheADMF(t *testing.T) {
	cert, key, ca := liPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	err := Init(Config{
		NEID: testNEID,
		// x1Listen absent. This is the whole fixture.
		MDF2: testDestinationAddr,
		Cert: cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: testADMFID,
	})
	if !errors.Is(err, errNoX1Listen) {
		t.Fatalf("Init returned %v, want errNoX1Listen — an empty address binds successfully on "+
			"an unpredictable port, so nothing further down will ever report it", err)
	}

	if active.Load() != nil {
		t.Error("interception was started, which is what makes an unprovisionable element look " +
			"healthy")
	}

	joined := strings.Join(admf.received(), "\n")
	if !strings.Contains(joined, "invalidConfig") {
		t.Errorf("the refusal was not reported to the ADMF, which is the one party that needs to "+
			"know this element cannot be provisioned:\n%s", joined)
	}
}
