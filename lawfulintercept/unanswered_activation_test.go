// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"testing"
	"time"

	"github.com/omec-project/util/li/types"
)

// An activation and its replay that both go unanswered may still be applied by the POI, which
// applies a request it has read whether or not the requester gave up. So the withdrawal that
// follows does not end at a 2020: the POI is asked again until it acknowledges.
func TestAWithdrawalAfterAnUnansweredActivationOutlivesA2020(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(t, poi)

	poi.mu.Lock()
	poi.activateScript = []string{scriptUnbindable, scriptUnbindable}
	poi.refuseOn, poi.refuseCode = deactivateTaskRequest, x1CodeNoSuchTask
	poi.mu.Unlock()
	// The POI applies the request it never answered, after it answered the first withdrawal.
	s.triggers.sleep = func(time.Duration) {
		poi.mu.Lock()
		poi.refuseOn = ""
		poi.mu.Unlock()
	}

	warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
	upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

	awaitMessages(t, poi, deactivateTaskRequest, 2)
	awaitPending(t, s.triggers, 0)
}

// The window is bounded: once it has passed, a 2020 says the POI does not hold the trigger.
func TestAnUnansweredActivationStaysOpenForItsWindowOnly(t *testing.T) {
	s := triggerSubsystem(t, newFakePOI(t))
	now := time.Unix(1_700_000_000, 0)
	s.triggers.now = func() time.Time { return now }

	const xid = types.XID(testXIDHeld)
	s.triggers.activationUnanswered(xid)

	now = now.Add(unansweredActivationWindow - time.Second)
	if !s.triggers.activationOpen(xid) {
		t.Error("the activation is closed inside its window")
	}
	now = now.Add(2 * time.Second)
	if s.triggers.activationOpen(xid) {
		t.Error("the activation is still open after its window")
	}
}

// Whether a trigger's activation is left open after its attempts, by the answers they got.
func TestWhichActivationOutcomesStayOpen(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []string
		open    bool
	}{
		{"both attempts unanswered", []string{scriptUnbindable, scriptUnbindable}, true},
		{"replay refused with 2010", []string{scriptUnbindable, scriptExists}, true},
		{"refused, then the re-provisioned retry unanswered", []string{scriptRefuse, scriptUnbindable}, true},
		{"replay refused, then the retry unanswered", []string{scriptUnbindable, scriptRefuse, scriptUnbindable}, true},
		{"replay refused, then the retry refused", []string{scriptUnbindable, scriptRefuse, scriptRefuse}, false},
		{"replay acknowledged", []string{scriptUnbindable, scriptOK}, false},
		{"refused, then the retry refused", []string{scriptRefuse, scriptRefuse}, false},
		{"acknowledged", []string{scriptOK}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			poi := newFakePOI(t)
			s := triggerSubsystem(t, poi)
			// The withdrawal a failed activation starts must not end it: refused with a code that
			// is not 2020, and held at its retry until the test is over. Then it is let finish
			// against this POI, before the POI goes: released with the POI still refusing, it
			// would retry without pause against a closed server, and against whichever later
			// test's fake POI reuses that port.
			held := make(chan struct{})
			t.Cleanup(func() {
				poi.mu.Lock()
				poi.refuseOn = ""
				poi.mu.Unlock()
				close(held)
				awaitPending(t, s.triggers, 0)
			})
			s.triggers.sleep = func(time.Duration) { <-held }

			poi.mu.Lock()
			poi.activateScript = tc.answers
			poi.refuseOn = deactivateTaskRequest
			poi.mu.Unlock()

			warrant := types.InterceptTask{XID: testXIDPrimary, Products: []types.ProductType{types.ProductCC}}
			upfs := []upfSession{{node: upfNode(trigNodeA), addr: trigNodeA, seid: 0x2632898145f4d191}}
			s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

			sent := poi.elements("ActivateTaskRequest", "xId")
			if len(sent) != len(tc.answers) {
				t.Fatalf("sent %d activations, want %d", len(sent), len(tc.answers))
			}
			if got := s.triggers.activationOpen(types.XID(sent[0])); got != tc.open {
				t.Errorf("the activation is open: %v, want %v", got, tc.open)
			}
		})
	}
}
