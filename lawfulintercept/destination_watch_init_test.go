// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
	"github.com/omec-project/util/li/x2x3"
)

// TestTheWatcherInitStartsWatchesOnlyIRIDestinations drives the destination watcher Init
// builds, not the predicate it is meant to use: TestTheWatcherDoesNotWatchMDF2ForAContentOnlyTask
// pins x2Health, and nothing pinned that Init's watcher samples through it. An unreachable
// MDF2 is not reported while only a content-only task is held — this element delivers no xIRI
// for it — and is reported once a task that delivers xIRI to it is.
func TestTheWatcherInitStartsWatchesOnlyIRIDestinations(t *testing.T) {
	restoreInterval, restoreStop := destinationWatchInterval, destinationWatchStop
	stop := make(chan struct{})
	destinationWatchInterval, destinationWatchStop = 50*time.Millisecond, stop
	t.Cleanup(func() {
		close(stop)
		destinationWatchInterval, destinationWatchStop = restoreInterval, restoreStop
	})

	// An MDF2 that refuses every connection, so one delivery marks it unreachable at once.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mdf2 := ln.Addr().String()
	_ = ln.Close()

	cert, key, ca, _ := loopbackPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	if err := Init(Config{
		NEID:     testNEID,
		X1Listen: testListenEphemeral,
		MDF2:     mdf2,
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: testADMFID,
		KeepaliveDisabled: true,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	sub := active.Load()
	if sub == nil {
		t.Fatal("interception did not start")
	}

	if !sub.store.Activate(types.InterceptTask{
		XID:      "11111111-1111-1111-1111-111111111111",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "001010000000001"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}) {
		t.Fatal("activate the content task")
	}

	pdu := &x2x3.PDU{
		Type:          x2x3.PDUTypeX2,
		PayloadFormat: x2x3.PayloadFormat3GPP33128,
		Direction:     x2x3.DirectionNotApplicable,
		Payload:       make([]byte, 64),
	}
	//nolint:errcheck // the delivery is meant to fail; its effect is read below
	_ = sub.senderFor(mdf2).Send(pdu)

	deadline := time.Now().Add(5 * time.Second)
	for !sub.unreachableAt(mdf2) {
		if time.Now().After(deadline) {
			t.Fatal("the refused delivery did not mark the MDF2 unreachable")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Many sampling intervals, and the delivery error's nudge, with only the content task held.
	time.Sleep(500 * time.Millisecond)
	if got := strings.Join(admf.received(), "\n"); strings.Contains(got, x1.NEIssueMDFUnreachable) {
		t.Fatalf("the MDF2 was reported unreachable while only a content-only task was held:\n%s", got)
	}

	// The positive half, so the silence above is the watcher's answer and not its absence.
	if !sub.store.Activate(types.InterceptTask{
		XID:      "22222222-2222-2222-2222-222222222222",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "001010000000002"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}) {
		t.Fatal("activate the IRI task")
	}
	deadline = time.Now().Add(5 * time.Second)
	for !strings.Contains(strings.Join(admf.received(), "\n"), x1.NEIssueMDFUnreachable) {
		if time.Now().After(deadline) {
			t.Fatalf("an MDF2 an IRI task delivers to, unreachable, was never reported:\n%s",
				strings.Join(admf.received(), "\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
