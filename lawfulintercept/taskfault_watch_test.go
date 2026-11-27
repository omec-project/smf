// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"strings"
	"testing"
	"time"

	"github.com/omec-project/smf/pfcp/lisequence"
	"github.com/omec-project/util/li/types"
)

// TestInitStartsTheTaskFaultWatcher: the task-fault watcher is the only thing that reports a
// warrant's state faults to the ADMF and retracts them (TS 103 221-1 clause 6.5.2.1). Started
// anywhere but Init, or not at all, the faults taskFaults answers would reach nobody. Driven end
// to end: a modification the element gave up on is reported against the warrant covering the
// session. The retraction needs an answer bound to the ADMF's certificate, which this plain stub
// cannot give; util's x1 tests cover it against a bound ADMF.
func TestInitStartsTheTaskFaultWatcher(t *testing.T) {
	restoreInterval, restoreStop := taskFaultInterval, taskFaultStop
	stop := make(chan struct{})
	taskFaultInterval, taskFaultStop = 50*time.Millisecond, stop
	t.Cleanup(func() {
		close(stop)
		taskFaultInterval, taskFaultStop = restoreInterval, restoreStop
	})

	cert, key, ca := liPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	if err := Init(Config{
		NEID:     testNEID,
		X1Listen: testListenEphemeral,
		MDF2:     testDestinationAddr,
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: testADMFID,
		KeepaliveDisabled: true,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	sub := active.Load()

	sc := duplicatingSession(t)
	warrant := types.InterceptTask{
		XID:      testXIDCovering,
		Products: []types.ProductType{types.ProductCC},
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
	}
	if !sub.store.Activate(warrant) {
		t.Fatal("Activate failed")
	}

	req := lisequence.Request{SEID: sc.PFCPContext[trigNodeA].LocalSEID, NodeID: trigNodeA, Duplicating: true}
	sub.noteModificationFailed(req, "the user plane did not apply a duplication this element has acknowledged")

	awaitTaskReport(t, admf, string(warrant.XID), "NonTerminatingFault")
}

// awaitTaskReport waits for a task report of the given type naming xid to reach the ADMF.
func awaitTaskReport(t *testing.T, admf *admfStub, xid, reportType string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, body := range admf.received() {
			if strings.Contains(body, xid) && strings.Contains(body, reportType) {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("no %s report for %s reached the ADMF; received:\n%s",
		reportType, xid, strings.Join(admf.received(), "\n"))
}
