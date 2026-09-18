// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/omec-project/smf/qos"
)

func pendingUpdate() *qos.PolicyUpdate {
	return &qos.PolicyUpdate{}
}

func TestCommitSmPolicyDecisionPopsThePendingUpdate(t *testing.T) {
	sm := &SMContext{}
	sm.SmPolicyUpdates = []*qos.PolicyUpdate{pendingUpdate()}

	if err := sm.CommitSmPolicyDecision(true); err != nil {
		t.Fatalf("commit returned %v", err)
	}
	if len(sm.SmPolicyUpdates) != 0 {
		t.Errorf("pending updates = %d, want 0 after a commit", len(sm.SmPolicyUpdates))
	}
}

func TestDiscardSmPolicyDecisionPopsWithoutApplying(t *testing.T) {
	sm := &SMContext{}
	sm.SmPolicyUpdates = []*qos.PolicyUpdate{pendingUpdate()}
	before := sm.SmPolicyData

	if err := sm.CommitSmPolicyDecision(false); err != nil {
		t.Fatalf("discard returned %v", err)
	}
	if len(sm.SmPolicyUpdates) != 0 {
		t.Errorf("pending updates = %d, want 0 after a discard", len(sm.SmPolicyUpdates))
	}
	if !reflect.DeepEqual(sm.SmPolicyData, before) {
		t.Error("a discarded update must leave the session's policy data untouched")
	}
}

// A PDU SESSION MODIFICATION COMPLETE can arrive with nothing pending — the UE retransmits it,
// or the update was already discarded. Indexing the pending slice there would take the SMF down.
func TestCommitSmPolicyDecisionWithNothingPending(t *testing.T) {
	for _, status := range []bool{true, false} {
		sm := &SMContext{}
		if err := sm.CommitSmPolicyDecision(status); err != nil {
			t.Fatalf("status=%v returned %v, want no error and no panic", status, err)
		}
	}
}

func TestCommitSmPolicyDecisionTwiceIsSafe(t *testing.T) {
	sm := &SMContext{}
	sm.SmPolicyUpdates = []*qos.PolicyUpdate{pendingUpdate()}

	if err := sm.CommitSmPolicyDecision(true); err != nil {
		t.Fatalf("first commit returned %v", err)
	}
	// A retransmitted acknowledgement takes this path a second time.
	if err := sm.CommitSmPolicyDecision(true); err != nil {
		t.Fatalf("second commit returned %v, want it tolerated", err)
	}
}

// An in-flight modification must not survive being written to the database and read back.
//
// The SM context is persisted with sonic.Marshal, so a field without a json:"-" tag is stored. A
// restored session that still believed the network were modifying it would have no timer and no
// procedure, and would disregard every UE modification request for the rest of its life. T3591
// and Realign are excluded for the same reason; this pins the third.
func TestInFlightModificationStateIsNotPersisted(t *testing.T) {
	encoded, err := json.Marshal(&SMContext{NwModificationPending: true})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	for _, transient := range []string{"NwModificationPending", "Realign", "T3591"} {
		if strings.Contains(string(encoded), transient) {
			t.Errorf("%s is persisted; a restored session would carry a modification that is not running", transient)
		}
	}
}
