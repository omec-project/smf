// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lisequence

import (
	"testing"
	"time"
)

// setClock replaces the clock and the table for one test.
func setClock(t *testing.T) *time.Time {
	t.Helper()

	at := time.Unix(1_000_000, 0)
	origNow, origPending, origLastPrune := now, pending, lastPrune
	now = func() time.Time { return at }
	pending = map[uint32]entry{}
	lastPrune = time.Time{}
	t.Cleanup(func() { now, pending, lastPrune = origNow, origPending, origLastPrune })

	return &at
}

// TestATakenSequenceIsATombstoneUntilItExpires covers the life of an answered entry: the first
// answer is reported as first, a repeat as LI but not first, and the record is gone once its
// tombstone has aged out, so a reused sequence number is not mistaken for LI forever.
func TestATakenSequenceIsATombstoneUntilItExpires(t *testing.T) {
	at := setClock(t)

	req := Request{SEID: 7, NodeID: "1.1.1.1", Duplicating: true}
	Mark(1, req)

	if got, ok, first := Take(1); !ok || !first || got != req {
		t.Fatalf("first answer: Take = %+v, %v, %v; want %+v, true, true", got, ok, first, req)
	}
	if got, ok, first := Take(1); !ok || first || got != req {
		t.Fatalf("repeated answer: Take = %+v, %v, %v; want %+v, true, false", got, ok, first, req)
	}
	if n := Outstanding(); n != 0 {
		t.Errorf("Outstanding = %d after the answer, want 0: a tombstone awaits nothing", n)
	}

	// A tombstone is not an unanswered modification.
	*at = at.Add(tombstoneAge() - time.Second)
	if expired := Expired(); len(expired) != 0 {
		t.Errorf("Expired returned %+v; an answered modification is not unanswered", expired)
	}
	if _, ok, _ := Take(1); !ok {
		t.Fatal("the tombstone was dropped before tombstoneAge")
	}

	// Past its age, Mark's pruning drops it.
	*at = at.Add(2 * time.Second)
	Mark(2, req)
	if _, ok, _ := Take(1); ok {
		t.Error("the tombstone outlived tombstoneAge, so the table is not bounded")
	}
}

// TestAnExpiredSequenceRecognisesALateAnswer covers the other way an entry closes: Expired
// reports it once, and an answer arriving after that is still recognised as LI, and not
// reported as first.
func TestAnExpiredSequenceRecognisesALateAnswer(t *testing.T) {
	at := setClock(t)

	req := Request{SEID: 8, NodeID: "2.2.2.2"}
	Mark(3, req)

	*at = at.Add(maxAge + time.Second)
	if expired := Expired(); len(expired) != 1 || expired[0] != req {
		t.Fatalf("Expired = %+v, want [%+v]", expired, req)
	}
	if expired := Expired(); len(expired) != 0 {
		t.Errorf("Expired reported the same modification again: %+v", expired)
	}
	if _, ok, first := Take(3); !ok || first {
		t.Errorf("a late answer: ok=%v first=%v, want ok=true first=false", ok, first)
	}

	*at = at.Add(tombstoneAge() + time.Second)
	Expired()
	if len(pending) != 0 {
		t.Errorf("%d entries left after every tombstone aged out", len(pending))
	}
}

// TestMarkPrunesAtMostOncePerInterval: a prune walks the whole table, which holds every
// modification of the last tombstoneAge, and Mark runs on the send path under the session's
// lock. So Mark prunes at most once per pruneInterval, and still prunes once it has passed.
func TestMarkPrunesAtMostOncePerInterval(t *testing.T) {
	at := setClock(t)

	req := Request{SEID: 9, NodeID: "3.3.3.3"}
	Mark(1, req)

	// A tombstone already past its age, which any prune drops.
	const aged = 99
	pending[aged] = entry{req: req, sent: at.Add(-3 * maxAge), closed: at.Add(-tombstoneAge() - time.Second)}

	*at = at.Add(pruneInterval / 2)
	Mark(2, req)
	if _, held := pending[aged]; !held {
		t.Error("Mark pruned twice within pruneInterval, walking the whole table on the send path")
	}

	*at = at.Add(pruneInterval)
	Mark(3, req)
	if _, held := pending[aged]; held {
		t.Error("Mark did not prune once pruneInterval had passed, so nothing bounds the table " +
			"where nothing sweeps")
	}
}
