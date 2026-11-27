// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package lisequence records the PFCP modifications this element sent for Lawful
// Interception, so their responses can be recognised, kept out of the session's own
// procedure handling, and acted on.
//
// It is its own package because both response handlers need it and they cannot both
// reach it anywhere else: pfcp/message calls pfcp/adapter, so the adapter cannot
// import pfcp/message. The guard has to be in the handler rather than at one call
// site — an LI response reaching subscriber procedure handling is the fault, whichever
// path delivered it — so the record lives where every handler can ask.
package lisequence

import (
	"sync"
	"time"
)

// Request is what an LI-initiated modification asked for, carried alongside its
// sequence number so the answer can be correlated with it.
//
// **The state has to travel, because it cannot be re-derived when the answer arrives.**
// BuildPfcpSessionModificationRequest sets `far.State = RULE_CREATE` for every FAR it
// encodes, so the `RULE_UPDATE` marker that selected these FARs is cleared by the send
// itself — and `applyCC` will not set it again, because the SMF-side `Dupl` bit already
// equals what the tasking implies. A response handler that went back to the session to
// work out what had been asked would therefore find nothing to do, and a refused
// activation would never be retried.
type Request struct {
	// SEID is the local PFCP session identifier the modification was sent for, which is
	// how the session is found again.
	SEID uint64
	// NodeID is the UPF it went to, as the session keys its PFCP context.
	NodeID string
	// Duplicating is what the datapath was asked to do with the session's forwarding
	// FARs: true to start duplicating, false to stop. Held because the two failures are
	// not the same condition — a refused activation is an interception that is not
	// running, and a refused withdrawal is one that has not stopped.
	Duplicating bool
}

// pending records the LI modifications awaiting an answer, and for a while the ones that have
// had it.
//
// Bounded on purpose. Entries are normally answered by the response they describe, but a
// response that never arrives — a lost datagram, a UPF that restarts — would otherwise
// leave one behind forever, and an unbounded map that grows with traffic while nothing
// prunes it is a fault in its own right. Expired hands the interception subsystem the
// records to sweep; Mark drops anything far past the window, at most once per pruneInterval,
// as the backstop for a deployment where nothing sweeps.
//
// **An answered entry stays as a tombstone for tombstoneAge.** A UPF can answer the same
// modification twice — once for the request and once for the SMF's retransmission of it —
// and the native UDP reader can hand the second answer to the handler before the
// transaction is gone. Without the tombstone that second answer is no longer recognised as
// LI, falls through to the session's own procedure handling, and can clear the pending UPF a
// concurrent subscriber modification is waiting on. The tombstone keeps it recognised, and
// Take reports it as not the first answer, so it is dropped.
var (
	pending = map[uint32]entry{}
	lock    sync.Mutex
	// maxAge is how long an answer may take before the modification counts as unanswered.
	// Comfortably longer than a UPF's own response time and far shorter than the interval
	// at which an operator would notice interception missing.
	maxAge = 30 * time.Second
	// now is the clock, held here so a test can move it rather than wait.
	now = time.Now
	// lastPrune is when prune last ran.
	lastPrune time.Time
)

// pruneInterval is the least time between two prunes from Mark. A prune walks the whole table,
// which holds every modification of the last tombstoneAge, and Mark runs on the send path under
// the session's lock. Expired prunes on every sweep regardless.
const pruneInterval = time.Second

// tombstoneAge is how long an answered or expired entry is kept to recognise a repeated or
// late answer: well past the SMF's retransmission schedule for one request.
func tombstoneAge() time.Duration { return 2 * maxAge }

type entry struct {
	req  Request
	sent time.Time
	// closed is when the entry was answered or expired; zero while it awaits an answer.
	closed time.Time
}

func (e entry) isTombstone() bool { return !e.closed.IsZero() }

// prune drops tombstones past tombstoneAge, and entries still awaiting an answer far past
// the window. The caller holds lock.
func prune(at time.Time) {
	lastPrune = at
	tombstoneCutoff := at.Add(-tombstoneAge())
	// The backstop: entries far past the window belong to a deployment where nothing is
	// sweeping, and they may not accumulate.
	cutoff := at.Add(-4 * maxAge)
	for seq, e := range pending {
		if e.isTombstone() {
			if e.closed.Before(tombstoneCutoff) {
				delete(pending, seq)
			}
		} else if e.sent.Before(cutoff) {
			delete(pending, seq)
		}
	}
}

// Mark records that seqNum belongs to an LI-initiated modification, and what it asked for.
func Mark(seqNum uint32, req Request) {
	lock.Lock()
	defer lock.Unlock()

	at := now()
	if at.Sub(lastPrune) >= pruneInterval {
		prune(at)
	}
	pending[seqNum] = entry{req: req, sent: at}
}

// Take reports whether seqNum was an LI-initiated modification, what it asked for, and
// whether this is the first answer to it.
//
// ok is true for any answer to an LI modification, first or not, so the caller keeps it out
// of the session's own procedure handling. first is true once: the caller acts on that
// answer and drops the rest. The record stays as a tombstone for tombstoneAge to recognise
// a repeated answer.
func Take(seqNum uint32) (req Request, ok, first bool) {
	lock.Lock()
	defer lock.Unlock()

	e, ok := pending[seqNum]
	if !ok {
		return Request{}, false, false
	}
	if e.isTombstone() {
		return e.req, true, false
	}
	e.closed = now()
	pending[seqNum] = e

	return e.req, true, true
}

// Expired returns the modifications no answer has arrived for within the window, leaving a
// tombstone for each so a late answer is still recognised as LI and dropped.
//
// An unanswered modification is not a lesser case than a refused one. A refusal says the
// datapath declined; silence says the element does not know, and the element must treat
// "do not know" as "not applied" — over-applying duplication is visible to the CC-POI as
// content it can attribute, while under-applying it is silent, which is why the ambiguous
// case resolves toward retry.
func Expired() []Request {
	lock.Lock()
	defer lock.Unlock()

	at := now()
	prune(at)
	cutoff := at.Add(-maxAge)

	var out []Request
	for seq, e := range pending {
		if !e.isTombstone() && e.sent.Before(cutoff) {
			out = append(out, e.req)
			e.closed = at
			pending[seq] = e
		}
	}

	return out
}

// Outstanding is how many LI modifications await an answer, tombstones not counted. For
// tests.
func Outstanding() int {
	lock.Lock()
	defer lock.Unlock()

	n := 0
	for _, e := range pending {
		if !e.isTombstone() {
			n++
		}
	}

	return n
}
