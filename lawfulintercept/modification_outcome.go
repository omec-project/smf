// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"maps"
	"slices"
	"time"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/lisequence"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
	"github.com/wmnsk/go-pfcp/ie"
)

// maxModificationAttempts is how many times an LI modification is sent before the element
// stops trying and reports it.
//
// Bounded because a datapath that refuses is refusing for a reason this element cannot fix,
// and a retry loop against it is a loop with no exit — the same mistake the withdrawal path
// documents for a POI answering "XID not held". Two retries cover a lost datagram and a UPF
// that was mid-restart; past that, what an operator needs is to be told, not for this
// element to keep asking.
const maxModificationAttempts = 3

// modificationSweepInterval is how often the element looks for LI modifications no answer
// arrived for. Short enough that an interception which never started is noticed in the same
// minute, long enough that it costs nothing.
const modificationSweepInterval = 10 * time.Second

// ModificationAnswered is what this element does with the answer to a PFCP modification it
// sent for Lawful Interception.
//
// **The guard that keeps this answer out of the subscriber's procedure is right and stays;
// what it must stop doing is discarding the Cause on the way past.** The element records
// duplication as applied when it sends the modification, so a refusal it never reads leaves
// a task reported as intercepting against a datapath that declined it — and nothing
// re-sends, because the send itself cleared the RULE_UPDATE marker that selects those FARs
// and applyCC will not set it again while the SMF-side Dupl bit already matches the tasking.
//
// answered is false where no Cause could be read or none arrived. That is treated as a
// refusal rather than as an acceptance, and the direction is deliberate: over-applying
// duplication is visible to the CC-POI as content it can attribute, while under-applying it
// is silent — so the ambiguous case resolves toward retry.
//
// Called from the PFCP response handlers, and possibly with the session lock held: with the UPF
// adapter the response is dispatched on the goroutine that sent the request, and every LI
// modification is sent under sc.SMLock. So nothing here takes that lock on the caller's
// goroutine; a re-send runs on its own (see modificationNotApplied).
func ModificationAnswered(req lisequence.Request, cause uint8, answered bool) {
	sub := active.Load()
	if sub == nil {
		return
	}
	if answered && cause == ie.CauseRequestAccepted {
		sub.modificationApplied(req)

		return
	}
	sub.modificationNotApplied(req)
}

// modKey names one session's LI modification at one UPF, which is what an attempt count
// belongs to: a session may be duplicated at several UPFs, and one refusing says nothing
// about the others.
type modKey struct {
	seid   uint64
	nodeID string
}

// modificationApplied forgets the attempts made for a modification the datapath took, and any
// failure recorded for the same session and UPF: the duplication that did not apply now has.
func (s *subsystem) modificationApplied(req lisequence.Request) {
	s.modMu.Lock()
	defer s.modMu.Unlock()

	k := modKey{seid: req.SEID, nodeID: req.NodeID}
	delete(s.modAttempts, k)
	delete(s.modFailed, k)
}

// noteModificationFailed records that this element gave up on a modification, as task-fault
// state for the warrants covering the session.
func (s *subsystem) noteModificationFailed(req lisequence.Request, detail string) {
	s.modMu.Lock()
	defer s.modMu.Unlock()

	if s.modFailed == nil {
		s.modFailed = map[modKey]string{}
	}
	s.modFailed[modKey{seid: req.SEID, nodeID: req.NodeID}] = detail
}

// failedModificationsFor returns, sorted, the recorded modification failures of sessions this
// warrant currently covers. A failure whose session has gone is forgotten: nothing is left to
// duplicate or to stop duplicating.
func (s *subsystem) failedModificationsFor(warrant types.XID) []string {
	s.modMu.Lock()
	failed := maps.Clone(s.modFailed)
	s.modMu.Unlock()

	var out []string
	for k, detail := range failed {
		sc := smfctx.GetSMContextBySEID(k.seid)
		if sc == nil {
			s.modMu.Lock()
			delete(s.modFailed, k)
			s.modMu.Unlock()

			continue
		}
		for _, task := range s.matchingTasks(sc) {
			if task.XID == warrant {
				out = append(out, detail)

				break
			}
		}
	}
	slices.Sort(out)

	return out
}

// attemptsFor records another attempt at this modification and reports how many have now
// been made.
func (s *subsystem) attemptsFor(req lisequence.Request) int {
	s.modMu.Lock()
	defer s.modMu.Unlock()

	if s.modAttempts == nil {
		s.modAttempts = map[modKey]int{}
	}
	k := modKey{seid: req.SEID, nodeID: req.NodeID}
	s.modAttempts[k]++

	return s.modAttempts[k]
}

// giveUpOn stops counting attempts for a modification this element will not retry again.
func (s *subsystem) giveUpOn(req lisequence.Request) {
	s.modMu.Lock()
	defer s.modMu.Unlock()

	delete(s.modAttempts, modKey{seid: req.SEID, nodeID: req.NodeID})
}

// modificationNotApplied retries an LI modification the datapath did not apply, or reports
// it where retrying is no longer the right answer.
func (s *subsystem) modificationNotApplied(req lisequence.Request) {
	if s.attemptsFor(req) >= maxModificationAttempts {
		s.giveUpOn(req)

		// **Two channels, because they carry different things and only one of them may name
		// a warrant.** The NE-level report below carries no target and no warrant, which is
		// what that channel permits. That limit does not mean the condition cannot be
		// attributed: a task report is scoped to a warrant by construction, and this element
		// knows which warrants cover the session, because the SEID names it.
		//
		// Without that, a LIPF holding several warrants is told only that *some* content
		// interception this element triggers is not running, which is a condition nobody can
		// act on — the reason `triggerFaulty` is attributed too.
		//
		// The two directions are separate facts and are reported as such: an activation
		// that did not take is an interception that is not running, and a withdrawal that
		// did not take is content still being duplicated under authority that has gone.
		detail := "the user plane did not apply the removal of a duplication this element has " +
			"withdrawn; a session may still be duplicated under authority that has gone"
		if req.Duplicating {
			detail = "the user plane did not apply a duplication this element has acknowledged; " +
				"content interception is not running for a session it covers"
		}

		s.reporter.NotifyAsync(x1.NEIssueDuplicationRefused, detail)

		// And against each warrant the session is covered by, as state rather than as a push:
		// the task-fault watcher reports it as a non-terminating fault — the tasking is intact
		// and it is the product that has stopped — and retracts it when a later modification
		// for this session and UPF applies (TS 103 221-1 clause 6.5.2.1). A push could only
		// ever be raised, never cleared.
		s.noteModificationFailed(req, detail)

		return
	}

	// On its own goroutine, because this may run on the goroutine that sent the refused
	// modification while it still holds sc.SMLock (the adapter answers inline), and the
	// re-send needs that lock. resends lets a test wait for it.
	s.resends.Add(1)
	go func() {
		defer s.resends.Done()
		s.resend(req)
	}()
}

// resend re-marks the forwarding FARs the refused send cleared and sends the modification
// again, under the session lock.
func (s *subsystem) resend(req lisequence.Request) {
	sc := smfctx.GetSMContextBySEID(req.SEID)
	if sc == nil {
		// The session went while the answer was in flight. Nothing is left to duplicate,
		// so the refused modification has nothing to apply to.
		return
	}

	sc.SMLock.Lock()
	defer sc.SMLock.Unlock()

	if sc.Tunnel == nil {
		// The session is being released. Its duplication goes with it.
		return
	}

	// **Re-establish the marker the send cleared.** BuildPfcpSessionModificationRequest
	// sets far.State = RULE_CREATE for every FAR it encodes, so by the time this runs the
	// RULE_UPDATE that ModifySessionForLI selects on is gone — and re-deriving finds
	// nothing to do, because the SMF-side Dupl bit already equals what the tasking implies.
	// Marking them here is what makes the re-send carry anything at all.
	//
	// Only the FARs the send left in RULE_CREATE: one still marked RULE_UPDATE belongs to a
	// modification the session's own path has not sent yet, and re-sending it here would
	// take it out from under that path.
	//
	// And only at the UPF that refused. ModifySessionForLI sends to every UPF with a
	// RULE_UPDATE FAR, so re-marking the session's other UPFs would re-send to each of them
	// too, and their answers would schedule more re-sends of their own: with two UPFs
	// refusing, every refusal re-sends to both, a UPF given up on is sent to again, and its
	// next refusal starts a fresh count, so the re-sends never stop.
	marked := 0
	forEachForwardingFARAt(sc, req.NodeID, func(far *smfctx.FAR) {
		if far.State == smfctx.RULE_CREATE {
			far.State = smfctx.RULE_UPDATE
			marked++
		}
	})
	if marked == 0 {
		return
	}

	// Under the session lock, as every other caller of this sends: the modifier reads the
	// session's data-path pool and its PFCP context.
	s.modifySession(sc)
}

// watchModifications sweeps the modifications no answer arrived for, and treats each as not
// applied.
//
// Silence is not a lesser case than a refusal: a refusal says the datapath declined, while
// silence says this element does not know — and it recorded the duplication as applied
// before it sent. So the two reach the same handling.
//
// It returns when stop is closed; production passes nil, because the condition can arise for
// as long as this element can send a modification.
func (s *subsystem) watchModifications(stop <-chan struct{}) {
	ticker := time.NewTicker(modificationSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, req := range lisequence.Expired() {
				s.modificationNotApplied(req)
			}
		case <-stop:
			return
		}
	}
}
