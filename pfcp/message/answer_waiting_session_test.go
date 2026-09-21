// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"errors"
	"testing"

	smf_context "github.com/omec-project/smf/context"
)

// waitingSession is a session in the state the create procedure holds while it waits for the
// user plane's answer.
func waitingSession(t *testing.T, state smf_context.SMContextState) *smf_context.SMContext {
	t.Helper()

	smContext := smf_context.NewSMContext("imsi-208930000000042", 7)
	// Assigned rather than ChangeState, which publishes to a metrics stream this test has none of.
	smContext.SMContextState = state

	return smContext
}

// A request that was never dispatched has no response handler to answer it, so the send path has
// to. Without this the goroutine holding the session waits on SBIPFCPCommunicationChan until the
// process ends.
func TestAnUndispatchedEstablishmentAnswersTheSessionWaitingForIt(t *testing.T) {
	smContext := waitingSession(t, smf_context.SmStatePfcpCreatePending)

	answerTheWaitingSession(smContext, awaitingEstablishment, smf_context.SessionEstablishFailed)

	select {
	case verdict := <-smContext.SBIPFCPCommunicationChan:
		if verdict != smf_context.SessionEstablishFailed {
			t.Errorf("verdict = %v, want SessionEstablishFailed", verdict)
		}
	default:
		t.Error("nothing was put on the channel, so the exchange that sent the request is still waiting")
	}
}

// And only when something is waiting. Restoration reissues establishments outside the create
// procedure and never reads this channel, so a verdict written there is read by whichever
// modification or release comes next, as its own answer.
func TestNoVerdictIsLeftForASessionThatIsNotWaiting(t *testing.T) {
	smContext := waitingSession(t, smf_context.SmStateActive)

	answerTheWaitingSession(smContext, awaitingEstablishment, smf_context.SessionEstablishFailed)

	select {
	case verdict := <-smContext.SBIPFCPCommunicationChan:
		t.Errorf("%v was left on the channel of a session in %v; the next exchange on this session reads it as its own answer",
			verdict, smContext.SMContextState)
	default:
	}
}

// A session that is being purged locally is not waiting either, which is the release handler's
// second condition.
func TestALocallyPurgedReleaseIsNotAnswered(t *testing.T) {
	smContext := waitingSession(t, smf_context.SmStatePfcpRelease)
	smContext.LocalPurged = true

	answerTheWaitingSession(smContext, awaitingRelease, smf_context.SessionReleaseSuccess)

	select {
	case verdict := <-smContext.SBIPFCPCommunicationChan:
		t.Errorf("%v was left on a locally purged session's channel", verdict)
	default:
	}
}

// The channel holds one verdict. A second one must not park the goroutine that sends it: several
// user planes fail their deletions on the same session, and the release reads the channel once.
func TestASecondVerdictDoesNotWedgeTheSender(t *testing.T) {
	smContext := waitingSession(t, smf_context.SmStatePfcpRelease)

	done := make(chan struct{})

	go func() {
		defer close(done)

		answerTheWaitingSession(smContext, awaitingRelease, smf_context.SessionReleaseSuccess)
		answerTheWaitingSession(smContext, awaitingRelease, smf_context.SessionReleaseSuccess)
	}()

	<-done

	if len(smContext.SBIPFCPCommunicationChan) != 1 {
		t.Errorf("channel holds %d verdicts, want the one the release will read",
			len(smContext.SBIPFCPCommunicationChan))
	}
}

// The first thing either send does is look up the user plane's PFCP context, and a session without
// one exits there. That exit answers the session too: a deferred call does not run for a return
// that precedes it, so registering the answer below this guard left the earliest exit of all --
// and the one a caller is most likely to hit -- parking the session exactly as before.
func TestAMissingPfcpContextStillAnswersTheEstablishment(t *testing.T) {
	smContext := waitingSession(t, smf_context.SmStatePfcpCreatePending)

	if err := SendPfcpSessionEstablishmentRequest(*smf_context.NewNodeID("10.0.0.9"), smContext,
		nil, nil, nil, nil, 8805); err == nil {
		t.Fatal("a session with no PFCP context for that node reported a request as sent")
	}

	select {
	case verdict := <-smContext.SBIPFCPCommunicationChan:
		if verdict != smf_context.SessionEstablishFailed {
			t.Errorf("verdict = %v, want SessionEstablishFailed", verdict)
		}
	default:
		t.Error("nothing was put on the channel, so the create exchange waits for an answer that cannot come")
	}
}

// And the same exit on the release path.
func TestAMissingPfcpContextStillAnswersTheRelease(t *testing.T) {
	smContext := waitingSession(t, smf_context.SmStatePfcpRelease)

	if err := SendPfcpSessionDeletionRequest(*smf_context.NewNodeID("10.0.0.9"), smContext, 8805); err == nil {
		t.Fatal("a session with no PFCP context for that node reported a deletion as sent")
	}

	select {
	case verdict := <-smContext.SBIPFCPCommunicationChan:
		if verdict != smf_context.SessionReleaseSuccess {
			t.Errorf("verdict = %v, want SessionReleaseSuccess", verdict)
		}
	default:
		t.Error("nothing was put on the channel, so the release waits for an answer that cannot come")
	}
}

// The producer decides whether a failed modification leaves the session untouched by asking
// whether the request was sent, so the exits that never reach the wire have to say so. This is
// the earliest of them: a user plane the session has no PFCP context for.
func TestAModificationWithNoPfcpContextReportsThatNothingWentOut(t *testing.T) {
	smContext := smf_context.NewSMContext("imsi-208930000000043", 3)

	err := SendPfcpSessionModificationRequest(*smf_context.NewNodeID("10.0.0.9"), smContext,
		nil, nil, nil, nil, nil, nil, nil, 8805)
	if err == nil {
		t.Fatal("a modification with no PFCP context for that user plane reported success")
	}

	if !errors.Is(err, ErrRequestNotSent) {
		t.Errorf("error %q does not report that nothing went out, so the caller cannot tell whether the session is untouched", err)
	}
}
