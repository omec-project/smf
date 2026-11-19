// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/transaction"
)

// liFailures records the failure hooks, alongside the teardown pair captureLI records.
type liFailures struct {
	*liCalls
	establishmentRejects []uint8
	modificationRejects  int
	releaseRejects       []uint8
	releaseRejectIDs     []int32
}

func captureLIFailures(t *testing.T) *liFailures {
	t.Helper()
	c := &liFailures{liCalls: captureLI(t)}
	establishment, modification, release := liReportEstablishmentReject, liReportModificationReject, liReportReleaseReject
	liReportEstablishmentReject = func(_ *smf_context.SMContext, cause uint8) {
		c.establishmentRejects = append(c.establishmentRejects, cause)
	}
	liReportModificationReject = func(*smf_context.SMContext, uint8) { c.modificationRejects++ }
	liReportReleaseReject = func(_ *smf_context.SMContext, pduSessionID int32, cause uint8) {
		c.releaseRejects = append(c.releaseRejects, cause)
		c.releaseRejectIDs = append(c.releaseRejectIDs, pduSessionID)
	}
	t.Cleanup(func() {
		liReportEstablishmentReject, liReportModificationReject, liReportReleaseReject = establishment, modification, release
	})

	return c
}

// A create that failed before its establishment was reported -- the UPF refused it, never answered,
// or the anchor was among those that did not accept -- is reported as a failed establishment, with
// the cause the reject to the UE carries. Its triggers are withdrawn as well: a UPF that accepted
// while another refused was triggered, and the context removed next is the last thing that could
// withdraw them.
func TestAFailedEstablishmentNeverReportedIsReportedAsFailed(t *testing.T) {
	calls := captureLIFailures(t)
	sc := teardownSession(t)
	t.Cleanup(func() { smf_context.RemoveSMContext(sc.Ref) })

	ReportEstablishmentFailure(sc)

	if len(calls.establishmentRejects) != 1 {
		t.Fatalf("failed-establishment records = %d, want 1: a tasked subject whose session failed at "+
			"the user plane otherwise leaves the agency the silence it also sees for a subject who never tried",
			len(calls.establishmentRejects))
	}
	if got := calls.establishmentRejects[0]; got != nasMessage.Cause5GSMRequestRejectedUnspecified {
		t.Errorf("record cause = %d, want %d, the cause the reject to the UE carries",
			got, nasMessage.Cause5GSMRequestRejectedUnspecified)
	}
	if calls.untasked != 1 {
		t.Errorf("triggers withdrawn %d times, want 1", calls.untasked)
	}
	if calls.released != 0 {
		t.Errorf("release reported %d times for a session whose establishment was never reported", calls.released)
	}
}

// A create can fail after its establishment was reported: the record goes out when the anchor UPF
// accepts, and another UPF's refusal fails the whole create afterwards. The agency then holds an
// establishment record, so the session is reported released -- what happened to it -- rather than
// as a failed establishment beside the one it already holds. And the trigger installed at the
// anchor is withdrawn.
func TestAFailedEstablishmentAlreadyReportedIsReportedReleased(t *testing.T) {
	calls := captureLIFailures(t)
	sc := teardownSession(t)
	t.Cleanup(func() { smf_context.RemoveSMContext(sc.Ref) })
	sc.LiEstablishmentReported = true

	ReportEstablishmentFailure(sc)

	if calls.released != 1 || calls.untasked != 1 {
		t.Errorf("release reported %d times and triggers withdrawn %d, want 1 and 1: the agency holds "+
			"an establishment record and the anchor holds a trigger for a session that no longer exists",
			calls.released, calls.untasked)
	}
	if len(calls.establishmentRejects) != 0 {
		t.Errorf("failed-establishment records = %d after an establishment record, want 0: the agency "+
			"would hold both", len(calls.establishmentRejects))
	}
}

// The create-failure handler calls ReportEstablishmentFailure without SMLock, and both of its
// outcomes read session state that the other session paths guard with it -- the record the
// identities and tunnels, the withdrawal the FARs. So every hook it reaches runs under the
// session's lock, on either branch, and the lock is released when it returns.
func TestReportEstablishmentFailureHoldsTheSessionLock(t *testing.T) {
	for _, reported := range []bool{false, true} {
		calls := captureLIFailures(t)
		sc := teardownSession(t)
		t.Cleanup(func() { smf_context.RemoveSMContext(sc.Ref) })
		sc.LiEstablishmentReported = reported

		unlocked := 0
		checkHeld := func() {
			if sc.SMLock.TryLock() {
				sc.SMLock.Unlock()
				unlocked++
			}
		}
		liReportEstablishmentReject = func(*smf_context.SMContext, uint8) { checkHeld() }
		liReportRelease = func(*smf_context.SMContext) { checkHeld(); calls.released++ }
		liUntriggerCC = func(*smf_context.SMContext) { checkHeld(); calls.untasked++ }

		ReportEstablishmentFailure(sc)

		if calls.untasked != 1 {
			t.Fatalf("establishment reported %v: triggers withdrawn %d times, want 1", reported, calls.untasked)
		}
		if unlocked != 0 {
			t.Errorf("establishment reported %v: %d hook calls ran without the session's SMLock", reported, unlocked)
		}
		if !sc.SMLock.TryLock() {
			t.Fatalf("establishment reported %v: SMLock still held after ReportEstablishmentFailure returned", reported)
		}
		sc.SMLock.Unlock()
	}
}

// A modification the UE's update asked for, which the user plane refused or never answered, is
// reported failed exactly once: the counterpart to the modification record emitted before the send.
func TestAFailedUeModificationIsReportedFailedOnce(t *testing.T) {
	for _, verdict := range failedModificationVerdicts {
		t.Run(verdict.String(), func(t *testing.T) {
			calls := captureLIFailures(t)
			smContext := sessionTheUserPlaneAnswers(t, verdict)

			request := models.UpdateSmContextRequest{}
			data := models.NewSmContextUpdateData()
			data.SetUpCnxState(models.UPCNXSTATE_DEACTIVATED)
			request.SetJsonData(*data)

			txn := &transaction.Transaction{Req: request, Ctxt: smContext}
			awaitHandler(t, func() {
				if err := HandlePDUSessionSMContextUpdate(txn); err != nil {
					t.Errorf("the update was not answered: %v", err)
				}
			})

			if len(smContext.SBIPFCPCommunicationChan) != 0 {
				t.Fatal("the answer was never read: the test did not reach the path it is about")
			}
			if calls.modificationRejects != 1 {
				t.Errorf("failed-modification records = %d, want 1: the agency otherwise holds a record "+
					"asserting a modification that never took effect", calls.modificationRejects)
			}
		})
	}
}

// One the user plane applied draws no failure record.
func TestAnAppliedUeModificationIsNotReportedFailed(t *testing.T) {
	calls := captureLIFailures(t)
	smContext := sessionTheUserPlaneAnswers(t, smf_context.SessionUpdateSuccess)

	request := models.UpdateSmContextRequest{}
	data := models.NewSmContextUpdateData()
	data.SetUpCnxState(models.UPCNXSTATE_DEACTIVATED)
	request.SetJsonData(*data)

	txn := &transaction.Transaction{Req: request, Ctxt: smContext}
	awaitHandler(t, func() {
		if err := HandlePDUSessionSMContextUpdate(txn); err != nil {
			t.Errorf("the update was not answered: %v", err)
		}
	})

	if calls.modificationRejects != 0 {
		t.Errorf("failed-modification records = %d for a modification the user plane applied", calls.modificationRejects)
	}
}

// A failed modification that no modification record preceded draws no failure record either. A
// policy update reports none before its send, so a failure record for it would be the counterpart
// of nothing -- the shape the hook had in the PFCP send-error handler, which every unanswered
// modification reached: this element's own interception updates and restoration's rule reissues
// among them.
func TestAFailedPolicyUpdateIsNotReportedAsAFailedModification(t *testing.T) {
	for _, verdict := range failedModificationVerdicts {
		t.Run(verdict.String(), func(t *testing.T) {
			calls := captureLIFailures(t)
			smContext := sessionTheUserPlaneAnswers(t, verdict)
			sendModificationRequest = func(smf_context.NodeID, *smf_context.SMContext, []*smf_context.PDR, []*smf_context.FAR,
				[]*smf_context.BAR, []*smf_context.QER, []*smf_context.PDR, []*smf_context.FAR, []*smf_context.QER, uint16,
			) error {
				smContext.PendingUPF["127.0.0.1"] = true
				return nil
			}

			txn := &transaction.Transaction{Req: models.SmPolicyNotification{}, Ctxt: smContext}
			awaitHandler(t, func() {
				if err := HandleSMPolicyUpdateNotify(txn); err == nil {
					t.Error("a policy update the user plane did not apply was reported as applied")
				}
			})

			if len(smContext.SBIPFCPCommunicationChan) != 0 {
				t.Fatal("the answer was never read: the test did not reach the path it is about")
			}
			if calls.modificationRejects != 0 {
				t.Errorf("failed-modification records = %d for a policy update no modification record preceded",
					calls.modificationRejects)
			}
		})
	}
}

// A release the SMF refuses because the session was never established is a refused release like
// the one naming the wrong identity, and is reported the same way, with the cause the reject carries.
func TestARefusedReleaseOfANeverEstablishedSessionIsReported(t *testing.T) {
	calls := captureLIFailures(t)
	const pduSessionID = 10

	smContext := smf_context.NewSMContext("imsi-208930100007488", pduSessionID)
	t.Cleanup(func() { smf_context.RemoveSMContext(smContext.Ref) })

	var request models.UpdateSmContextRequest
	request.SetJsonData(models.SmContextUpdateData{})
	request.SetBinaryDataN1SmMessage(n1SmMessageFile(t, encodeReleaseRequest(t, pduSessionID, requestPti)))

	txn := transaction.NewTransaction(request, nil, svcmsgtypes.UpdateSmContext)
	txn.Ctxt = smContext

	if err := HandleUpdateN1Msg(txn, models.NewUpdateSmContext200Response(), &pfcpAction{}); err != nil {
		t.Fatalf("HandleUpdateN1Msg returned %v, want the release to be refused without error", err)
	}

	if len(calls.releaseRejects) != 1 {
		t.Fatalf("failed-release records = %d, want 1", len(calls.releaseRejects))
	}
	if got := calls.releaseRejects[0]; got != nasMessage.Cause5GSMInvalidPDUSessionIdentity {
		t.Errorf("record cause = %d, want #43, the cause the reject carries", got)
	}
	if got := calls.releaseRejectIDs[0]; got != pduSessionID {
		t.Errorf("record PDU session ID = %d, want %d", got, pduSessionID)
	}
}

// A release naming a session other than the one this context holds is refused as an invalid
// identity, and the record names the session the request named: the context's own session is
// still up, and a record naming it would report a refused release of a session nobody asked to
// release.
func TestARefusedReleaseNamingAnotherSessionIsReportedForThatSession(t *testing.T) {
	calls := captureLIFailures(t)
	// Any PTI the UE may use; the reject echoes it, and the record does not carry one.
	const contextID, requestedID, pti = 10, 11, 7

	smContext := smf_context.NewSMContext("imsi-208930100007489", contextID)
	t.Cleanup(func() { smf_context.RemoveSMContext(smContext.Ref) })

	var request models.UpdateSmContextRequest
	request.SetJsonData(models.SmContextUpdateData{})
	request.SetBinaryDataN1SmMessage(n1SmMessageFile(t, encodeReleaseRequest(t, requestedID, pti)))

	txn := transaction.NewTransaction(request, nil, svcmsgtypes.UpdateSmContext)
	txn.Ctxt = smContext

	if err := HandleUpdateN1Msg(txn, models.NewUpdateSmContext200Response(), &pfcpAction{}); err != nil {
		t.Fatalf("HandleUpdateN1Msg returned %v, want the release to be refused without error", err)
	}

	if len(calls.releaseRejects) != 1 {
		t.Fatalf("failed-release records = %d, want 1", len(calls.releaseRejects))
	}
	if got := calls.releaseRejects[0]; got != nasMessage.Cause5GSMInvalidPDUSessionIdentity {
		t.Errorf("record cause = %d, want #43, the cause the reject carries", got)
	}
	if got := calls.releaseRejectIDs[0]; got != requestedID {
		t.Errorf("record PDU session ID = %d, want %d, the session the refused request named, not this context's %d",
			got, requestedID, contextID)
	}
}
