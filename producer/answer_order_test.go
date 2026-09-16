// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"os"
	"testing"
	"time"

	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapType"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
	"github.com/omec-project/smf/transaction"
)

// modifyingCommittableSmContext is the shared modification fixture with its committed policy store
// initialised, as a session that reached Active has. These cases are the ones that let the UE's
// acknowledgement commit, and committing writes into that store.
func modifyingCommittableSmContext(t *testing.T) *smf_context.SMContext {
	t.Helper()

	smContext := modifyingSmContext(t)
	smContext.SmPolicyData.Initialize()

	return smContext
}

// deliverModificationComplete hands the UE's acknowledgement to the handler the way the N1 path
// does, with SMLock held as HandlePDUSessionSMContextUpdate holds it.
func deliverModificationComplete(t *testing.T, smContext *smf_context.SMContext) {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "n1sm")
	if err != nil {
		t.Fatalf("could not create the N1 payload file: %v", err)
	}
	if _, err := file.Write(craftModificationComplete(t, 10, 0)); err != nil {
		t.Fatalf("could not write the N1 payload: %v", err)
	}

	body := models.UpdateSmContextRequest{}
	body.SetBinaryDataN1SmMessage(file)
	txn := &transaction.Transaction{Req: body, Ctxt: smContext}

	done := make(chan struct{})
	go func() {
		smContext.SMLock.Lock()
		defer smContext.SMLock.Unlock()
		if err := HandleUpdateN1Msg(txn, models.NewUpdateSmContext200Response(), &pfcpAction{}); err != nil {
			t.Errorf("handling the modification complete returned an error: %v", err)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the completion handler did not return with SMLock held: it deadlocked")
	}
}

// The UE's acknowledgement and the radio's answer are two independent answers to one command, and
// nothing orders them: the UE's can arrive first, and on a short radio link with a busy gNB it
// does.
//
// That order is the one with nothing watching it. The completion is where a partial rejection is
// acted on -- it prunes the pending update to the flows the radio built, commits that, and issues
// the correction -- so when it runs first there is no rejection to read yet, and it commits the
// modification whole. The answer that follows finds no pending update to prune and, before the
// retained copy, only left a marker for a completion that had already been.
//
// Everything downstream then disagrees: the session's record names the refused flow, the UE has
// acknowledged it, and the user plane carries rules for it. Downlink traffic classified onto it
// goes to a QoS flow with no radio bearer and is dropped.
func TestARadioRefusalAfterTheUeCompletedStillWithdrawsTheRefusedFlow(t *testing.T) {
	original := applyModification
	t.Cleanup(func() { applyModification = original })

	// The correction runs on its own goroutine, so it is captured rather than executed: without
	// this it outlives the test and reaches the real user plane.
	corrected := make(chan *qos.PolicyUpdate, 1)
	applyModification = func(_ *smf_context.SMContext, u *qos.PolicyUpdate) error {
		corrected <- u
		return nil
	}

	smContext := modifyingCommittableSmContext(t)

	// The UE answers first. The radio has said nothing, so this commits flows 1 and 2 both.
	deliverModificationComplete(t, smContext)

	if len(smContext.SmPolicyUpdates) != 0 {
		t.Fatal("the completion did not commit the modification, so this is not the order under test")
	}

	// And now the radio: flow 1 was built, flow 2 was refused.
	deliverModifyResponse(t, smContext, craftModifyResponseTransfer(t, []int64{1}, []int64{2}))

	select {
	case update := <-corrected:
		if update == nil || update.QosFlowUpdate == nil {
			t.Fatal("the correction carried no flows to withdraw")
		}
		deleted := update.QosFlowUpdate.GetDeleted()
		if _, withdrawn := deleted["2"]; !withdrawn {
			t.Errorf("withdrawn flows = %v, want the refused flow 2: the UE and the user plane keep a flow the radio never built", deleted)
		}
		if _, withdrawn := deleted["1"]; withdrawn {
			t.Error("flow 1 was established and must not be withdrawn")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no corrective modification was issued: the refused flow stays on the record, on the UE and in the user plane")
	}
}

// A radio answer refusing everything, in the same order. The abandonment path discards the pending
// update, and by this point there is none -- so without the correction a whole rejection after the
// UE's acknowledgement leaves every flow of the modification in place.
func TestARadioRefusingEverythingAfterTheUeCompletedWithdrawsEveryFlow(t *testing.T) {
	original := applyModification
	t.Cleanup(func() { applyModification = original })

	corrected := make(chan *qos.PolicyUpdate, 1)
	applyModification = func(_ *smf_context.SMContext, u *qos.PolicyUpdate) error {
		corrected <- u
		return nil
	}

	smContext := modifyingCommittableSmContext(t)
	deliverModificationComplete(t, smContext)
	deliverModifyResponse(t, smContext, craftModifyResponseTransfer(t, nil, []int64{1, 2}))

	select {
	case update := <-corrected:
		if update == nil || update.QosFlowUpdate == nil {
			t.Fatal("the correction carried no flows to withdraw")
		}
		deleted := update.QosFlowUpdate.GetDeleted()
		for _, qfi := range []string{"1", "2"} {
			if _, withdrawn := deleted[qfi]; !withdrawn {
				t.Errorf("flow %s was refused by the radio and is still in force; withdrawn = %v", qfi, deleted)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no corrective modification was issued for a modification the radio refused outright")
	}

	if smContext.RanAnswerPending {
		t.Error("the session is still waiting on a radio answer it has already had")
	}
}

// The ordinary order must keep working: when the radio answers first, the completion is what
// prunes and corrects, and no copy is retained for an answer that has already come.
func TestTheRadioAnsweringFirstLeavesNothingRetained(t *testing.T) {
	smContext := modifyingSmContext(t)

	deliverModifyResponse(t, smContext, craftModifyResponseTransfer(t, []int64{1}, []int64{2}))

	if smContext.Realign == nil {
		t.Fatal("the answer recorded no realignment, so this is not the order under test")
	}
	if smContext.CommittedBeforeRanAnswer != nil {
		t.Error("an update was retained for an answer that has already been given; the next modification's answer would correct against it")
	}
}

// craftModifyFailureTransfer builds what a gNB puts on the wire when it refuses a modification in
// its entirety, rather than reporting a fate per flow.
func craftModifyFailureTransfer(t *testing.T) []byte {
	t.Helper()

	transfer := ngapType.PDUSessionResourceModifyUnsuccessfulTransfer{}
	transfer.Cause.Present = ngapType.CausePresentRadioNetwork
	transfer.Cause.RadioNetwork = &ngapType.CauseRadioNetwork{
		Value: ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable,
	}

	encoded, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		t.Fatalf("encoding the modify failure: %v", err)
	}

	return encoded
}

// deliverModifyFailure hands the refusal to the handler the way the N2 path does, with SMLock held.
func deliverModifyFailure(t *testing.T, smContext *smf_context.SMContext) {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "n2sm")
	if err != nil {
		t.Fatalf("could not create the N2 payload file: %v", err)
	}
	if _, err := file.Write(craftModifyFailureTransfer(t)); err != nil {
		t.Fatalf("could not write the N2 payload: %v", err)
	}

	body := models.UpdateSmContextRequest{}
	body.SetBinaryDataN2SmInformation(file)

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	if err := handleModifyFailure(smContext, body); err != nil {
		t.Errorf("handleModifyFailure returned an error: %v", err)
	}
}

// The radio can refuse a modification through the failure message rather than through a response
// naming every flow, and the two arrive at different handlers. In the order where the UE has
// already completed, the abandonment that answers a refusal has nothing left to discard -- the
// pending update it would drop was popped by the commit -- so the refused modification stayed in
// force on the record, on the UE and in the user plane, exactly as it did on the response path.
func TestARadioFailureAfterTheUeCompletedWithdrawsTheModification(t *testing.T) {
	original := applyModification
	t.Cleanup(func() { applyModification = original })

	corrected := make(chan *qos.PolicyUpdate, 1)
	applyModification = func(_ *smf_context.SMContext, u *qos.PolicyUpdate) error {
		corrected <- u
		return nil
	}

	smContext := modifyingCommittableSmContext(t)
	deliverModificationComplete(t, smContext)
	deliverModifyFailure(t, smContext)

	select {
	case update := <-corrected:
		if update == nil || update.QosFlowUpdate == nil {
			t.Fatal("the correction carried no flows to withdraw")
		}
		deleted := update.QosFlowUpdate.GetDeleted()
		for _, qfi := range []string{"1", "2"} {
			if _, withdrawn := deleted[qfi]; !withdrawn {
				t.Errorf("flow %s was refused with the whole modification and is still in force; withdrawn = %v", qfi, deleted)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no corrective modification was issued for a modification the radio refused outright")
	}

	// Nothing else clears this on the correcting path -- the abandonment that used to is exactly
	// what it returns instead of -- so a stray or repeated answer would pass the gate at the top of
	// the handler and abandon a session running no modification at all.
	if smContext.RanAnswerPending {
		t.Error("the session is still waiting on a radio answer it has already had")
	}
}
