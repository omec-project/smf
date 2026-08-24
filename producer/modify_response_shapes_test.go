// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapType"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
)

// craftModifyResponseTransfer builds what a gNB puts on the wire to report the fate of each flow.
func craftModifyResponseTransfer(t *testing.T, accepted, refused []int64) []byte {
	t.Helper()

	transfer := ngapType.PDUSessionResourceModifyResponseTransfer{}
	if len(accepted) > 0 {
		list := &ngapType.QosFlowAddOrModifyResponseList{}
		for _, qfi := range accepted {
			item := ngapType.QosFlowAddOrModifyResponseItem{}
			item.QosFlowIdentifier.Value = qfi
			list.List = append(list.List, item)
		}
		transfer.QosFlowAddOrModifyResponseList = list
	}
	if len(refused) > 0 {
		list := &ngapType.QosFlowListWithCause{}
		for _, qfi := range refused {
			item := ngapType.QosFlowWithCauseItem{}
			item.QosFlowIdentifier.Value = qfi
			item.Cause.Present = ngapType.CausePresentRadioNetwork
			item.Cause.RadioNetwork = &ngapType.CauseRadioNetwork{
				Value: ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable,
			}
			list.List = append(list.List, item)
		}
		transfer.QosFlowFailedToAddOrModifyList = list
	}

	encoded, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		t.Skipf("blocked on the omec-project/ngap optional-tag fix: %v", err)
	}
	return encoded
}

// modifyingSmContext is a session with a modification in flight: the policy update is pending,
// T3591 is armed, and the network's procedure is marked as running. That is the state the radio
// access network's answer actually arrives in, and testing the answer against anything else tests
// nothing.
func modifyingSmContext(t *testing.T) *smf_context.SMContext {
	t.Helper()

	smContext := activeSmContext(10)
	smContext.Supi = testSupi
	smContext.Identifier = testSupi
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.19")}
	smContext.T3591Value = 16 * time.Second
	smContext.NwModificationPending = true
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{}}
	smContext.T3591 = smf_context.NewTimer(smContext.T3591Value, 4, func(int32) {}, func() {})
	t.Cleanup(func() { smContext.StopT3591() })

	return smContext
}

// deliverModifyResponse hands the transfer to the handler the way the N2 path does, with SMLock
// held as HandlePDUSessionSMContextUpdate holds it.
func deliverModifyResponse(t *testing.T, smContext *smf_context.SMContext, transfer []byte) {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "n2sm")
	if err != nil {
		t.Fatalf("could not create the N2 payload file: %v", err)
	}
	if _, err := file.Write(transfer); err != nil {
		t.Fatalf("could not write the N2 payload: %v", err)
	}

	body := models.UpdateSmContextRequest{}
	body.SetBinaryDataN2SmInformation(file)

	done := make(chan struct{})
	go func() {
		smContext.SMLock.Lock()
		defer smContext.SMLock.Unlock()
		if err := handleModifyResponse(smContext, body); err != nil {
			t.Errorf("handleModifyResponse returned an error: %v", err)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleModifyResponse did not return with SMLock held: it deadlocked")
	}
}

// The radio access network's answer has three shapes and the network owes something different for
// each. Establishing all the flows means carry on and wait for the UE. Establishing none means the
// modification did not happen, so abandon it. Establishing some means the UE has been told about
// flows that do not exist, which has to be corrected — and that last one is the case that is easy
// to get wrong by treating it as either of the other two.
func TestModifyResponseShapesAreHandledDifferently(t *testing.T) {
	t.Run("all flows established: nothing is abandoned and the timer keeps running", func(t *testing.T) {
		smContext := modifyingSmContext(t)

		deliverModifyResponse(t, smContext, craftModifyResponseTransfer(t, []int64{1, 2}, nil))

		if smContext.T3591 == nil {
			t.Error("T3591 was stopped; the UE has not acknowledged yet, so the network is still waiting")
		}
		if !smContext.NwModificationPending {
			t.Error("the procedure was ended early; it ends when the UE answers, not when the radio does")
		}
		if smContext.Realign != nil {
			t.Error("a realignment was recorded for a modification the radio established in full")
		}
	})

	t.Run("no flow established: the modification is abandoned", func(t *testing.T) {
		smContext := modifyingSmContext(t)

		deliverModifyResponse(t, smContext, craftModifyResponseTransfer(t, nil, []int64{1, 2}))

		if smContext.T3591 != nil {
			t.Error("T3591 is still armed for a modification that will never be acknowledged")
		}
		if smContext.NwModificationPending {
			t.Error("the session still looks as though a modification were running")
		}
		if len(smContext.SmPolicyUpdates) != 0 {
			t.Error("the pending policy update was not discarded, so the record now describes flows that do not exist")
		}
	})

	t.Run("some flows established: a realignment is recorded, not an abandonment", func(t *testing.T) {
		smContext := modifyingSmContext(t)

		deliverModifyResponse(t, smContext, craftModifyResponseTransfer(t, []int64{1}, []int64{2}))

		if smContext.Realign == nil {
			t.Fatal("no realignment recorded; the UE will keep believing the refused flow exists")
		}
		if len(smContext.Realign.EstablishedQFIs) != 1 || smContext.Realign.EstablishedQFIs[0] != 1 {
			t.Errorf("established = %v, want [1]", smContext.Realign.EstablishedQFIs)
		}
		if len(smContext.Realign.RefusedQFIs) != 1 || smContext.Realign.RefusedQFIs[0] != 2 {
			t.Errorf("refused = %v, want [2]", smContext.Realign.RefusedQFIs)
		}
		// The correction runs after the UE acknowledges the first modification, per TS 23.502
		// clause 4.3.3.2, so the timer must still be running here.
		if smContext.T3591 == nil {
			t.Error("T3591 was stopped, so the acknowledgement that triggers the correction can never arrive")
		}
	})
}
