// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapType"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/qos"
	"go.uber.org/zap"
)

// modifyingContext is a session with a modification pending that adds two dedicated QoS flows,
// which is what an application function asking for audio and video produces.
func modifyingContext(t *testing.T, added map[string]*models.QosData) *SMContext {
	t.Helper()

	ctx := &SMContext{
		Supi:          "imsi-208930100007487",
		PDUSessionID:  10,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
	}
	ctx.SmPolicyData.SmCtxtSessionRules.ActiveRule = &models.SessionRule{
		SessRuleId:   "rule-1",
		AuthSessAmbr: &models.Ambr{Uplink: "50 Mbps", Downlink: "50 Mbps"},
		AuthDefQos:   &models.AuthorizedDefaultQos{Var5qi: openapi.PtrInt32(9)},
	}
	// A default flow exists, so the old behaviour had something to fall back on. If the list is
	// still built from it, the assertions below catch that rather than passing on an empty session.
	defQos := &models.QosData{QosId: "1", Var5qi: openapi.PtrInt32(9)}
	defQos.SetDefQosFlowIndication(true)
	ctx.SmPolicyData.SmCtxtQosData.QosData = map[string]*models.QosData{"1": defQos}

	// Built through the real delta function rather than a test-only constructor, so the test
	// exercises the same shape production produces.
	pcfQosData := make(map[string]models.QosData, len(added)+1)
	pcfQosData["1"] = *defQos
	for id, qd := range added {
		pcfQosData[id] = *qd
	}
	ctx.SmPolicyUpdates = []*qos.PolicyUpdate{{
		QosFlowUpdate: qos.GetQosFlowDescUpdate(pcfQosData, ctx.SmPolicyData.SmCtxtQosData.QosData),
	}}
	return ctx
}

func decodeModifyRequest(t *testing.T, encoded []byte) *ngapType.QosFlowAddOrModifyRequestList {
	t.Helper()

	transfer := ngapType.PDUSessionResourceModifyRequestTransfer{}
	if err := aper.UnmarshalWithParams(encoded, &transfer, "valueExt"); err != nil {
		t.Fatalf("the transfer this SMF produced does not decode: %v", err)
	}
	for _, ie := range transfer.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDQosFlowAddOrModifyRequestList {
			return ie.Value.QosFlowAddOrModifyRequestList
		}
	}
	return nil
}

// The radio must be asked about every flow the modification concerns.
//
// The request used to carry exactly one item, taken from the session's default flow indication.
// So a modification adding dedicated flows asked the radio about none of them: the UE was told
// about all of them over NAS while the radio was told about one, which is the divergence the
// realignment procedure exists to repair — manufactured in the request itself. Observed on a
// cluster as NAS rules for QFI 2 and QFI 3 with the gNB asked about QFI 2 alone.
func TestModifyRequestCarriesEveryFlowTheModificationConcerns(t *testing.T) {
	ctx := modifyingContext(t, map[string]*models.QosData{
		"2": {QosId: "2", Var5qi: openapi.PtrInt32(1)},
		"3": {QosId: "3", Var5qi: openapi.PtrInt32(2)},
	})

	encoded, err := BuildPDUSessionResourceModifyRequestTransfer(ctx)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	list := decodeModifyRequest(t, encoded)
	if list == nil {
		t.Fatal("no QoS flow add-or-modify list in the request")
	}
	if len(list.List) != 2 {
		t.Fatalf("flows in the request = %d, want 2: the radio must be asked about every flow the UE is told about", len(list.List))
	}

	seen := map[int64]bool{}
	for _, item := range list.List {
		seen[item.QosFlowIdentifier.Value] = true
	}
	for _, want := range []int64{2, 3} {
		if !seen[want] {
			t.Errorf("QFI %d is missing from the request; the UE will believe it exists and the radio will not have built it", want)
		}
	}
	if seen[1] {
		t.Error("the default flow was included; this modification does not concern it")
	}
}

// A modification that names no flows still has to ask about something, and the default flow is
// the right fallback — that is the one case the old single-item behaviour was correct for.
func TestModifyRequestFallsBackToTheDefaultFlowWhenNoFlowsAreNamed(t *testing.T) {
	ctx := modifyingContext(t, nil)

	encoded, err := BuildPDUSessionResourceModifyRequestTransfer(ctx)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	list := decodeModifyRequest(t, encoded)
	if list == nil || len(list.List) != 1 {
		t.Fatalf("flows in the request = %v, want exactly the default flow", list)
	}
	if got := list.List[0].QosFlowIdentifier.Value; got != 1 {
		t.Errorf("QFI = %d, want the default flow 1", got)
	}
}

// A corrective modification carries only deletions, and the radio must not be asked to modify a
// flow that was never in question.
//
// After a partial rejection the SMF withdraws the flows the radio refused. Those flows were never
// built at the radio, so the correct N2 content is nothing — the UE needs the NAS withdrawal and
// the user plane needs its rules removed, but the radio has no state to change. The no-flows
// fallback above was written for a modification that names none at all, such as a session-AMBR
// change, and a delete-only update reaches it too. Falling back there spends a radio
// reconfiguration per partial rejection to re-assert a flow nobody asked about, which on a
// constrained air interface is exactly the cost the rest of this work is careful about.
func TestCorrectiveModificationDoesNotAskTheRadioAboutTheDefaultFlow(t *testing.T) {
	ctx := modifyingContext(t, map[string]*models.QosData{
		"2": {QosId: "2", Var5qi: openapi.PtrInt32(1)},
		"3": {QosId: "3", Var5qi: openapi.PtrInt32(2)},
	})

	// The radio refused flow 3; RemoveFlows prunes the pending update to what was established and
	// returns the delete-only corrective, which is what the realignment sends.
	corrective := ctx.SmPolicyUpdates[0].RemoveFlows(qos.RefusedFlowSet([]int64{3}))
	if corrective == nil {
		t.Fatal("no corrective was produced, so the rest of this test would pass vacuously")
	}
	ctx.SmPolicyUpdates = []*qos.PolicyUpdate{corrective}

	encoded, err := BuildPDUSessionResourceModifyRequestTransfer(ctx)
	if err != nil {
		t.Fatalf("building the corrective transfer failed: %v", err)
	}

	list := decodeModifyRequest(t, encoded)
	if list == nil {
		return // nothing asked of the radio, which is the correct answer
	}
	var qfis []int64
	for _, item := range list.List {
		qfis = append(qfis, item.QosFlowIdentifier.Value)
	}
	t.Errorf("the corrective asked the radio to add or modify QoS flow(s) %v; it carries only deletions, so the radio should be asked for nothing",
		qfis)
}
