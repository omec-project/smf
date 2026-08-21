// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

func updateWithFlows(qosIDs ...string) *PolicyUpdate {
	add := map[string]*models.QosData{}
	for _, id := range qosIDs {
		add[id] = &models.QosData{QosId: id}
	}
	return &PolicyUpdate{QosFlowUpdate: &QosFlowsUpdate{add: add, mod: map[string]*models.QosData{}}}
}

func TestRemoveFlowsDropsOnlyTheRefusedOnes(t *testing.T) {
	u := updateWithFlows("1", "2", "3")

	corrective := u.RemoveFlows(RefusedFlowSet([]int64{3}))
	if corrective == nil || corrective.QosFlowUpdate.del["3"] == nil {
		t.Fatal("the refused flow must come back as a deletion the UE can be told about")
	}

	if _, still := u.QosFlowUpdate.add["3"]; still {
		t.Error("a refused flow must not be recorded as established")
	}
	for _, kept := range []string{"1", "2"} {
		if _, ok := u.QosFlowUpdate.add[kept]; !ok {
			t.Errorf("flow %s was established and must be kept", kept)
		}
	}
}

func TestRemoveFlowsDropsRulesThatReferencedThem(t *testing.T) {
	u := updateWithFlows("1", "2")
	u.PccRuleUpdate = &PccRulesUpdate{
		add: map[string]*models.PccRule{
			"keep": {PccRuleId: "keep", RefQosData: []string{"1"}},
			"drop": {PccRuleId: "drop", RefQosData: []string{"2"}},
		},
		mod: map[string]*models.PccRule{},
	}

	corrective := u.RemoveFlows(RefusedFlowSet([]int64{2}))
	if corrective == nil || corrective.PccRuleUpdate.del["drop"] == nil {
		t.Fatal("the rule referencing a refused flow must come back as a deletion")
	}

	if _, still := u.PccRuleUpdate.add["drop"]; still {
		t.Error("a rule referencing a refused flow must not be recorded as active; nothing would enforce it")
	}
	if _, ok := u.PccRuleUpdate.add["keep"]; !ok {
		t.Error("a rule referencing an established flow must be kept")
	}
}

func TestRemoveFlowsIsANoOpWithoutRefusals(t *testing.T) {
	u := updateWithFlows("1", "2")
	if corrective := u.RemoveFlows(RefusedFlowSet(nil)); corrective != nil {
		t.Error("nothing refused means nothing to correct")
	}

	if len(u.QosFlowUpdate.add) != 2 {
		t.Errorf("flows = %d, want both kept when nothing was refused", len(u.QosFlowUpdate.add))
	}
}

func TestRemoveFlowsToleratesAnEmptyUpdate(t *testing.T) {
	var u *PolicyUpdate
	if corrective := u.RemoveFlows(RefusedFlowSet([]int64{1})); corrective != nil {
		t.Error("a nil update has nothing to correct")
	}

	if corrective := (&PolicyUpdate{}).RemoveFlows(RefusedFlowSet([]int64{1})); corrective != nil {
		t.Error("an empty update has nothing to correct")
	}
}

// The realignment exists for the case a single flow cannot produce. This pins what a
// multi-flow partial rejection leaves behind on both sides: the record keeps only what the
// radio access network established, and the corrective update carries exactly what it refused.
func TestMultiFlowPartialRejectionSplitsCleanly(t *testing.T) {
	u := updateWithFlows("1", "2", "3", "4")
	u.PccRuleUpdate = &PccRulesUpdate{
		add: map[string]*models.PccRule{
			"r1": {PccRuleId: "r1", RefQosData: []string{"1"}},
			"r2": {PccRuleId: "r2", RefQosData: []string{"2"}},
			"r3": {PccRuleId: "r3", RefQosData: []string{"3"}},
			"r4": {PccRuleId: "r4", RefQosData: []string{"4"}},
		},
		mod: map[string]*models.PccRule{},
	}

	corrective := u.RemoveFlows(RefusedFlowSet([]int64{2, 4}))

	// What stays is what exists.
	for _, established := range []string{"1", "3"} {
		if _, ok := u.QosFlowUpdate.add[established]; !ok {
			t.Errorf("flow %s was established and must remain in the update that becomes the record", established)
		}
	}
	for _, refused := range []string{"2", "4"} {
		if _, still := u.QosFlowUpdate.add[refused]; still {
			t.Errorf("flow %s was refused and must not be recorded as established", refused)
		}
	}
	if len(u.PccRuleUpdate.add) != 2 {
		t.Errorf("rules kept = %d, want the two whose flows were established", len(u.PccRuleUpdate.add))
	}

	// What goes back is exactly what the UE has to be told about.
	if corrective == nil {
		t.Fatal("a partial rejection must yield a corrective update")
	}
	if len(corrective.QosFlowUpdate.del) != 2 {
		t.Errorf("flows to delete = %d, want 2", len(corrective.QosFlowUpdate.del))
	}
	for _, refused := range []string{"2", "4"} {
		if corrective.QosFlowUpdate.del[refused] == nil {
			t.Errorf("flow %s was refused and the UE must be told to drop it", refused)
		}
	}
	if len(corrective.PccRuleUpdate.del) != 2 {
		t.Errorf("rules to delete = %d, want the two whose flows were refused", len(corrective.PccRuleUpdate.del))
	}
}

// Committing a pruned update must leave the session's policy data describing the established
// flows only — that is what a later modification computes its delta against.
func TestCommittingAPrunedUpdateRecordsOnlyEstablishedFlows(t *testing.T) {
	u := updateWithFlows("1", "2", "3")
	u.RemoveFlows(RefusedFlowSet([]int64{3}))

	polData := SmCtxtPolicyData{}
	polData.Initialize()

	if err := CommitSmPolicyDecision(&polData, u); err != nil {
		t.Fatalf("commit failed: %v", err)
	}

	if _, recorded := polData.SmCtxtQosData.QosData["3"]; recorded {
		t.Error("a refused flow must not reach the record; the next modification would compute its delta against it")
	}
	for _, established := range []string{"1", "2"} {
		if _, ok := polData.SmCtxtQosData.QosData[established]; !ok {
			t.Errorf("flow %s was established and must be recorded", established)
		}
	}
}

// A QoS flow identifier outside the assignable range is dropped, not narrowed.
//
// GetQosFlowIdFromQosId returns 0 for a QoS identifier it cannot parse. If 0 were admitted here,
// an unparseable identifier on one side and a malformed report on the other would combine to
// delete a flow the radio access network never refused — and the session would then be recorded
// as missing a flow that is in fact established.
func TestRefusedFlowSetRejectsIdentifiersOutsideTheAssignableRange(t *testing.T) {
	set := RefusedFlowSet([]int64{0, 1, 63, 64, 256, -1})

	for _, valid := range []uint8{1, 63} {
		if !set[valid] {
			t.Errorf("QFI %d is assignable and must be kept", valid)
		}
	}
	if len(set) != 2 {
		t.Errorf("set has %d entries, want only the two assignable ones: %v", len(set), set)
	}
	// 256 truncates to 0 in a uint8, so this catches the narrowing as well as the reserved value.
	if set[0] {
		t.Error("QFI 0 was admitted; it is reserved, and it is also what an unparseable QoS identifier becomes")
	}
}
