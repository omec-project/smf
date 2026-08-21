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
