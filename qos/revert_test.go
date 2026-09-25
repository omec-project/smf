// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

// The revert of a modification undoes each of the three things one can do: what it added is
// deleted, what it deleted is added back, and what it changed is changed back. And the committed
// record it is computed from is left as it was.
func TestRevertOfUndoesAnAbandonedModification(t *testing.T) {
	const kept, dropped, added = "kept", "dropped", "new"

	var committed SmCtxtPolicyData
	committed.Initialize()
	committed.SmCtxtPccRules.PccRules[kept] = &models.PccRule{PccRuleId: kept, RefQosData: []string{"1"}}
	committed.SmCtxtPccRules.PccRules[dropped] = &models.PccRule{PccRuleId: dropped, RefQosData: []string{"2"}}
	committed.SmCtxtQosData.QosData["1"] = &models.QosData{QosId: "1", MaxbrUl: *openapi.NewNullableString(openapi.PtrString("3 Mbps"))}
	committed.SmCtxtQosData.QosData["2"] = &models.QosData{QosId: "2"}

	abandoned := BuildSmPolicyUpdate(&committed, &models.SmPolicyDecision{
		PccRules: map[string]models.PccRule{
			kept:    {PccRuleId: kept, RefQosData: []string{"1"}},
			dropped: {},
			added:   {PccRuleId: added, RefQosData: []string{"3"}},
		},
		QosDecs: &map[string]models.QosData{
			"1": {QosId: "1", MaxbrUl: *openapi.NewNullableString(openapi.PtrString("5 Mbps"))},
			"2": {},
			"3": {QosId: "3"},
		},
	})

	revert := RevertOf(&committed, abandoned)

	if _, ok := revert.PccRuleUpdate.GetDelPccRuleUpdate()[added]; !ok {
		t.Error("the rule the modification added is not deleted")
	}
	if _, ok := revert.PccRuleUpdate.GetAddPccRuleUpdate()[dropped]; !ok {
		t.Error("the rule the modification deleted is not added back")
	}
	if q, ok := revert.QosFlowUpdate.GetModified()["1"]; !ok || q.GetMaxbrUl() != "3 Mbps" {
		t.Errorf("the changed QoS data is not changed back to 3 Mbps (%v)", q)
	}
	if _, ok := revert.QosFlowUpdate.GetDeleted()["3"]; !ok {
		t.Error("QoS data the modification added is not deleted")
	}
	if _, ok := revert.PccRuleUpdate.GetModPccRuleUpdate()[kept]; ok {
		t.Error("a rule the modification left alone reads as changed by the revert")
	}

	if len(committed.SmCtxtPccRules.PccRules) != 2 || committed.SmCtxtQosData.QosData["1"].GetMaxbrUl() != "3 Mbps" {
		t.Error("computing the revert changed the committed record")
	}
}
