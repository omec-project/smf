// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

// A modification the UE accepted is what the session now runs, and the record has to say so. The
// commit applied added and deleted entries and left modified ones as a TODO, so the record kept the
// original rates and the rule's original QoS reference.
func TestCommittingAModificationRecordsTheModifiedEntries(t *testing.T) {
	const ruleID, qosID, newQosID = "rule", "1", "2"

	var committed SmCtxtPolicyData
	committed.Initialize()
	committed.SmCtxtQosData.QosData[qosID] = &models.QosData{
		QosId: qosID, MaxbrUl: *openapi.NewNullableString(openapi.PtrString("3 Mbps")),
	}
	committed.SmCtxtPccRules.PccRules[ruleID] = &models.PccRule{PccRuleId: ruleID, RefQosData: []string{qosID}}

	decision := &models.SmPolicyDecision{
		PccRules: map[string]models.PccRule{ruleID: {PccRuleId: ruleID, RefQosData: []string{newQosID}}},
		QosDecs: &map[string]models.QosData{
			qosID:    {QosId: qosID, MaxbrUl: *openapi.NewNullableString(openapi.PtrString("5 Mbps"))},
			newQosID: {QosId: newQosID},
		},
	}
	if err := CommitSmPolicyDecision(&committed, BuildSmPolicyUpdate(&committed, decision)); err != nil {
		t.Fatal(err)
	}

	if got := committed.SmCtxtQosData.QosData[qosID].GetMaxbrUl(); got != "5 Mbps" {
		t.Errorf("committed MBR uplink = %q, want the accepted 5 Mbps", got)
	}
	if got := committed.SmCtxtPccRules.PccRules[ruleID].RefQosData; len(got) != 1 || got[0] != newQosID {
		t.Errorf("committed rule refers to %v, want the QoS data it was re-pointed at", got)
	}

	// And a second, identical decision now changes nothing.
	if again := BuildSmPolicyUpdate(&committed, decision); len(again.QosFlowUpdate.GetModified()) != 0 {
		t.Errorf("the same decision again reads as modifying %d flow(s)", len(again.QosFlowUpdate.GetModified()))
	}
}
