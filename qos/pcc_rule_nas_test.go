// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// The two ends have to be told the same thing. The user plane refuses a PCC rule that names no
// flows -- there is nothing to build a PDI from -- so the UE must not be given a QoS rule for it
// either: a rule that creates or replaces all packet filters without carrying one is not
// installable (TS 24.501 subclause 9.11.4.13), and announcing traffic handling that no PDR
// implements leaves the UE and the user plane disagreeing about the session.
func TestAPccRuleWithNoFlowsBuildsNoQosRuleForTheUe(t *testing.T) {
	pccRule := models.NewPccRule("app-rule")
	pccRule.SetAppId("app-1")
	pccRule.SetRefQosData([]string{"QosData1"})
	appRule := pccRule
	qosData := models.NewQosData("1")

	if rule := BuildAddQoSRuleFromPccRule(appRule, qosData, OperationCodeCreateNewQoSRule); rule != nil {
		t.Errorf("the UE was given a create rule with %d packet filters for a rule the user plane has no PDR for",
			len(rule.PacketFilterList))
	}

	if rule := BuildModifyQosRuleFromPccRule(appRule, qosData,
		OperationCodeModifyExistingQoSRuleAndReplaceAllPacketFilters); rule != nil {
		t.Errorf("the UE was told to replace its packet filters with %d of them",
			len(rule.PacketFilterList))
	}
}

// And a rule that does name a flow is still built, so the guard above refuses the shape rather
// than the operation.
func TestAPccRuleWithAFlowStillBuildsItsQosRule(t *testing.T) {
	flowInfo := models.NewFlowInformation()
	flowInfo.SetPackFiltId("1")
	flowInfo.SetFlowDescription("permit out ip from any to assigned")
	flowRule := models.NewPccRule("flow-rule")
	flowRule.SetRefQosData([]string{"QosData1"})
	flowRule.SetFlowInfos([]models.FlowInformation{*flowInfo})

	rule := BuildAddQoSRuleFromPccRule(flowRule, models.NewQosData("1"), OperationCodeCreateNewQoSRule)
	if rule == nil {
		t.Fatal("a rule naming one flow was refused; the UE is told nothing about traffic the user plane does program")
	}

	if len(rule.PacketFilterList) != 1 {
		t.Errorf("rule carries %d packet filters, want the one flow it names", len(rule.PacketFilterList))
	}
}
