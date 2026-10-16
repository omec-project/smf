// SPDX-FileCopyrightText: 2026-present Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos_test

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

const (
	testTcData1 = "TC1"
	testTcData2 = "TC2"
)

func TestSamplePolicyDecisionBuilders(t *testing.T) {
	decision := MakeSamplePolicyDecision()
	if decision == nil || len(decision.GetPccRules()) == 0 || len(decision.GetQosDecs()) == 0 {
		t.Fatalf("unexpected sample policy decision: %+v", decision)
	}
}

// MakeSamplePolicyDecision builds sample policy decision data for QoS tests.
func MakeSamplePolicyDecision() *models.SmPolicyDecision {
	decision := models.NewSmPolicyDecision()
	decision.SetPccRules(MakePccRules())
	decision.SetSessRules(MakeSessionRule())
	decision.SetQosDecs(MakeQosData())
	decision.SetTraffContDecs(MakeTrafficControlData())
	return decision
}

// MakePccRules builds sample PCC rules for QoS tests.
func MakePccRules() map[string]models.PccRule {
	var pccRuleDef models.PccRule
	pccRuleDef.SetPccRuleId("255")
	pccRuleDef.SetPrecedence(255)
	pccRuleDef.SetRefQosData([]string{testQosData1})
	pccRuleDef.SetRefTcData([]string{testTcData1})

	var flowInfoDef models.FlowInformation
	flowInfoDef.SetFlowDescription("permit out ip from any to assigned")
	flowInfoDef.SetPackFiltId("1")
	flowInfoDef.SetPacketFilterUsage(true)
	flowInfoDef.SetFlowDirection(models.FLOWDIRECTIONRM_BIDIRECTIONAL)
	pccRuleDef.SetFlowInfos([]models.FlowInformation{flowInfoDef})

	var pccRule1 models.PccRule
	pccRule1.SetPccRuleId("1")
	pccRule1.SetPrecedence(111)
	pccRule1.SetRefQosData([]string{testQosData1})
	pccRule1.SetRefTcData([]string{testTcData1})

	var flowInfo1 models.FlowInformation
	flowInfo1.SetFlowDescription("permit out ip from 1.1.1.1 1000-1200 to assigned")
	flowInfo1.SetPackFiltId("1")
	flowInfo1.SetPacketFilterUsage(true)
	flowInfo1.SetFlowDirection(models.FLOWDIRECTIONRM_BIDIRECTIONAL)
	var flowInfo2 models.FlowInformation
	flowInfo2.SetFlowDescription("permit out 17 from 3.3.3.3/24 3000 to 4.4.4.4/24 4000")
	flowInfo2.SetPackFiltId("2")
	flowInfo2.SetPacketFilterUsage(true)
	flowInfo2.SetFlowDirection(models.FLOWDIRECTIONRM_BIDIRECTIONAL)
	pccRule1.SetFlowInfos([]models.FlowInformation{flowInfo1, flowInfo2})

	var pccRule2 models.PccRule
	pccRule2.SetPccRuleId("2")
	pccRule2.SetPrecedence(222)
	pccRule2.SetRefQosData([]string{"QosData2"})
	pccRule2.SetRefTcData([]string{testTcData2})

	var flowInfo3 models.FlowInformation
	flowInfo3.SetFlowDescription("permit out ip from 5.5.5.5 1000-1200 to assigned")
	flowInfo3.SetPackFiltId("1")
	flowInfo3.SetPacketFilterUsage(true)
	flowInfo3.SetFlowDirection(models.FLOWDIRECTIONRM_BIDIRECTIONAL)
	var flowInfo4 models.FlowInformation
	flowInfo4.SetFlowDescription("permit out 17 from 3.3.3.3/24 3000 to 4.4.4.4/24 4000")
	flowInfo4.SetPackFiltId("2")
	flowInfo4.SetPacketFilterUsage(true)
	flowInfo4.SetFlowDirection(models.FLOWDIRECTIONRM_BIDIRECTIONAL)
	pccRule2.SetFlowInfos([]models.FlowInformation{flowInfo3, flowInfo4})

	return map[string]models.PccRule{
		"PccRule1":   pccRule1,
		"PccRule2":   pccRule2,
		"PccRuleDef": pccRuleDef,
	}
}

// MakeQosData builds sample QoS data for QoS tests.
func MakeQosData() map[string]models.QosData {
	arp1 := models.NewArpWithDefaults()
	arp1.SetPriorityLevel(3)
	arp1.SetPreemptCap(models.PREEMPTIONCAPABILITY_MAY_PREEMPT)
	arp1.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_PREEMPTABLE)
	qosData1 := models.NewQosData("1")
	qosData1.SetVar5qi(9)
	qosData1.SetMaxbrUl("101 Mbps")
	qosData1.SetMaxbrDl("201 Mbps")
	qosData1.SetGbrUl("11 Mbps")
	qosData1.SetGbrDl("21 Mbps")
	qosData1.SetPriorityLevel(5)
	qosData1.SetDefQosFlowIndication(true)
	qosData1.SetArp(*arp1)

	arp2 := models.NewArpWithDefaults()
	arp2.SetPriorityLevel(3)
	arp2.SetPreemptCap(models.PREEMPTIONCAPABILITY_NOT_PREEMPT)
	arp2.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE)
	qosData2 := models.NewQosData("2")
	qosData2.SetVar5qi(9)
	qosData2.SetMaxbrUl("301 Mbps")
	qosData2.SetMaxbrDl("401 Mbps")
	qosData2.SetGbrUl("31 Mbps")
	qosData2.SetGbrDl("41 Mbps")
	qosData2.SetPriorityLevel(3)
	qosData2.SetDefQosFlowIndication(false)
	qosData2.SetArp(*arp2)

	return map[string]models.QosData{
		testQosData1: *qosData1,
		"QosData2":   *qosData2,
	}
}

// MakeSessionRule builds sample session rules for QoS tests.
func MakeSessionRule() map[string]models.SessionRule {
	arp1 := models.NewArpWithDefaults()
	arp1.SetPriorityLevel(8)
	arp1.SetPreemptCap(models.PREEMPTIONCAPABILITY_MAY_PREEMPT)
	arp1.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE)
	authorizedDefaultQos1 := models.NewAuthorizedDefaultQos()
	authorizedDefaultQos1.SetVar5qi(9)
	authorizedDefaultQos1.SetArp(*arp1)
	authorizedDefaultQos1.SetPriorityLevel(8)
	sessRule1 := models.NewSessionRule("RuleId-1")
	sessRule1.SetAuthSessAmbr(*models.NewAmbr("77 Mbps", "99 Mbps"))
	sessRule1.SetAuthDefQos(*authorizedDefaultQos1)

	arp2 := models.NewArpWithDefaults()
	arp2.SetPriorityLevel(7)
	arp2.SetPreemptCap(models.PREEMPTIONCAPABILITY_MAY_PREEMPT)
	arp2.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE)
	authorizedDefaultQos2 := models.NewAuthorizedDefaultQos()
	authorizedDefaultQos2.SetVar5qi(9)
	authorizedDefaultQos2.SetArp(*arp2)
	authorizedDefaultQos2.SetPriorityLevel(7)

	sessRule2 := models.NewSessionRule("RuleId-2")
	sessRule2.SetAuthSessAmbr(*models.NewAmbr("55 Mbps", "33 Mbps"))
	sessRule2.SetAuthDefQos(*authorizedDefaultQos2)

	return map[string]models.SessionRule{
		"SessRule1": *sessRule1,
		"SessRule2": *sessRule2,
	}
}

// MakeTrafficControlData builds sample traffic control data for QoS tests.
func MakeTrafficControlData() map[string]models.TrafficControlData {
	var tc1 models.TrafficControlData
	tc1.SetTcId(testTcData1)
	tc1.SetFlowStatus(models.FLOWSTATUS_ENABLED)

	var tc2 models.TrafficControlData
	tc2.SetTcId(testTcData2)
	tc2.SetFlowStatus(models.FLOWSTATUS_ENABLED)

	return map[string]models.TrafficControlData{
		testTcData1: tc1,
		testTcData2: tc2,
	}
}
