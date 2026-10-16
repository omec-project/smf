// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos_test

import (
	"bytes"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/qos"
)

const testQosData1 = "QosData1"

var flowDesc = []string{
	"permit out ip from 1.1.1.1 1000 to 2.2.2.2 2000",
	"permit out ip from 1.1.1.1/24 1000 to 2.2.2.2/24 2000",
	"permit out ip from any 1000 to 2.2.2.2/24 2000",
	"permit out ip from any 1000 to assigned 2000",
	"permit out 17 from 1.1.1.1/24 1000-1200 to 2.2.2.2/24 2000-2500",
}

func TestDecodeFlowDescToIPFilters(t *testing.T) {
	for i, flow := range flowDesc {
		ipf := qos.DecodeFlowDescToIPFilters(flow)
		t.Logf("flow: %v %v", i, ipf.String())
	}
}

func TestGetPfContent(t *testing.T) {
	pf := &qos.PacketFilter{}
	for i, flow := range flowDesc {
		pf.GetPfContent(flow)
		t.Logf("Flow: %v", i)
		for _, pfc := range pf.Content {
			t.Logf("%v", pfc.String())
		}
	}
}

func TestBuildQosRules(t *testing.T) {
	// make SM Policy Decision
	smPolicyDecision := models.NewSmPolicyDecision()

	// make Sm ctxt Policy Data
	smCtxtPolData := &qos.SmCtxtPolicyData{}

	smPolicyDecision.SetPccRules(makeSamplePccRules())
	smPolicyDecision.SetQosDecs(*makeSampleQosData())
	smPolicyDecision.SetSessRules(*makeSampleSessionRule())

	smPolicyUpdates := qos.BuildSmPolicyUpdate(smCtxtPolData, smPolicyDecision)

	qosRules := qos.BuildQosRules(smPolicyUpdates)

	t.Logf("QosRules: %v", qosRules)

	if data, err := qosRules.MarshalBinary(); err != nil {
		t.Logf("marshal Error: %v", err.Error())
	} else {
		t.Logf("encoded Bytes: %v", data)
		expectedBytes := []byte{
			0x1, 0x0, 0x37, 0x32, 0x31, 0x18, 0x10,
			0x1, 0x1, 0x1, 0x1, 0xff, 0xff, 0xff, 0xff, 0x50, 0x3, 0xe8,
			0x11, 0x2, 0x2, 0x2, 0x2, 0xff, 0xff, 0xff, 0xff, 0x40, 0x7,
			0xd0, 0x32, 0x18, 0x10, 0x3, 0x3, 0x3, 0x3, 0xff, 0xff, 0xff,
			0xff, 0x50, 0xb, 0xb8, 0x11, 0x4, 0x4, 0x4, 0x4, 0xff, 0xff,
			0xff, 0xff, 0x40, 0xf, 0xa0, 0xc8, 0x5,
		}
		if !bytes.Equal(data, expectedBytes) {
			t.Fatalf("Content mismatch. got = %v, want = %v", data, expectedBytes)
		}
	}
}

func TestBuildAddQoSRuleFromPccRuleNilQosData(t *testing.T) {
	pccRule := models.NewPccRule("1")
	pccRule.SetPrecedence(1)

	if rule := qos.BuildAddQoSRuleFromPccRule(pccRule, nil, qos.OperationCodeCreateNewQoSRule); rule != nil {
		t.Fatal("expected nil QoS rule when QoS data is missing")
	}
}

func TestBuildQosRules_SkipsPccRuleWithoutRefQosData(t *testing.T) {
	var pccRule models.PccRule
	pccRule.SetPccRuleId("missing-qos-ref")
	pccRule.SetPrecedence(1)
	smPolicyDecision := models.NewSmPolicyDecision()
	smPolicyDecision.SetPccRules(map[string]models.PccRule{"missing-qos-ref": pccRule})
	smPolicyUpdates := qos.BuildSmPolicyUpdate(&qos.SmCtxtPolicyData{}, smPolicyDecision)

	if got := qos.BuildQosRules(smPolicyUpdates); len(got) != 0 {
		t.Fatalf("expected no QoS rules, got %+v", got)
	}
}

func makeSamplePccRules() map[string]models.PccRule {
	var pccRule1 models.PccRule
	pccRule1.SetPccRuleId("1")
	pccRule1.SetPrecedence(200)
	pccRule1.SetRefQosData([]string{testQosData1})
	pccRule1.SetFlowInfos(make([]models.FlowInformation, 0))
	var flowInfo1 models.FlowInformation
	flowInfo1.SetFlowDescription("permit out ip from 1.1.1.1 1000 to 2.2.2.2 2000")
	flowInfo1.SetPackFiltId("1")
	flowInfo1.SetPacketFilterUsage(true)
	flowInfo1.SetFlowDirection(models.FLOWDIRECTIONRM_BIDIRECTIONAL)
	var flowInfo2 models.FlowInformation
	flowInfo2.SetFlowDescription("permit out ip from 3.3.3.3 3000 to 4.4.4.4 4000")
	flowInfo2.SetPackFiltId("2")
	flowInfo2.SetPacketFilterUsage(true)
	flowInfo2.SetFlowDirection(models.FLOWDIRECTIONRM_BIDIRECTIONAL)

	pccRule1.SetFlowInfos([]models.FlowInformation{flowInfo1, flowInfo2})

	return map[string]models.PccRule{"PccRule1": pccRule1}
}

func makeSampleQosData() *map[string]models.QosData {
	qosData1 := models.NewQosData("5")
	qosData1.SetVar5qi(5)
	qosData1.SetMaxbrUl("101 Mbps")
	qosData1.SetMaxbrDl("201 Mbps")
	qosData1.SetGbrUl("11 Mbps")
	qosData1.SetGbrDl("21 Mbps")
	qosData1.SetPriorityLevel(5)
	qosData1.SetDefQosFlowIndication(true)

	qosDataMap := map[string]models.QosData{
		testQosData1: *qosData1,
	}

	return &qosDataMap
}

func makeSampleSessionRule() *map[string]models.SessionRule {
	arp1 := models.NewArpWithDefaults()
	arp1.SetPriorityLevel(8)
	arp1.SetPreemptCap(models.PREEMPTIONCAPABILITY_MAY_PREEMPT)
	arp1.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE)
	authorizedDefaultQos1 := models.NewAuthorizedDefaultQos()
	authorizedDefaultQos1.SetVar5qi(9)
	authorizedDefaultQos1.SetArp(*arp1)
	authorizedDefaultQos1.SetPriorityLevel(8)
	sessRule1 := models.NewSessionRuleWithDefaults()
	sessRule1.SetAuthSessAmbr(*models.NewAmbr("77 Mbps", "99 Mbps"))
	sessRule1.SetAuthDefQos(*authorizedDefaultQos1)

	arp2 := models.NewArpWithDefaults()
	arp2.SetPriorityLevel(7)
	arp2.SetPreemptCap(models.PREEMPTIONCAPABILITY_MAY_PREEMPT)
	arp2.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE)
	authorizedDefaultQos2 := models.NewAuthorizedDefaultQos()
	authorizedDefaultQos2.SetVar5qi(8)
	authorizedDefaultQos2.SetArp(*arp2)
	authorizedDefaultQos2.SetPriorityLevel(7)
	sessRule2 := models.NewSessionRuleWithDefaults()
	sessRule2.SetAuthSessAmbr(*models.NewAmbr("55 Mbps", "33 Mbps"))
	sessRule2.SetAuthDefQos(*authorizedDefaultQos2)

	sessionRuleMap := map[string]models.SessionRule{
		"SessRule1": *sessRule1,
		"SessRule2": *sessRule2,
	}

	return &sessionRuleMap
}
