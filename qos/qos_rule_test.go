// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos_test

import (
	"bytes"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/qos"
)

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

	smPolicyDecision.PccRules = makeSamplePccRules()
	smPolicyDecision.QosDecs = makeSampleQosData()
	smPolicyDecision.SessRules = makeSampleSessionRule()

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
	pccRule := &models.PccRule{
		PccRuleId:  "1",
		Precedence: openapi.PtrInt32(1),
	}

	if rule := qos.BuildAddQoSRuleFromPccRule(pccRule, nil, qos.OperationCodeCreateNewQoSRule); rule != nil {
		t.Fatal("expected nil QoS rule when QoS data is missing")
	}
}

func TestBuildQosRules_SkipsPccRuleWithoutRefQosData(t *testing.T) {
	smPolicyDecision := models.NewSmPolicyDecision()
	smPolicyDecision.PccRules = map[string]models.PccRule{
		"missing-qos-ref": {
			PccRuleId:  "missing-qos-ref",
			Precedence: openapi.PtrInt32(1),
		},
	}
	smPolicyUpdates := qos.BuildSmPolicyUpdate(&qos.SmCtxtPolicyData{}, smPolicyDecision)

	if got := qos.BuildQosRules(smPolicyUpdates); len(got) != 0 {
		t.Fatalf("expected no QoS rules, got %+v", got)
	}
}

func makeSamplePccRules() map[string]models.PccRule {
	pccRule1 := models.PccRule{
		PccRuleId:  "1",
		Precedence: openapi.PtrInt32(200),
		RefQosData: []string{"QosData1"},
		FlowInfos:  make([]models.FlowInformation, 0),
	}

	flowInfos := []models.FlowInformation{
		{
			FlowDescription:   openapi.PtrString("permit out ip from 1.1.1.1 1000 to 2.2.2.2 2000"),
			PackFiltId:        openapi.PtrString("1"),
			PacketFilterUsage: openapi.PtrBool(true),
			FlowDirection:     models.FLOWDIRECTIONRM_BIDIRECTIONAL.Ptr(),
		},
		{
			FlowDescription:   openapi.PtrString("permit out ip from 3.3.3.3 3000 to 4.4.4.4 4000"),
			PackFiltId:        openapi.PtrString("2"),
			PacketFilterUsage: openapi.PtrBool(true),
			FlowDirection:     models.FLOWDIRECTIONRM_BIDIRECTIONAL.Ptr(),
		},
	}

	pccRule1.FlowInfos = append(pccRule1.FlowInfos, flowInfos...)

	return map[string]models.PccRule{"PccRule1": pccRule1}
}

func makeSampleQosData() *map[string]models.QosData {
	var maxbrUl openapi.NullableString
	var maxbrDl openapi.NullableString
	var gbrbrUl openapi.NullableString
	var gbrbrDl openapi.NullableString
	var prioLevel openapi.NullableInt32
	maxbrUl.Set(openapi.PtrString("101 Mbps"))
	maxbrDl.Set(openapi.PtrString("201 Mbps"))
	gbrbrUl.Set(openapi.PtrString("11 Mbps"))
	gbrbrDl.Set(openapi.PtrString("21 Mbps"))
	prioLevel.Set(openapi.PtrInt32(5))

	qosData1 := models.QosData{
		QosId:                "5",
		Var5qi:               openapi.PtrInt32(5),
		MaxbrUl:              maxbrUl,
		MaxbrDl:              maxbrDl,
		GbrUl:                gbrbrUl,
		GbrDl:                gbrbrDl,
		PriorityLevel:        prioLevel,
		DefQosFlowIndication: openapi.PtrBool(true),
	}

	/*
		qosData2 := models.QosData{
			QosId:                "QosData2",
			Var5qi:               3,
			MaxbrUl:              "301 Mbps",
			MaxbrDl:              "401 Mbps",
			GbrUl:                "31 Mbps",
			GbrDl:                "41 Mbps",
			PriorityLevel:        3,
			DefQosFlowIndication: false,
		}
	*/

	qosDataMap := map[string]models.QosData{
		"QosData1": qosData1,
		//		"QosData2": &qosData2,
	}

	return &qosDataMap
}

func makeSampleSessionRule() *map[string]models.SessionRule {
	var prioLevel openapi.NullableInt32
	var prioLevelArp openapi.NullableInt32
	prioLevel.Set(openapi.PtrInt32(8))
	prioLevelArp.Set(openapi.PtrInt32(8))

	sessRule1 := models.SessionRule{
		AuthSessAmbr: &models.Ambr{
			Uplink:   "77 Mbps",
			Downlink: "99 Mbps",
		},
		AuthDefQos: &models.AuthorizedDefaultQos{
			Var5qi: openapi.PtrInt32(9),
			Arp: &models.Arp{
				PriorityLevel: prioLevelArp,
				PreemptCap:    models.PREEMPTIONCAPABILITY_MAY_PREEMPT,
				PreemptVuln:   models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE,
			},
			PriorityLevel: prioLevel,
		},
	}

	prioLevel.Set(openapi.PtrInt32(7))
	prioLevelArp.Set(openapi.PtrInt32(7))

	sessRule2 := models.SessionRule{
		AuthSessAmbr: &models.Ambr{
			Uplink:   "55 Mbps",
			Downlink: "33 Mbps",
		},
		AuthDefQos: &models.AuthorizedDefaultQos{
			Var5qi: openapi.PtrInt32(8),
			Arp: &models.Arp{
				PriorityLevel: prioLevelArp,
				PreemptCap:    models.PREEMPTIONCAPABILITY_MAY_PREEMPT,
				PreemptVuln:   models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE,
			},
			PriorityLevel: prioLevel,
		},
	}

	sessionRuleMap := map[string]models.SessionRule{
		"SessRule1": sessRule1,
		"SessRule2": sessRule2,
	}

	return &sessionRuleMap
}
