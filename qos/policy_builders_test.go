// SPDX-FileCopyrightText: 2026-present Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos_test

import (
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

func TestSamplePolicyDecisionBuilders(t *testing.T) {
	decision := MakeSamplePolicyDecision()
	if decision == nil || len(decision.PccRules) == 0 || len(decision.GetQosDecs()) == 0 {
		t.Fatalf("unexpected sample policy decision: %+v", decision)
	}
}

// MakeSamplePolicyDecision builds sample policy decision data for QoS tests.
func MakeSamplePolicyDecision() *models.SmPolicyDecision {
	decision := &models.SmPolicyDecision{
		PccRules: MakePccRules(),
	}
	decision.SetSessRules(MakeSessionRule())
	decision.SetQosDecs(MakeQosData())
	decision.SetTraffContDecs(MakeTrafficControlData())
	return decision
}

// MakePccRules builds sample PCC rules for QoS tests.
func MakePccRules() map[string]models.PccRule {
	pccRuleDef := models.PccRule{
		PccRuleId:  "255",
		Precedence: openapi.PtrInt32(255),
		RefQosData: []string{"QosData1"},
		RefTcData:  []string{"TC1"},
		FlowInfos:  make([]models.FlowInformation, 0),
	}

	flowInfosDef := []models.FlowInformation{
		{
			FlowDescription:   openapi.PtrString("permit out ip from any to assigned"),
			PackFiltId:        openapi.PtrString("1"),
			PacketFilterUsage: openapi.PtrBool(true),
			FlowDirection:     models.FLOWDIRECTIONRM_BIDIRECTIONAL.Ptr(),
		},
	}
	pccRuleDef.FlowInfos = append(pccRuleDef.FlowInfos, flowInfosDef...)

	pccRule1 := models.PccRule{
		PccRuleId:  "1",
		Precedence: openapi.PtrInt32(111),
		RefQosData: []string{"QosData1"},
		RefTcData:  []string{"TC1"},
		FlowInfos:  make([]models.FlowInformation, 0),
	}

	flowInfos := []models.FlowInformation{
		{
			FlowDescription:   openapi.PtrString("permit out ip from 1.1.1.1 1000-1200 to assigned"),
			PackFiltId:        openapi.PtrString("1"),
			PacketFilterUsage: openapi.PtrBool(true),
			FlowDirection:     models.FLOWDIRECTIONRM_BIDIRECTIONAL.Ptr(),
		},
		{
			FlowDescription:   openapi.PtrString("permit out 17 from 3.3.3.3/24 3000 to 4.4.4.4/24 4000"),
			PackFiltId:        openapi.PtrString("2"),
			PacketFilterUsage: openapi.PtrBool(true),
			FlowDirection:     models.FLOWDIRECTIONRM_BIDIRECTIONAL.Ptr(),
		},
	}
	pccRule1.FlowInfos = append(pccRule1.FlowInfos, flowInfos...)

	pccRule2 := models.PccRule{
		PccRuleId:  "2",
		Precedence: openapi.PtrInt32(222),
		RefQosData: []string{"QosData2"},
		RefTcData:  []string{"TC2"},
		FlowInfos:  make([]models.FlowInformation, 0),
	}

	flowInfos1 := []models.FlowInformation{
		{
			FlowDescription:   openapi.PtrString("permit out ip from 5.5.5.5 1000-1200 to assigned"),
			PackFiltId:        openapi.PtrString("1"),
			PacketFilterUsage: openapi.PtrBool(true),
			FlowDirection:     models.FLOWDIRECTIONRM_BIDIRECTIONAL.Ptr(),
		},
		{
			FlowDescription:   openapi.PtrString("permit out 17 from 3.3.3.3/24 3000 to 4.4.4.4/24 4000"),
			PackFiltId:        openapi.PtrString("2"),
			PacketFilterUsage: openapi.PtrBool(true),
			FlowDirection:     models.FLOWDIRECTIONRM_BIDIRECTIONAL.Ptr(),
		},
	}
	pccRule2.FlowInfos = append(pccRule2.FlowInfos, flowInfos1...)

	return map[string]models.PccRule{
		"PccRule1":   pccRule1,
		"PccRule2":   pccRule2,
		"PccRuleDef": pccRuleDef,
	}
}

// MakeQosData builds sample QoS data for QoS tests.
func MakeQosData() map[string]models.QosData {
	qosData1 := models.QosData{
		QosId:                "1",
		Var5qi:               openapi.PtrInt32(9),
		MaxbrUl:              *openapi.NewNullableString(openapi.PtrString("101 Mbps")),
		MaxbrDl:              *openapi.NewNullableString(openapi.PtrString("201 Mbps")),
		GbrUl:                *openapi.NewNullableString(openapi.PtrString("11 Mbps")),
		GbrDl:                *openapi.NewNullableString(openapi.PtrString("21 Mbps")),
		PriorityLevel:        *openapi.NewNullableInt32(openapi.PtrInt32(5)),
		DefQosFlowIndication: openapi.PtrBool(true),
		Arp: &models.Arp{
			PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(3)),
			PreemptCap:    models.PREEMPTIONCAPABILITY_MAY_PREEMPT,
			PreemptVuln:   models.PREEMPTIONVULNERABILITY_PREEMPTABLE,
		},
	}

	qosData2 := models.QosData{
		QosId:                "2",
		Var5qi:               openapi.PtrInt32(9),
		MaxbrUl:              *openapi.NewNullableString(openapi.PtrString("301 Mbps")),
		MaxbrDl:              *openapi.NewNullableString(openapi.PtrString("401 Mbps")),
		GbrUl:                *openapi.NewNullableString(openapi.PtrString("31 Mbps")),
		GbrDl:                *openapi.NewNullableString(openapi.PtrString("41 Mbps")),
		PriorityLevel:        *openapi.NewNullableInt32(openapi.PtrInt32(3)),
		DefQosFlowIndication: openapi.PtrBool(false),
		Arp: &models.Arp{
			PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(3)),
			PreemptCap:    models.PREEMPTIONCAPABILITY_NOT_PREEMPT,
			PreemptVuln:   models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE,
		},
	}

	return map[string]models.QosData{
		"QosData1": qosData1,
		"QosData2": qosData2,
	}
}

// MakeSessionRule builds sample session rules for QoS tests.
func MakeSessionRule() map[string]models.SessionRule {
	sessRule1 := models.SessionRule{
		SessRuleId: "RuleId-1",
		AuthSessAmbr: &models.Ambr{
			Uplink:   "77 Mbps",
			Downlink: "99 Mbps",
		},
		AuthDefQos: &models.AuthorizedDefaultQos{
			Var5qi: openapi.PtrInt32(9),
			Arp: &models.Arp{
				PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(8)),
				PreemptCap:    models.PREEMPTIONCAPABILITY_MAY_PREEMPT,
				PreemptVuln:   models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE,
			},
			PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(8)),
		},
	}
	sessRule2 := models.SessionRule{
		SessRuleId: "RuleId-2",
		AuthSessAmbr: &models.Ambr{
			Uplink:   "55 Mbps",
			Downlink: "33 Mbps",
		},
		AuthDefQos: &models.AuthorizedDefaultQos{
			Var5qi: openapi.PtrInt32(9),
			Arp: &models.Arp{
				PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(7)),
				PreemptCap:    models.PREEMPTIONCAPABILITY_MAY_PREEMPT,
				PreemptVuln:   models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE,
			},
			PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(7)),
		},
	}

	return map[string]models.SessionRule{
		"SessRule1": sessRule1,
		"SessRule2": sessRule2,
	}
}

// MakeTrafficControlData builds sample traffic control data for QoS tests.
func MakeTrafficControlData() map[string]models.TrafficControlData {
	tc1 := models.TrafficControlData{
		TcId:       "TC1",
		FlowStatus: models.FLOWSTATUS_ENABLED.Ptr(),
	}

	tc2 := models.TrafficControlData{
		TcId:       "TC2",
		FlowStatus: models.FLOWSTATUS_ENABLED.Ptr(),
	}

	return map[string]models.TrafficControlData{
		"TC1": tc1,
		"TC2": tc2,
	}
}
