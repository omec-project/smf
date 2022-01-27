// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package qos_test

import (
	"fmt"
	"testing"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/smf/qos"
)

var flowDesc = []string{
	"permit out ip from 1.1.1.1 1000 to 2.2.2.2 2000",
	"permit out ip from 1.1.1.1/24 1000 to 2.2.2.2/24 2000",
	"permit out ip from any 1000 to 2.2.2.2/24 2000",
	"permit out ip from any 1000 to assigned 2000",
	"permit out 17 from 1.1.1.1/24 1000-1200 to 2.2.2.2/24 2000-2500"}

func TestDecodeFlowDescToIPFilters(t *testing.T) {
	for i, flow := range flowDesc {
		ipf := qos.DecodeFlowDescToIPFilters(flow)
		fmt.Printf("Flow: %v %v\n", i, ipf.String())
	}
}

func TestGetPfContent(t *testing.T) {
	for i, flow := range flowDesc {
		pfcList := qos.GetPfContent(flow)
		fmt.Println("Flow:", i)
		for _, pfc := range pfcList {
			fmt.Printf("%v", pfc.String())
		}
	}
}

func TestBuildQosRules(t *testing.T) {
	//make SM Policy Decision
	smPolicyDecision := &models.SmPolicyDecision{}

	//make Sm ctxt Policy Data
	smCtxtPolData := &qos.SmCtxtPolicyData{}

	smPolicyDecision.PccRules = makeSamplePccRules()
	smPolicyDecision.QosDecs = makeSampleQosData()

	smPolicyUpdates := qos.BuildSmPolicyUpdate(smCtxtPolData, smPolicyDecision)

	qosRules := qos.BuildQosRules(smPolicyUpdates)

	fmt.Println("QosRules:", qosRules)
}

func makeSamplePccRules() map[string]*models.PccRule {

	pccRule1 := models.PccRule{
		PccRuleId:  "PccRule1",
		Precedence: 200,
		RefQosData: []string{"QosData1"},
		FlowInfos:  make([]models.FlowInformation, 0),
	}

	flowInfos := []models.FlowInformation{
		{
			FlowDescription:   "permit out ip from 1.1.1.1 1000 to 2.2.2.2 2000",
			PackFiltId:        "1",
			PacketFilterUsage: true,
			FlowDirection:     models.FlowDirectionRm_BIDIRECTIONAL,
		},
		{
			FlowDescription:   "permit out ip from 3.3.3.3 3000 to 4.4.4.4 4000",
			PackFiltId:        "2",
			PacketFilterUsage: true,
			FlowDirection:     models.FlowDirectionRm_BIDIRECTIONAL,
		},
	}

	pccRule1.FlowInfos = append(pccRule1.FlowInfos, flowInfos...)

	return map[string]*models.PccRule{"PccRule1": &pccRule1}
}

func makeSampleQosData() map[string]*models.QosData {
	qosData1 := models.QosData{
		QosId:                "QosData1",
		Var5qi:               5,
		MaxbrUl:              "101 Mbps",
		MaxbrDl:              "201 Mbps",
		GbrUl:                "11 Mbps",
		GbrDl:                "21 Mbps",
		PriorityLevel:        5,
		DefQosFlowIndication: true,
	}

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

	return map[string]*models.QosData{
		"QosData1": &qosData1,
		"QosData2": &qosData2,
	}
}

/*
func TestBuildPFCompProtocolId(t *testing.T) {
	pfc := qos.BuildPFCompProtocolId("17")
	fmt.Printf("PFC: %v \n", pfc.String())
}
*/
