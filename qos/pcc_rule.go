// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package qos

import (
	"log"
	"strconv"

	"github.com/free5gc/openapi/models"
)

func GetQoSDataFromPolicyDecision(smPolicyDec *models.SmPolicyDecision, refQosData string) *models.QosData {

	return smPolicyDec.QosDecs[refQosData]
}

func BuildQosRulesFromPccRules(smPolicyDec *models.SmPolicyDecision) QoSRules {
	qosRules := QoSRules{}
	for pccRuleName, pccRuleVal := range smPolicyDec.PccRules {
		log.Printf("Building QoS Rule from PCC rule [%s]", pccRuleName)
		refQosData := GetQoSDataFromPolicyDecision(smPolicyDec, pccRuleVal.RefQosData[1])
		qosRule := BuildQoSRuleFromPccRule(pccRuleVal, refQosData, OperationCodeCreateNewQoSRule)
		qosRules = append(qosRules, *qosRule)
	}
	return qosRules
}

func BuildQoSRuleFromPccRule(pccRule *models.PccRule, qosData *models.QosData, pccRuleOpCode uint8) *QoSRule {

	qRule := QoSRule{
		Identifier:       GetQosRuleIdFromPccRuleId(pccRule.PccRuleId),
		DQR:              btou(qosData.DefQosFlowIndication),
		OperationCode:    pccRuleOpCode,
		Precedence:       uint8(pccRule.Precedence),
		QFI:              uint8(qosData.Var5qi),
		PacketFilterList: BuildPacketFilterListFromPccRule(pccRule),
	}

	return &qRule
}

func btou(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func GetQosRuleIdFromPccRuleId(pccRuleId string) uint8 {
	if id, err := strconv.Atoi(pccRuleId); err != nil {
		//TODO: Error Log
		return 0
	} else {
		return uint8(id)
	}
}

func BuildPacketFilterListFromPccRule(pccRule *models.PccRule) []PacketFilter {

	pfList := []PacketFilter{}

	//Iterate through
	for _, flow := range pccRule.FlowInfos {
		pf := GetPacketFilterFromFlowInfo(&flow)
		pfList = append(pfList, pf)
	}
	return pfList
}

func GetPacketFilterFromFlowInfo(flowInfo *models.FlowInformation) (pf PacketFilter) {

	return PacketFilter{
		Identifier: GetPfId(flowInfo.PackFiltId),
		Direction:  GetPfDirectionFromPccFlowInfo(flowInfo.FlowDirection),
		Content:    GetPfContent(flowInfo.FlowDescription),
	}
}

func GetPfId(ids string) uint8 {
	if id, err := strconv.Atoi(ids); err != nil {
		//TODO: Error Log
		return 0
	} else {
		return uint8(id)
	}
}

func GetPfDirectionFromPccFlowInfo(flowDir models.FlowDirectionRm) uint8 {
	switch flowDir {
	case models.FlowDirectionRm_UPLINK:
		return PacketFilterDirectionUplink
	case models.FlowDirectionRm_DOWNLINK:
		return PacketFilterDirectionDownlink
	case models.FlowDirectionRm_BIDIRECTIONAL:
		return PacketFilterDirectionBidirectional
	default:
		//TODO: Error Log
		return PacketFilterDirectionBidirectional
	}
}

//BuildPfContent- builds PF content from Flow Description(only if required to be sent to UE)
func GetPfContent(flowDes string) []PacketFilterComponent {
	//Tokenize flow desc and make PF components
	//strings.Fields("string")
	pfc := PacketFilterComponent{
		ComponentType: PacketFilterComponentTypeMatchAll,
	}
	return []PacketFilterComponent{pfc}
}

func GetPccRuleChanges(pcfPccRules, ctxtPccRules map[string]*models.PccRule) *PccRulesUpdate {

	var change PccRulesUpdate

	//Iterate through all session rules from PCF and check agains ctxt session rules

	return &change
}
