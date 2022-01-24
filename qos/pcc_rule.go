// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package qos

import (
	"github.com/free5gc/openapi/models"
)

func BuildSmPolicyUpdate(smCtxtPolData *SmCtxtPolicyData, smPolicyDecision *models.SmPolicyDecision) *PolicyUpdate {

	update := &PolicyUpdate{}

	//Keep copy of SmPolicyDecision received from PCF
	update.SmPolicyDecision = smPolicyDecision

	//Qos Flows update
	update.QosFlowUpdate = GetQosFlowDescUpdate(smPolicyDecision.QosDecs, smCtxtPolData.SmCtxtQosData.QosData)

	//Pcc Rules update
	update.PccRuleUpdate = GetPccRulesUpdate(smPolicyDecision.PccRules, smCtxtPolData.SmCtxtPccRules.PccRules)

	//Session Rules update
	update.SessRuleUpdate = GetSessionRulesUpdate(smPolicyDecision.SessRules, smCtxtPolData.SmCtxtSessionRules.SessionRules)

	return update
}

func GetPccRulesUpdate(pcfPccRules, ctxtPccRules map[string]*models.PccRule) *PccRulesUpdate {

	change := PccRulesUpdate{
		add: make(map[string]*models.PccRule),
		mod: make(map[string]*models.PccRule),
		del: make(map[string]*models.PccRule)}

	//Compare against Ctxt rules to get added or modified rules
	for name, pcfRule := range pcfPccRules {
		//match against SM ctxt Rules
		if ctxtrule := ctxtPccRules[name]; ctxtrule == nil {
			change.add[name] = pcfRule
		} else if GetPccRuleChanges(pcfRule, ctxtrule) {
			change.mod[name] = pcfRule
		}
	}

	//Compare Ctxt rules against PCF rules to get deleted rules
	for name, ctxtRule := range ctxtPccRules {
		//match against PCF provided Rules
		if pcfRule := pcfPccRules[name]; pcfRule == nil {
			change.del[name] = ctxtRule
		}
	}
	return &change
}

//Get the difference between 2 pcc rules
func GetPccRuleChanges(s, d *models.PccRule) bool {
	//TODO
	return false
}
