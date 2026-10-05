// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/util"
)

// Define SMF Session-Rule/PccRule/Rule-Qos-Data
type PolicyUpdate struct {
	SessRuleUpdate *SessRulesUpdate
	PccRuleUpdate  *PccRulesUpdate
	QosFlowUpdate  *QosFlowsUpdate
	TCUpdate       *TrafficControlUpdate
	CondDataUpdate *CondDataUpdate

	// relevant SM Policy Decision from PCF
	SmPolicyDecision *models.SmPolicyDecision
}

type SmCtxtPolicyData struct {
	// maintain all session rule-info and current active sess rule
	SmCtxtPccRules     SmCtxtPccRulesInfo
	SmCtxtQosData      SmCtxtQosData
	SmCtxtTCData       SmCtxtTrafficControlData
	SmCtxtChargingData SmCtxtChargingData
	SmCtxtCondData     SmCtxtCondData
	SmCtxtSessionRules SmCtxtSessionRulesInfo
}

// maintain all session rule-info and current active sess rule
type SmCtxtSessionRulesInfo struct {
	ActiveRule     *models.SessionRule
	SessionRules   map[string]*models.SessionRule
	ActiveRuleName string
}

type SmCtxtPccRulesInfo struct {
	PccRules map[string]*models.PccRule
	// TODO:Rulename to RuleId Map
}

type SmCtxtQosData struct {
	QosData map[string]*models.QosData
}

type SmCtxtTrafficControlData struct {
	TrafficControlData map[string]*models.TrafficControlData
}

type SmCtxtChargingData struct {
	ChargingData map[string]*models.ChargingData
}

type SmCtxtCondData struct {
	CondData map[string]*models.ConditionData
}

func (obj *SmCtxtPolicyData) Initialize() {
	obj.SmCtxtSessionRules.SessionRules = make(map[string]*models.SessionRule)
	obj.SmCtxtPccRules.PccRules = make(map[string]*models.PccRule)
	obj.SmCtxtQosData.QosData = make(map[string]*models.QosData)
	obj.SmCtxtCondData.CondData = make(map[string]*models.ConditionData)
	obj.SmCtxtChargingData.ChargingData = make(map[string]*models.ChargingData)
	obj.SmCtxtTCData.TrafficControlData = make(map[string]*models.TrafficControlData)
}

func BuildSmPolicyUpdate(smCtxtPolData *SmCtxtPolicyData, smPolicyDecision *models.SmPolicyDecision) *PolicyUpdate {
	update := &PolicyUpdate{}

	// Keep copy of SmPolicyDecision received from PCF
	update.SmPolicyDecision = smPolicyDecision

	normalizeSessionAmbrRates(smPolicyDecision)

	// Qos Flows update
	update.QosFlowUpdate = GetQosFlowDescUpdate(smPolicyDecision.GetQosDecs(), smCtxtPolData.SmCtxtQosData.QosData)

	// Pcc Rules update
	update.PccRuleUpdate = GetPccRulesUpdate(smPolicyDecision.GetPccRules(), smCtxtPolData.SmCtxtPccRules.PccRules)

	// Session Rules update
	update.SessRuleUpdate = GetSessionRulesUpdate(smPolicyDecision.GetSessRules(),
		smCtxtPolData.SmCtxtSessionRules.SessionRules, smCtxtPolData.SmCtxtSessionRules.ActiveRuleName)

	// Traffic Control Data update
	update.TCUpdate = GetTrafficControlUpdate(smPolicyDecision.GetTraffContDecs(), smCtxtPolData.SmCtxtTCData.TrafficControlData)

	// Condition Data update
	update.CondDataUpdate = GetConditionDataUpdate(smPolicyDecision.GetConds(), smCtxtPolData.SmCtxtCondData.CondData)

	return update
}

// normalizeSessionAmbrRates canonicalizes the session AMBR on every decided session rule, in
// place, before anything downstream reads it.
//
// The session AMBR reaches three converters as one raw string: the gNB's (sessionAmbrToBps), the
// user plane's (util.BitRateTokbps) and the UE's (sessionAmbrForNas). They agree on most
// spellings, but not on a double space or a lowercase unit -- one reads a rate the others read as
// zero, which is a live mismatch between what the radio enforces and what the user plane does.
// Normalizing separately in each converter would only move the mismatch around; done once here,
// every reader of this decision sees the same canonical string.
func normalizeSessionAmbrRates(smPolicyDecision *models.SmPolicyDecision) {
	for _, rule := range smPolicyDecision.GetSessRules() {
		if rule.AuthSessAmbr == nil {
			continue
		}
		rule.AuthSessAmbr.Uplink = util.NormalizeBitRate(rule.AuthSessAmbr.Uplink)
		rule.AuthSessAmbr.Downlink = util.NormalizeBitRate(rule.AuthSessAmbr.Downlink)
	}
}

func CommitSmPolicyDecision(smCtxtPolData *SmCtxtPolicyData, smPolicyUpdate *PolicyUpdate) error {
	// Update Qos Flows
	if smPolicyUpdate.QosFlowUpdate != nil {
		CommitQosFlowDescUpdate(smCtxtPolData, smPolicyUpdate.QosFlowUpdate)
	}

	// Update PCC Rules
	if smPolicyUpdate.PccRuleUpdate != nil {
		CommitPccRulesUpdate(smCtxtPolData, smPolicyUpdate.PccRuleUpdate)
	}

	// Update Session Rules
	if smPolicyUpdate.SessRuleUpdate != nil {
		CommitSessionRulesUpdate(smCtxtPolData, smPolicyUpdate.SessRuleUpdate)
	}

	// Update Traffic Control data
	if smPolicyUpdate.TCUpdate != nil {
		CommitTrafficControlUpdate(smCtxtPolData, smPolicyUpdate.TCUpdate)
	}

	// Update Condition Data
	if smPolicyUpdate.CondDataUpdate != nil {
		CommitConditionDataUpdate(smCtxtPolData, smPolicyUpdate.CondDataUpdate)
	}

	return nil
}
