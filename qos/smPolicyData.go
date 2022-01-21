// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package qos

import "github.com/free5gc/openapi/models"

//Define SMF Session-Rule/PccRule/Rule-Qos-Data

type PccRulesUpdate struct {
	add, mod, del map[string]*models.PccRule
}

type PolicyUpdate struct {
	SessRuleUpdate *SessRulesUpdate
	PccRuleUpdate  *PccRulesUpdate
	QosFlowUpdate  *QosFlowsUpdate
}

type SmCtxtPolicyData struct {

	//maintain all session rule-info and current active sess rule
	SmCtxtSessionRules SmCtxtSessionRulesInfo
	SmCtxtPccRules     SmCtxtPccRulesInfo
	SmCtxtQosData      SmCtxtQosData
	SmCtxtTCData       SmCtxtTrafficControlData
	SmCtxtChargingData SmCtxtChargingData
	SmCtxtCondData     SmCtxtCondData
}

//maintain all session rule-info and current active sess rule
type SmCtxtSessionRulesInfo struct {
	SessionRules map[string]*models.SessionRule
	ActiveRule   string
}

type SmCtxtPccRulesInfo struct {
	PccRules map[string]*models.PccRule
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

/*
//maintain all pcc rule-info and associated Qos-Data/Condition data
type SmCtxtPccRule struct {
	PccRule      *models.PccRule
	QosData      *models.QosData
	ChargingData *models.ChargingData
	CondData     *models.ConditionData
}
*/
