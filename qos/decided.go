// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import "github.com/omec-project/openapi/v2/models"

// A decision is a change to the policy in force, not all of it (TS 29.512 subclause 4.2.6.1): an
// entry it carries replaces the committed one, an empty entry deletes it, and an entry it leaves out
// stays as committed. The functions below read one entry as the session will have it once the
// decision is applied, which is what programming the user plane for a rule needs: a rule the
// decision does not repeat still refers to QoS data the decision changes, and a rule it does repeat
// can refer to traffic control data it leaves out. Nil means there is no such entry.

// DecidedPccRule is the PCC rule called name once decision is applied to committed.
func DecidedPccRule(decision *models.SmPolicyDecision, committed *SmCtxtPolicyData, name string) *models.PccRule {
	if rule, ok := decision.GetPccRules()[name]; ok {
		if rule.GetPccRuleId() == "" {
			return nil
		}
		return &rule
	}

	return committed.SmCtxtPccRules.PccRules[name]
}

// DecidedQosData is the QoS data called name once decision is applied to committed.
func DecidedQosData(decision *models.SmPolicyDecision, committed *SmCtxtPolicyData, name string) *models.QosData {
	if qosData, ok := decision.GetQosDecs()[name]; ok {
		if qosData.GetQosId() == "" {
			return nil
		}
		return &qosData
	}

	return committed.SmCtxtQosData.QosData[name]
}

// DecidedTcData is the traffic control data called name once decision is applied to committed.
func DecidedTcData(decision *models.SmPolicyDecision, committed *SmCtxtPolicyData, name string) *models.TrafficControlData {
	if tcData, ok := decision.GetTraffContDecs()[name]; ok {
		if tcData.GetTcId() == "" {
			return nil
		}
		return &tcData
	}

	return committed.SmCtxtTCData.TrafficControlData[name]
}
