// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import "github.com/omec-project/openapi/v2/models"

// RemoveFlows drops the given QoS flow identifiers from an update that has not been committed,
// together with any PCC rule that referenced them.
//
// The radio access network can establish part of a modification and refuse the rest. What it
// established is what the session has, so the update the SMF is about to record must describe
// that rather than what was attempted — otherwise the next modification computes its delta
// against flows that do not exist.
//
// Rules are dropped alongside their flows deliberately. A PCC rule whose referenced QoS data was
// never established would be recorded as active while nothing enforces it, which is the same
// class of divergence in a different place.
func (u *PolicyUpdate) RemoveFlows(refused map[uint8]bool) {
	if u == nil || len(refused) == 0 {
		return
	}

	removedQosIDs := make(map[string]bool)

	if u.QosFlowUpdate != nil {
		for _, flows := range []map[string]*models.QosData{u.QosFlowUpdate.add, u.QosFlowUpdate.mod} {
			for qosID := range flows {
				if refused[GetQosFlowIdFromQosId(qosID)] {
					removedQosIDs[qosID] = true
					delete(flows, qosID)
				}
			}
		}
	}

	if u.PccRuleUpdate == nil || len(removedQosIDs) == 0 {
		return
	}

	for _, rules := range []map[string]*models.PccRule{u.PccRuleUpdate.add, u.PccRuleUpdate.mod} {
		for ruleID, rule := range rules {
			if rule == nil {
				continue
			}
			for _, qosID := range rule.RefQosData {
				if removedQosIDs[qosID] {
					delete(rules, ruleID)
					break
				}
			}
		}
	}
}

// RefusedFlowSet turns the radio access network's refused QoS flow identifiers into the form
// RemoveFlows expects.
func RefusedFlowSet(qfis []int64) map[uint8]bool {
	set := make(map[uint8]bool, len(qfis))
	for _, qfi := range qfis {
		set[uint8(qfi)] = true
	}
	return set
}
