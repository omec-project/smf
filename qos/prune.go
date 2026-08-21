// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/logger"
)

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
// It returns a delete-only update describing what it removed, or nil if it removed nothing. That
// is what the corrective modification is built from: the UE was told these flows were authorized
// and has to be told they are not, and their identities are only available here.
func (u *PolicyUpdate) RemoveFlows(refused map[uint8]bool) *PolicyUpdate {
	if u == nil || len(refused) == 0 {
		return nil
	}

	removedQosIDs := make(map[string]bool)
	removedFlows := make(map[string]*models.QosData)
	removedRules := make(map[string]*models.PccRule)

	if u.QosFlowUpdate != nil {
		for _, flows := range []map[string]*models.QosData{u.QosFlowUpdate.add, u.QosFlowUpdate.mod} {
			for qosID, flow := range flows {
				if refused[GetQosFlowIdFromQosId(qosID)] {
					removedQosIDs[qosID] = true
					removedFlows[qosID] = flow
					delete(flows, qosID)
				}
			}
		}
	}

	if len(removedQosIDs) == 0 {
		return nil
	}

	if u.PccRuleUpdate != nil {
		for _, rules := range []map[string]*models.PccRule{u.PccRuleUpdate.add, u.PccRuleUpdate.mod} {
			for ruleID, rule := range rules {
				if rule == nil {
					continue
				}
				for _, qosID := range rule.RefQosData {
					if removedQosIDs[qosID] {
						removedRules[ruleID] = rule
						delete(rules, ruleID)
						break
					}
				}
			}
		}
	}

	return &PolicyUpdate{
		QosFlowUpdate: &QosFlowsUpdate{
			add: map[string]*models.QosData{},
			mod: map[string]*models.QosData{},
			del: removedFlows,
		},
		PccRuleUpdate: &PccRulesUpdate{
			add: map[string]*models.PccRule{},
			mod: map[string]*models.PccRule{},
			del: removedRules,
		},
		SmPolicyDecision: u.SmPolicyDecision,
	}
}

// RefusedFlowSet turns the radio access network's refused QoS flow identifiers into the form
// RemoveFlows expects.
//
// Values outside the valid QoS flow identifier range are dropped rather than narrowed. TS 23.501
// table 5.7.1.1 gives the range as 1 to 63; 0 is not assignable. That matters here because
// GetQosFlowIdFromQosId returns 0 for a QoS identifier it cannot parse, so admitting 0 would let
// an unparseable identifier and a malformed report from the gNB combine to delete a flow the
// radio access network never refused.
func RefusedFlowSet(qfis []int64) map[uint8]bool {
	set := make(map[uint8]bool, len(qfis))
	for _, qfi := range qfis {
		if qfi < 1 || qfi > 63 {
			logger.CtxLog.Warnf("ignoring out-of-range QoS flow identifier %d reported as refused", qfi)
			continue
		}
		set[uint8(qfi)] = true
	}
	return set
}
