// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// An entry the decision carries is the session's; an empty one deletes it; one the decision leaves
// out stays as committed.
func TestADecidedEntryIsTheDecisionsTheCommittedOneOrNone(t *testing.T) {
	const kept, changed, deleted = "kept", "changed", "deleted"

	committed := &SmCtxtPolicyData{}
	committed.Initialize()
	for _, name := range []string{kept, changed, deleted} {
		committed.SmCtxtPccRules.PccRules[name] = &models.PccRule{PccRuleId: name, RefQosData: []string{"committed"}}
		committed.SmCtxtQosData.QosData[name] = &models.QosData{QosId: name + "-committed"}
		committed.SmCtxtTCData.TrafficControlData[name] = &models.TrafficControlData{TcId: name + "-committed"}
	}

	decision := &models.SmPolicyDecision{
		PccRules: map[string]models.PccRule{
			changed: {PccRuleId: changed, RefQosData: []string{"decided"}},
			deleted: {},
		},
		QosDecs:       &map[string]models.QosData{changed: {QosId: changed + "-decided"}, deleted: {}},
		TraffContDecs: &map[string]models.TrafficControlData{changed: {TcId: changed + "-decided"}, deleted: {}},
	}

	for name, want := range map[string]string{kept: "committed", changed: "decided", deleted: ""} {
		rule := DecidedPccRule(decision, committed, name)
		qosData := DecidedQosData(decision, committed, name)
		tcData := DecidedTcData(decision, committed, name)

		if want == "" {
			if rule != nil || qosData != nil || tcData != nil {
				t.Errorf("%s: an entry the decision deletes was read as %v, %v, %v", name, rule, qosData, tcData)
			}
			continue
		}
		if rule == nil || rule.RefQosData[0] != want {
			t.Errorf("%s: PCC rule = %+v, want the %s one", name, rule, want)
		}
		if qosData == nil || qosData.QosId != name+"-"+want {
			t.Errorf("%s: QoS data = %+v, want the %s one", name, qosData, want)
		}
		if tcData == nil || tcData.TcId != name+"-"+want {
			t.Errorf("%s: traffic control data = %+v, want the %s one", name, tcData, want)
		}
	}
}
