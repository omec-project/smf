// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// A JSON null in a decision's rule maps decodes to a nil entry, and a nil entry is a deletion
// (TS 29.512 subclause 4.2.6.1). Every consumer of the update must treat it as one without
// dereferencing it.
func TestNullDeletionOfTheActiveSessionRuleLeavesNoneActive(t *testing.T) {
	established := models.NewSessionRule(establishedRuleID)
	established.SetAuthSessAmbr(*models.NewAmbr(ambrBefore, ambrBefore))

	polData := &SmCtxtPolicyData{}
	polData.SmCtxtSessionRules.SessionRules = map[string]*models.SessionRule{establishedRuleID: established}
	polData.SmCtxtSessionRules.ActiveRule = established
	polData.SmCtxtSessionRules.ActiveRuleName = establishedRuleID

	update := GetSessionRulesUpdate(map[string]*models.SessionRule{establishedRuleID: nil},
		polData.SmCtxtSessionRules.SessionRules, establishedRuleID)
	if update == nil || update.del[establishedRuleID] == nil {
		t.Fatal("a null session rule must land in del as a non-nil entry")
	}

	CommitSessionRulesUpdate(polData, update)

	if polData.SmCtxtSessionRules.ActiveRule != nil || polData.SmCtxtSessionRules.ActiveRuleName != "" {
		t.Error("the withdrawn rule is still the active one")
	}
	if _, ok := polData.SmCtxtSessionRules.SessionRules[establishedRuleID]; ok {
		t.Error("the withdrawn rule is still committed")
	}
}

func TestNullEntriesAreDeletionsAndFormatSafely(t *testing.T) {
	pcc := GetPccRulesUpdate(map[string]*models.PccRule{"r": nil}, nil)
	tc := GetTrafficControlUpdate(map[string]*models.TrafficControlData{"t": nil}, nil)
	sess := GetSessionRulesUpdate(map[string]*models.SessionRule{"s": nil}, nil, "")

	if pcc.del["r"] == nil || tc.del["t"] == nil || sess.del["s"] == nil {
		t.Fatal("a null entry must be a non-nil deletion")
	}

	// Must not panic.
	_ = pcc.String()
	_ = tc.String()
	_ = sess.String()
	_ = TCDataString(nil)

	decision := models.NewSmPolicyDecision()
	decision.SetSessRules(map[string]*models.SessionRule{"s": nil})
	decision.SetTraffContDecs(map[string]*models.TrafficControlData{"t": nil})
	decision.SetPccRules(map[string]*models.PccRule{"r": nil})
	_ = SmPolicyDecisionString(decision)
}

func TestNormalizeSessionAmbrRatesSkipsNullSessionRule(t *testing.T) {
	decision := models.NewSmPolicyDecision()
	decision.SetSessRules(map[string]*models.SessionRule{"active": nil})

	normalizeSessionAmbrRates(decision)
}
