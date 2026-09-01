// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// An update that says nothing about session rules is not saying there are none.
//
// GetSessionRulesUpdate names an active rule only when the rule is new. On a modification the
// rule already exists, so the update carries none — and committing used to assign that nil
// straight over the active rule. Establishment set it, the first modification wiped it, and
// anything afterwards that needed the session AMBR from committed state found nothing. Two
// separate failures traced back here: a corrective modification that could not be built, and a
// panic when an application function added a flow mid-session.
const establishedRuleID = "rule-1"

// Repeated below; goconst asks for a name.
const testRuleID2 = "rule-2"

func TestCommittingAnUpdateWithNoSessionRuleKeepsTheActiveOne(t *testing.T) {
	established := &models.SessionRule{
		SessRuleId:   establishedRuleID,
		AuthSessAmbr: &models.Ambr{Uplink: "50 Mbps", Downlink: "50 Mbps"},
	}

	polData := &SmCtxtPolicyData{}
	polData.SmCtxtSessionRules.SessionRules = map[string]*models.SessionRule{establishedRuleID: established}
	polData.SmCtxtSessionRules.ActiveRule = established
	polData.SmCtxtSessionRules.ActiveRuleName = establishedRuleID

	// What a modification produces: the rule is already in the context, so it lands in mod and
	// no active rule is named.
	update := GetSessionRulesUpdate(
		map[string]models.SessionRule{establishedRuleID: *established},
		polData.SmCtxtSessionRules.SessionRules,
	)
	if update == nil {
		t.Fatal("no update produced")
	}
	if update.ActiveSessRule != nil {
		t.Fatal("this test is built on a modification naming no active rule; that is no longer true")
	}

	CommitSessionRulesUpdate(polData, update)

	if polData.SmCtxtSessionRules.ActiveRule == nil {
		t.Fatal("the active session rule was cleared by an update that said nothing about it; the session AMBR is now unavailable to every later modification")
	}
	if polData.SmCtxtSessionRules.ActiveRuleName != establishedRuleID {
		t.Errorf("active rule name = %q, want rule-1", polData.SmCtxtSessionRules.ActiveRuleName)
	}
}

// When an update does name an active rule — establishment, or a genuine change of session rule —
// it replaces the old one.
func TestCommittingAnUpdateThatNamesAnActiveRuleReplacesIt(t *testing.T) {
	old := &models.SessionRule{SessRuleId: establishedRuleID}
	polData := &SmCtxtPolicyData{}
	polData.SmCtxtSessionRules.SessionRules = map[string]*models.SessionRule{}
	polData.SmCtxtSessionRules.ActiveRule = old
	polData.SmCtxtSessionRules.ActiveRuleName = establishedRuleID

	update := GetSessionRulesUpdate(
		map[string]models.SessionRule{testRuleID2: {
			SessRuleId:   testRuleID2,
			AuthSessAmbr: &models.Ambr{Uplink: "100 Mbps", Downlink: "100 Mbps"},
		}},
		polData.SmCtxtSessionRules.SessionRules,
	)
	if update == nil || update.ActiveSessRule == nil {
		t.Fatal("a new rule must be named active")
	}

	CommitSessionRulesUpdate(polData, update)

	if polData.SmCtxtSessionRules.ActiveRuleName != testRuleID2 {
		t.Errorf("active rule name = %q, want rule-2: a named rule must take effect",
			polData.SmCtxtSessionRules.ActiveRuleName)
	}
}
