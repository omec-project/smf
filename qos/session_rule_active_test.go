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

// The rates these tests move between; named because goconst counts them across the file.
const (
	ambrBefore = "50 Mbps"
	ambrAfter  = "100 Mbps"
)

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

// A session rule the decision deletes carries no identity, so it lands in del with no active rule
// named. Keeping the active rule there leaves the session pointing at a rule the policy has
// removed -- and the next thing to read the session AMBR reads one that is no longer in force.
func TestCommittingADeletionOfTheActiveRuleLeavesNoneActive(t *testing.T) {
	committed := &SmCtxtPolicyData{}
	committed.Initialize()
	committed.SmCtxtSessionRules.SessionRules[establishedRuleID] = &models.SessionRule{SessRuleId: establishedRuleID}
	committed.SmCtxtSessionRules.ActiveRule = &models.SessionRule{SessRuleId: establishedRuleID}
	committed.SmCtxtSessionRules.ActiveRuleName = establishedRuleID

	// A rule with no identity is how the decision expresses a deletion.
	CommitSessionRulesUpdate(committed, GetSessionRulesUpdate(
		map[string]models.SessionRule{establishedRuleID: {}}, committed.SmCtxtSessionRules.SessionRules))

	if committed.SmCtxtSessionRules.ActiveRule != nil {
		t.Errorf("the deleted rule is still the active one: %+v", committed.SmCtxtSessionRules.ActiveRule)
	}

	if name := committed.SmCtxtSessionRules.ActiveRuleName; name != "" {
		t.Errorf("active rule name = %q, want none", name)
	}
}

// A rule that changed lands in mod, also with no active rule named. Keeping the old pointer leaves
// the session enforcing the rate it used to have, and never commits the one the policy now says.
func TestCommittingAChangeToTheActiveRuleReplacesIt(t *testing.T) {
	committed := &SmCtxtPolicyData{}
	committed.Initialize()
	committed.SmCtxtSessionRules.SessionRules[establishedRuleID] = &models.SessionRule{
		SessRuleId:   establishedRuleID,
		AuthSessAmbr: &models.Ambr{Uplink: ambrBefore, Downlink: ambrBefore},
	}
	committed.SmCtxtSessionRules.ActiveRule = committed.SmCtxtSessionRules.SessionRules[establishedRuleID]
	committed.SmCtxtSessionRules.ActiveRuleName = establishedRuleID

	CommitSessionRulesUpdate(committed, GetSessionRulesUpdate(
		map[string]models.SessionRule{establishedRuleID: {
			SessRuleId:   establishedRuleID,
			AuthSessAmbr: &models.Ambr{Uplink: ambrAfter, Downlink: ambrAfter},
		}}, committed.SmCtxtSessionRules.SessionRules))

	active := committed.SmCtxtSessionRules.ActiveRule
	if active == nil || active.AuthSessAmbr == nil {
		t.Fatal("the session has no active rule after a change to the one it had")
	}

	if got := active.AuthSessAmbr.Uplink; got != ambrAfter {
		t.Errorf("the active rule's uplink AMBR = %q, want the changed 100 Mbps: the session enforces the rate it used to have", got)
	}
}
