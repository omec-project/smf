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

// An update that does not touch the rule in force keeps it.
//
// GetSessionRulesUpdate names an active rule when the decision adds one, and now also when it
// changes the one in force. It still names none when the decision touches some other rule -- and
// an update that says nothing about the active rule is not saying there is none. Assigning
// unconditionally cleared it on every such update: establishment set the active rule, the first
// one of these wiped it, and everything afterwards that needed the session AMBR from committed
// state found nothing.
func TestCommittingAnUpdateThatDoesNotTouchTheActiveRuleKeepsIt(t *testing.T) {
	established := &models.SessionRule{
		SessRuleId:   establishedRuleID,
		AuthSessAmbr: &models.Ambr{Uplink: ambrBefore, Downlink: ambrBefore},
	}
	other := &models.SessionRule{
		SessRuleId:   testRuleID2,
		AuthSessAmbr: &models.Ambr{Uplink: ambrAfter, Downlink: ambrAfter},
	}

	polData := &SmCtxtPolicyData{}
	polData.SmCtxtSessionRules.SessionRules = map[string]*models.SessionRule{
		establishedRuleID: established,
		testRuleID2:       other,
	}
	polData.SmCtxtSessionRules.ActiveRule = established
	polData.SmCtxtSessionRules.ActiveRuleName = establishedRuleID

	// A decision that changes the other rule and leaves the active one alone.
	update := GetSessionRulesUpdate(
		map[string]models.SessionRule{testRuleID2: *other},
		polData.SmCtxtSessionRules.SessionRules,
		polData.SmCtxtSessionRules.ActiveRuleName,
	)
	if update == nil {
		t.Fatal("no update produced")
	}

	if update.ActiveSessRule != nil {
		t.Fatal("an update touching another rule named an active one; this test is about the case where none is named")
	}

	CommitSessionRulesUpdate(polData, update)

	if polData.SmCtxtSessionRules.ActiveRule == nil {
		t.Fatal("the active session rule was cleared by an update that said nothing about it; the session AMBR is now unavailable to every later modification")
	}

	if got := polData.SmCtxtSessionRules.ActiveRuleName; got != establishedRuleID {
		t.Errorf("active rule name = %q, want %q", got, establishedRuleID)
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
		polData.SmCtxtSessionRules.ActiveRuleName,
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
		map[string]models.SessionRule{establishedRuleID: {}}, committed.SmCtxtSessionRules.SessionRules,
		committed.SmCtxtSessionRules.ActiveRuleName))

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
		}}, committed.SmCtxtSessionRules.SessionRules, committed.SmCtxtSessionRules.ActiveRuleName))

	active := committed.SmCtxtSessionRules.ActiveRule
	if active == nil || active.AuthSessAmbr == nil {
		t.Fatal("the session has no active rule after a change to the one it had")
	}

	if got := active.AuthSessAmbr.Uplink; got != ambrAfter {
		t.Errorf("the active rule's uplink AMBR = %q, want the changed 100 Mbps: the session enforces the rate it used to have", got)
	}
}

// A change to the rule in force has to reach the UE, and the NAS command is built from the pending
// update: BuildGSMPDUSessionModificationCommand emits the Session-AMBR only when the update carries
// an active rule. Leaving a changed active rule in the mod map alone had the SMF commit the new
// rate and never tell the UE about it -- the two then disagree about what the session is allowed,
// which is the divergence the whole procedure exists to avoid.
func TestAChangeToTheActiveRuleIsNamedInTheUpdate(t *testing.T) {
	established := &models.SessionRule{
		SessRuleId:   establishedRuleID,
		AuthSessAmbr: &models.Ambr{Uplink: ambrBefore, Downlink: ambrBefore},
	}

	polData := &SmCtxtPolicyData{}
	polData.SmCtxtSessionRules.SessionRules = map[string]*models.SessionRule{establishedRuleID: established}
	polData.SmCtxtSessionRules.ActiveRule = established
	polData.SmCtxtSessionRules.ActiveRuleName = establishedRuleID

	update := GetSessionRulesUpdate(
		map[string]models.SessionRule{establishedRuleID: {
			SessRuleId:   establishedRuleID,
			AuthSessAmbr: &models.Ambr{Uplink: ambrAfter, Downlink: ambrAfter},
		}},
		polData.SmCtxtSessionRules.SessionRules,
		polData.SmCtxtSessionRules.ActiveRuleName,
	)

	if update.ActiveSessRule == nil {
		t.Fatal("the update does not name the rule it changes, so the command carries no Session-AMBR and the UE is never told the new rate")
	}

	if update.ActiveSessRule.AuthSessAmbr == nil || update.ActiveSessRule.AuthSessAmbr.Uplink != ambrAfter {
		t.Errorf("the named rule carries %+v, want the changed %s", update.ActiveSessRule.AuthSessAmbr, ambrAfter)
	}
}

// A policy notification that repeats the session rule unchanged is not an active-rule change.
//
// Every rule the decision repeats lands in mod, unchanged ones included, because the update does
// not compare them. Naming the active rule for one of those puts a Session-AMBR in the UE's
// modification command for a notification that altered nothing, and has the rest of the SMF treat
// an unrelated update as a change to the rule in force.
func TestRepeatingTheActiveRuleUnchangedNamesNothing(t *testing.T) {
	established := &models.SessionRule{
		SessRuleId:   establishedRuleID,
		AuthSessAmbr: &models.Ambr{Uplink: ambrBefore, Downlink: ambrBefore},
	}

	polData := &SmCtxtPolicyData{}
	polData.SmCtxtSessionRules.SessionRules = map[string]*models.SessionRule{establishedRuleID: established}
	polData.SmCtxtSessionRules.ActiveRule = established
	polData.SmCtxtSessionRules.ActiveRuleName = establishedRuleID

	// The same rule again, as a notification about something else would carry it -- with its own
	// Ambr, because a decision is freshly decoded and never shares the committed rule's pointers.
	// Comparing the structs directly would find the two pointers different and call that a change;
	// what this pins is that the comparison reaches the rates.
	repeated := *established
	repeated.AuthSessAmbr = &models.Ambr{Uplink: ambrBefore, Downlink: ambrBefore}

	update := GetSessionRulesUpdate(
		map[string]models.SessionRule{establishedRuleID: repeated},
		polData.SmCtxtSessionRules.SessionRules,
		polData.SmCtxtSessionRules.ActiveRuleName,
	)

	if update.ActiveSessRule != nil {
		t.Error("an unchanged rule was named as an active-rule change; the UE is sent a Session-AMBR for a policy update that altered nothing")
	}
}
