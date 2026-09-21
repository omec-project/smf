// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"reflect"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/logger"
)

// Handle Session Rule related info
type SessRulesUpdate struct {
	add, mod, del  map[string]*models.SessionRule
	ActiveSessRule *models.SessionRule
	activeRuleName string
}

// Get Session rule changes delta
// GetSessionRulesUpdate sorts the decision's session rules into what is new, changed and gone, and
// names the rule the session should be enforcing when this update changes it.
//
// activeRuleName is the rule in force now. A decision that changes that rule names it again here,
// because the pending update is what the NAS command is built from: the Session-AMBR is emitted
// only when the update carries an active rule, so a changed rate that was left to the mod map
// alone was committed by the SMF and never told to the UE.
func GetSessionRulesUpdate(pcfSessRules map[string]models.SessionRule, ctxtSessRules map[string]*models.SessionRule, activeRuleName string) *SessRulesUpdate {
	if len(pcfSessRules) == 0 {
		return nil
	}

	change := SessRulesUpdate{
		add: make(map[string]*models.SessionRule),
		mod: make(map[string]*models.SessionRule),
		del: make(map[string]*models.SessionRule),
	}

	// TODO: Iterate through all session rules from PCF and check against ctxt session rules
	// Get only active session Rule for now
	for name, sessRule := range pcfSessRules {
		rule := sessRule
		// Rules to be deleted
		if rule.GetSessRuleId() == "" {
			change.del[name] = &rule // nil
			continue
		}

		// Rules to be added
		if ctxtSessRules[name] == nil {
			change.add[name] = &rule

			// Activate last rule
			change.activeRuleName = name
			change.ActiveSessRule = &rule
		} else {
			change.mod[name] = &rule

			// A change to the rule in force is a change the UE has to be told about, and the
			// builder reads it from here -- but only a change. Every rule the decision repeats
			// lands in mod, unchanged ones included, because this function does not compare them;
			// naming the active rule for one of those would put a Session-AMBR in the command for
			// a policy notification that altered nothing, and have the rest of the SMF treat an
			// unrelated update as an active-rule change.
			if name == activeRuleName && sessionRuleChanged(&rule, ctxtSessRules[name]) {
				change.activeRuleName = name
				change.ActiveSessRule = &rule
			}
		}
	}
	return &change
}

// sessionRuleChanged reports whether the decision's rule differs from the one the session has.
//
// Compared whole rather than field by field: what the UE is told about a session rule is built
// from the rule, so any difference in it is a difference the UE has to hear about, and a list of
// fields here would go stale the first time the model grew one.
func sessionRuleChanged(decided, committed *models.SessionRule) bool {
	if committed == nil {
		return true
	}

	return !reflect.DeepEqual(*decided, *committed)
}

func CommitSessionRulesUpdate(smCtxtPolData *SmCtxtPolicyData, update *SessRulesUpdate) {
	// Iterate through Add/Mod/Del rules

	// Add new Rules
	if len(update.add) > 0 {
		for name, rule := range update.add {
			smCtxtPolData.SmCtxtSessionRules.SessionRules[name] = rule
		}
	}

	// Mod rules
	for name, rule := range update.mod {
		smCtxtPolData.SmCtxtSessionRules.SessionRules[name] = rule
	}

	// Del Rules
	if len(update.del) > 0 {
		for name := range update.del {
			delete(smCtxtPolData.SmCtxtSessionRules.SessionRules, name)
		}
	}

	// The active rule, which this update may name, change, remove, or say nothing about. Those
	// are four different things and only the first is written on the rule itself.
	//
	// GetSessionRulesUpdate names the rule to activate when the decision adds one and when it
	// changes the one in force. Assigning unconditionally cleared the active rule on every update
	// that named neither: establishment set it, the first such update wiped it, and everything
	// afterwards that needed it from committed state found nothing. Two symptoms traced back to
	// that -- a corrective modification could not be built at all, because the session AMBR comes
	// from the active rule, and CreateSessRuleQer had no rate to program.
	//
	// But nil does not mean "no change" either. A rule the decision deletes carries no identity,
	// so it lands in del with no active rule named; keeping the active rule there would leave the
	// session pointing at a rule the policy has removed.
	active := smCtxtPolData.SmCtxtSessionRules.ActiveRuleName

	switch {
	case update.ActiveSessRule != nil:
		smCtxtPolData.SmCtxtSessionRules.ActiveRule = update.ActiveSessRule
		smCtxtPolData.SmCtxtSessionRules.ActiveRuleName = update.activeRuleName

	case active == "":
		// Nothing was active and this update names nothing.

	case update.del[active] != nil:
		logger.CtxLog.Infof("the active session rule %q was deleted by this update; the session has none", active)

		smCtxtPolData.SmCtxtSessionRules.ActiveRule = nil
		smCtxtPolData.SmCtxtSessionRules.ActiveRuleName = ""

	default:
		// Debug, not Info: an update that carries session rules without touching the active one is
		// the ordinary modification, so this would be one line per modification in a deployment.
		logger.CtxLog.Debugf("keeping the active session rule %q: this update does not touch it", active)
	}
}
