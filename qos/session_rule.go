// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos

import (
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
func GetSessionRulesUpdate(pcfSessRules map[string]models.SessionRule, ctxtSessRules map[string]*models.SessionRule) *SessRulesUpdate {
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
			// Rules to be modified
			// TODO
		}
	}
	return &change
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
	// TODO

	// Del Rules
	if len(update.del) > 0 {
		for name := range update.del {
			delete(smCtxtPolData.SmCtxtSessionRules.SessionRules, name)
		}
	}

	// Set the active rule, but only when this update actually names one.
	//
	// GetSessionRulesUpdate sets ActiveSessRule only in its add branch — when the rule is not
	// already in the context. On a modification the rule exists, takes the mod branch, and
	// ActiveSessRule is left nil. Assigning unconditionally therefore cleared the active rule on
	// every modification that carried session rules: establishment set it, the first modification
	// wiped it, and everything afterwards that needed it from committed state found nothing.
	//
	// Two symptoms traced back to this. A corrective modification could not be built at all,
	// because the session AMBR comes from the active rule. And CreatePccRuleQer dereferenced it,
	// which took the SMF down when an application function added a flow mid-session.
	//
	// An update that says nothing about session rules is not saying there are none.
	if update.ActiveSessRule != nil {
		smCtxtPolData.SmCtxtSessionRules.ActiveRule = update.ActiveSessRule
		smCtxtPolData.SmCtxtSessionRules.ActiveRuleName = update.activeRuleName
		return
	}

	if smCtxtPolData.SmCtxtSessionRules.ActiveRule != nil {
		// Debug, not Info: an update that carries session rules without naming a new active one is
		// the ordinary modification, so this would be one line per modification in a running
		// deployment.
		logger.CtxLog.Debugf("keeping the active session rule %q: this update names none",
			smCtxtPolData.SmCtxtSessionRules.ActiveRuleName)
	}
}
