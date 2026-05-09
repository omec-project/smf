// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"github.com/omec-project/openapi/v2/models"
)

// Handle Session Rule related info
type SessRulesUpdate struct {
	add, mod, del  map[string]*models.SessionRule
	ActiveSessRule *models.SessionRule
	activeRuleName string
}

// Get Session rule changes delta
func GetSessionRulesUpdate(pcfSessRules *map[string]models.SessionRule, ctxtSessRules map[string]*models.SessionRule) *SessRulesUpdate {
	if pcfSessRules == nil || len(*pcfSessRules) == 0 {
		return nil
	}

	change := SessRulesUpdate{
		add: make(map[string]*models.SessionRule),
		mod: make(map[string]*models.SessionRule),
		del: make(map[string]*models.SessionRule),
	}

	// TODO: Iterate through all session rules from PCF and check against ctxt session rules
	// Get only active session Rule for now
	for name, sessRule := range *pcfSessRules {
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

	// Set Active Rule
	smCtxtPolData.SmCtxtSessionRules.ActiveRule = update.ActiveSessRule
	smCtxtPolData.SmCtxtSessionRules.ActiveRuleName = update.activeRuleName
}
