// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package qos

import (
	"github.com/free5gc/openapi/models"
)

//Handle Session Rule related info
type SessRulesUpdate struct {
	add, mod, del  map[string]*models.SessionRule
	ActiveSessRule *models.SessionRule
	activeRuleName string
}

//Get Session rule changes delta
func GetSessionRulesUpdate(pcfSessRules, ctxtSessRules map[string]*models.SessionRule) *SessRulesUpdate {
	change := SessRulesUpdate{
		add: make(map[string]*models.SessionRule),
		mod: make(map[string]*models.SessionRule),
		del: make(map[string]*models.SessionRule),
	}

	//TODO: Iterate through all session rules from PCF and check agains ctxt session rules
	//Get only active session Rule for now
	for name, sessRule := range pcfSessRules {
		change.activeRuleName = name
		change.ActiveSessRule = sessRule
	}
	return &change
}
