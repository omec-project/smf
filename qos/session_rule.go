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
	add, mod, del []*models.SessionRule
}

type PccRulesUpdate struct {
	add, mod, del []*models.PccRule
}

type PolicyUpdate struct {
	SessRuleUpdate *SessRulesUpdate
	PccRuleUpdate  *PccRulesUpdate
}

//Get Session rule changes delta
func GetSessionRuleChanges(pcfSessRules, ctxtSessRules map[string]*models.SessionRule) *SessRulesUpdate {
	var change SessRulesUpdate

	//Iterate through all session rules from PCF and check agains ctxt session rules

	return &change
}
