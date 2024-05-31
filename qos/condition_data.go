// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos

import "github.com/omec-project/openapi/models"

type CondDataUpdate struct {
	add, mod, del map[string]*models.ConditionData
}

func GetConditionDataUpdate(condData, ctxtCondData map[string]*models.ConditionData) *CondDataUpdate {
	change := CondDataUpdate{
		add: make(map[string]*models.ConditionData),
		mod: make(map[string]*models.ConditionData),
		del: make(map[string]*models.ConditionData),
	}

	// TODO
	return &change
}

func CommitConditionDataUpdate(smCtxtPolData *SmCtxtPolicyData, update *CondDataUpdate) {
	// TODO
}
