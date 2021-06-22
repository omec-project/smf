// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package context

import (
	"github.com/free5gc/openapi/models"
)

// PCCRule - Policy and Charging Rule
type PCCRule struct {
	// shall include attribute
	PCCRuleID  string
	Precedence int32

	// maybe include attribute
	AppID     string
	FlowInfos []models.FlowInformation

	// Reference Data
	refTrafficControlData *TrafficControlData

	// related Data
	Datapath *DataPath
}

// NewPCCRuleFromModel - create PCC rule from OpenAPI models
func NewPCCRuleFromModel(pccModel *models.PccRule) *PCCRule {
	if pccModel == nil {
		return nil
	}
	pccRule := new(PCCRule)

	pccRule.PCCRuleID = pccModel.PccRuleId
	pccRule.Precedence = pccModel.Precedence
	pccRule.AppID = pccModel.AppId
	pccRule.FlowInfos = pccModel.FlowInfos

	return pccRule
}

// SetRefTrafficControlData - setting reference traffic control data
func (r *PCCRule) SetRefTrafficControlData(tcData *TrafficControlData) {
	r.refTrafficControlData = tcData

	tcData.refedPCCRule[r.PCCRuleID] = r
}

// GetRefTrafficControlData - returns refernece traffic control data
func (r *PCCRule) RefTrafficControlData() *TrafficControlData {
	return r.refTrafficControlData
}

func (r *PCCRule) ResetRefTrafficControlData() {
	if refTcData := r.refTrafficControlData; refTcData != nil {
		delete(refTcData.refedPCCRule, r.PCCRuleID)
	}

	r.refTrafficControlData = nil
}
