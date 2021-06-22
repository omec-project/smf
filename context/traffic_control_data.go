// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package context

import (
	"github.com/free5gc/openapi/models"
)

// TrafficControlData - Traffic control data defines how traffic data flows
// associated with a rule are treated (e.g. blocked, redirected).
type TrafficControlData struct {
	// shall include attribute
	TrafficControlID string

	// maybe include attribute
	FlowStatus     models.FlowStatus
	RouteToLocs    []models.RouteToLocation
	UpPathChgEvent *models.UpPathChgEvent

	// referenced dataType
	refedPCCRule map[string]*PCCRule
}

// NewTrafficControlDataFromModel - create the traffic control data from OpenAPI model
func NewTrafficControlDataFromModel(model *models.TrafficControlData) *TrafficControlData {
	trafficControlData := new(TrafficControlData)

	trafficControlData.TrafficControlID = model.TcId
	trafficControlData.FlowStatus = model.FlowStatus
	trafficControlData.RouteToLocs = model.RouteToLocs
	trafficControlData.UpPathChgEvent = model.UpPathChgEvent

	trafficControlData.refedPCCRule = make(map[string]*PCCRule)

	return trafficControlData
}

// RefedPCCRules - returns the PCCRules that reference this tcData
func (tc *TrafficControlData) RefedPCCRules() map[string]*PCCRule {
	return tc.refedPCCRule
}

/*func (tc *TrafficControlData) AddRefedPCCRules(PCCref string) {
	tc.refedPCCRule[tc.PCCref] = PCCref
}

func (tc *TrafficControlData) DeleteRefedPCCRules(PCCref string) {
	delete(tc.refedPCCRule, PCCref)
}*/
