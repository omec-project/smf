// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"encoding/json"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

// Traffic control data had both defects QoS data had: compared by pointer, so an unchanged entry of
// a decoded decision read as modified, and committed without its modified entries.
func TestTrafficControlDataIsComparedAndCommittedByValue(t *testing.T) {
	enabled, disabled := models.FLOWSTATUS_ENABLED, models.FLOWSTATUS_DISABLED
	committedTc := models.TrafficControlData{
		TcId:                   "tc",
		FlowStatus:             &enabled,
		MuteNotif:              openapi.PtrBool(false),
		TrafficSteeringPolIdDl: *openapi.NewNullableString(openapi.PtrString("steer")),
	}

	raw, err := json.Marshal(committedTc)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &models.TrafficControlData{}
	if err := json.Unmarshal(raw, decoded); err != nil {
		t.Fatal(err)
	}
	if GetTCDataChanges(decoded, &committedTc) {
		t.Error("an unchanged traffic control entry, decoded afresh, reads as modified")
	}

	var committed SmCtxtPolicyData
	committed.Initialize()
	committed.SmCtxtTCData.TrafficControlData["tc"] = &committedTc

	changed := *decoded
	changed.FlowStatus = &disabled
	update := GetTrafficControlUpdate(map[string]models.TrafficControlData{"tc": changed},
		committed.SmCtxtTCData.TrafficControlData)
	if _, ok := update.GetModified()["tc"]; !ok {
		t.Fatal("disabling the flow does not read as a modification")
	}

	CommitTrafficControlUpdate(&committed, update)
	if got := committed.SmCtxtTCData.TrafficControlData["tc"].GetFlowStatus(); got != disabled {
		t.Errorf("committed flow status = %v, want the accepted %v", got, disabled)
	}
}
