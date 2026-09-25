// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"encoding/json"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

// A decision arrives decoded from JSON, so an unchanged QoS entry shares no pointer with the one
// the session committed. Compared by pointer it read as modified on every notification.
func TestGetQosDataChangesComparesValuesNotPointers(t *testing.T) {
	committed := models.QosData{
		QosId:                "1",
		Var5qi:               openapi.PtrInt32(1),
		MaxbrUl:              *openapi.NewNullableString(openapi.PtrString("3 Mbps")),
		MaxbrDl:              *openapi.NewNullableString(openapi.PtrString("6 Mbps")),
		GbrUl:                *openapi.NewNullableString(openapi.PtrString("1 Mbps")),
		GbrDl:                *openapi.NewNullableString(openapi.PtrString("2 Mbps")),
		PriorityLevel:        *openapi.NewNullableInt32(openapi.PtrInt32(20)),
		DefQosFlowIndication: openapi.PtrBool(false),
		Arp: &models.Arp{
			PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(5)),
			PreemptCap:    models.PREEMPTIONCAPABILITY_NOT_PREEMPT,
			PreemptVuln:   models.PREEMPTIONVULNERABILITY_PREEMPTABLE,
		},
	}

	decode := func(q models.QosData) *models.QosData {
		raw, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		out := &models.QosData{}
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if GetQosDataChanges(decode(committed), &committed) {
		t.Error("an unchanged QoS entry, decoded afresh, reads as modified")
	}

	for name, edit := range map[string]func(*models.QosData){
		"GBR uplink":   func(q *models.QosData) { q.GbrUl = *openapi.NewNullableString(openapi.PtrString("1500 Kbps")) },
		"MBR downlink": func(q *models.QosData) { q.MaxbrDl = *openapi.NewNullableString(openapi.PtrString("8 Mbps")) },
		"5QI":          func(q *models.QosData) { q.Var5qi = openapi.PtrInt32(2) },
		"5QI absent":   func(q *models.QosData) { q.Var5qi = nil },
		"ARP priority": func(q *models.QosData) {
			arp := *q.Arp
			arp.PriorityLevel = *openapi.NewNullableInt32(openapi.PtrInt32(6))
			q.Arp = &arp
		},
		"GBR withdrawn": func(q *models.QosData) { q.GbrDl = *openapi.NewNullableString(nil) },
	} {
		changed := decode(committed)
		edit(changed)
		if !GetQosDataChanges(changed, &committed) {
			t.Errorf("%s: a changed QoS entry reads as unchanged", name)
		}
	}
}
