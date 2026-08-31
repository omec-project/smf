// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

const (
	testKeyAdd  = "add"
	testKeyAdd2 = "add-2"
	testKeyDelA = "del-a"
	testKeyDelB = "del-b"

	testSessAdd  = "sess-add"
	testSessAdd2 = "sess-add-2"
)

func TestGetSessionRulesUpdateUsesDistinctPointersPerEntry(t *testing.T) {
	pcfRules := map[string]models.SessionRule{
		testKeyAdd:  {SessRuleId: testSessAdd},
		testKeyAdd2: {SessRuleId: testSessAdd2},
	}
	ctxtRules := map[string]*models.SessionRule{}

	update := GetSessionRulesUpdate(pcfRules, ctxtRules)
	if update == nil {
		t.Fatal("expected non-nil update")
		return
	}
	if update.add[testKeyAdd] == update.add[testKeyAdd2] {
		t.Fatal("expected add entries to point to distinct copies")
	}
	if update.add[testKeyAdd].GetSessRuleId() != testSessAdd {
		t.Fatalf("unexpected add rule id %q", update.add[testKeyAdd].GetSessRuleId())
	}
	if update.add[testKeyAdd2].GetSessRuleId() != testSessAdd2 {
		t.Fatalf("unexpected add rule id %q", update.add[testKeyAdd2].GetSessRuleId())
	}
	if update.ActiveSessRule == nil {
		t.Fatal("expected active rule to be set")
		return
	}
	if got := update.ActiveSessRule.GetSessRuleId(); got != testSessAdd && got != testSessAdd2 {
		t.Fatalf("unexpected active rule %+v", update.ActiveSessRule)
	}
}

func TestGetSessionRulesUpdateDeletePointersRemainDistinct(t *testing.T) {
	pcfRules := map[string]models.SessionRule{
		testKeyDelA: {},
		testKeyDelB: {},
	}

	update := GetSessionRulesUpdate(pcfRules, map[string]*models.SessionRule{})
	if update.del[testKeyDelA] == update.del[testKeyDelB] {
		t.Fatal("expected distinct delete pointers")
	}
}

func TestGetPccRulesUpdateUsesDistinctPointersPerEntry(t *testing.T) {
	pcfRules := map[string]models.PccRule{
		testKeyAdd:  {PccRuleId: "pcc-add"},
		testKeyAdd2: {PccRuleId: "pcc-add-2"},
		testKeyDelA: {},
		testKeyDelB: {},
	}
	ctxtRules := map[string]*models.PccRule{}

	update := GetPccRulesUpdate(pcfRules, ctxtRules)
	if update.add[testKeyAdd] == update.add[testKeyAdd2] {
		t.Fatal("expected distinct add pointers")
	}
	if update.del[testKeyDelA] == update.del[testKeyDelB] {
		t.Fatal("expected distinct delete pointers")
	}
	if update.add[testKeyAdd].GetPccRuleId() != "pcc-add" || update.add[testKeyAdd2].GetPccRuleId() != "pcc-add-2" {
		t.Fatal("unexpected pcc rule ids in update")
	}
}

func TestGetQosFlowDescUpdateUsesDistinctPointersPerEntry(t *testing.T) {
	pcfQos := map[string]models.QosData{
		testKeyAdd:  {QosId: "qos-add"},
		testKeyAdd2: {QosId: "qos-add-2"},
		testKeyDelA: {},
		testKeyDelB: {},
	}
	ctxtQos := map[string]*models.QosData{}

	update := GetQosFlowDescUpdate(pcfQos, ctxtQos)
	if update.add[testKeyAdd] == update.add[testKeyAdd2] {
		t.Fatal("expected distinct add pointers")
	}
	if update.del[testKeyDelA] == update.del[testKeyDelB] {
		t.Fatal("expected distinct delete pointers")
	}
	if update.add[testKeyAdd].GetQosId() != "qos-add" || update.add[testKeyAdd2].GetQosId() != "qos-add-2" {
		t.Fatal("unexpected qos ids in update")
	}
}

func TestGetTrafficControlUpdateUsesDistinctPointersPerEntry(t *testing.T) {
	pcfTc := map[string]models.TrafficControlData{
		testKeyAdd:  {TcId: "tc-add"},
		testKeyAdd2: {TcId: "tc-add-2"},
		testKeyDelA: {},
		testKeyDelB: {},
	}
	ctxtTc := map[string]*models.TrafficControlData{}

	update := GetTrafficControlUpdate(pcfTc, ctxtTc)
	if update.add[testKeyAdd] == update.add[testKeyAdd2] {
		t.Fatal("expected distinct add pointers")
	}
	if update.del[testKeyDelA] == update.del[testKeyDelB] {
		t.Fatal("expected distinct delete pointers")
	}
	if update.add[testKeyAdd].GetTcId() != "tc-add" || update.add[testKeyAdd2].GetTcId() != "tc-add-2" {
		t.Fatal("unexpected traffic control ids in update")
	}
}
