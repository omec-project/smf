// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

func TestGetSessionRulesUpdateUsesDistinctPointersPerEntry(t *testing.T) {
	pcfRules := map[string]models.SessionRule{
		"add":   {SessRuleId: "sess-add"},
		"add-2": {SessRuleId: "sess-add-2"},
	}
	ctxtRules := map[string]*models.SessionRule{}

	update := GetSessionRulesUpdate(&pcfRules, ctxtRules)
	if update == nil {
		t.Fatal("expected non-nil update")
	}
	if update.add["add"] == update.add["add-2"] {
		t.Fatal("expected add entries to point to distinct copies")
	}
	if update.add["add"].GetSessRuleId() != "sess-add" {
		t.Fatalf("unexpected add rule id %q", update.add["add"].GetSessRuleId())
	}
	if update.add["add-2"].GetSessRuleId() != "sess-add-2" {
		t.Fatalf("unexpected add rule id %q", update.add["add-2"].GetSessRuleId())
	}
	if update.ActiveSessRule == nil {
		t.Fatal("expected active rule to be set")
	}
	if got := update.ActiveSessRule.GetSessRuleId(); got != "sess-add" && got != "sess-add-2" {
		t.Fatalf("unexpected active rule %+v", update.ActiveSessRule)
	}
}

func TestGetSessionRulesUpdateDeletePointersRemainDistinct(t *testing.T) {
	pcfRules := map[string]models.SessionRule{
		"del-a": {},
		"del-b": {},
	}

	update := GetSessionRulesUpdate(&pcfRules, map[string]*models.SessionRule{})
	if update.del["del-a"] == update.del["del-b"] {
		t.Fatal("expected distinct delete pointers")
	}
}

func TestGetPccRulesUpdateUsesDistinctPointersPerEntry(t *testing.T) {
	pcfRules := map[string]models.PccRule{
		"add":   {PccRuleId: "pcc-add"},
		"add-2": {PccRuleId: "pcc-add-2"},
		"del-a": {},
		"del-b": {},
	}
	ctxtRules := map[string]*models.PccRule{}

	update := GetPccRulesUpdate(pcfRules, ctxtRules)
	if update.add["add"] == update.add["add-2"] {
		t.Fatal("expected distinct add pointers")
	}
	if update.del["del-a"] == update.del["del-b"] {
		t.Fatal("expected distinct delete pointers")
	}
	if update.add["add"].GetPccRuleId() != "pcc-add" || update.add["add-2"].GetPccRuleId() != "pcc-add-2" {
		t.Fatal("unexpected pcc rule ids in update")
	}
}

func TestGetQosFlowDescUpdateUsesDistinctPointersPerEntry(t *testing.T) {
	pcfQos := map[string]models.QosData{
		"add":   {QosId: "qos-add"},
		"add-2": {QosId: "qos-add-2"},
		"del-a": {},
		"del-b": {},
	}
	ctxtQos := map[string]*models.QosData{}

	update := GetQosFlowDescUpdate(&pcfQos, ctxtQos)
	if update.add["add"] == update.add["add-2"] {
		t.Fatal("expected distinct add pointers")
	}
	if update.del["del-a"] == update.del["del-b"] {
		t.Fatal("expected distinct delete pointers")
	}
	if update.add["add"].GetQosId() != "qos-add" || update.add["add-2"].GetQosId() != "qos-add-2" {
		t.Fatal("unexpected qos ids in update")
	}
}

func TestGetTrafficControlUpdateUsesDistinctPointersPerEntry(t *testing.T) {
	pcfTc := map[string]models.TrafficControlData{
		"add":   {TcId: "tc-add"},
		"add-2": {TcId: "tc-add-2"},
		"del-a": {},
		"del-b": {},
	}
	ctxtTc := map[string]*models.TrafficControlData{}

	update := GetTrafficControlUpdate(&pcfTc, ctxtTc)
	if update.add["add"] == update.add["add-2"] {
		t.Fatal("expected distinct add pointers")
	}
	if update.del["del-a"] == update.del["del-b"] {
		t.Fatal("expected distinct delete pointers")
	}
	if update.add["add"].GetTcId() != "tc-add" || update.add["add-2"].GetTcId() != "tc-add-2" {
		t.Fatal("unexpected traffic control ids in update")
	}
}
