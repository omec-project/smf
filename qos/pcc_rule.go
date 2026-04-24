// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"github.com/omec-project/openapi/models"
)

type PccRulesUpdate struct {
	add, mod, del map[string]*models.PccRule
}

func GetPccRulesUpdate(pcfPccRules, ctxtPccRules map[string]*models.PccRule) *PccRulesUpdate {
	if len(pcfPccRules) == 0 {
		return nil
	}

	change := PccRulesUpdate{
		add: make(map[string]*models.PccRule),
		mod: make(map[string]*models.PccRule),
		del: make(map[string]*models.PccRule),
	}

	// Compare against Ctxt rules to get added or modified rules
	for name, pcfRule := range pcfPccRules {
		// if pcfRule is nil then it need to be deleted
		if pcfRule == nil {
			change.del[name] = pcfRule // nil
			continue
		}

		// match against SM ctxt Rules for add/mod
		if ctxtrule := ctxtPccRules[name]; ctxtrule == nil {
			change.add[name] = pcfRule
		} else if GetPccRuleChanges(pcfRule, ctxtrule) {
			change.mod[name] = pcfRule
		}
	}

	return &change
}

func CommitPccRulesUpdate(smCtxtPolData *SmCtxtPolicyData, update *PccRulesUpdate) {
	// Iterate through Add/Mod/Del rules

	// Add new Rules
	if len(update.add) > 0 {
		for name, rule := range update.add {
			smCtxtPolData.SmCtxtPccRules.PccRules[name] = rule
		}
	}

	// Mod rules
	// TODO

	// Del Rules
	if len(update.del) > 0 {
		for name := range update.del {
			delete(smCtxtPolData.SmCtxtPccRules.PccRules, name)
		}
	}
}

// Get the difference between 2 pcc rules
func GetPccRuleChanges(s, d *models.PccRule) bool {
	if s == nil || d == nil {
		return true
	}

	if s.PccRuleId != d.PccRuleId ||
		s.AppId != d.AppId ||
		s.ContVer != d.ContVer ||
		s.Precedence != d.Precedence ||
		s.AfSigProtocol != d.AfSigProtocol ||
		s.AppReloc != d.AppReloc ||
		s.RefCondData != d.RefCondData {
		return true
	}

	if !stringSlicesEqual(s.RefQosData, d.RefQosData) ||
		!stringSlicesEqual(s.RefTcData, d.RefTcData) ||
		!stringSlicesEqual(s.RefChgData, d.RefChgData) ||
		!stringSlicesEqual(s.RefUmData, d.RefUmData) {
		return true
	}

	if len(s.FlowInfos) != len(d.FlowInfos) {
		return true
	}
	for i := range s.FlowInfos {
		if s.FlowInfos[i] != d.FlowInfos[i] {
			return true
		}
	}

	return false
}

// Helper to compare two string slices (order matters)
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (upd *PccRulesUpdate) GetAddPccRuleUpdate() map[string]*models.PccRule {
	return upd.add
}
