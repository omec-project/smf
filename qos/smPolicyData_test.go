// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// The session AMBR reaches the gNB, the user plane and the UE as one raw string, and their
// converters do not all read every spelling the same way -- a double space or a lowercase unit is
// read by one and not the others. BuildSmPolicyUpdate is where every one of those readers' input
// comes from, so canonicalizing there is what keeps them agreeing.
func TestBuildSmPolicyUpdateCanonicalizesTheSessionAmbr(t *testing.T) {
	const ruleName = "rule-1"
	decision := models.NewSmPolicyDecision()
	decision.SetSessRules(map[string]models.SessionRule{
		ruleName: {
			SessRuleId:   ruleName,
			AuthSessAmbr: &models.Ambr{Uplink: "100  Mbps", Downlink: "100 mbps"},
		},
	})

	BuildSmPolicyUpdate(&SmCtxtPolicyData{}, decision)

	rule := decision.GetSessRules()[ruleName]
	if rule.AuthSessAmbr.Uplink != ambrAfter {
		t.Errorf("Uplink = %q, want the double space collapsed", rule.AuthSessAmbr.Uplink)
	}
	if rule.AuthSessAmbr.Downlink != ambrAfter {
		t.Errorf("Downlink = %q, want the unit's casing canonicalized", rule.AuthSessAmbr.Downlink)
	}
}

// A session rule with no AMBR at all -- a decision later refused downstream for exactly that --
// must not be dereferenced here before that refusal happens.
func TestBuildSmPolicyUpdateToleratesANilSessionAmbr(t *testing.T) {
	const ruleName = "rule-1"
	decision := models.NewSmPolicyDecision()
	decision.SetSessRules(map[string]models.SessionRule{
		ruleName: {SessRuleId: ruleName},
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BuildSmPolicyUpdate panicked on a session rule with no AMBR: %v", r)
		}
	}()

	BuildSmPolicyUpdate(&SmCtxtPolicyData{}, decision)
}
