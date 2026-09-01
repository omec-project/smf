// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/qos"
	"go.uber.org/zap"
)

// SelectedSessionRule may legitimately return nil, and callers have to cope.
//
// A modification that adds a PCC rule without touching session rules leaves SessRuleUpdate nil,
// and the fallback to the committed active rule is itself nil on a session that never had one.
// Dereferencing that took the SMF down on a live cluster the first time an application function
// added two flows mid-session — which is the ordinary case, not an exotic one.
func TestSelectedSessionRuleIsNilWhenNothingSuppliesOne(t *testing.T) {
	smContext := &SMContext{
		SubCtxLog: zap.NewNop().Sugar(),
	}

	// A pending update that changes PCC rules but no session rule — exactly what an application
	// function adding a flow produces.
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{}}

	if got := smContext.SelectedSessionRule(); got != nil {
		t.Fatalf("SelectedSessionRule() = %+v, want nil: nothing in this context supplies one", got)
	}
}

// And when one is supplied, it is returned.
func TestSelectedSessionRuleReturnsTheCommittedRule(t *testing.T) {
	rule := &models.SessionRule{
		SessRuleId:   testRuleID1,
		AuthSessAmbr: &models.Ambr{Uplink: testSessionAmbr, Downlink: testSessionAmbr},
	}
	smContext := &SMContext{SubCtxLog: zap.NewNop().Sugar()}
	smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule = rule

	got := smContext.SelectedSessionRule()
	if got == nil || got.SessRuleId != testRuleID1 {
		t.Fatalf("SelectedSessionRule() = %+v, want the committed rule", got)
	}
}
