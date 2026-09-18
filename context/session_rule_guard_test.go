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
		SessRuleId:   "rule-1",
		AuthSessAmbr: &models.Ambr{Uplink: "50 Mbps", Downlink: "50 Mbps"},
	}
	smContext := &SMContext{SubCtxLog: zap.NewNop().Sugar()}
	smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule = rule

	got := smContext.SelectedSessionRule()
	if got == nil || got.SessRuleId != "rule-1" {
		t.Fatalf("SelectedSessionRule() = %+v, want the committed rule", got)
	}
}

// The session QER is the one every PDR on the path carries, and the caller appends what this
// returns without looking. Handing back a nil QER with no error therefore does not avoid the
// failure, it moves it: the PFCP builders dereference each QER in the list, so the session dies
// later and somewhere that cannot say why.
func TestTheSessionQerIsRefusedRatherThanReturnedEmpty(t *testing.T) {
	node := &DataPathNode{UPF: &UPF{NodeID: *NewNodeID("10.0.0.1")}}

	// A session with a pending update but no session rule -- an update that changes PCC rules and
	// nothing else, which is what an application function adding a flow produces.
	smContext := &SMContext{
		Supi:      "imsi-208930000000001",
		SubCtxLog: zap.NewNop().Sugar(),
	}
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{}}

	qer, err := node.CreateSessRuleQer(smContext)
	if err == nil {
		t.Error("building the session QER with no session rule reported success")
	}

	if qer != nil {
		t.Errorf("CreateSessRuleQer() = %+v alongside its refusal; the caller appends what it gets", qer)
	}
}

// And with nothing pending at all, which is the state the user plane is rebuilt in when an
// undelivered modification is reverted.
func TestTheSessionQerIsRefusedWhenNothingIsPendingAndNothingIsCommitted(t *testing.T) {
	node := &DataPathNode{UPF: &UPF{NodeID: *NewNodeID("10.0.0.1")}}
	smContext := &SMContext{
		Supi:      "imsi-208930000000001",
		SubCtxLog: zap.NewNop().Sugar(),
	}

	qer, err := node.CreateSessRuleQer(smContext)
	if err == nil || qer != nil {
		t.Errorf("CreateSessRuleQer() = %+v, %v; want a refusal and no QER", qer, err)
	}
}
