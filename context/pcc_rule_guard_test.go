// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/qos"
	"go.uber.org/zap"
)

// Flow information is optional in a PCC rule: one that identifies an application carries none.
// Both tunnels are built from the same rules, and both read the first flow without looking, so a
// rule the PCF may legitimately send took the SMF down while the tunnel was being built. This
// drives the downlink; the uplink builds from the identical statement.
func TestTheDownlinkTunnelSkipsAPccRuleThatCarriesNoFlows(t *testing.T) {
	upf := NewUPF(NewNodeID("10.0.0.1"), nil)
	upf.UPFStatus = AssociatedSetUpSuccess

	node := &DataPathNode{
		UPF:            upf,
		UpLinkTunnel:   &GTPTunnel{PDR: make(map[string]*PDR)},
		DownLinkTunnel: &GTPTunnel{PDR: make(map[string]*PDR)},
	}

	appID := "app-1"
	smContext := &SMContext{Supi: testSupi, SubCtxLog: zap.NewNop().Sugar()}
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{
		PccRuleUpdate: qos.GetPccRulesUpdate(map[string]models.PccRule{
			"app-rule": {PccRuleId: "app-rule", AppId: &appID},
		}, nil),
	}}

	// The call fails at the end, putting PDRs into a PFCP session this fixture never established.
	// What is under test is that it gets that far at all rather than dying on the rule.
	if err := node.ActivateDownLinkTunnel(smContext); err != nil {
		t.Logf("tunnel activation reported %v, which is this fixture's missing PFCP session", err)
	}

	if _, built := node.DownLinkTunnel.PDR["app-rule"]; built {
		t.Error("a PDR was built for a rule carrying nothing to build one from")
	}
}
