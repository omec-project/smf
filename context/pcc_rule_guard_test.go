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

// countAllocated reports how many PDRs and FARs the user plane still holds.
func countAllocated(upf *UPF) (pdrs, fars int) {
	upf.pdrPool.Range(func(_, _ any) bool { pdrs++; return true })
	upf.farPool.Range(func(_, _ any) bool { fars++; return true })

	return pdrs, fars
}

// A refused activation gives back what it allocated. The tunnels are built before the session QER,
// so a session refused at the QER leaves PDRs and FARs on the user plane -- and the caller of a
// refused activation rejects the session and never releases it, which is the only thing that
// returns those ids. A policy that supplies no session rule refuses every session, so the pools
// drain one attempt at a time until the user plane can allocate nothing at all.
func TestARefusedActivationReturnsWhatItAllocated(t *testing.T) {
	upf := NewUPF(NewNodeID("10.0.0.2"), nil)
	upf.UPFStatus = AssociatedSetUpSuccess

	node := &DataPathNode{
		UPF:            upf,
		UpLinkTunnel:   &GTPTunnel{PDR: make(map[string]*PDR)},
		DownLinkTunnel: &GTPTunnel{PDR: make(map[string]*PDR)},
	}
	dataPath := &DataPath{FirstDPNode: node}

	smContext := NewSMContext(testSupi, 11)
	// The PFCP context a session reaching this point already has; supplied here so the fixture
	// does not need the SEID allocator, which belongs to a configured SMF.
	smContext.PFCPContext[upf.NodeID.ResolveNodeIdToIp().String()] = &PFCPSessionContext{
		PDRs:      make(map[uint16]*PDR),
		NodeID:    upf.NodeID,
		LocalSEID: 1,
	}

	// A pending update with no session rule: the tunnels build, and the session QER cannot.
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{}}

	if err := dataPath.ActivateTunnelAndPDR(smContext, 255); err == nil {
		t.Fatal("activation with no session rule reported success")
	}

	if pdrs, fars := countAllocated(upf); pdrs != 0 || fars != 0 {
		t.Errorf("after a refused activation the user plane still holds %d PDRs and %d FARs; every refused session keeps its own", pdrs, fars)
	}
}
