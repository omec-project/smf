// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"testing"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
)

// A modification the SMF could not build in full is not sent. The update is committed and the UE
// told once the user plane has accepted what was built, so a rule left without a PDR or flow QER,
// or a PDR left on its old rates, would be enforced differently from what the UE and the policy
// record say. The revert refused a partial build already; a forward modification sent it.
func TestAModificationThatCannotBeBuiltInFullIsNotSent(t *testing.T) {
	sent := func(t *testing.T) *int {
		t.Helper()
		original, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
		t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = original, originalN1N2 })

		count := 0
		sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
			count++
			return nil
		}
		sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return nil }
		return &count
	}

	// refused applies the update and checks what a refusal leaves: nothing sent, no procedure
	// running, nothing pending, and the session in the state it was in.
	refused := func(t *testing.T, s *twoRuleSession, update *qos.PolicyUpdate, count *int) {
		t.Helper()
		s.sm.ChangeState(smf_context.SmStateActive)
		s.sm.NwModificationPending = false

		err := ApplyModification(s.sm, update)
		if !errors.Is(err, ErrPfcpModifyFailed) {
			t.Fatalf("ApplyModification returned %v, want %v", err, ErrPfcpModifyFailed)
		}
		if *count != 0 {
			t.Errorf("%d modification(s) were sent to the user plane, want none", *count)
		}
		if s.sm.NwModificationPending || s.sm.NwModificationUnsent {
			t.Error("the refused modification is left looking as though it were running")
		}
		if len(s.sm.SmPolicyUpdates) != 0 {
			t.Errorf("%d update(s) left pending, want the refused one discarded", len(s.sm.SmPolicyUpdates))
		}
		if s.sm.SMContextState != smf_context.SmStateActive {
			t.Errorf("the session is %s, want it left Active", s.sm.SMContextState)
		}
	}

	t.Run("an added rule left without its flow QER leaves no PDR in the tunnels", func(t *testing.T) {
		count := sent(t)
		s := newTwoRuleSession(t, false)
		s.withPfcpContext()
		decision := s.addAppRule()
		// The rule names QoS data the decision does not carry, so its flow QERs cannot be built.
		delete(*decision.QosDecs, "2")

		refused(t, s, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision), count)

		node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
		for dir, tunnel := range map[string]*smf_context.GTPTunnel{"uplink": node.UpLinkTunnel, "downlink": node.DownLinkTunnel} {
			if _, ok := tunnel.PDR["app"]; ok {
				t.Errorf("the %s tunnel still holds the PDR of the rule that was not sent", dir)
			}
			if len(tunnel.PDR) != 2 {
				t.Errorf("the %s tunnel holds %d PDRs, want the 2 established", dir, len(tunnel.PDR))
			}
		}
		if _, ok := s.sm.SmPolicyData.SmCtxtPccRules.PccRules["app"]; ok {
			t.Error("the refused rule was committed to the session's policy")
		}
	})

	t.Run("a rule whose uplink F-TEID is unknown keeps its PDRs as they were", func(t *testing.T) {
		count := sent(t)
		s := newTwoRuleSession(t, false)
		// Still carrying the CHOOSE it was established with, on a tunnel that has no TEID recorded.
		chosen := &smf_context.FTEID{Ch: true}
		s.cirUL.PDI.LocalFTeid = chosen
		heldQERs, heldPrecedence, heldState := qerIDs(s.cirUL), s.cirUL.Precedence, s.cirUL.State
		heldDLQERs := qerIDs(s.cirDL)

		refused(t, s, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.rateChange()), count)

		same := func(got, want map[uint32]bool) bool {
			if len(got) != len(want) {
				return false
			}
			for id := range want {
				if !got[id] {
					return false
				}
			}
			return true
		}
		if got := qerIDs(s.cirUL); !same(got, heldQERs) {
			t.Errorf("the uplink PDR carries QERs %v, want %v", got, heldQERs)
		}
		if got := qerIDs(s.cirDL); !same(got, heldDLQERs) {
			t.Errorf("the downlink PDR carries QERs %v, want %v", got, heldDLQERs)
		}
		if s.cirUL.Precedence != heldPrecedence || s.cirUL.State != heldState || s.cirUL.PDI.LocalFTeid != chosen {
			t.Errorf("the uplink PDR was left changed: precedence %d, state %v", s.cirUL.Precedence, s.cirUL.State)
		}
		if got := s.sm.SmPolicyData.SmCtxtQosData.QosData[cirQosID]; got.GetMaxbrUl() != s.cirQosSent.GetMaxbrUl() {
			t.Errorf("the refused rates were committed: %q", got.GetMaxbrUl())
		}
	})

	t.Run("a modification that builds in full is sent", func(t *testing.T) {
		count := sent(t)
		s := newTwoRuleSession(t, false)
		t.Cleanup(func() {
			s.sm.SMLock.Lock()
			s.sm.StopT3591()
			s.sm.SMLock.Unlock()
		})
		s.sm.ChangeState(smf_context.SmStateActive)
		s.sm.NwModificationPending = false

		// The control for the two above: nothing is refused when nothing failed to build.
		if err := ApplyModification(s.sm, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.rateChange())); errors.Is(err, ErrPfcpModifyFailed) {
			t.Fatalf("a modification that builds in full was refused: %v", err)
		}
		if *count != 1 {
			t.Errorf("%d modification(s) were sent, want 1", *count)
		}
	})
}

// discardBuiltRules gives back what the tunnel build took for the rules an update adds, and
// touches no other rule.
func TestDiscardBuiltRulesGivesBackOnlyTheAddedRulesPDRs(t *testing.T) {
	s := newTwoRuleSession(t, false)
	s.withPfcpContext()
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.addAppRule())}

	if param := BuildPfcpParam(s.sm); len(param.pdrList) == 0 {
		t.Fatal("the build made no PDR for the added rule")
	}
	node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
	if node.UpLinkTunnel.PDR["app"] == nil || node.DownLinkTunnel.PDR["app"] == nil {
		t.Fatal("the build left the added rule without a PDR in a tunnel")
	}

	discardBuiltRules(s.sm)

	for dir, tunnel := range map[string]*smf_context.GTPTunnel{"uplink": node.UpLinkTunnel, "downlink": node.DownLinkTunnel} {
		if tunnel.PDR["app"] != nil {
			t.Errorf("the %s tunnel still holds the added rule's PDR", dir)
		}
		if tunnel.PDR[allowRuleID] == nil || tunnel.PDR[cirRuleID] == nil {
			t.Errorf("the %s tunnel lost an established rule's PDR", dir)
		}
	}
}
