// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"testing"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
	"go.uber.org/zap"
)

func TestAbandonModificationDiscardsAndSettlesTheSession(t *testing.T) {
	smContext := &smf_context.SMContext{
		Supi:          "imsi-208930100007487",
		PDUSessionID:  10,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		// ChangeState reads the address when a session enters or leaves the active state; a
		// session being modified always has one.
		PDUAddress: &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.1")},
	}
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{}}
	smContext.ChangeState(smf_context.SmStatePfcpModify)

	abandonModification(smContext, "t3591_expiry", "ue_did_not_acknowledge")

	if len(smContext.SmPolicyUpdates) != 0 {
		t.Errorf("pending updates = %d, want the abandoned one discarded", len(smContext.SmPolicyUpdates))
	}
	if smContext.SMContextState != smf_context.SmStateActive {
		t.Errorf("state = %s, want %s so a later modification can be attempted",
			smContext.SMContextState, smf_context.SmStateActive)
	}
	if smContext.T3591 != nil {
		t.Error("the timer handle must be dropped once the procedure is abandoned")
	}
}

// Abandoning twice must not panic. The timer can abort while an acknowledgement is in flight.
func TestAbandonModificationTwiceIsSafe(t *testing.T) {
	smContext := &smf_context.SMContext{
		Supi:          "imsi-208930100007487",
		PDUSessionID:  10,
		SubPduSessLog: zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		// ChangeState reads the address when a session enters or leaves the active state; a
		// session being modified always has one.
		PDUAddress: &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.1")},
	}
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{}}

	abandonModification(smContext, "t3591_expiry", "ue_did_not_acknowledge")
	abandonModification(smContext, "t3591_expiry", "ue_did_not_acknowledge")
}
