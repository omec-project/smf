// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"go.uber.org/zap"
)

// A modification that was never sent must leave nothing behind that waits for an answer.
//
// The state and the pending entry are asserted together on purpose: reverting only the state
// leaves an entry that no response will ever delete, and since the response handlers signal
// SBIPFCPCommunicationChan only once PendingUPF is empty, the next operation to wait on that
// channel would hang.
func TestAbandonPendingModifyClearsBothHalves(t *testing.T) {
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled},
		},
	}

	smContext := &smf_context.SMContext{
		PendingUPF:     smf_context.PendingUPF{"10.0.0.1": true},
		SMContextState: smf_context.SmStatePfcpModify,
		SubCtxLog:      zap.NewNop().Sugar(),
	}

	abandonPendingModify(smContext, smf_context.SmStateN1N2TransferPending)

	if got := smContext.SMContextState; got != smf_context.SmStateN1N2TransferPending {
		t.Errorf("state = %v, want the state from before the modification was attempted", got)
	}
	if !smContext.PendingUPF.IsEmpty() {
		t.Errorf("PendingUPF = %v, want empty: nothing was sent, so nothing can answer", smContext.PendingUPF)
	}
}
