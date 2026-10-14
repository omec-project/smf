// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"testing"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/transaction"
	"go.uber.org/zap"
)

// pagingFailure delivers the AMF's transfer failure notification to an active session through the
// state machine, as the transaction that carries it does. The session has no tunnel, so the
// paging failure sends the user plane nothing.
func pagingFailure(t *testing.T, modificationPending bool) *smf_context.SMContext {
	t.Helper()

	// Leaving SmStateActive publishes the session, which reads the Kafka switch.
	prevConfig := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prevConfig })
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled}},
	}

	sm := &smf_context.SMContext{
		SubFsmLog:     zap.NewNop().Sugar(),
		SubCtxLog:     zap.NewNop().Sugar(),
		SubPduSessLog: zap.NewNop().Sugar(),
	}
	sm.SMContextState = smf_context.SmStateActive
	sm.NwModificationPending = modificationPending

	txn := transaction.NewTransaction(nil, nil, svcmsgtypes.N1N2MessageTransferFailureNotification)
	txn.Ctxt = sm
	if err := HandleEvent(sm, SmEventPduSessN1N2TransferFailureIndication, SmEventData{Txn: txn}); err != nil {
		t.Fatalf("handling the paging failure: %v", err)
	}

	return sm
}

// A paging failure that meets a network-requested modification leaves the session where the UE's
// answer to the Command is handled. In SmStateInit the Complete met EmptyEventHandler, and T3591
// went on to abandon a modification the UE had applied.
func TestAPagingFailureLeavesAPendingModificationAnswerable(t *testing.T) {
	sm := pagingFailure(t, true)

	if sm.SMContextState != smf_context.SmStateActive {
		t.Errorf("a paging failure during a modification left the session in %s, where the UE's answer is not handled", sm.SMContextState)
	}
}

// Without a modification in flight, a paging failure ends as it always has.
func TestAPagingFailureWithNothingPendingEndsAsBefore(t *testing.T) {
	if sm := pagingFailure(t, false); sm.SMContextState != smf_context.SmStateInit {
		t.Errorf("a paging failure left the session in %s, want %s", sm.SMContextState, smf_context.SmStateInit)
	}
}
