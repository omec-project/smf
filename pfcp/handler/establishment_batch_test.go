// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
)

// ensureSmfConfig provides the minimal factory configuration NewSMContext dereferences, matching the
// guard the other handler tests use.
func ensureSmfConfig() {
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: openapi.PtrBool(false)},
				EnableUpfAdapter: false,
			},
		}
	}
}

// TestFailPendingEstablishmentDrainsBatchAndSignalsFailure covers the fix for a create whose
// establishment response is unusable (missing/garbled Cause, missing NodeID, etc.). The PFCP
// transaction has already been consumed by the time the handler detects the problem, so every early
// return past that point must fold the response into the create's PendingUPF batch as this UPF's
// failure -- otherwise the entry never clears and the create FSM's blocking receive on
// SBIPFCPCommunicationChan hangs forever. The verdict is queued exactly when the last pending UPF
// drains, and it is a failure because an unusable response cannot be a success.
func TestFailPendingEstablishmentDrainsBatchAndSignalsFailure(t *testing.T) {
	ensureSmfConfig()
	smContext := context.NewSMContext("imsi-100000000000021", 10)
	smContext.ChangeState(context.SmStatePfcpCreatePending)

	// The key every PendingUPF correlation uses: the UPF address as recorded at dispatch, which the
	// handler recovers from the response's local SEID (GetPFCPContextKeyByLocalSEID) rather than by
	// re-resolving the NodeID.
	keyA := context.NewNodeID("1.1.1.1").ResolveNodeIdToIp().String()
	keyB := context.NewNodeID("1.1.1.2").ResolveNodeIdToIp().String()
	smContext.AddPendingUPF(keyA)
	smContext.AddPendingUPF(keyB)

	// First unusable response: the batch still holds B, so no verdict is queued yet.
	failPendingEstablishment(smContext, keyA)
	if len(smContext.SBIPFCPCommunicationChan) != 0 {
		t.Fatalf("a verdict was queued before the batch drained")
	}

	// Second unusable response empties the batch, so the aggregated failure verdict is queued and the
	// create FSM can complete instead of blocking on an entry nothing else would ever clear.
	failPendingEstablishment(smContext, keyB)
	select {
	case v := <-smContext.SBIPFCPCommunicationChan:
		if v != context.SessionEstablishFailed {
			t.Fatalf("verdict = %v, want SessionEstablishFailed", v)
		}
	default:
		t.Fatalf("no verdict queued after the batch drained; the create FSM would block forever")
	}
}

// TestFailPendingEstablishmentIgnoresResponseOutsideCreate covers the state gate: smContext.PendingUPF
// is shared with the awaited modification and the release flows, so an establishment response arriving
// when the session is not create-pending (a stale duplicate, say) must not delete an entry another
// operation owns or queue an establishment verdict nothing is waiting for.
func TestFailPendingEstablishmentIgnoresResponseOutsideCreate(t *testing.T) {
	ensureSmfConfig()
	smContext := context.NewSMContext("imsi-100000000000022", 10)
	smContext.ChangeState(context.SmStatePfcpModify)

	key := context.NewNodeID("1.1.1.3").ResolveNodeIdToIp().String()
	smContext.AddPendingUPF(key)

	failPendingEstablishment(smContext, key)

	if smContext.PendingUPFIsEmpty() {
		t.Error("failPendingEstablishment drained a batch that did not belong to a create")
	}
	if len(smContext.SBIPFCPCommunicationChan) != 0 {
		t.Error("failPendingEstablishment queued a verdict outside a create")
	}
}
