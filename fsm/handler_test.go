// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"net"
	"testing"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/qos"
	"github.com/omec-project/smf/transaction"
	"go.uber.org/zap"
)

// A modification whose delivery failed and whose user-plane revert failed too is marked for
// release by the producer, and the state the FSM applies afterwards has to keep that mark. The
// handler returned Init for it, and HandleEvent applies whatever the handler returns, so the
// session that needs releasing was relabelled as one that had never been set up.
//
// The revert fails for real here: the session has no tunnel, so the PFCP send refuses it.
func TestARevertThatFailedLeavesTheSessionMarkedForRelease(t *testing.T) {
	// Every state change publishes the session, which reads this.
	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig = factory.Config{Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &off}}}
	}

	log := zap.NewNop().Sugar()
	sm := &smf_context.SMContext{
		Supi:                  "imsi-208930000000101",
		PDUSessionID:          10,
		SMContextState:        smf_context.SmStateActive,
		NwModificationPending: true,
		SubPduSessLog:         log,
		SubCtxLog:             log,
		SubFsmLog:             log,
		SubPfcpLog:            log,
		PDUAddress:            &smf_context.UeIpAddr{Ip: net.ParseIP("192.168.100.2")},
	}
	sm.SmPolicyUpdates = []*qos.PolicyUpdate{{}}

	txn := &transaction.Transaction{Ctxt: sm}
	if err := HandleEvent(sm, SmEventPduSessN1N2TransferFailureIndication, SmEventData{Txn: txn}); err != nil {
		t.Fatalf("handling the failure indication: %v", err)
	}

	if sm.SMContextState != smf_context.SmStatePfcpRelease {
		t.Errorf("state = %s, want %s: the session runs parameters the UE was never told about",
			sm.SMContextState, smf_context.SmStatePfcpRelease)
	}
}
