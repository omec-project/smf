// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"testing"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/transaction"
)

// Every PFCP establishment failure reaches the create-failure handler -- a UPF that refused, a
// request that timed out, an adapter error, a verdict collected across several UPFs -- so that is
// where Lawful Interception hears of it. A PFCP send-error handler is not such a point: the native
// establishment path does not use one, so a record raised there would leave a tasked subject's
// failed establishment unreported, and one that failed after the anchor accepted with its
// establishment record and its trigger standing.
//
// The hook must run while the context exists: the record and the withdrawal both read the session,
// and the handler removes it.
func TestTheCreateFailureHandlerReportsTheFailedEstablishment(t *testing.T) {
	prevConfig := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prevConfig })
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled}},
	}

	sm := smf_context.NewSMContext("imsi-262019876543210", 6)
	t.Cleanup(func() { smf_context.RemoveSMContext(sm.Ref) })
	sm.SMContextState = smf_context.SmStatePfcpCreatePending

	var (
		calls         int
		presentAtCall bool
	)
	hook := liEstablishmentFailed
	liEstablishmentFailed = func(sc *smf_context.SMContext) {
		calls++
		presentAtCall = sc == sm && smf_context.GetSMContext(sm.Ref) != nil
	}
	t.Cleanup(func() { liEstablishmentFailed = hook })

	txn := transaction.NewTransaction(nil, nil, svcmsgtypes.PfcpSessCreateFailure)
	txn.Ctxt = sm
	// The failure notice to the AMF has nowhere to go here, so the handler reports an error; what
	// is asserted is the interception outcome, which is decided before that notice is sent.
	if err := HandleEvent(sm, SmEventPfcpSessCreateFailure, SmEventData{Txn: txn}); err != nil {
		t.Logf("the create-failure handler: %v", err)
	}

	if calls != 1 {
		t.Fatalf("the create-failure handler raised the LI hook %d times, want 1", calls)
	}
	if !presentAtCall {
		t.Error("the LI hook ran without the failed session's context in place; the record and the " +
			"withdrawal read it")
	}
	if smf_context.GetSMContext(sm.Ref) != nil {
		t.Error("the failed session's context was not removed: the test did not run the handler through")
	}
}
