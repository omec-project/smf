// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"testing"
	"time"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/transaction"
	"go.uber.org/zap"
)

// A revert waits on the session's one PFCP response channel, which does not say which request an
// answer belongs to, and it runs outside the transaction queue. A transaction for the same session
// that sent its own PFCP request meanwhile -- a release, a handover, going idle -- could take the
// revert's answer or give it its own. Nothing queued for the session may start processing while a
// revert is owed.
func TestATransactionWaitsForAnOwedRevert(t *testing.T) {
	// What processing reads once it gets past the wait.
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig.Configuration = &factory.Configuration{}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	sm := &smf_context.SMContext{SubFsmLog: zap.NewNop().Sugar(), SubCtxLog: zap.NewNop().Sugar(), SubPduSessLog: zap.NewNop().Sugar()}
	owed := make(chan struct{})
	sm.RevertInFlight = owed

	txn := transaction.NewTransaction(nil, nil, svcmsgtypes.MsgTypeNone)
	txn.Ctxt = sm

	processed := make(chan struct{})
	go func() {
		// The transaction carries no message, so it fails once processed; when is what is tested.
		if _, err := (SmfTxnFsm{}).TxnProcess(txn); err == nil {
			t.Error("a transaction carrying no message was processed as a success")
		}
		close(processed)
	}()

	select {
	case <-processed:
		t.Fatal("a transaction was processed while a revert was owed on its session")
	case <-time.After(300 * time.Millisecond):
	}

	sm.SMLock.Lock()
	sm.RevertInFlight = nil
	sm.SMLock.Unlock()
	close(owed)

	select {
	case <-processed:
	case <-time.After(5 * time.Second):
		t.Fatal("the transaction was never processed after the revert finished")
	}
}
