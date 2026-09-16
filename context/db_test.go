// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

package context

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/omec-project/smf/factory"
	"github.com/omec-project/util/mongoapi"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// fakeDeleteOneDBClient implements mongoapi.DBInterface, answering RestfulAPIDeleteOne with
// failThenSucceed errors before succeeding. All other methods are unused by the code under test.
type fakeDeleteOneDBClient struct {
	mongoapi.DBInterface
	failThenSucceed int32 // number of calls that should fail before one succeeds
	calls           int32
}

func (f *fakeDeleteOneDBClient) RestfulAPIDeleteOne(_ string, _ bson.M) error {
	if atomic.AddInt32(&f.calls, 1) <= atomic.LoadInt32(&f.failThenSucceed) {
		return errors.New("simulated mongo delete failure")
	}
	return nil
}

// withSmContextWriteWorkers swaps in fake and a fresh worker pool for the duration of fn, then
// restores the previous CommonDBClient.
func withSmContextWriteWorkers(t *testing.T, fake *fakeDeleteOneDBClient, fn func()) {
	t.Helper()
	prevClient := mongoapi.CommonDBClient
	prevQueues := smContextWriteQueues
	mongoapi.CommonDBClient = fake
	startSmContextWriteWorkers()
	defer func() {
		mongoapi.CommonDBClient = prevClient
		smContextWriteQueues = prevQueues
	}()
	fn()
}

func TestDeleteSmContextInDBByRef_RetriesUntilSuccess(t *testing.T) {
	fake := &fakeDeleteOneDBClient{failThenSucceed: 2}
	ref := "some-ref-retries-until-success"
	withSmContextWriteWorkers(t, fake, func() {
		DeleteSmContextInDBByRef(ref)
	})
	if got := atomic.LoadInt32(&fake.calls); got != 3 {
		t.Errorf("expected 3 delete attempts (2 failures + 1 success), got %d", got)
	}
	if IsSmContextDeleteFailed(ref) {
		t.Errorf("ref %q succeeded on retry and must not be tombstoned", ref)
	}
}

func TestDeleteSmContextInDBByRef_GivesUpAfterMaxAttempts(t *testing.T) {
	fake := &fakeDeleteOneDBClient{failThenSucceed: 100}
	ref := "some-ref-gives-up"
	withSmContextWriteWorkers(t, fake, func() {
		DeleteSmContextInDBByRef(ref)
	})
	if got := atomic.LoadInt32(&fake.calls); got != 3 {
		t.Errorf("expected exactly 3 delete attempts before giving up, got %d", got)
	}
	if !IsSmContextDeleteFailed(ref) {
		t.Errorf("expected ref %q to be tombstoned as a delete failure", ref)
	}
}

// fakeGetOneDBClient implements mongoapi.DBInterface, answering RestfulAPIGetOne with a fixed
// document regardless of the filter. All other methods are unused by the code under test.
type fakeGetOneDBClient struct {
	mongoapi.DBInterface
	doc map[string]any
}

func (f *fakeGetOneDBClient) RestfulAPIGetOne(_ string, _ bson.M) (map[string]any, error) {
	return f.doc, nil
}

// TestGetSMContext_DoesNotResurrectAfterDeleteFailed covers the rollback scenario a failed
// DeleteSmContextInDBByRef leaves behind: the by-ref document is still in Mongo, but the ref must
// not be readable back into the pool because RemoveSMContextLocked already released it.
func TestGetSMContext_DoesNotResurrectAfterDeleteFailed(t *testing.T) {
	prevClient := mongoapi.CommonDBClient
	prevConfig := factory.SmfConfig
	defer func() {
		mongoapi.CommonDBClient = prevClient
		factory.SmfConfig = prevConfig
	}()
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{EnableDbStore: true},
	}

	ref := "some-ref-resurrection-check"
	staleDoc := map[string]any{refFilterKey: ref}
	mongoapi.CommonDBClient = &fakeGetOneDBClient{doc: staleDoc}

	smContextDeleteFailed.Store(ref, struct{}{})
	defer smContextDeleteFailed.Delete(ref)

	if got := GetSMContext(ref); got != nil {
		t.Errorf("expected GetSMContext(%q) to return nil while tombstoned as a delete failure, got %+v", ref, got)
	}
	if _, ok := smContextPool.Load(ref); ok {
		t.Errorf("expected ref %q to not be resurrected into smContextPool", ref)
	}

	// Sanity check: with the tombstone cleared, the same stale document is loaded normally,
	// proving the nil result above came from the tombstone and not the test fixture.
	smContextDeleteFailed.Delete(ref)
	if got := GetSMContext(ref); got == nil {
		t.Errorf("expected GetSMContext(%q) to fall back to Mongo once the tombstone is cleared", ref)
	}
	smContextPool.Delete(ref)
}
