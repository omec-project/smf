// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

package context

import (
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/omec-project/openapi/v2/Namf_Communication"
	"github.com/omec-project/openapi/v2/Npcf_SMPolicyControl"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/util/mongoapi"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// fakeDeleteOneDBClient implements mongoapi.DBInterface, answering RestfulAPIDeleteOne with
// failThenSucceed errors before succeeding. All other methods are unused by the code under test.
type fakeDeleteOneDBClient struct {
	mongoapi.DBInterface
	failThenSucceed int32 // number of calls that should fail before one succeeds
	calls           atomic.Int32
}

func (f *fakeDeleteOneDBClient) RestfulAPIDeleteOne(_ string, _ bson.M) error {
	if f.calls.Add(1) <= atomic.LoadInt32(&f.failThenSucceed) {
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
	if got := fake.calls.Load(); got != 3 {
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
	if got := fake.calls.Load(); got != 3 {
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

// TestSMContextDBRoundTrip_PreservesFieldsAcrossSerializerMigration is a representative
// store/recover regression test for the Sonic -> go-json serializer migration: it exercises
// ToBsonM's custom PFCP/tunnel/BPManager transformations and the API-client shadowing, then
// recovers via SMContext.UnmarshalJSON exactly as GetSMContextByRefInDB does, so a future encoder
// swap that silently drops or reshapes persisted fields fails here instead of in production.
func TestSMContextDBRoundTrip_PreservesFieldsAcrossSerializerMigration(t *testing.T) {
	sd := "0a0b0c"
	defaultSessionType := models.PDUSESSIONTYPE_IPV4
	const nodeAddr = "10.1.1.1"
	original := &SMContext{
		Ref:            "round-trip-ref",
		Supi:           testSupi,
		Dnn:            "round-trip-dnn",
		Identifier:     testSupi,
		PDUSessionID:   5,
		AnType:         models.ACCESSTYPE__3_GPP_ACCESS,
		SMContextState: SmStateActive,
		Snssai:         &models.Snssai{Sst: 1, Sd: &sd},
		// NfStatus and SscModes.DefaultSscMode have custom UnmarshalJSON that reject "": real
		// values are required here, since the zero-value structs would otherwise fail to
		// unmarshal and make this a vacuous, unrepresentative round trip.
		AMFProfile: models.NFProfileDiscovery{
			NfInstanceId: "amf-instance-1",
			NfType:       models.NFTYPE_AMF,
			NfStatus:     models.NFSTATUS_REGISTERED,
		},
		SelectedPCFProfile: models.NFProfileDiscovery{
			NfInstanceId: "pcf-instance-1",
			NfType:       models.NFTYPE_PCF,
			NfStatus:     models.NFSTATUS_REGISTERED,
		},
		DnnConfiguration: models.DnnConfiguration{
			PduSessionTypes: models.PduSessionTypes{
				DefaultSessionType: &defaultSessionType,
			},
			SscModes: models.SscModes{DefaultSscMode: models.SSCMODE_SSC_MODE_1},
		},
		PFCPContext: map[string]*PFCPSessionContext{
			nodeAddr: {
				NodeID:     *NewNodeID(nodeAddr),
				LocalSEID:  0x1122334455667788,
				RemoteSEID: 0x8877665544332211,
			},
		},
		Tunnel: &UPTunnel{
			ANInformation: struct {
				IPAddress net.IP
				TEID      uint32
			}{IPAddress: net.ParseIP("10.10.0.1"), TEID: 42},
		},
		BPManager: &BPManager{
			BPStatus:       AddPSASuccess,
			AddingPSAState: Finished,
			PendingUPF:     PendingUPF{"upf-1": true},
		},
		// Unreconstructable API handles: ToBsonM must drop these rather than persist a stale
		// client across a restart; they are rebuilt from AMFProfile/SelectedPCFProfile instead.
		SMPolicyClient:      &Npcf_SMPolicyControl.APIClient{},
		CommunicationClient: &Namf_Communication.APIClient{},
	}

	doc := ToBsonM(original)

	recovered := &SMContext{}
	if err := recovered.UnmarshalJSON(mapToByte(doc)); err != nil {
		t.Fatalf("round-trip unmarshal failed: %v", err)
	}

	if recovered.Supi != original.Supi {
		t.Errorf("Supi = %q, want %q", recovered.Supi, original.Supi)
	}
	if recovered.Dnn != original.Dnn {
		t.Errorf("Dnn = %q, want %q", recovered.Dnn, original.Dnn)
	}
	if recovered.PDUSessionID != original.PDUSessionID {
		t.Errorf("PDUSessionID = %d, want %d", recovered.PDUSessionID, original.PDUSessionID)
	}
	if recovered.AnType != original.AnType {
		t.Errorf("AnType = %q, want %q", recovered.AnType, original.AnType)
	}
	if !reflect.DeepEqual(recovered.Snssai, original.Snssai) {
		t.Errorf("Snssai = %+v, want %+v", recovered.Snssai, original.Snssai)
	}
	if !reflect.DeepEqual(recovered.AMFProfile, original.AMFProfile) {
		t.Errorf("AMFProfile = %+v, want %+v", recovered.AMFProfile, original.AMFProfile)
	}
	if !reflect.DeepEqual(recovered.SelectedPCFProfile, original.SelectedPCFProfile) {
		t.Errorf("SelectedPCFProfile = %+v, want %+v", recovered.SelectedPCFProfile, original.SelectedPCFProfile)
	}
	pfcpCtx, ok := recovered.PFCPContext[nodeAddr]
	if !ok {
		t.Fatalf("expected PFCPContext entry for %q to survive the round trip", nodeAddr)
	}
	wantPFCPCtx := original.PFCPContext[nodeAddr]
	if !pfcpCtx.NodeID.Equal(wantPFCPCtx.NodeID) {
		t.Errorf("PFCPContext NodeID = %+v, want %+v", pfcpCtx.NodeID, wantPFCPCtx.NodeID)
	}
	if pfcpCtx.LocalSEID != wantPFCPCtx.LocalSEID {
		t.Errorf("LocalSEID = %x, want %x", pfcpCtx.LocalSEID, wantPFCPCtx.LocalSEID)
	}
	if pfcpCtx.RemoteSEID != wantPFCPCtx.RemoteSEID {
		t.Errorf("RemoteSEID = %x, want %x", pfcpCtx.RemoteSEID, wantPFCPCtx.RemoteSEID)
	}

	if recovered.Tunnel == nil {
		t.Fatalf("expected Tunnel to survive the round trip")
	}
	if !recovered.Tunnel.ANInformation.IPAddress.Equal(original.Tunnel.ANInformation.IPAddress) {
		t.Errorf("Tunnel.ANInformation.IPAddress = %v, want %v",
			recovered.Tunnel.ANInformation.IPAddress, original.Tunnel.ANInformation.IPAddress)
	}
	if recovered.Tunnel.ANInformation.TEID != original.Tunnel.ANInformation.TEID {
		t.Errorf("Tunnel.ANInformation.TEID = %d, want %d",
			recovered.Tunnel.ANInformation.TEID, original.Tunnel.ANInformation.TEID)
	}

	if recovered.BPManager == nil {
		t.Fatalf("expected BPManager to survive the round trip")
	}
	if recovered.BPManager.BPStatus != original.BPManager.BPStatus {
		t.Errorf("BPManager.BPStatus = %v, want %v", recovered.BPManager.BPStatus, original.BPManager.BPStatus)
	}
	if recovered.BPManager.AddingPSAState != original.BPManager.AddingPSAState {
		t.Errorf("BPManager.AddingPSAState = %v, want %v", recovered.BPManager.AddingPSAState, original.BPManager.AddingPSAState)
	}
	if !reflect.DeepEqual(recovered.BPManager.PendingUPF, original.BPManager.PendingUPF) {
		t.Errorf("BPManager.PendingUPF = %+v, want %+v", recovered.BPManager.PendingUPF, original.BPManager.PendingUPF)
	}

	// SMPolicyClient/CommunicationClient are unreconstructable API handles: ToBsonM shadows them
	// with nil so a stale client from before a restart is never persisted or resurrected as-is.
	if recovered.SMPolicyClient != nil {
		t.Errorf("expected SMPolicyClient to be dropped across the DB round trip, got %+v", recovered.SMPolicyClient)
	}
	if recovered.CommunicationClient != nil {
		t.Errorf("expected CommunicationClient to be dropped across the DB round trip, got %+v", recovered.CommunicationClient)
	}
}
