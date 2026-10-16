// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
)

// TestSendSMPolicyAssociationDeleteWithNoPCFIsANoOp is a regression test: a session released
// before it ever got a PCF policy client (e.g. caught mid-establishment) has nothing to tear down.
// This used to report an error, which made callers such as releaseUnrestorableSession count the
// session as not released even though it had already been removed and the UE told to drop it.
func TestSendSMPolicyAssociationDeleteWithNoPCFIsANoOp(t *testing.T) {
	smContext := &smf_context.SMContext{}

	status, err := SendSMPolicyAssociationDelete(smContext, models.NewReleaseSmContextRequest())
	if err != nil {
		t.Fatalf("SendSMPolicyAssociationDelete returned %v, want nil", err)
	}
	if status != http.StatusNoContent {
		t.Errorf("status = %d, want %d", status, http.StatusNoContent)
	}
}

// TestSendSMPolicyAssociationCreateOmitsAbsentSubscriptionFields is a regression test: when the
// DNN configuration carries no subscribed session-AMBR or default QoS profile, the create request
// must leave subsSessAmbr/subsDefQos absent rather than sending zero-valued data, which a PCF can
// reject as a malformed policy association request.
func TestSendSMPolicyAssociationCreateOmitsAbsentSubscriptionFields(t *testing.T) {
	// Read off the wire rather than through models.SmPolicyContextData: unmarshalling into the
	// generated model would turn an absent field back into a zero value, hiding the regression.
	var sent map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Errorf("decode create body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(models.SmPolicyDecision{}); err != nil {
			t.Errorf("encode decision: %v", err)
		}
	}))
	defer server.Close()

	smContext := smContextWithPCF(t, server)
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP(testSmfAllocatedIpv4)}
	smContext.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
	snssai := models.NewSnssai(1)
	snssai.SetSd("010203")
	smContext.Snssai = snssai
	smContext.DnnConfiguration = models.DnnConfiguration{}

	if _, _, err := SendSMPolicyAssociationCreate(smContext); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	if _, present := sent["subsSessAmbr"]; present {
		t.Errorf("subsSessAmbr present in request body %v, want absent when DnnConfiguration has no SessionAmbr", sent)
	}
	if _, present := sent["subsDefQos"]; present {
		t.Errorf("subsDefQos present in request body %v, want absent when DnnConfiguration has no Var5gQosProfile", sent)
	}
}
