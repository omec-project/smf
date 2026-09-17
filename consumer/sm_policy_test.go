// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"net/http"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
)

// TestSendSMPolicyAssociationDeleteWithNoPCFIsANoOp is a regression test: a session released
// before it ever got a PCF policy client (e.g. caught mid-establishment) has nothing to tear down.
// This used to report an error, which made callers such as releaseUnrestorableSession count the
// session as not released even though it had already been removed and the UE told to drop it.
func TestSendSMPolicyAssociationDeleteWithNoPCFIsANoOp(t *testing.T) {
	smContext := &smf_context.SMContext{}

	status, err := SendSMPolicyAssociationDelete(smContext, &models.ReleaseSmContextRequest{})
	if err != nil {
		t.Fatalf("SendSMPolicyAssociationDelete returned %v, want nil", err)
	}
	if status != http.StatusNoContent {
		t.Errorf("status = %d, want %d", status, http.StatusNoContent)
	}
}
