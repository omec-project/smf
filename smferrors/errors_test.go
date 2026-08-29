// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package smferrors

import (
	"net/http"
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/utils"
)

func TestNewExtProblemDetails(t *testing.T) {
	pd := NewExtProblemDetails("Test Error", http.StatusBadRequest, "Test detail")

	if pd.GetTitle() != "Test Error" {
		t.Fatalf("expected title %q, got %q", "Test Error", pd.GetTitle())
	}
	if pd.GetStatus() != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, pd.GetStatus())
	}
	if pd.GetDetail() != "Test detail" {
		t.Fatalf("expected detail %q, got %q", "Test detail", pd.GetDetail())
	}
}

func TestNewExtProblemDetailsWithCause(t *testing.T) {
	pd := NewExtProblemDetailsWithCause("Request Rejected", http.StatusForbidden, "Invalid request", utils.CauseRequestRejected)

	if pd.GetTitle() != "Request Rejected" {
		t.Fatalf("expected title %q, got %q", "Request Rejected", pd.GetTitle())
	}
	if pd.GetStatus() != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, pd.GetStatus())
	}
	if pd.GetDetail() != "Invalid request" {
		t.Fatalf("expected detail %q, got %q", "Invalid request", pd.GetDetail())
	}
	if pd.GetCause() != utils.CauseRequestRejected {
		t.Fatalf("expected cause %q, got %q", utils.CauseRequestRejected, pd.GetCause())
	}
}

func TestNewExtProblemDetailsSystemFailure(t *testing.T) {
	pd := NewExtProblemDetailsSystemFailure()

	if pd.GetStatus() != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, pd.GetStatus())
	}
	if pd.GetCause() != utils.CauseSystemFailure {
		t.Fatalf("expected cause %q, got %q", utils.CauseSystemFailure, pd.GetCause())
	}
}

// TestErrorCauseValuesAre5GSMCauses guards the whole ErrorCause table. Every value in it is
// written into the 5GSM cause IE of a PDU SESSION ESTABLISHMENT REJECT or a PDU SESSION
// RELEASE REJECT, so a value from another register - 5GMM causes are the easy mistake, since
// their names describe the same conditions - is a defect even when the name reads correctly.
//
// TS 24.501 clause 9.11.4.2 requires a UE receiving an undefined 5GSM cause to treat it as
// #31 "request rejected, unspecified", so a wrong-register value does not fail loudly. It
// silently collapses into the generic cause and the UE cannot tell the difference.
func TestErrorCauseValuesAre5GSMCauses(t *testing.T) {
	for key, value := range ErrorCause {
		// Cause5GSMToString returns the empty string for a value TS 24.501 does not define, which
		// is the same contract Cause5GMMToString has. The set used to be duplicated here; nas
		// v2.2.1 carries it, so the library that owns the constants owns the answer too.
		name := nasMessage.Cause5GSMToString(value)
		if name == "" {
			t.Errorf("ErrorCause[%q] = %#02x, which is not a cause value defined for the 5GSM cause IE; "+
				"a UE would decode it as #31 \"request rejected, unspecified\" per TS 24.501 clause 9.11.4.2", key, value)
		} else if testing.Verbose() {
			t.Logf("ErrorCause[%q] = %s", key, name)
		}
	}
}

// TestDnnRejectCausesAreSliceScoped pins the DNN rejection causes to #70 rather than #27.
//
// The two differ only in scope, and the scope is not cosmetic: per TS 24.501 clause 6.4.1.4.2
// a UE receiving #27 backs off the [PLMN, DNN] combination, suppressing that DNN across every
// slice, while #70 scopes the back-off to [PLMN, DNN, S-NSSAI]. RetrieveDnnInformation matches
// the S-NSSAI before looking up the DNN, so it never determines anything about the DNN in
// another slice - sending #27 would deny the subscriber a DNN that may be correctly configured
// elsewhere.
func TestDnnRejectCausesAreSliceScoped(t *testing.T) {
	for _, key := range []string{errKeyDnnNotSupported, errKeyDnnDeniedError} {
		got, ok := ErrorCause[key]
		if !ok {
			t.Fatalf("ErrorCause has no entry for %q", key)
		}
		if got != nasMessage.Cause5GSMMissingOrUnknownDNNInASlice {
			t.Errorf("ErrorCause[%q] = %#02x, want Cause5GSMMissingOrUnknownDNNInASlice (%#02x): the DNN lookup is slice-scoped",
				key, got, nasMessage.Cause5GSMMissingOrUnknownDNNInASlice)
		}
	}
}
