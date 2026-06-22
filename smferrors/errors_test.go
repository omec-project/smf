// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package smferrors

import (
	"net/http"
	"testing"
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
	pd := NewExtProblemDetailsWithCause("Request Rejected", http.StatusForbidden, "Invalid request", "REQUEST_REJECTED")

	if pd.GetTitle() != "Request Rejected" {
		t.Fatalf("expected title %q, got %q", "Request Rejected", pd.GetTitle())
	}
	if pd.GetStatus() != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, pd.GetStatus())
	}
	if pd.GetDetail() != "Invalid request" {
		t.Fatalf("expected detail %q, got %q", "Invalid request", pd.GetDetail())
	}
	if pd.GetCause() != "REQUEST_REJECTED" {
		t.Fatalf("expected cause %q, got %q", "REQUEST_REJECTED", pd.GetCause())
	}
}

func TestNewExtProblemDetailsSystemFailure(t *testing.T) {
	pd := NewExtProblemDetailsSystemFailure()

	if pd.GetStatus() != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, pd.GetStatus())
	}
	if pd.GetCause() != "SYSTEM_FAILURE" {
		t.Fatalf("expected cause SYSTEM_FAILURE, got %q", pd.GetCause())
	}
}
