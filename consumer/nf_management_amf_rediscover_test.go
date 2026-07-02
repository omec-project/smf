// SPDX-FileCopyrightText: 2026 Forsway Solutions AB
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

// ② re-discovery must fire only on transport-level failures, not on an HTTP error
// from a reachable AMF, and not when the caller context is already done.
func TestShouldRediscoverAMF(t *testing.T) {
	t.Run("transport error -> retry", func(t *testing.T) {
		if !shouldRediscoverAMF(context.Background(), errors.New("dial tcp 10.0.0.1:29518: i/o timeout")) {
			t.Error("expected re-discovery on a transport error")
		}
	})
	t.Run("cancelled context -> no retry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if shouldRediscoverAMF(ctx, errors.New("any error")) {
			t.Error("expected no re-discovery when caller context is cancelled")
		}
	})
	t.Run("HTTP error from AMF (pointer, as the client returns it) -> no retry", func(t *testing.T) {
		var apiErr error = &openapi.GenericOpenAPIError{}
		if shouldRediscoverAMF(context.Background(), apiErr) {
			t.Error("expected no re-discovery when the AMF returned an HTTP error")
		}
	})
	t.Run("wrapped pointer HTTP error from AMF -> no retry", func(t *testing.T) {
		wrapped := fmt.Errorf("n1n2 transfer: %w", &openapi.GenericOpenAPIError{})
		if shouldRediscoverAMF(context.Background(), wrapped) {
			t.Error("expected no re-discovery for a wrapped *GenericOpenAPIError")
		}
	})
	t.Run("HTTP error from AMF (value) -> no retry", func(t *testing.T) {
		var apiErr error = openapi.GenericOpenAPIError{}
		if shouldRediscoverAMF(context.Background(), apiErr) {
			t.Error("expected no re-discovery for a value GenericOpenAPIError")
		}
	})
}

func amfDiscoveryProfile(nfInstanceId, apiPrefix string) models.NFProfileDiscovery {
	return models.NFProfileDiscovery{
		NfInstanceId: nfInstanceId,
		NfType:       models.NFTYPE_AMF,
		NfStatus:     models.NFSTATUS_REGISTERED,
		NfServices: []models.NFService{
			{ServiceName: models.SERVICENAME_NAMF_COMM, ApiPrefix: openapi.PtrString(apiPrefix)},
		},
	}
}

func ids(profiles []models.NFProfileDiscovery) []string {
	out := make([]string, 0, len(profiles))
	for i := range profiles {
		out = append(out, profiles[i].GetNfInstanceId())
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Different NfInstanceIds come first; the one matching the failed id is moved last
// (NOT dropped) — its NRF profile may carry a refreshed ApiPrefix.
func TestOrderAmfCandidates_FailedIdMovedLast(t *testing.T) {
	a := amfDiscoveryProfile("amf-a", "http://10.42.0.10:29518")
	b := amfDiscoveryProfile("amf-b", "http://10.42.0.20:29518")
	c := amfDiscoveryProfile("amf-c", "http://10.42.0.30:29518")

	got := orderAmfCandidates([]models.NFProfileDiscovery{a, b, c}, "amf-b")
	want := []string{"amf-a", "amf-c", "amf-b"}
	if !equalStrings(ids(got), want) {
		t.Errorf("expected order %v, got %v", want, ids(got))
	}
}

// Pattern B: AMF re-registered in place — same NfInstanceId, new ApiPrefix.
// The same-id candidate MUST still be returned (so it gets retried with the
// refreshed endpoint), not filtered out.
func TestOrderAmfCandidates_SameIdRetainedForInPlaceReRegistration(t *testing.T) {
	refreshed := amfDiscoveryProfile("amf-stable", "http://10.42.0.99:29518") // new endpoint, same id

	got := orderAmfCandidates([]models.NFProfileDiscovery{refreshed}, "amf-stable")
	if len(got) != 1 {
		t.Fatalf("expected the same-id candidate to be retained for in-place re-registration, got %d", len(got))
	}
	if got[0].GetNfInstanceId() != "amf-stable" {
		t.Errorf("expected amf-stable, got %s", got[0].GetNfInstanceId())
	}
	svc := got[0].GetNfServices()
	if len(svc) == 0 || svc[0].GetApiPrefix() != "http://10.42.0.99:29518" {
		t.Errorf("expected refreshed ApiPrefix to be preserved, got %+v", svc)
	}
}

func TestOrderAmfCandidates_PreservesOrderWhenNoMatch(t *testing.T) {
	a := amfDiscoveryProfile("amf-a", "http://10.42.0.10:29518")
	b := amfDiscoveryProfile("amf-b", "http://10.42.0.20:29518")
	c := amfDiscoveryProfile("amf-c", "http://10.42.0.30:29518")

	got := orderAmfCandidates([]models.NFProfileDiscovery{a, b, c}, "does-not-match-any")
	want := []string{"amf-a", "amf-b", "amf-c"}
	if !equalStrings(ids(got), want) {
		t.Errorf("expected unchanged order %v, got %v", want, ids(got))
	}
}

func TestOrderAmfCandidates_EmptyInput(t *testing.T) {
	if got := orderAmfCandidates(nil, "anything"); len(got) != 0 {
		t.Errorf("expected empty result for nil input, got %d", len(got))
	}
}
