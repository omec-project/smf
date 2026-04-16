// SPDX-FileCopyrightText: 2026 Forsway Solutions AB
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

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

func TestSelectableAmfCandidates_SkipsFailedNfInstanceId(t *testing.T) {
	a := amfDiscoveryProfile("amf-a", "http://10.42.0.10:29518")
	b := amfDiscoveryProfile("amf-b", "http://10.42.0.20:29518")
	c := amfDiscoveryProfile("amf-c", "http://10.42.0.30:29518")

	got := selectableAmfCandidates([]models.NFProfileDiscovery{a, b, c}, "amf-b")
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates after filtering, got %d", len(got))
	}
	if got[0].GetNfInstanceId() != "amf-a" || got[1].GetNfInstanceId() != "amf-c" {
		t.Errorf("expected order [amf-a, amf-c], got [%s, %s]", got[0].GetNfInstanceId(), got[1].GetNfInstanceId())
	}
}

func TestSelectableAmfCandidates_PreservesOrder(t *testing.T) {
	a := amfDiscoveryProfile("amf-a", "http://10.42.0.10:29518")
	b := amfDiscoveryProfile("amf-b", "http://10.42.0.20:29518")
	c := amfDiscoveryProfile("amf-c", "http://10.42.0.30:29518")

	got := selectableAmfCandidates([]models.NFProfileDiscovery{a, b, c}, "does-not-match-any")
	if len(got) != 3 {
		t.Fatalf("expected 3 candidates when no match, got %d", len(got))
	}
	for i, want := range []string{"amf-a", "amf-b", "amf-c"} {
		if got[i].GetNfInstanceId() != want {
			t.Errorf("position %d: got %s, want %s", i, got[i].GetNfInstanceId(), want)
		}
	}
}

func TestSelectableAmfCandidates_AllFiltered_ReturnsEmpty(t *testing.T) {
	a := amfDiscoveryProfile("amf-x", "http://10.42.0.10:29518")
	b := amfDiscoveryProfile("amf-x", "http://10.42.0.20:29518")

	got := selectableAmfCandidates([]models.NFProfileDiscovery{a, b}, "amf-x")
	if len(got) != 0 {
		t.Errorf("expected empty result when every candidate matches failed NfId, got %d", len(got))
	}
}

func TestSelectableAmfCandidates_EmptyInput_ReturnsEmpty(t *testing.T) {
	got := selectableAmfCandidates(nil, "anything")
	if len(got) != 0 {
		t.Errorf("expected empty result for nil input, got %d", len(got))
	}
}
