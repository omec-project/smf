// SPDX-FileCopyrightText: 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package nasconv

import (
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
)

func TestPDUSessionTypeConversions(t *testing.T) {
	for _, tc := range []struct {
		nas   uint8
		model models.PduSessionType
	}{
		{nasMessage.PDUSessionTypeIPv4, models.PDUSESSIONTYPE_IPV4},
		{nasMessage.PDUSessionTypeIPv6, models.PDUSESSIONTYPE_IPV6},
		{nasMessage.PDUSessionTypeIPv4IPv6, models.PDUSESSIONTYPE_IPV4_V6},
		{nasMessage.PDUSessionTypeEthernet, models.PDUSESSIONTYPE_ETHERNET},
		{nasMessage.PDUSessionTypeUnstructured, models.PDUSESSIONTYPE_UNSTRUCTURED},
	} {
		if got := PDUSessionTypeToModels(tc.nas); got != tc.model {
			t.Fatalf("PDUSessionTypeToModels(%d) = %q, want %q", tc.nas, got, tc.model)
		}
		if got := ModelsToPDUSessionType(tc.model); got != tc.nas {
			t.Fatalf("ModelsToPDUSessionType(%q) = %d, want %d", tc.model, got, tc.nas)
		}
	}
}

func TestModelsToSessionAMBR(t *testing.T) {
	got := ModelsToSessionAMBR(&models.Ambr{Uplink: "10 Mbps", Downlink: "20 Kbps"})
	if rate := got.GetSessionAMBRForUplink(); rate != [2]byte{0, 10} {
		t.Fatalf("uplink rate = %v, want [0 10]", rate)
	}
	if unit := got.GetUnitForSessionAMBRForUplink(); unit != nasMessage.SessionAMBRUnit1Mbps {
		t.Fatalf("uplink unit = %d, want Mbps", unit)
	}
	if rate := got.GetSessionAMBRForDownlink(); rate != [2]byte{0, 20} {
		t.Fatalf("downlink rate = %v, want [0 20]", rate)
	}
	if unit := got.GetUnitForSessionAMBRForDownlink(); unit != nasMessage.SessionAMBRUnit1Kbps {
		t.Fatalf("downlink unit = %d, want Kbps", unit)
	}
}
