// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// A guarantee configured in one direction only must be honoured.
//
// The branch used to require both directions and dropped the whole guarantee when an operator
// configured one, saying nothing. That is a plausible thing to configure and the likelier one on a
// satellite link, where the return path is the scarce direction. TS 29.244 carries both rates in
// the same IE, and zero in a direction means no guaranteed rate there — so the direction that was
// not configured is left at zero rather than invented or used to veto the other.
func TestAOneDirectionalGuaranteeIsHonoured(t *testing.T) {
	tests := []struct {
		name           string
		gbrUl, gbrDl   string
		wantNil        bool
		wantUL, wantDL uint64
	}{
		{"both directions", "1 Mbps", "2 Mbps", false, 1000, 2000},
		{"uplink only", "1 Mbps", "", false, 1000, 0},
		{"downlink only", "", "2 Mbps", false, 0, 2000},
		{"neither", "", "", true, 0, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			qos := &models.QosData{QosId: "2"}
			if tc.gbrUl != "" {
				qos.SetGbrUl(tc.gbrUl)
			}
			if tc.gbrDl != "" {
				qos.SetGbrDl(tc.gbrDl)
			}

			got := BuildGBR(qos)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("GBR = %+v, want nil: neither direction carries a guarantee", got)
				}
				return
			}
			if got == nil {
				t.Fatal("GBR is nil, so a configured guarantee was silently discarded")
			}
			if got.ULGBR != tc.wantUL {
				t.Errorf("ULGBR = %d kbps, want %d", got.ULGBR, tc.wantUL)
			}
			if got.DLGBR != tc.wantDL {
				t.Errorf("DLGBR = %d kbps, want %d", got.DLGBR, tc.wantDL)
			}
		})
	}
}
