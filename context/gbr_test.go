// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"math"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/qos"
	"github.com/omec-project/smf/util"
	"github.com/omec-project/util/idgenerator"
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

// qerCapableUPF is the minimum a QER allocation needs. NewUPF would do it, but it also registers
// the UPF in the package-level pool, which a unit test of QER building has no reason to touch.
func qerCapableUPF() *UPF {
	upf := &UPF{UPFStatus: AssociatedSetUpSuccess}
	upf.qerIDGenerator = idgenerator.NewGenerator(1, math.MaxUint32)

	return upf
}

// The establishment path has to program the guarantee too, and this is the test that says so.
//
// CreateDedicatedQosQer, on the policy-update path, has always set the QER's GBR.
// CreatePccRuleQer, which the establishment datapath uses, set only the MBR — so a configured
// guarantee reached the UPF on a policy edit and was dropped when the session was established.
// The failure mode is the awkward one: the guarantee works, then disappears the next time the UE
// attaches, which reads as intermittent rather than as unimplemented.
func TestCreatePccRuleQerProgramsTheGuaranteedRate(t *testing.T) {
	const qosID = "1"
	node := &DataPathNode{UPF: qerCapableUPF()}
	smContext := &SMContext{
		Supi: "imsi-208930000000001",
		SmPolicyUpdates: []*qos.PolicyUpdate{{
			SmPolicyDecision: &models.SmPolicyDecision{
				QosDecs: &map[string]models.QosData{qosID: {
					QosId:   qosID,
					MaxbrUl: *openapi.NewNullableString(openapi.PtrString("100 Mbps")),
					MaxbrDl: *openapi.NewNullableString(openapi.PtrString("200 Mbps")),
					GbrUl:   *openapi.NewNullableString(openapi.PtrString("10 Mbps")),
					GbrDl:   *openapi.NewNullableString(openapi.PtrString("20 Mbps")),
				}},
			},
		}},
	}

	qer, err := node.CreatePccRuleQer(smContext, qosID, "")
	if err != nil {
		t.Fatalf("CreatePccRuleQer: %v", err)
	}
	if qer == nil {
		t.Fatal("no QER was built")
		return
	}
	if qer.GBR == nil {
		t.Fatal("the QER carries no GBR, so a configured guarantee is dropped at establishment")
	}
	if got, want := qer.GBR.ULGBR, util.BitRateTokbps(util.NormalizeBitRate("10 Mbps")); got != want {
		t.Errorf("ULGBR = %d, want %d kbps", got, want)
	}
	if got, want := qer.GBR.DLGBR, util.BitRateTokbps(util.NormalizeBitRate("20 Mbps")); got != want {
		t.Errorf("DLGBR = %d, want %d kbps", got, want)
	}
	// The maximum rate is the flow's own, not the session fallback, and must be untouched by this.
	if qer.MBR == nil || qer.MBR.ULMBR != util.BitRateTokbps("100 Mbps") {
		t.Errorf("MBR = %+v, want the flow's own maximum rates unaffected", qer.MBR)
	}
}

// A PCC rule with no guaranteed rate must not acquire one from the session AMBR: a guarantee is a
// commitment to one flow, while the session rule is a ceiling over all of them, so the fallback
// that is right for the maximum rate would be wrong here.
func TestCreatePccRuleQerLeavesAnUnconfiguredGuaranteeUnset(t *testing.T) {
	const qosID = "1"
	node := &DataPathNode{UPF: qerCapableUPF()}
	smContext := &SMContext{
		Supi: "imsi-208930000000001",
		SmPolicyUpdates: []*qos.PolicyUpdate{{
			SmPolicyDecision: &models.SmPolicyDecision{
				QosDecs: &map[string]models.QosData{qosID: {
					QosId:   qosID,
					MaxbrUl: *openapi.NewNullableString(openapi.PtrString("100 Mbps")),
					MaxbrDl: *openapi.NewNullableString(openapi.PtrString("200 Mbps")),
				}},
			},
		}},
	}

	qer, err := node.CreatePccRuleQer(smContext, qosID, "")
	if err != nil {
		t.Fatalf("CreatePccRuleQer: %v", err)
	}
	if qer == nil {
		t.Fatal("no QER was built")
		return
	}
	if qer.GBR != nil {
		t.Errorf("GBR = %+v, want it unset when the policy configures no guarantee", qer.GBR)
	}
}
