// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"math"
	"net"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/qos"
	"github.com/omec-project/smf/util"
	"github.com/omec-project/util/idgenerator"
	"go.uber.org/zap"
)

// The downlink rate these tests configure; named because goconst counts it across the file.
const testGbrDownlink = "2 Mbps"

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
		{"both directions", "1 Mbps", testGbrDownlink, false, 1000, 2000},
		{"uplink only", "1 Mbps", "", false, 1000, 0},
		{"downlink only", "", testGbrDownlink, false, 0, 2000},
		{"neither", "", "", true, 0, 0},
		// A value that is only whitespace is not a configured rate. Untrimmed it is not the empty
		// string either, so it built a GBR IE carrying zero in both directions -- telling the user
		// plane the flow has a guaranteed rate of nothing rather than none at all.
		{"whitespace only", " ", "  ", true, 0, 0},
		{"whitespace in one direction", " ", testGbrDownlink, false, 0, 2000},
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

// withSessionAmbr gives the session the committed rule the maximum rate falls back to. The
// guarantee under test has no such fallback, but the fallback is read on the same path.
func withSessionAmbr(smContext *SMContext) {
	const sessionAmbr = "50 Mbps"

	smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule = &models.SessionRule{
		AuthSessAmbr: &models.Ambr{Uplink: sessionAmbr, Downlink: sessionAmbr},
	}
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
	// A committed session rule, because the maximum rate falls back to the session AMBR when the
	// QoS data names none. The guarantee has no such fallback, which is what this is about, but
	// the fallback is read either way.
	withSessionAmbr(smContext)

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
	withSessionAmbr(smContext)

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

// Rates come from policy, and a policy can carry one with no unit. The conversion reads the unit
// from the second field, so "10" indexed past the end of the split and took the process down --
// on any rate the SMF converts, not only a guaranteed one.
func TestARateWithNoUnitDoesNotEndTheProcess(t *testing.T) {
	for _, rate := range []string{"10", "", "Mbps", "not-a-rate"} {
		if got := util.BitRateTokbps(util.NormalizeBitRate(rate)); got != 0 {
			t.Errorf("BitRateTokbps(%q) = %d, want 0: a rate that cannot be read is not a rate", rate, got)
		}
	}
}

// The user plane is told the rate the radio is told. The session AMBR reaches the user plane's
// converter and the gNB's -- ngapConvert.UEAmbrToInt64, through sessionAmbrToBps -- as the same
// raw string, so wherever the two parse it differently the user plane enforces one rate while the
// gNB is sent another. Tightening or loosening one parser alone did exactly that for some
// spellings; this pins the two together.
//
// Two spellings still differ, and differed before: "100  Mbps" and "100 mbps", where the gNB's
// parser takes an empty or unrecognised unit to be bits per second and this one reads no rate.
// Settling those means both parsers reading one canonical string, which belongs where the rate
// first arrives.
func TestTheUserPlaneIsToldTheRateTheRadioIsTold(t *testing.T) {
	for _, rate := range []string{
		"100 Mbps", "100 Mbps ", "100 Mbps junk", "100Mbps", " 100 Mbps", "100\tMbps", "2 Gbps", "10", "",
	} {
		if upf, gnb := int64(util.BitRateTokbps(rate))*1000, sessionAmbrToBps(rate); upf != gnb {
			t.Errorf("%q: the user plane enforces %d bps and the gNB is told %d", rate, upf, gnb)
		}
	}
}

// A session AMBR with no unit has to reach every end without taking the SMF down. The user plane's
// converter was guarded against "10"; the gNB's and the UE's were not, and the same string reaches
// all three, so the process still went down -- one step later, building the transfer for the radio
// or the NAS message for the UE.
func TestAUnitlessSessionAmbrTakesNoPathDown(t *testing.T) {
	node := NewDataPathNode()
	node.UPF = &UPF{}

	smContext := &SMContext{
		Supi: testSupi,
		Tunnel: &UPTunnel{DataPathPool: DataPathPool{
			1: &DataPath{IsDefaultPath: true, FirstDPNode: node},
		}},
	}
	smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule = &models.SessionRule{
		AuthSessAmbr: &models.Ambr{Uplink: "10", Downlink: "10"},
	}

	// The transfer is refused later for want of an N3 interface in this fixture; what is under
	// test is that it gets past the AMBR at all.
	if _, err := BuildPDUSessionResourceSetupRequestTransfer(smContext); err != nil {
		t.Logf("setup transfer refused after the AMBR, as the fixture has no N3 interface: %v", err)
	}

	// And the modification transfer, which reads the same AMBR for the radio.
	defQos := &models.QosData{QosId: "1"}
	defQos.SetDefQosFlowIndication(true)
	smContext.SmPolicyData.SmCtxtQosData.QosData = map[string]*models.QosData{"1": defQos}
	smContext.SubPduSessLog = zap.NewNop().Sugar()

	if _, err := BuildPDUSessionResourceModifyRequestTransfer(smContext); err != nil {
		t.Logf("modification transfer refused: %v", err)
	}

	// The UE's establishment accept, which carries the Session-AMBR as a mandatory IE. By the time a
	// session is accepted it has an address, which the accept reads after the AMBR.
	smContext.SubGsmLog = zap.NewNop().Sugar()
	smContext.PDUAddress = &UeIpAddr{Ip: net.ParseIP("10.1.0.12")}
	smContext.Snssai = &models.Snssai{Sst: 1}
	smContext.ProtocolConfigurationOptions = &ProtocolConfigurationOptions{}
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{{}}

	if _, err := BuildGSMPDUSessionEstablishmentAccept(smContext); err != nil {
		t.Logf("establishment accept refused: %v", err)
	}

	// And the modification command, when the update names the rule.
	smContext.SmPolicyUpdates[0].SessRuleUpdate = &qos.SessRulesUpdate{
		ActiveSessRule: smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule,
	}

	if _, err := BuildGSMPDUSessionModificationCommand(smContext); err != nil {
		t.Logf("modification command refused: %v", err)
	}
}

// And the UE is told a rate of zero for a direction with no unit, which is what the user plane and
// the gNB are given for the same string, and what the NAS converter already encodes for a rate it
// cannot read.
func TestAUnitlessDirectionIsEncodedForTheUeAsZero(t *testing.T) {
	encoded := sessionAmbrForNas(&models.Ambr{Uplink: "10", Downlink: "20 Mbps"})

	if got := encoded.GetSessionAMBRForUplink(); got != [2]byte{} {
		t.Errorf("uplink encoded as %v, want zero: the user plane and the gNB are given zero for a rate with no unit", got)
	}

	if got := encoded.GetSessionAMBRForDownlink(); got != [2]byte{0, 20} {
		t.Errorf("downlink encoded as %v, want 20: a direction with a unit is unaffected", got)
	}
}

// And a rate that can be read still is.
func TestAReadableRateStillConverts(t *testing.T) {
	if got, want := util.BitRateTokbps(util.NormalizeBitRate("10 Mbps")), uint64(10000); got != want {
		t.Errorf("BitRateTokbps(10 Mbps) = %d, want %d", got, want)
	}

	if got, want := util.BitRateTokbps(util.NormalizeBitRate("10Mbps")), uint64(10000); got != want {
		t.Errorf("BitRateTokbps(10Mbps) = %d, want %d: the concatenated form is what NormalizeBitRate exists for", got, want)
	}
}
