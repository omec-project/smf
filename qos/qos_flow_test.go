// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos_test

import (
	"bytes"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/qos"
)

func TestBuildAuthorizedQosFlowDescriptions(t *testing.T) {
	// make SM Policy Decision
	smPolicyDecision := &models.SmPolicyDecision{}

	// make Sm ctxt Policy Data
	smCtxtPolData := &qos.SmCtxtPolicyData{}

	smPolicyDecision.PccRules = makeSamplePccRules()
	smPolicyDecision.QosDecs = makeSampleQosData()

	smPolicyUpdates := qos.BuildSmPolicyUpdate(smCtxtPolData, smPolicyDecision)

	authorizedQosFlow := qos.BuildAuthorizedQosFlowDescriptions(smPolicyUpdates)

	t.Logf("authorized QosFlow: %v", authorizedQosFlow.Content)
	expectedBytes := []byte{
		0x5, 0x20, 0x45, 0x1, 0x1, 0x5, 0x4, 0x3, 0x6, 0x0,
		0x65, 0x5, 0x3, 0x6, 0x0, 0xc9, 0x2, 0x3, 0x6, 0x0, 0xb, 0x3, 0x3, 0x6,
		0x0, 0x15,
	}
	if !bytes.Equal(authorizedQosFlow.Content, expectedBytes) {
		t.Fatalf("Content mismatch. got = %v, want = %v", authorizedQosFlow.Content, expectedBytes)
	}
}

func TestBuildAuthorizedQosFlowDescriptionsSkipsExplicitNullRates(t *testing.T) {
	var maxbrUl openapi.NullableString
	var maxbrDl openapi.NullableString
	var gbrUl openapi.NullableString
	var gbrDl openapi.NullableString

	maxbrUl.Set(nil)
	maxbrDl.Set(nil)
	gbrUl.Set(nil)
	gbrDl.Set(nil)

	smPolicyDecision := &models.SmPolicyDecision{}
	smPolicyDecision.QosDecs = &map[string]models.QosData{
		"null-rates": {
			QosId:   "5",
			Var5qi:  openapi.PtrInt32(5),
			MaxbrUl: maxbrUl,
			MaxbrDl: maxbrDl,
			GbrUl:   gbrUl,
			GbrDl:   gbrDl,
		},
	}

	smCtxtPolData := &qos.SmCtxtPolicyData{}
	smCtxtPolData.Initialize()
	smPolicyUpdates := qos.BuildSmPolicyUpdate(smCtxtPolData, smPolicyDecision)

	authorizedQosFlow := qos.BuildAuthorizedQosFlowDescriptions(smPolicyUpdates)
	expectedBytes := []byte{0x5, 0x20, 0x41, 0x1, 0x1, 0x5}

	if !bytes.Equal(authorizedQosFlow.Content, expectedBytes) {
		t.Fatalf("Content mismatch. got = %v, want = %v", authorizedQosFlow.Content, expectedBytes)
	}
}

// A non-GBR flow (e.g. the default 5QI 9 flow) may carry an explicit zero MFBR
// in the policy decision. Encoding "0 Mbps" produces an invalid QoS flow rate
// parameter that real UEs reject (5GSM cause 0x22), so it must be omitted even
// though the NullableString is set and non-empty.
func TestBuildAuthorizedQosFlowDescriptionsSkipsZeroRates(t *testing.T) {
	var maxbrUl openapi.NullableString
	var maxbrDl openapi.NullableString

	maxbrUl.Set(openapi.PtrString("0 Mbps"))
	maxbrDl.Set(openapi.PtrString("0 Mbps"))

	smPolicyDecision := &models.SmPolicyDecision{}
	smPolicyDecision.QosDecs = &map[string]models.QosData{
		"zero-rates": {
			QosId:   "9",
			Var5qi:  openapi.PtrInt32(9),
			MaxbrUl: maxbrUl,
			MaxbrDl: maxbrDl,
		},
	}

	smCtxtPolData := &qos.SmCtxtPolicyData{}
	smCtxtPolData.Initialize()
	smPolicyUpdates := qos.BuildSmPolicyUpdate(smCtxtPolData, smPolicyDecision)

	authorizedQosFlow := qos.BuildAuthorizedQosFlowDescriptions(smPolicyUpdates)
	// Only the 5QI parameter remains; both zero MFBR parameters are omitted.
	expectedBytes := []byte{0x9, 0x20, 0x41, 0x1, 0x1, 0x9}

	if !bytes.Equal(authorizedQosFlow.Content, expectedBytes) {
		t.Fatalf("Content mismatch. got = %v, want = %v", authorizedQosFlow.Content, expectedBytes)
	}
}

// Rate strings that GetBitRate cannot turn into a valid 16-bit positive rate
// must also be omitted: a missing unit ("10") is encoded as 0, a negative value
// ("-1 Mbps") wraps to a bogus uint16, and an oversized value ("100000 Mbps")
// overflows the 16-bit rate field. All would otherwise reintroduce the invalid
// rate parameter that this guard prevents.
func TestBuildAuthorizedQosFlowDescriptionsSkipsMalformedRates(t *testing.T) {
	var maxbrUl openapi.NullableString
	var maxbrDl openapi.NullableString
	var gbrUl openapi.NullableString

	maxbrUl.Set(openapi.PtrString("10"))        // missing unit -> GetBitRate yields 0
	maxbrDl.Set(openapi.PtrString("-1 Mbps"))   // negative -> rejected by ParseUint
	gbrUl.Set(openapi.PtrString("100000 Mbps")) // > 65535 -> overflows uint16

	smPolicyDecision := &models.SmPolicyDecision{}
	smPolicyDecision.QosDecs = &map[string]models.QosData{
		"malformed-rates": {
			QosId:   "9",
			Var5qi:  openapi.PtrInt32(9),
			MaxbrUl: maxbrUl,
			MaxbrDl: maxbrDl,
			GbrUl:   gbrUl,
		},
	}

	smCtxtPolData := &qos.SmCtxtPolicyData{}
	smCtxtPolData.Initialize()
	smPolicyUpdates := qos.BuildSmPolicyUpdate(smCtxtPolData, smPolicyDecision)

	authorizedQosFlow := qos.BuildAuthorizedQosFlowDescriptions(smPolicyUpdates)
	// Only the 5QI parameter remains; all three malformed rate parameters are omitted.
	expectedBytes := []byte{0x9, 0x20, 0x41, 0x1, 0x1, 0x9}

	if !bytes.Equal(authorizedQosFlow.Content, expectedBytes) {
		t.Fatalf("Content mismatch. got = %v, want = %v", authorizedQosFlow.Content, expectedBytes)
	}
}
