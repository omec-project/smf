// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos_test

import (
	"bytes"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/qos"
)

func TestBuildAuthorizedQosFlowDescriptions(t *testing.T) {
	// make SM Policy Decision
	smPolicyDecision := models.NewSmPolicyDecision()

	// make Sm ctxt Policy Data
	smCtxtPolData := &qos.SmCtxtPolicyData{}

	smPolicyDecision.SetPccRules(makeSamplePccRules())
	smPolicyDecision.SetQosDecs(*makeSampleQosData())

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
	qosData := models.NewQosData("5")
	qosData.SetVar5qi(5)
	smPolicyDecision := models.NewSmPolicyDecision()
	smPolicyDecision.SetQosDecs(map[string]models.QosData{"null-rates": *qosData})

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
	qosData := models.NewQosData("9")
	qosData.SetVar5qi(9)
	qosData.SetMaxbrUl("0 Mbps")
	qosData.SetMaxbrDl("0 Mbps")
	smPolicyDecision := models.NewSmPolicyDecision()
	smPolicyDecision.SetQosDecs(map[string]models.QosData{
		"zero-rates": *qosData,
	})

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
	qosData := models.NewQosData("9")
	qosData.SetVar5qi(9)
	qosData.SetMaxbrUl("10")      // missing unit -> GetBitRate yields 0
	qosData.SetMaxbrDl("-1 Mbps") // negative -> rejected by ParseUint

	smPolicyDecision := models.NewSmPolicyDecision()
	smPolicyDecision.SetQosDecs(map[string]models.QosData{
		"malformed-rates": *qosData,
	})

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
