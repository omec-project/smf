// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos_test

import (
	"fmt"
	"testing"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/smf/qos"
	"github.com/stretchr/testify/require"
)

func TestBuildAuthorizedQosFlowDescriptions(t *testing.T) {
	//make SM Policy Decision
	smPolicyDecision := &models.SmPolicyDecision{}

	//make Sm ctxt Policy Data
	smCtxtPolData := &qos.SmCtxtPolicyData{}

	smPolicyDecision.PccRules = makeSamplePccRules()
	smPolicyDecision.QosDecs = makeSampleQosData()

	smPolicyUpdates := qos.BuildSmPolicyUpdate(smCtxtPolData, smPolicyDecision)

	authorizedQosFlow := qos.BuildAuthorizedQosFlowDescriptions(smPolicyUpdates)

	fmt.Printf("Authorized QosFlow: %v", authorizedQosFlow)
	expectedBytes := []byte{0x5, 0x20, 0x45, 0x1, 0x1, 0x5, 0x4, 0x3, 0x6, 0x0,
		0x65, 0x5, 0x3, 0x6, 0x0, 0xc9, 0x2, 0x3, 0x6, 0x0, 0xb, 0x3, 0x3, 0x6,
		0x0, 0x15, 0x3, 0x20, 0x45, 0x1, 0x1, 0x3, 0x4, 0x3, 0x6, 0x1, 0x2d, 0x5,
		0x3, 0x6, 0x1, 0x91, 0x2, 0x3, 0x6, 0x0, 0x1f, 0x3, 0x3, 0x6, 0x0, 0x29}

	require.Equal(t, expectedBytes, authorizedQosFlow.Content)
}
