// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package consumer

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pkg/errors"

	"github.com/free5gc/nas/nasConvert"
	"github.com/free5gc/openapi/models"
	smf_context "github.com/free5gc/smf/context"
)

// SendSMPolicyAssociationCreate create the session management association to the PCF
func SendSMPolicyAssociationCreate(smContext *smf_context.SMContext) (*models.SmPolicyDecision, int, error) {
	httpRspStatusCode := http.StatusInternalServerError
	if smContext.SMPolicyClient == nil {
		return nil, httpRspStatusCode, errors.Errorf("smContext not selected PCF")
	}

	smPolicyData := models.SmPolicyContextData{}

	smPolicyData.Supi = smContext.Supi
	smPolicyData.PduSessionId = smContext.PDUSessionID
	smPolicyData.NotificationUri = fmt.Sprintf("%s://%s:%d/nsmf-callback/sm-policies/%s",
		smf_context.SMF_Self().URIScheme,
		smf_context.SMF_Self().RegisterIPv4,
		smf_context.SMF_Self().SBIPort,
		smContext.Ref,
	)
	smPolicyData.Dnn = smContext.Dnn
	smPolicyData.PduSessionType = nasConvert.PDUSessionTypeToModels(smContext.SelectedPDUSessionType)
	smPolicyData.AccessType = smContext.AnType
	smPolicyData.RatType = smContext.RatType
	smPolicyData.Ipv4Address = smContext.PDUAddress.To4().String()
	smPolicyData.SubsSessAmbr = smContext.DnnConfiguration.SessionAmbr
	smPolicyData.SubsDefQos = smContext.DnnConfiguration.Var5gQosProfile
	smPolicyData.SliceInfo = smContext.Snssai
	smPolicyData.ServingNetwork = &models.NetworkId{
		Mcc: smContext.ServingNetwork.Mcc,
		Mnc: smContext.ServingNetwork.Mnc,
	}
	smPolicyData.SuppFeat = "F"

	var smPolicyDecision *models.SmPolicyDecision
	if smPolicyDecisionFromPCF, httpRsp, err := smContext.SMPolicyClient.
		DefaultApi.SmPoliciesPost(context.Background(), smPolicyData); err != nil {
		if httpRsp != nil {
			httpRspStatusCode = httpRsp.StatusCode
		}
		return nil, httpRspStatusCode, fmt.Errorf("setup sm policy association failed: %s", err.Error())
	} else {
		httpRspStatusCode = http.StatusCreated
		smPolicyDecision = &smPolicyDecisionFromPCF
	}

	return smPolicyDecision, httpRspStatusCode, nil
}

func SendSMPolicyAssociationModify(smContext *smf_context.SMContext) {
	//TODO
}

func SendSMPolicyAssociationDelete(smContext *smf_context.SMContext) {
	//TODO
}
