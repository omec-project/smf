// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net/http"

	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/openapi/Nsmf_PDUSession"
	"github.com/free5gc/openapi/models"
	smf_context "github.com/free5gc/smf/context"
	pfcp_message "github.com/free5gc/smf/pfcp/message"
)

func SendPfcpSessionModifyReq(smContext *smf_context.SMContext, response *models.UpdateSmContextResponse, pfcpParam *pfcpParam) (*http_wrapper.Response, error) {
	var httpResponse *http_wrapper.Response
	defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
	ANUPF := defaultPath.FirstDPNode
	pfcp_message.SendPfcpSessionModificationRequest(ANUPF.UPF.NodeID, smContext,
		pfcpParam.pdrList, pfcpParam.farList, pfcpParam.barList, pfcpParam.qerList)

	PFCPResponseStatus := <-smContext.SBIPFCPCommunicationChan

	switch PFCPResponseStatus {
	case smf_context.SessionUpdateSuccess:
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, PFCP Session Update Success")
		smContext.ChangeState(smf_context.SmStateActive)
		smContext.SubCtxLog.Traceln("SMContextState Change State: ", smContext.SMContextState.String())
		httpResponse = &http_wrapper.Response{
			Status: http.StatusOK,
			Body:   response,
		}
	case smf_context.SessionUpdateFailed:
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, PFCP Session Update Failed")
		smContext.ChangeState(smf_context.SmStateActive)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		// It is just a template
		httpResponse = &http_wrapper.Response{
			Status: http.StatusForbidden,
			Body: models.UpdateSmContextErrorResponse{
				JsonData: &models.SmContextUpdateError{
					Error: &Nsmf_PDUSession.N1SmError,
				},
			}, // Depends on the reason why N4 fail
		}
	case smf_context.SessionUpdateTimeout:
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, PFCP Session Modification Timeout")

		/* TODO: exact http error response code for this usecase is 504, so relevant cause for
		   this usecase is 500. If it gets added in spec 29.502 new release that can be added
		*/
		problemDetail := models.ProblemDetails{
			Title:  "PFCP Session Mod Timeout",
			Status: http.StatusInternalServerError,
			Detail: "PFCP Session Modification Timeout",
			Cause:  "UPF_NOT_RESPONDING",
		}
		var n1buf, n2buf []byte
		var err error
		if n1buf, err = smf_context.BuildGSMPDUSessionReleaseCommand(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build GSM PDUSessionReleaseCommand failed: %+v", err)
		}

		if n2buf, err = smf_context.BuildPDUSessionResourceReleaseCommandTransfer(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSessionResourceReleaseCommandTransfer failed: %+v", err)
		}

		smContext.ChangeState(smf_context.SmStatePfcpModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())

		// It is just a template
		httpResponse = &http_wrapper.Response{
			Status: http.StatusServiceUnavailable,
			Body: models.UpdateSmContextErrorResponse{
				JsonData: &models.SmContextUpdateError{
					Error:        &problemDetail,
					N1SmMsg:      &models.RefToBinaryData{ContentId: smf_context.PDU_SESS_REL_CMD},
					N2SmInfo:     &models.RefToBinaryData{ContentId: smf_context.PDU_SESS_REL_CMD},
					N2SmInfoType: models.N2SmInfoType_PDU_RES_REL_CMD,
				},
				BinaryDataN1SmMessage:     n1buf,
				BinaryDataN2SmInformation: n2buf,
			}, // Depends on the reason why N4 fail
		}

		SendPfcpSessionReleaseReq(smContext, response)
	}

	return httpResponse, nil
}

func SendPfcpSessionReleaseReq(smContext *smf_context.SMContext, response *models.UpdateSmContextResponse) (*http_wrapper.Response, error) {
	var httpResponse *http_wrapper.Response

	releaseTunnel(smContext)

	PFCPResponseStatus := <-smContext.SBIPFCPCommunicationChan
	switch PFCPResponseStatus {
	case smf_context.SessionReleaseSuccess:
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, PFCP Session Release Success")
		smContext.ChangeState(smf_context.SmStateInActivePending)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		httpResponse = &http_wrapper.Response{
			Status: http.StatusOK,
			Body:   response,
		}

	case smf_context.SessionReleaseTimeout:
		fallthrough
	case smf_context.SessionReleaseFailed:
		// Update SmContext Request(N1 PDU Session Release Request)
		// Send PDU Session Release Reject
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, PFCP Session Release Failed")
		problemDetail := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILULE",
		}
		httpResponse = &http_wrapper.Response{
			Status: int(problemDetail.Status),
		}
		smContext.ChangeState(smf_context.SmStateActive)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		errResponse := models.UpdateSmContextErrorResponse{
			JsonData: &models.SmContextUpdateError{
				Error: &problemDetail,
			},
		}
		if buf, err := smf_context.BuildGSMPDUSessionReleaseReject(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build GSM PDUSessionReleaseReject failed: %+v", err)
		} else {
			errResponse.BinaryDataN1SmMessage = buf
		}

		errResponse.JsonData.N1SmMsg = &models.RefToBinaryData{ContentId: "PDUSessionReleaseReject"}
		httpResponse.Body = errResponse
	}
	/*
		switch PFCPResponseStatus {
		case smf_context.SessionReleaseSuccess:
			smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, PFCP SessionReleaseSuccess")
			smContext.ChangeState(smf_context.SmStateInActivePending)
			smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, SMContextState Change State: ", smContext.SMContextState.String())
		//TODO: i will uncomment this in next PR SDCORE-209
		//case smf_context.SessionReleaseTimeout:
		//	fallthrough
		case smf_context.SessionReleaseFailed:
			smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, PFCP SessionReleaseFailed")
			smContext.ChangeState(smf_context.SmStateInActivePending)
			smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease,  SMContextState Change State: ", smContext.SMContextState.String())
		}

		smf_context.RemoveSMContext(smContext.Ref)
	*/
	return httpResponse, nil
}
