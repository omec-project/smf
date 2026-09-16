// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/omec-project/nas/v2/nasConvert"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
)

// SendSMPolicyAssociationCreate create the session management association to the PCF
func SendSMPolicyAssociationCreate(smContext *smf_context.SMContext) (*models.SmPolicyDecision, int, error) {
	httpRspStatusCode := http.StatusInternalServerError
	if smContext.SMPolicyClient == nil {
		return nil, httpRspStatusCode, fmt.Errorf("smContext not selected PCF")
	}

	pduSessionType := nasConvert.PDUSessionTypeToModels(smContext.SelectedPDUSessionType)
	if !pduSessionType.IsValid() {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid selected PDU session type %d for PCF policy association", smContext.SelectedPDUSessionType)
	}

	if smContext.Snssai == nil {
		return nil, http.StatusBadRequest, fmt.Errorf("missing S-NSSAI for PCF policy association")
	}

	smPolicyData := models.SmPolicyContextData{
		Supi:         smContext.Supi,
		PduSessionId: smContext.PDUSessionID,
		NotificationUri: fmt.Sprintf("%s://%s:%d/nsmf-callback/sm-policies/%s",
			smf_context.SMF_Self().URIScheme,
			smf_context.SMF_Self().RegisterIPv4,
			smf_context.SMF_Self().SBIPort,
			smContext.Ref,
		),
		Dnn:            smContext.Dnn,
		PduSessionType: pduSessionType,
		AccessType:     smContext.AnType.Ptr(),
		RatType:        smContext.RatType.Ptr(),
		Ipv4Address:    openapi.PtrString(smContext.PDUAddress.Ip.To4().String()),
		SubsSessAmbr:   smContext.DnnConfiguration.SessionAmbr,
		SubsDefQos:     smContext.DnnConfiguration.Var5gQosProfile,
		SliceInfo:      *smContext.Snssai,
		ServingNetwork: models.NewPlmnIdNid(smContext.ServingNetwork.Mcc, smContext.ServingNetwork.Mnc),
		SuppFeat:       openapi.PtrString("F"),
	}

	var smPolicyDecision *models.SmPolicyDecision
	apiCreateSMPolicyRequest := smContext.SMPolicyClient.SMPoliciesCollectionAPI.CreateSMPolicy(context.Background())
	apiCreateSMPolicyRequest = apiCreateSMPolicyRequest.SmPolicyContextData(smPolicyData)
	if smPolicyDecisionFromPCF, httpRsp, err := smContext.SMPolicyClient.SMPoliciesCollectionAPI.CreateSMPolicyExecute(apiCreateSMPolicyRequest); err != nil {
		if httpRsp != nil {
			httpRspStatusCode = httpRsp.StatusCode
			if rspCloseErr := httpRsp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("CreateSMPolicy response body cannot close: %+v", rspCloseErr)
			}
		}
		return nil, httpRspStatusCode, fmt.Errorf("setup sm policy association failed: %s", err.Error())
	} else {
		httpRspStatusCode = http.StatusCreated
		smPolicyDecision = smPolicyDecisionFromPCF
		if httpRsp != nil {
			if rspCloseErr := httpRsp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("CreateSMPolicy response body cannot close: %+v", rspCloseErr)
			}
		}
	}

	if err := validateSmPolicyDecision(smPolicyDecision); err != nil {
		return nil, httpRspStatusCode, fmt.Errorf("setup sm policy association failed: %s", err.Error())
	}

	// What the PCF now believes, kept so a later change to it can be recognised as one.
	smContext.PolicyReportedIpv4 = smPolicyData.GetIpv4Address()

	return smPolicyDecision, httpRspStatusCode, nil
}

// releasedIpv4 is the address the PCF is currently binding this session by, and
// which this report therefore has to retire.
//
// Normally that is PolicyReportedIpv4, recorded when the association was
// created. A session established before that field existed and restored from the
// datastore decodes it as empty, though, and reporting no released address would
// leave the PCF binding the old one for the rest of the session -- the exact
// outcome this report exists to prevent. For those, the address the PCF was told
// at create is still the one the context holds, because this runs before the
// UPF's address is adopted and before the old one is released.
func releasedIpv4(smContext *smf_context.SMContext) string {
	if smContext.PolicyReportedIpv4 != "" {
		return smContext.PolicyReportedIpv4
	}
	if smContext.PDUAddress == nil || smContext.PDUAddress.Ip == nil {
		return ""
	}
	ipv4 := smContext.PDUAddress.Ip.To4()
	if ipv4 == nil {
		return ""
	}
	return ipv4.String()
}

// ueIpChangeReportTimeout bounds one UE_IP_CH report. It matches
// n1n2TransferTimeout, the timeout the SMF already puts on a single SBI attempt
// made from a handler.
const ueIpChangeReportTimeout = 5 * time.Second

// SendSMPolicyAssociationUpdateUeIpChange reports the UE IPv4 address to the PCF as the UE_IP_CH
// policy control request trigger, and records what was reported. This is the SMF-initiated update
// of TS 29.512 clause 4.2.4.2, which is also where the ipv4Address and relIpv4Address attributes it
// carries are specified.
//
// The policy association is created before the N4 session, so the address the PCF is given is the
// one the SMF allocated. A UPF that allocates its own supplies a different one in the establishment
// response, and the SMF then releases the address it had allocated -- so without this the PCF holds
// an address the UE does not have and that is back in the pool. That is worse than merely stale:
// an application function's session binding is matched on the address, so once the pool hands it
// out again the PCF's key can come to match a different subscriber's session.
//
// Unconditional, because UE_IP_CH is one of the triggers TS 29.512 clause 4.1.5 calls pre-configured
// in the SMF -- "i.e. always report" -- rather than one the PCF provisions. Clause 5.6.3.6 puts it in
// that category: the SMF "shall" include UE_IP_CH when it detects an address allocated or released,
// and its row in table 5.6.3.6-1 is footnoted "The NF service consumer always reports to the PCF".
// Annex A.2's OpenAPI description of the same enumeration names the NF outright -- "UE_IP_CH: UE IP
// address change. The SMF always reports to the PCF." So there is deliberately no check that the PCF
// asked for it.
//
// The released address goes in the same report, which is what lets the PCF drop the binding key it
// should no longer honour.
func SendSMPolicyAssociationUpdateUeIpChange(smContext *smf_context.SMContext, newIpv4 string) (int, error) {
	// An error, as in SendSMPolicyAssociationCreate, rather than the successful no-op
	// SendSMPolicyAssociationDelete makes of the same condition. The difference is the path: a
	// session that reaches this point was established, so it already passed the create, which
	// refuses a nil client -- nil here is anomalous. On the release path it is ordinary, because
	// a session can be torn down having never had an association at all.
	if smContext.SMPolicyClient == nil {
		return http.StatusInternalServerError, fmt.Errorf("smContext not selected PCF")
	}

	smPolicyUpdateData := models.SmPolicyUpdateContextData{
		RepPolicyCtrlReqTriggers: []models.PolicyControlRequestTrigger{
			models.POLICYCONTROLREQUESTTRIGGER_UE_IP_CH,
		},
		Ipv4Address: openapi.PtrString(newIpv4),
	}
	// Only when there is one, and only when it is not the address being reported: releasing the
	// address in the same breath as claiming it would have the PCF clear the binding it just set.
	if released := releasedIpv4(smContext); released != "" && released != newIpv4 {
		smPolicyUpdateData.RelIpv4Address = openapi.PtrString(released)
	}

	smPolicyID := fmt.Sprintf("%s-%d", smContext.Supi, smContext.PDUSessionID)

	// Bounded, unlike the create and delete calls in this file, because this one
	// runs on the establishment path while the PFCP handler holds SMLock and
	// before the establishment response is signalled. A PCF that accepts the
	// connection and never answers would otherwise hold that lock for as long as
	// it stayed silent -- the generated client has no timeout of its own -- and
	// take the session's release path down with it. The report is worth a short
	// wait and not an unbounded one: losing it costs the PCF an application-function
	// binding, where blocking costs the session.
	ctx, cancel := context.WithTimeout(context.Background(), ueIpChangeReportTimeout)
	defer cancel()

	apiUpdateSMPolicyRequest := smContext.SMPolicyClient.IndividualSMPolicyDocumentAPI.UpdateSMPolicy(ctx, smPolicyID)
	apiUpdateSMPolicyRequest = apiUpdateSMPolicyRequest.SmPolicyUpdateContextData(smPolicyUpdateData)
	_, httpRsp, err := smContext.SMPolicyClient.IndividualSMPolicyDocumentAPI.UpdateSMPolicyExecute(apiUpdateSMPolicyRequest)
	if httpRsp != nil {
		defer func() {
			if rspCloseErr := httpRsp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("UpdateSMPolicy response body cannot close: %+v", rspCloseErr)
			}
		}()
	}
	if err != nil {
		statusCode := http.StatusInternalServerError
		if httpRsp != nil {
			statusCode = httpRsp.StatusCode
		}
		return statusCode, fmt.Errorf("sm policy association update failed: %s", err.Error())
	}

	// Only after the PCF has accepted it. Recording the address before the call would make a failed
	// report look like a delivered one, and the next establishment response would send nothing.
	smContext.PolicyReportedIpv4 = newIpv4

	return httpRsp.StatusCode, nil
}

func SendSMPolicyAssociationDelete(smContext *smf_context.SMContext, smDelReq *models.ReleaseSmContextRequest) (int, error) {
	// A session released before ever getting a PCF policy client (e.g. caught mid-establishment)
	// has nothing to tear down. This is a successful no-op, not an error: callers such as
	// releaseUnrestorableSession must not report the session as failed to release just because
	// it never had a PCF association to delete.
	if smContext.SMPolicyClient == nil {
		return http.StatusNoContent, nil
	}

	smPolicyDelData := models.SmPolicyDeleteData{
		ServingNetwork: models.NewPlmnIdNid(smContext.ServingNetwork.Mcc, smContext.ServingNetwork.Mnc),
	}

	// User location info
	jd := smDelReq.GetJsonData()
	if jd.HasUeLocation() {
		smPolicyDelData.SetUserLocationInfo(jd.GetUeLocation())
	} else if jd.HasAddUeLocation() {
		smPolicyDelData.SetUserLocationInfo(jd.GetAddUeLocation())
	}

	// UE Time Zone
	if jd.GetUeTimeZone() != "" {
		smPolicyDelData.SetUeTimeZone(jd.GetUeTimeZone())
	}

	// RAN/NAS Release Cause
	ranNasRelCause := models.NewRanNasRelCause()
	ranNasRelCause.SetVar5gMmCause(jd.GetVar5gMmCauseValue())
	if jd.HasNgApCause() {
		ranNasRelCause.SetNgApCause(jd.GetNgApCause())
	}
	smPolicyDelData.SetRanNasRelCauses([]models.RanNasRelCause{*ranNasRelCause})

	// Policy Id (supi-pduSessId)
	smPolicyID := fmt.Sprintf("%s-%d", smContext.Supi, smContext.PDUSessionID)

	// Send to  PCF
	apiDeleteSMPolicyRequest := smContext.SMPolicyClient.IndividualSMPolicyDocumentAPI.DeleteSMPolicy(context.Background(), smPolicyID)
	apiDeleteSMPolicyRequest = apiDeleteSMPolicyRequest.SmPolicyDeleteData(smPolicyDelData)
	if httpRsp, err := smContext.SMPolicyClient.IndividualSMPolicyDocumentAPI.DeleteSMPolicyExecute(apiDeleteSMPolicyRequest); err != nil {
		logger.ConsumerLog.Warnf("smf policy delete failed, [%v] ", err.Error())
		if httpRsp != nil {
			if rspCloseErr := httpRsp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("DeleteSMPolicy response body cannot close: %+v", rspCloseErr)
			}
		}
		return 0, err
	} else {
		defer func() {
			if rspCloseErr := httpRsp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("DeleteSMPolicy response body cannot close: %+v", rspCloseErr)
			}
		}()
		return httpRsp.StatusCode, nil
	}
}

func validateSmPolicyDecision(smPolicy *models.SmPolicyDecision) error {
	// Validate just presence of important IEs as of now
	// Sess Rules
	for name, rule := range smPolicy.GetSessRules() {
		if rule.AuthSessAmbr == nil {
			logger.ConsumerLog.Errorf("SM policy decision rule [%s] validation failure, authorised session ambr missing", name)
			return fmt.Errorf("authorised session ambr missing")
		}

		if rule.AuthDefQos == nil {
			logger.ConsumerLog.Errorf("SM policy decision rule [%s] validation failure, authorised default qos missing", name)
			return fmt.Errorf("authorised default qos missing")
		}
	}
	return nil
}

// ReportUeIpChange tells the PCF the address the UPF allocated, when it differs from the one the
// PCF was given when the policy association was created.
//
// Called from the PFCP establishment response, where the divergence is created -- the address the
// SMF allocated has just been released and replaced. It lives here rather than in either dispatcher
// because there are two of them, native and upf-adapter, carrying the same release-and-adopt block;
// one function with two call sites is what stops them drifting apart again.
//
// It runs under the SM context lock the calling handler holds, which is where the other two PCF
// calls of a session's life also run, and before the establishment response is signalled, so an
// application function cannot observe the session between the address moving and the PCF being told.
//
// Sent whether or not the PCF asked for UE_IP_CH, for the reason given on
// SendSMPolicyAssociationUpdateUeIpChange: the specification makes it an always-report trigger.
//
// A failure is logged and nothing else. The session is established and the user plane is correct;
// what is lost is the PCF's ability to bind an application function to it, and failing an
// establishment over that would trade a working session for a reporting gap.
func ReportUeIpChange(smContext *smf_context.SMContext, ueIPAddress net.IP) {
	ipv4 := ueIPAddress.To4()
	if ipv4 == nil {
		return
	}
	newIpv4 := ipv4.String()
	if newIpv4 == smContext.PolicyReportedIpv4 {
		return
	}

	// Read before the call, because a successful one overwrites it -- and the whole
	// point of the line is which address the PCF should stop binding to.
	reported := smContext.PolicyReportedIpv4

	if statusCode, err := SendSMPolicyAssociationUpdateUeIpChange(smContext, newIpv4); err != nil {
		smContext.SubPfcpLog.Errorf("failed to report ue ip address change to PCF [%s -> %s]: %v",
			reported, newIpv4, err)
	} else {
		smContext.SubPfcpLog.Infof("reported ue ip address change to PCF [%s -> %s], http status %d",
			reported, newIpv4, statusCode)
	}
}
