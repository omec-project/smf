// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/omec-project/nas/nasType"
	"github.com/omec-project/openapi/models"
	nrfCache "github.com/omec-project/openapi/nrfcache"
	"github.com/omec-project/smf/consumer"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/qos"
	"github.com/omec-project/smf/transaction"
	"github.com/omec-project/util/httpwrapper"
)

var (
	NRFCacheRemoveNfProfileFromNrfCache = nrfCache.RemoveNfProfileFromNrfCache
	SendRemoveSubscription              = consumer.SendRemoveSubscription
)

func HandleSMPolicyUpdateNotify(eventData interface{}) error {
	txn := eventData.(*transaction.Transaction)
	request := txn.Req.(models.SmPolicyNotification)
	smContext := txn.Ctxt.(*smfContext.SMContext)

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	logger.PduSessLog.Infoln("In HandleSMPolicyUpdateNotify")
	pcfPolicyDecision := request.SmPolicyDecision

	if smContext.SMContextState != smfContext.SmStateActive {
		logger.PduSessLog.Warnf("SMContext[%s-%02d] should be SmStateActive, but actual %s",
			smContext.Supi, smContext.PDUSessionID, smContext.SMContextState.String())
	}

	// Derive QoS change
	logger.PduSessLog.Infof("Building SM Policy Update for UE [%s], PDU Session ID [%d]",
		smContext.Supi, smContext.PDUSessionID)

	policyUpdates := qos.BuildSmPolicyUpdate(&smContext.SmPolicyData, pcfPolicyDecision)

	logger.PduSessLog.Infof("SM Policy Update built: %+v", policyUpdates)

	smContext.SmPolicyUpdates = append(smContext.SmPolicyUpdates[:0], policyUpdates)
	logger.PduSessLog.Infof("Appended SM Policy Update, total updates count: %d",
		len(smContext.SmPolicyUpdates))
	logger.PduSessLog.Infof("SmPolicyUpdates: %v", smContext.SmPolicyUpdates)

	// Build PFCP parameters
	pfcpParam := BuildPfcpParam(smContext)
	// Set state to PFCP Modify before sending PFCP request
	smContext.ChangeState(smfContext.SmStatePfcpModify)

	if err := SendPfcpSessionModifyReq(smContext, pfcpParam); err != nil {
		// PFCP modify failed — revert state and return error
		smContext.SubCtxLog.Errorf("PFCP session modify error: %v", err)
		// smContext.ChangeState(prevState)
		logger.PduSessLog.Infof("SMContext[%s-%02d] state reverted to %s after PFCP error",
			smContext.Supi, smContext.PDUSessionID, smContext.SMContextState.String())

		// Build HTTP error response for the original transaction
		httpResponse := makePduCtxtModifyErrRsp(smContext, err.Error())
		txn.Err = err
		txn.Rsp = httpResponse
		return err
	}

	smContext.SubCtxLog.Infoln("SMContextState Change State:", smContext.SMContextState.String())
	logger.PduSessLog.Infof("PFCP modify successful for UE [%s], PDU Session ID [%d]",
		smContext.Supi, smContext.PDUSessionID)

	// Now send N1/N2 Msg after PFCP success
	if err := BuildAndSendQosN1N2TransferMsg(smContext); err != nil {
		logger.PduSessLog.Errorf("Failed to build/send N1/N2 QoS transfer message: %v", err)
		txn.Err = err
		return err
	}

	// Set response and change state to active
	smContext.ChangeState(smfContext.SmStateActive)
	smContext.SubCtxLog.Info("PFCP Modify success and N1N2 Msg sent, new state:", smContext.SMContextState.String())

	httpResponse := &httpwrapper.Response{
		Status: http.StatusOK,
		Body:   nil,
	}
	txn.Rsp = httpResponse

	return nil
}

// BuildPfcpParam constructs the PFCP parameters (PDRs, FARs, QERs,) for a given SMContext.
// It analyzes the SM Policy updates and the current data paths in the SM context to:
//  1. Create or modify PDRs (Packet Detection Rules), FARs (Forwarding Action Rules), and QERs (QoS Enforcement Rules).
//  2. Identify PDRs, FARs, and QERs to be removed if the policy indicates a release-only scenario.
//  3. Activate UL/DL tunnels on the UPFs if needed.
//
// This function returns a pfcpParam structure containing lists of rules to add or remove for PFCP session management.
func BuildPfcpParam(smContext *smfContext.SMContext) *pfcpParam {
	// Initialize PFCP parameter container
	pfcpParam := &pfcpParam{
		pdrList:   []*smfContext.PDR{},
		farList:   []*smfContext.FAR{},
		qerList:   []*smfContext.QER{},
		removePDR: []*smfContext.PDR{},
		removeFAR: []*smfContext.FAR{},
		removeQER: []*smfContext.QER{},
	}

	// Initialize map to track UPFs pending PFCP configuration
	smContext.PendingUPF = make(smfContext.PendingUPF)

	// Determine if we only need to release existing rules (no new policy)
	shouldSendReleaseOnly := false
	ruleid := "0"

	if len(smContext.SmPolicyUpdates) > 0 && smContext.SmPolicyUpdates[0].SmPolicyDecision.PccRules != nil {
		if len(smContext.SmPolicyUpdates[0].SmPolicyDecision.PccRules) == 0 {
			shouldSendReleaseOnly = true
		} else {
			for ruleId, rule := range smContext.SmPolicyUpdates[0].SmPolicyDecision.PccRules {
				logger.PduSessLog.Infof("[BuildPfcpParam] Checking PCC RuleId=%s, Rule=%+v", ruleId, rule)
				ruleid = ruleId
				// If any PCC rule is invalid or empty, we treat this as release-only
				if ruleId == "" || rule == nil || rule.PccRuleId == "" {
					shouldSendReleaseOnly = true
					break
				}
			}
		}
	}
	logger.PduSessLog.Infof("[BuildPfcpParam] Checking PCC RuleId=%s", ruleid)

	// Iterate over all active data paths in the SM context
	for dpIndex, dataPath := range smContext.Tunnel.DataPathPool {
		logger.PduSessLog.Infof("[BuildPfcpParam] Processing DataPath[%d], Activated=%v", dpIndex, dataPath.Activated)
		if !dataPath.Activated {
			logger.PduSessLog.Infof("Skipping inactive DataPath: %+v", dataPath)
			continue
		}

		ANUPF := dataPath.FirstDPNode
		var dedQER *smfContext.QER
		var err error
		logger.PduSessLog.Infof("Processing DataPath with UPF Node: %s", ANUPF.GetNodeIP())

		// Only create/activate QERs and tunnels if not release-only
		if !shouldSendReleaseOnly {
			dedQER, err = ANUPF.CreateDedicatedQosQer(smContext)
			if err != nil {
				logger.PduSessLog.Warnf("[BuildPfcpParam] CreateSessRuleQer failed: %v", err)
			} else {
				logger.PduSessLog.Infof("[BuildPfcpParam] Created default QER: %+v", dedQER)
			}

			if err := dataPath.ActivateUlDlTunnel(smContext); err != nil {
				logger.PduSessLog.Errorf("activate UL/DL tunnel error %v", err.Error())
			}
		}

		// ----------------------
		// Handle Downlink PDRs
		// ----------------------
		if dlPDR, ok := ANUPF.DownLinkTunnel.PDR[ruleid]; ok {
			logger.PduSessLog.Infof("[BuildPfcpParam] Checking DL PDR: Name=%s, ID=%d", ruleid, dlPDR.PDRID)

			// Release-only scenario: mark PDR, FAR, QER for removal
			if shouldSendReleaseOnly {
				logger.PduSessLog.Infof("[BuildPfcpParam] Marking DL PDR[%s] for removal", ruleid)
				pfcpParam.removePDR = append(pfcpParam.removePDR, dlPDR)
				if dlPDR.FAR != nil {
					pfcpParam.removeFAR = append(pfcpParam.removeFAR, dlPDR.FAR)
				}
				if dlPDR.QER != nil {
					pfcpParam.removeQER = append(pfcpParam.removeQER, dlPDR.QER...)
				}
				continue
			}

			// Attach dedicated QER to DL PDR
			dlPDR.QER = []*smfContext.QER{dedQER}
			if dlPDR.Precedence == 0 {
				dlPDR.Precedence = 1
			}

			// Set PDI fields for core interface
			dlPDR.PDI.SourceInterface = smfContext.SourceInterface{InterfaceValue: smfContext.SourceInterfaceCore}
			dlPDR.PDI.NetworkInstance = nasType.Dnn(smContext.Dnn)

			// Configure FAR for downlink traffic
			dlFAR := dlPDR.FAR
			dlFAR.ApplyAction = smfContext.ApplyAction{
				Buff: true, Drop: false, Dupl: false, Forw: false, Nocp: true,
			}

			// Append to PFCP param lists
			pfcpParam.pdrList = append(pfcpParam.pdrList, dlPDR)
			if dlFAR != nil {
				pfcpParam.farList = append(pfcpParam.farList, dlFAR)
			}
			if dedQER != nil {
				pfcpParam.qerList = append(pfcpParam.qerList, dedQER)
			}

			smContext.PendingUPF[ANUPF.GetNodeIP()] = true
		}

		// ----------------------
		// Handle Uplink PDRs
		// ----------------------
		if ulPDR, ok := ANUPF.UpLinkTunnel.PDR[ruleid]; ok {
			if shouldSendReleaseOnly {
				// Mark UL PDR, FAR, QER for removal
				pfcpParam.removePDR = append(pfcpParam.removePDR, ulPDR)
				if ulPDR.FAR != nil {
					pfcpParam.removeFAR = append(pfcpParam.removeFAR, ulPDR.FAR)
				}
				if ulPDR.QER != nil {
					pfcpParam.removeQER = append(pfcpParam.removeQER, ulPDR.QER...)
				}
				continue
			}

			// Attach dedicated QER to UL PDR
			ulPDR.QER = []*smfContext.QER{dedQER}
			if ulPDR.Precedence == 0 {
				ulPDR.Precedence = 1
			}

			// Set PDI and outer header removal for access interface
			ulPDR.PDI.SourceInterface = smfContext.SourceInterface{InterfaceValue: smfContext.SourceInterfaceAccess}
			ulPDR.PDI.LocalFTeid = &smfContext.FTEID{Ch: true}
			ulPDR.PDI.NetworkInstance = nasType.Dnn(smContext.Dnn)
			ulPDR.OuterHeaderRemoval = &smfContext.OuterHeaderRemoval{
				OuterHeaderRemovalDescription: smfContext.OuterHeaderRemovalGtpUUdpIpv4,
			}

			// Configure FAR for UL traffic
			ulFAR := ulPDR.FAR
			ulFAR.ApplyAction = smfContext.ApplyAction{Forw: true}
			ulFAR.ForwardingParameters = &smfContext.ForwardingParameters{
				DestinationInterface: smfContext.DestinationInterface{
					InterfaceValue: smfContext.DestinationInterfaceCore,
				},
				NetworkInstance: []byte(smContext.Dnn),
			}

			// Append to PFCP param lists
			pfcpParam.pdrList = append(pfcpParam.pdrList, ulPDR)
			if ulFAR != nil {
				pfcpParam.farList = append(pfcpParam.farList, ulFAR)
			}

			smContext.PendingUPF[ANUPF.GetNodeIP()] = true
			logger.CtxLog.Infof("activate UpLink PDR[%v]:[%v]", ruleid, ulPDR)
		}
	}

	return pfcpParam
}

// 3GPP Reference: TS 23.502 §4.3.3.4 – "PDU Session Modification" procedure
func BuildAndSendQosN1N2TransferMsg(smContext *smfContext.SMContext) error {
	// -------------------------------
	// Initialize N1N2 Message Transfer Request
	// -------------------------------
	n1n2Request := models.N1N2MessageTransferRequest{}

	// -------------------------------
	// Prepare N2 container info (NGAP message)
	// -------------------------------
	n2InfoContainer := models.N2InfoContainer{
		N2InformationClass: models.N2InformationClass_SM, // SM information for NGAP
		SmInfo: &models.N2SmInformation{
			PduSessionId: smContext.PDUSessionID, // PDU session ID
			N2InfoContent: &models.N2InfoContent{
				NgapIeType: models.NgapIeType_PDU_RES_MOD_REQ, // NGAP IE type for PDUSessionResourceModifyRequest
				NgapData: &models.RefToBinaryData{
					ContentId: "N2SmInformation", // Reference ID for binary data
				},
			},
			SNssai: smContext.Snssai, // Slice information
		},
	}

	// -------------------------------
	// Prepare N1 container info (NAS message)
	// -------------------------------
	n1MsgContainer := models.N1MessageContainer{
		N1MessageClass:   "SM",                                          // Session Management NAS message
		N1MessageContent: &models.RefToBinaryData{ContentId: "GSM_NAS"}, // Binary content reference
	}

	// -------------------------------
	// Fill JsonData for N1N2 transfer
	// -------------------------------
	n1n2Request.JsonData = &models.N1N2MessageTransferReqData{
		PduSessionId: smContext.PDUSessionID,
	}

	// -------------------------------
	// Build N1 (NAS) PDU Session Modification Command
	// -------------------------------
	if smNasBuf, err := smfContext.BuildGSMPDUSessionModificationCommand(smContext); err != nil {
		logger.PduSessLog.Errorf("BuildGSMPDUSessionModificationCommand failed: %s", err)
	} else {
		n1n2Request.BinaryDataN1Message = smNasBuf                // Attach binary NAS message
		n1n2Request.JsonData.N1MessageContainer = &n1MsgContainer // Attach N1 container
	}

	// -------------------------------
	// Build N2 (NGAP) PDUSessionResourceModifyRequestTransfer
	// -------------------------------
	n2Pdu, err := smfContext.BuildPDUSessionResourceModifyRequestTransfer(smContext)
	if err != nil {
		smContext.SubPduSessLog.Errorf("Build PDUSessionResourceModifyRequestTransfer failed: %s", err.Error())
	} else {
		n1n2Request.BinaryDataN2Information = n2Pdu             // Attach binary NGAP message
		n1n2Request.JsonData.N2InfoContainer = &n2InfoContainer // Attach N2 container
	}

	smContext.SubPduSessLog.Infoln("QoS N1N2 transfer initiated")

	// -------------------------------
	// Send N1N2 Message Transfer to AMF
	// -------------------------------
	rspData, _, err := smContext.CommunicationClient.
		N1N2MessageCollectionDocumentApi.
		N1N2MessageTransfer(context.Background(), smContext.Supi, n1n2Request)
	if err != nil {
		smContext.SubPfcpLog.Warnf("Send N1N2Transfer failed: %v", err.Error())
		return err
	}

	// -------------------------------
	// Check response cause
	// -------------------------------
	if rspData.Cause == models.N1N2MessageTransferCause_N1_MSG_NOT_TRANSFERRED {
		smContext.SubPfcpLog.Errorf("N1N2MessageTransfer failure: %v", rspData.Cause)
		return fmt.Errorf("N1N2MessageTransfer failure: %v", rspData.Cause)
	}

	smContext.SubPduSessLog.Infoln("QoS N1N2 Transfer completed")
	return nil
}

func HandleNfSubscriptionStatusNotify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.PduSessLog.Debugln("[SMF] Handle NF Status Notify")

	notificationData := request.Body.(models.NotificationData)

	problemDetails := NfSubscriptionStatusNotifyProcedure(notificationData)
	if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

// NfSubscriptionStatusNotifyProcedure is handler method of notification procedure.
// According to event type retrieved in the notification data, it performs some actions.
// For example, if event type is deregistered, it deletes cached NF profile and performs an NF discovery.
func NfSubscriptionStatusNotifyProcedure(notificationData models.NotificationData) *models.ProblemDetails {
	logger.ProducerLog.Debugf("NfSubscriptionStatusNotify: %+v", notificationData)

	if notificationData.Event == "" || notificationData.NfInstanceUri == "" {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusBadRequest,
			Cause:  "MANDATORY_IE_MISSING", // Defined in TS 29.510 6.1.6.2.17
			Detail: "Missing IE [Event]/[NfInstanceUri] in NotificationData",
		}
		return problemDetails
	}
	nfInstanceId := notificationData.NfInstanceUri[strings.LastIndex(notificationData.NfInstanceUri, "/")+1:]

	logger.ProducerLog.Infof("Received Subscription Status Notification from NRF: %v", notificationData.Event)
	// If nrf caching is enabled, go ahead and delete the entry from the cache.
	// This will force the PCF to do nf discovery and get the updated nf profile from the NRF.
	if notificationData.Event == models.NotificationEventType_DEREGISTERED {
		if smfContext.SMF_Self().EnableNrfCaching {
			ok := NRFCacheRemoveNfProfileFromNrfCache(nfInstanceId)
			logger.ProducerLog.Debugf("nfinstance %v deleted from cache: %v", nfInstanceId, ok)
		}
		if subscriptionId, ok := smfContext.SMF_Self().NfStatusSubscriptions.Load(nfInstanceId); ok {
			logger.ConsumerLog.Debugf("SubscriptionId of nfInstance %v is %v", nfInstanceId, subscriptionId.(string))
			problemDetails, err := SendRemoveSubscription(subscriptionId.(string))
			if problemDetails != nil {
				logger.ConsumerLog.Errorf("Remove NF Subscription Failed Problem[%+v]", problemDetails)
			} else if err != nil {
				logger.ConsumerLog.Errorf("Remove NF Subscription Error[%+v]", err)
			} else {
				logger.ConsumerLog.Infoln("Remove NF Subscription successful")
				smfContext.SMF_Self().NfStatusSubscriptions.Delete(nfInstanceId)
			}
		} else {
			logger.ProducerLog.Infof("nfinstance %v not found in map", nfInstanceId)
		}
	}

	return nil
}
