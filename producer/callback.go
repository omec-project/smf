// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/omec-project/nas/v2/nasType"
	"github.com/omec-project/openapi/v2/models"
	nrfCache "github.com/omec-project/openapi/v2/nrfcache"
	"github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/smf/consumer"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/qos"
	"github.com/omec-project/smf/transaction"
	"github.com/omec-project/smf/util"
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

	logger.PduSessLog.Infoln("In HandleSMPolicyUpdateNotify")

	smContext.SMLock.Lock()

	if smContext.SMContextState != smfContext.SmStateActive {
		logger.PduSessLog.Warnf("SMContext[%s-%02d] should be SmStateActive, but actual %s",
			smContext.Supi, smContext.PDUSessionID, smContext.SMContextState.String())
	}

	logger.PduSessLog.Infof("Building SM Policy Update for UE [%s], PDU Session ID [%d]",
		smContext.Supi, smContext.PDUSessionID)

	policyUpdates := qos.BuildSmPolicyUpdate(&smContext.SmPolicyData, request.SmPolicyDecision)

	smContext.SmPolicyUpdates = append(smContext.SmPolicyUpdates[:0], policyUpdates)

	// Build PFCP params while locked (if it reads shared state)
	pfcpParam := BuildPfcpParam(smContext)

	// Change state before sending PFCP
	smContext.ChangeState(smfContext.SmStatePfcpModify)

	smContext.SMLock.Unlock()

	if err := SendPfcpSessionModifyReq(smContext, pfcpParam); err != nil {
		smContext.SMLock.Lock()

		smContext.SubCtxLog.Errorf("PFCP session modify error: %v", err)

		logger.PduSessLog.Infof("SMContext[%s-%02d] state after PFCP error: %s",
			smContext.Supi, smContext.PDUSessionID, smContext.SMContextState.String())

		smContext.SMLock.Unlock()

		httpResponse := makePduCtxtModifyErrRsp(smContext, err.Error())
		txn.Err = err
		txn.Rsp = httpResponse
		return err
	}

	logger.PduSessLog.Infof("PFCP modify successful for UE [%s], PDU Session ID [%d]",
		smContext.Supi, smContext.PDUSessionID)

	if err := BuildAndSendQosN1N2TransferMsg(smContext); err != nil {
		logger.PduSessLog.Errorf("Failed to build/send N1/N2 QoS transfer message: %v", err)
		txn.Err = err
		return err
	}

	smContext.SMLock.Lock()

	smContext.ChangeState(smfContext.SmStateActive)
	smContext.SubCtxLog.Info("PFCP Modify success and N1N2 Msg sent, new state:",
		smContext.SMContextState.String())

	smContext.SMLock.Unlock()

	txn.Rsp = &httpwrapper.Response{
		Status: http.StatusOK,
		Body:   nil,
	}

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

	// Determine if we only need to release existing rules (no new policy).
	// A valid rule is one where both the map key and PccRuleId are non-empty.
	// Release-only when PccRules is present but contains no valid rules.
	shouldSendReleaseOnly := false
	ruleid := "default"

	if len(smContext.SmPolicyUpdates) > 0 && smContext.SmPolicyUpdates[0].SmPolicyDecision.PccRules != nil {
		validRuleID := ""
		for ruleId, rule := range smContext.SmPolicyUpdates[0].SmPolicyDecision.PccRules {
			logger.PduSessLog.Infof("[BuildPfcpParam] Checking PCC RuleId=%s, Rule=%+v", ruleId, rule)
			if ruleId != "" && rule.GetPccRuleId() != "" {
				validRuleID = ruleId
				break
			}
			logger.PduSessLog.Warnf("[BuildPfcpParam] Skipping invalid PCC rule: key=%q, PccRuleId=%q", ruleId, rule.GetPccRuleId())
		}
		if validRuleID != "" {
			ruleid = validRuleID
		} else {
			shouldSendReleaseOnly = true
		}
	}
	logger.PduSessLog.Infof("[BuildPfcpParam] Using PCC RuleId=%s, releaseOnly=%v", ruleid, shouldSendReleaseOnly)

	// Iterate over all active data paths in the SM context
	for dpIndex, dataPath := range smContext.Tunnel.DataPathPool {
		logger.PduSessLog.Infof("[BuildPfcpParam] Processing DataPath[%d], Activated=%v", dpIndex, dataPath.Activated)
		if !dataPath.Activated {
			logger.PduSessLog.Infof("Skipping inactive DataPath: %+v", dataPath)
			continue
		}

		ANUPF := dataPath.FirstDPNode
		var dedQERs []*smfContext.QER
		var err error
		logger.PduSessLog.Infof("Processing DataPath with UPF Node: %s", ANUPF.GetNodeIP())

		// Only create/activate QERs and tunnels if not release-only
		if !shouldSendReleaseOnly {
			dedQERs, err = ANUPF.CreateDedicatedQosQer(smContext)
			if err != nil {
				logger.PduSessLog.Warnf("[BuildPfcpParam] CreateSessRuleQer failed: %v", err)
			} else {
				logger.PduSessLog.Infof("[BuildPfcpParam] Created %d dedicated QER(s)", len(dedQERs))
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

				// Mark UL PDR, FAR, QER for removal
				if ulPDR, ok := ANUPF.UpLinkTunnel.PDR[ruleid]; ok {
					logger.PduSessLog.Infof("[BuildPfcpParam] Marking UL PDR[%s] for removal", ruleid)
					pfcpParam.removePDR = append(pfcpParam.removePDR, ulPDR)
					if ulPDR.FAR != nil {
						pfcpParam.removeFAR = append(pfcpParam.removeFAR, ulPDR.FAR)
					}
					if ulPDR.QER != nil {
						pfcpParam.removeQER = append(pfcpParam.removeQER, ulPDR.QER...)
					}
				}
				continue
			}

			// Attach dedicated QERs to DL PDR
			if len(dedQERs) > 0 {
				dlPDR.QER = dedQERs
			}
			if dlPDR.Precedence == 0 {
				dlPDR.Precedence = 1
			}

			// Set PDI fields for core interface
			dlPDR.PDI.SourceInterface = smfContext.SourceInterface{InterfaceValue: smfContext.SourceInterfaceCore}
			dlPDR.PDI.NetworkInstance = nasType.Dnn(smContext.Dnn)

			// Configure FAR for downlink traffic
			if dlPDR.FAR == nil {
				logger.PduSessLog.Errorf("dlPDR.FAR is nil")
			}
			dlFAR := dlPDR.FAR
			if dlFAR != nil {
				dlFAR.ApplyAction = smfContext.ApplyAction{
					Buff: true, Drop: false, Dupl: false, Forw: false, Nocp: true,
				}
			}

			// Append to PFCP param lists
			pfcpParam.pdrList = append(pfcpParam.pdrList, dlPDR)
			if dlFAR != nil {
				pfcpParam.farList = append(pfcpParam.farList, dlFAR)
			} else {
				logger.PduSessLog.Errorf("dlPDR.FAR is nil")
			}
			if len(dedQERs) > 0 {
				pfcpParam.qerList = append(pfcpParam.qerList, dedQERs...)
			} else {
				logger.PduSessLog.Errorf("dedicated QER is nil")
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

			// Attach dedicated QERs to UL PDR
			if len(dedQERs) > 0 {
				ulPDR.QER = dedQERs
			}
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
			if ulPDR.FAR == nil {
				logger.PduSessLog.Errorf("ulPDR.FAR is nil")
			}
			ulFAR := ulPDR.FAR
			if ulFAR != nil {
				ulFAR.ApplyAction = smfContext.ApplyAction{Forw: true}
				ulFAR.ForwardingParameters = &smfContext.ForwardingParameters{
					DestinationInterface: smfContext.DestinationInterface{
						InterfaceValue: smfContext.DestinationInterfaceCore,
					},
					NetworkInstance: []byte(smContext.Dnn),
				}
			}

			// Append to PFCP param lists
			pfcpParam.pdrList = append(pfcpParam.pdrList, ulPDR)
			if ulFAR != nil {
				pfcpParam.farList = append(pfcpParam.farList, ulFAR)
			} else {
				logger.PduSessLog.Errorf("ulFAR is nil")
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
	defer util.CleanupMultipartTempFiles(&n1n2Request)

	// -------------------------------
	// Prepare N2 container info (NGAP message)
	// -------------------------------
	// N2 Container Info
	n2InfoContent := models.NewN2InfoContent(models.RefToBinaryData{ContentId: "N2SmInformation"})
	n2InfoContent.SetNgapIeType(models.NGAPIETYPE_PDU_RES_MOD_REQ)
	smInfo := models.NewN2SmInformation(smContext.PDUSessionID)
	smInfo.SetN2InfoContent(*n2InfoContent)
	if smContext.Snssai != nil {
		smInfo.SetSNssai(*smContext.Snssai)
	}
	n2InfoContainer := models.NewN2InfoContainer(models.N2INFORMATIONCLASS_SM)
	n2InfoContainer.SetSmInfo(*smInfo)

	// -------------------------------
	// Prepare N1 container info (NAS message)
	// -------------------------------

	n1MessageClass, err := models.NewN1MessageClassFromValue("SM")
	if err != nil {
		smContext.SubPduSessLog.Errorf("failed to create N1 message class: %v", err)
		return err
	}
	n1MessageContent := models.NewRefToBinaryData("GSM_NAS")
	n1MsgContainer := models.NewN1MessageContainer(*n1MessageClass, *n1MessageContent)

	// -------------------------------
	// Fill JsonData for N1N2 transfer
	// -------------------------------
	n1n2Request.JsonData = models.NewN1N2MessageTransferReqData()
	n1n2Request.JsonData.SetPduSessionId(smContext.PDUSessionID)

	// -------------------------------
	// Build N1 (NAS) PDU Session Modification Command
	// -------------------------------
	if smNasBuf, err1 := smfContext.BuildGSMPDUSessionModificationCommand(smContext); err1 != nil {
		logger.PduSessLog.Errorf("build GSM BuildGSMPDUSessionModificationCommand failed: %s", err1.Error())
		return err1
	} else {
		tmpFile, err2 := util.CreatePayloadTempFile(smNasBuf)
		if err2 != nil {
			smContext.SubPduSessLog.Errorf("failed to create temp file: %s", err2.Error())
			return err2
		} else {
			n1n2Request.SetBinaryDataN1Message(tmpFile)
			jsonData := n1n2Request.GetJsonData()
			jsonData.SetN1MessageContainer(*n1MsgContainer)
			n1n2Request.SetJsonData(jsonData)
		}
	}

	// -------------------------------
	// Build N2 (NGAP) PDUSessionResourceModifyRequestTransfer
	// -------------------------------
	n2Pdu, err := smfContext.BuildPDUSessionResourceModifyRequestTransfer(smContext)
	if err != nil {
		smContext.SubPduSessLog.Errorf("Build PDUSessionResourceModifyRequestTransfer failed: %s", err.Error())
		return err
	} else {
		tmpFile, err1 := util.CreatePayloadTempFile(n2Pdu)
		if err1 != nil {
			smContext.SubPduSessLog.Errorf("error creating temp file (%s)", err1.Error())
			return err1
		} else {
			n1n2Request.SetBinaryDataN2Information(tmpFile)
			jsonData := n1n2Request.GetJsonData()
			jsonData.SetN2InfoContainer(*n2InfoContainer)
			n1n2Request.SetJsonData(jsonData)
		}
	}

	smContext.SubPduSessLog.Infoln("QoS N1N2 transfer initiated")
	// Hold SMLock across the transfer so AMF re-discovery's mutation of
	// AMFProfile/ServingNfId/CommunicationClient doesn't race with other SMContext users.
	smContext.SMLock.Lock()
	rspData, err := consumer.SendN1N2TransferWithRediscovery(context.Background(), smContext, &n1n2Request)
	smContext.SMLock.Unlock()
	if err != nil {
		smContext.SubPfcpLog.Warnf("Send N1N2Transfer failed: %v", err.Error())
		return err
	}
	// -------------------------------
	// Check response cause
	// -------------------------------
	if rspData.GetCause() == models.N1N2MESSAGETRANSFERCAUSE_N1_MSG_NOT_TRANSFERRED {
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
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
		problemDetails := utils.ProblemDetailsMandatoryIeMissing("Missing IE [Event]/[NfInstanceUri] in NotificationData")
		return problemDetails
	}
	nfInstanceId := notificationData.NfInstanceUri[strings.LastIndex(notificationData.NfInstanceUri, "/")+1:]

	logger.ProducerLog.Infof("Received Subscription Status Notification from NRF: %v", notificationData.Event)
	// If nrf caching is enabled, go ahead and delete the entry from the cache.
	// This will force the PCF to do nf discovery and get the updated nf profile from the NRF.
	if notificationData.GetEvent() == models.NOTIFICATIONEVENTTYPE_NF_DEREGISTERED {
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
