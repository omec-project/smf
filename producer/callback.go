// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/omec-project/nas/v2/nasType"
	"github.com/omec-project/openapi/v2/models"
	nrfCache "github.com/omec-project/openapi/v2/nrfcache"
	"github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/smf/consumer"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/qos"
	"github.com/omec-project/smf/transaction"
	"github.com/omec-project/smf/util"
	"github.com/omec-project/util/httpwrapper"
)

var (
	NRFCacheRemoveNfProfileFromNrfCache = nrfCache.RemoveNfProfileFromNrfCache
	SendRemoveSubscription              = consumer.SendRemoveSubscription

	// Seams for fault injection. Every behaviour this file adds is a failure path, and a test
	// that only exercises the successful modification demonstrates none of them.
	// Every modification path sends through these rather than calling the functions directly, so a
	// test can observe what the network decided to send without opening a PFCP association or an
	// N1N2 transfer. Three call sites on this file's modification paths were calling the underlying
	// functions directly, which left the main network-initiated path — the one an operator policy
	// change takes — as the only one with no test.
	sendPfcpSessionModifyReq = SendPfcpSessionModifyReq
	sendQosN1N2TransferMsg   = BuildAndSendQosN1N2TransferMsg

	// applyModification is behind a seam for the same reason as the two above, and for one more:
	// the corrective modification after a partial rejection runs on its own goroutine, so without
	// a seam a test cannot tell whether it was issued, and the goroutine outlives the test and
	// reaches the real user plane.
	applyModification = ApplyModification
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
	smContext.SMLock.Unlock()

	if err := ApplyModification(smContext, policyUpdates); err != nil {
		txn.Err = err
		if errors.Is(err, ErrPfcpModifyFailed) {
			txn.Rsp = makePduCtxtModifyErrRsp(smContext, err.Error())
		}
		return err
	}

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

	if len(smContext.SmPolicyUpdates) > 0 && smContext.SmPolicyUpdates[0].SmPolicyDecision.HasPccRules() {
		validRuleID := ""
		for ruleId, rule := range smContext.SmPolicyUpdates[0].SmPolicyDecision.GetPccRules() {
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
	if smContext.Tunnel == nil {
		// A session with no tunnel has no rules to program. Reachable on the failure paths, where
		// a modification can be reverted for a session that is being torn down concurrently, and
		// the release handling elsewhere in this producer already treats a nil tunnel as a real
		// state rather than an impossible one.
		smContext.SubPduSessLog.Warnln("no tunnel for this session; nothing to program")
		return pfcpParam
	}

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
	n1n2Request := models.NewN1N2MessageTransferRequest()
	defer util.CleanupMultipartTempFiles(n1n2Request)

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
	n1n2Request.SetJsonData(*models.NewN1N2MessageTransferReqData())
	jsonData := n1n2Request.GetJsonData()
	jsonData.SetPduSessionId(smContext.PDUSessionID)
	n1n2Request.SetJsonData(jsonData)

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
		smContext.SubPduSessLog.Errorf("build PDUSessionResourceModifyRequestTransfer failed: %s", err.Error())
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
	rspData, err := consumer.SendN1N2TransferWithRediscovery(context.Background(), smContext, n1n2Request)
	smContext.SMLock.Unlock()
	if err != nil {
		smContext.SubPfcpLog.Warnf("send N1N2Transfer failed: %v", err.Error())
		return err
	}
	// -------------------------------
	// Check response cause
	// -------------------------------
	if rspData.GetCause() == models.N1N2MESSAGETRANSFERCAUSE_N1_MSG_NOT_TRANSFERRED {
		smContext.SubPfcpLog.Errorf("N1N2MessageTransfer failure: %v", rspData.GetCause())
		return fmt.Errorf("N1N2MessageTransfer failure: %v", rspData.GetCause())
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

	if notificationData.GetEvent() == "" || notificationData.GetNfInstanceUri() == "" {
		problemDetails := utils.ProblemDetailsMandatoryIeMissing("Missing IE [Event]/[NfInstanceUri] in NotificationData")
		return problemDetails
	}
	nfInstanceUri := notificationData.GetNfInstanceUri()
	nfInstanceId := nfInstanceUri[strings.LastIndex(nfInstanceUri, "/")+1:]

	logger.ProducerLog.Infof("Received Subscription Status Notification from NRF: %v", notificationData.GetEvent())
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

// startT3591 arms the retransmission timer for a modification command that has just been sent.
// TS 24.501 subclause 6.3.2.5 item a: the command is resent on each of the first four expiries
// and the procedure is abandoned on the fifth.
// ErrPfcpModifyFailed distinguishes a modification that could not be programmed into the user
// plane from one that could not be delivered to the UE. The caller answers the two differently.
var ErrPfcpModifyFailed = errors.New("pfcp session modify failed")

// ApplyModification carries out a network-requested PDU session modification: program the user
// plane, tell the UE, then arm the timer that governs the acknowledgement.
//
// It takes a prepared policy update rather than deriving one, so anything that can describe a
// change to a session can drive a modification through the same path — including the corrective
// modification that follows a partial rejection, which is a deletion of the refused flows and
// nothing more exotic than that. Having one implementation is the point: the realignment used to
// do its own user-plane rebuild and its own N1N2 send, and got both wrong in ways this path had
// already got right.
//
// The caller must not hold SMLock. This blocks on the user plane's answer, and doing that under
// the session lock is what wedges a session.
func ApplyModification(smContext *smfContext.SMContext, update *qos.PolicyUpdate) error {
	smContext.SMLock.Lock()
	smContext.SmPolicyUpdates = append(smContext.SmPolicyUpdates[:0], update)
	// From here the network owns this session's modification, and a UE request for the same session
	// is a collision to be disregarded rather than refused.
	smContext.NwModificationPending = true
	pfcpParam := BuildPfcpParam(smContext)
	smContext.ChangeState(smfContext.SmStatePfcpModify)
	smContext.SMLock.Unlock()

	if err := sendPfcpSessionModifyReq(smContext, pfcpParam); err != nil {
		smContext.SubCtxLog.Errorf("PFCP session modify error: %v", err)
		smContext.SMLock.Lock()
		// The procedure never got started, so it must not leave the session looking as though one
		// were running: every later UE request would be disregarded, silently and forever.
		smContext.NwModificationPending = false
		// Nor may it leave the session mid-modification. The user plane was not programmed, so the
		// pending update describes a change that never happened — discarding it puts the policy
		// state back to what is actually in force, and the state back to what it was on entry.
		// The path upstream reached this way left both behind; it was only ever driven by an
		// operator policy change, and this function is now reached by the corrective modification
		// after a partial rejection as well.
		if discardErr := smContext.CommitSmPolicyDecisionLocked(false); discardErr != nil {
			smContext.SubPduSessLog.Errorf("discarding the unprogrammed modification failed: %v", discardErr)
		}
		smContext.ChangeState(smfContext.SmStateActive)
		smContext.SMLock.Unlock()
		return fmt.Errorf("%w: %v", ErrPfcpModifyFailed, err)
	}

	logger.PduSessLog.Infof("PFCP modify successful for UE [%s], PDU Session ID [%d]",
		smContext.Supi, smContext.PDUSessionID)

	if err := sendQosN1N2TransferMsg(smContext); err != nil {
		logger.PduSessLog.Errorf("Failed to build/send N1/N2 QoS transfer message: %v", err)
		// The user plane was programmed before this. Leaving it there would have the session
		// enforcing parameters the UE was never told about, which is the divergence this whole
		// path exists to avoid.
		revertModification(smContext, "n1n2_transfer_failed")
		return err
	}

	smContext.SMLock.Lock()
	smContext.ChangeState(smfContext.SmStateActive)
	smContext.SubCtxLog.Info("PFCP Modify success and N1N2 Msg sent, new state:",
		smContext.SMContextState.String())
	smContext.SMLock.Unlock()

	startT3591(smContext)
	return nil
}

func startT3591(smContext *smfContext.SMContext) {
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	enabled, maxRetries := effectiveT3591Retries(smContext)
	if !enabled {
		return
	}
	startT3591Locked(smContext, maxRetries)

	smContext.SubPduSessLog.Infof("T3591 started at %s with %d retransmissions before abandonment",
		smContext.T3591Value, maxRetries)
}

// startT3591Locked arms the retransmission timer for a caller that already holds SMLock. The N1
// and N2 update handlers all run under it, so they must use this rather than startT3591: SMLock
// is not reentrant, and taking it twice wedges the session for good.
func startT3591Locked(smContext *smfContext.SMContext, maxRetries int) {
	// A previous attempt on this session must not keep running alongside this one.
	smContext.StopT3591()

	// The abandonment closure checks that it is still the session's timer before acting.
	//
	// Stopping a timer cannot recall an expiry already in flight. The abort runs on the timer's
	// own goroutine and takes SMLock, so it queues behind whatever holds the lock — and the thing
	// most likely to be holding it is the acknowledgement that just arrived and superseded this
	// procedure. Without this check the queued abort resumes afterwards and discards whatever
	// modification is pending by then, which after a partial rejection is the corrective one that
	// was started in the meantime.
	//
	// The window is narrow and it is exactly the satellite case: a UE that acknowledges at the
	// fifth expiry, after a fade almost long enough to abandon the procedure.
	var timer *smfContext.Timer
	timer = smfContext.NewTimer(smContext.T3591Value, maxRetries,
		func(expireTimes int32) {
			smContext.SubPduSessLog.Warnf("T3591 expired (%d of %d), retransmitting PDU session modification command",
				expireTimes, maxRetries)
			if err := sendQosN1N2TransferMsg(smContext); err != nil {
				smContext.SubPduSessLog.Errorf("retransmitting the modification command failed: %v", err)
			}
		},
		func() {
			abandonIfCurrent(smContext, timer, "t3591_expiry", "ue_did_not_acknowledge")
		})
	smContext.T3591 = timer
	// StopT3591 above cleared it; the procedure is still running.
	smContext.NwModificationPending = true
}

// effectiveT3591Retries reports whether the timer is enabled and how many retransmissions it
// allows, so a caller holding SMLock can arm it without re-reading configuration.
func effectiveT3591Retries(smContext *smfContext.SMContext) (bool, int) {
	enabled, maxRetries := smfContext.EffectiveT3591(factory.SmfConfig.Configuration.T3591)
	if !enabled {
		smContext.SubPduSessLog.Warnf("T3591 is disabled by configuration; an unacknowledged modification will be neither retransmitted nor abandoned")
		smContext.NwModificationPending = false
	}
	return enabled, maxRetries
}

// abandonModification gives up on a modification and leaves the session on the parameters it
// already had, by discarding the pending policy update rather than committing it.
//
// Nothing re-drives the change afterwards. On a link where a fade can outlast the whole
// retransmission sequence, abandonment is an ordinary outcome rather than a rare one, so the
// site stays on its old policy until someone re-issues it — which is why this is reported
// rather than only logged at debug.
func abandonModification(smContext *smfContext.SMContext, path, cause string) {
	reportAbandonment(smContext, path, cause)

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	abandonModificationLocked(smContext)
}

// abandonModificationLocked is the state half of abandonModification, for a caller that already
// holds SMLock. The N1 and N2 update handlers are all called with it held.
func abandonModificationLocked(smContext *smfContext.SMContext) {
	if err := smContext.CommitSmPolicyDecisionLocked(false); err != nil {
		smContext.SubPduSessLog.Errorf("discarding the abandoned modification failed: %v", err)
	}

	// Drop the timer handle and leave the session settled so a later modification of the same
	// session can be attempted.
	smContext.T3591 = nil
	smContext.NwModificationPending = false
	smContext.ChangeState(smfContext.SmStateActive)
}

// abandonIfCurrent abandons the modification only if the expiring timer is still the session's.
//
// Stopping a timer cannot recall an expiry already in flight. The abort runs on the timer's own
// goroutine and takes SMLock, so it queues behind whatever holds the lock — and the thing most
// likely to be holding it is the acknowledgement that just arrived and superseded this procedure.
// Resuming afterwards, it would discard whatever modification is pending by then, which after a
// partial rejection is the corrective one started in the meantime.
func abandonIfCurrent(smContext *smfContext.SMContext, timer *smfContext.Timer, path, cause string) {
	// The timer goroutine holds no lock, so this takes it.
	smContext.SMLock.Lock()
	superseded := smContext.T3591 != timer
	smContext.SMLock.Unlock()

	if superseded {
		smContext.SubPduSessLog.Infof("a T3591 expiry arrived for a modification that has already finished; ignoring it rather than abandoning the one now in progress")
		return
	}
	abandonModification(smContext, path, cause)
}

// reportAbandonment logs and counts an abandonment without touching session state, so the two
// halves can be used separately by callers that differ only in whether they hold SMLock.
func reportAbandonment(smContext *smfContext.SMContext, path, cause string) {
	smContext.SubPduSessLog.Errorf("abandoning PDU session modification: supi %s, pdu session %d, path %s, cause %s; the session keeps its previous parameters and the change is not retried",
		smContext.Supi, smContext.PDUSessionID, path, cause)
	metrics.IncrementModificationAbandonedStats(path, cause)
}

// abandonModificationUnderLock is abandonModification for a caller that already holds SMLock.
func abandonModificationUnderLock(smContext *smfContext.SMContext, path, cause string) {
	reportAbandonment(smContext, path, cause)
	abandonModificationLocked(smContext)
}

// revertModification gives up on a modification that could not be delivered and puts the user
// plane back to the parameters the UE still believes are in force.
//
// The discard comes first and does the heavy lifting: the pending policy update was never
// committed, so once it is dropped the session's policy state already describes the
// pre-modification session, and rebuilding the PFCP parameters from it yields exactly the rules
// that were in force. Nothing is snapshotted and nothing is copied.
//
// The path is always "delivery_failure": that is what reverting means, as distinct from a
// modification abandoned because the UE did not answer or the radio refused it. Only the cause
// varies, by how the delivery failed.
func revertModification(smContext *smfContext.SMContext, cause string) {
	const path = "delivery_failure"
	abandonModification(smContext, path, cause)

	smContext.SMLock.Lock()
	pfcpParam := BuildPfcpParam(smContext)
	smContext.SMLock.Unlock()

	if err := sendPfcpSessionModifyReq(smContext, pfcpParam); err != nil {
		// The session is now genuinely divergent: the user plane still enforces the modification
		// the UE was never told about, and putting it back has failed too. Releasing the session
		// is the right answer and this is deliberately not the place that does it.
		//
		// A release is releaseTunnel plus a read of SBIPFCPCommunicationChan plus RemoveSMContext
		// plus notifying the AMF. That channel is a single-slot rendezvous with five existing
		// readers, and this runs on a background goroutine — adding a sixth reader here would risk
		// consuming another transaction's response to clean up after a rare double failure, which
		// is a worse outcome than the divergence it repairs.
		//
		// So this marks and reports, and does not pretend to have released. The state is a label
		// nothing acts on; the metric is what makes the session findable.
		smContext.SubPduSessLog.Errorf("reverting the user plane failed: %v; this session now enforces parameters the UE was never told about and needs releasing, which this path deliberately does not attempt", err)
		metrics.IncrementModificationAbandonedStats("revert_failure", "upf_unreachable")
		smContext.SMLock.Lock()
		smContext.ChangeState(smfContext.SmStatePfcpRelease)
		smContext.SMLock.Unlock()
		return
	}

	smContext.SubPduSessLog.Infof("user plane returned to its pre-modification parameters")
}
