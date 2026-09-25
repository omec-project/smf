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
	// the corrective modification after a partial rejection runs asynchronously, as a task in the
	// session's queue, so without a seam a test cannot tell whether it was issued, and the work
	// outlives the test and reaches the real user plane.
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

// deletedPccRules names the PCC rules the pending update removes. The tunnels key their PDRs by
// rule id, so this is what says which of them the user plane should stop carrying.
func deletedPccRules(smContext *smfContext.SMContext) map[string]*models.PccRule {
	if len(smContext.SmPolicyUpdates) == 0 {
		return nil
	}

	update := smContext.SmPolicyUpdates[0]
	if update == nil || update.PccRuleUpdate == nil {
		return nil
	}

	return update.PccRuleUpdate.GetDelPccRuleUpdate()
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
	logger.PduSessLog.Infof("[BuildPfcpParam] releaseOnly=%v", shouldSendReleaseOnly)

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
		logger.PduSessLog.Infof("Processing DataPath with UPF Node: %s", ANUPF.GetNodeIP())

		// Read before the tunnels are extended below: a PDR built there for an added rule does not
		// carry the session QER yet, so it would empty the intersection this is.
		sessQERs := sessionQERs(ANUPF)

		// Only activate tunnels if not release-only
		if !shouldSendReleaseOnly {
			if err := dataPath.ActivateUlDlTunnel(smContext); err != nil {
				logger.PduSessLog.Errorf("activate UL/DL tunnel error %v", err.Error())
			}
		}

		// A rule the update deletes is withdrawn from the user plane here. The radio is told to
		// release the flow and the UE is told to stop using it; without this the PDR went on
		// forwarding it, so the only party still carrying the deleted rule was the one actually
		// moving the traffic. The release-only branch below is a different case: it fires when a
		// decision has no valid rules at all, not when one rule among several goes away.
		//
		// The PDR, its FAR and the rule's own flow QER go; the session QER does not. It is
		// attached to every PDR on the path, so removing it would take the session AMBR off the
		// rules that remain -- but a rule's flow QER is built for that rule and direction alone,
		// and left behind it stayed installed with nothing referring to it.
		for deletedRule := range deletedPccRules(smContext) {
			for _, tunnel := range []*smfContext.GTPTunnel{ANUPF.DownLinkTunnel, ANUPF.UpLinkTunnel} {
				pdr, ok := tunnel.PDR[deletedRule]
				if !ok {
					continue
				}

				pfcpParam.removePDR = append(pfcpParam.removePDR, pdr)
				if pdr.FAR != nil {
					pfcpParam.removeFAR = append(pfcpParam.removeFAR, pdr.FAR)
				}
				for _, qer := range pdr.QER {
					if qer == nil {
						continue
					}
					if _, session := sessQERs[qer.QERID]; !session {
						pfcpParam.removeQER = append(pfcpParam.removeQER, qer)
					}
				}

				smContext.PendingUPF[ANUPF.GetNodeIP()] = true
			}
		}

		if shouldSendReleaseOnly {
			releaseRule(pfcpParam, ANUPF, ruleid)
			continue
		}

		// Each rule is programmed on its own PDRs. This used to take the first valid rule in map
		// order and hang every dedicated QER in the decision on that one rule's PDRs, replacing
		// what they carried. With a single PCC rule that is always the right rule, which is why
		// nothing caught it; with a catch-all beside a dedicated flow it is a coin flip, and on
		// the losing side the catch-all's traffic is metered at the dedicated flow's rates with
		// its own flow QER and the session AMBR gone from it.
		for name := range addedPccRules(smContext) {
			programAddedRule(smContext, pfcpParam, ANUPF, name, sessQERs)
		}
		for name, qosRef := range requalifiedPccRules(smContext) {
			requalifyRule(smContext, pfcpParam, ANUPF, name, qosRef, sessQERs)
		}
	}

	return pfcpParam
}

// sessionQERs returns, by ID, the QERs carried by every PDR on the node, which is the session QER:
// it is built once per node and attached to all of them, while a rule's flow QER is built per
// direction and so is on one PDR only.
//
// Matched by ID, not by pointer. A session restored from the database has its tunnels decoded PDR
// by PDR, so each PDR holds its own copy of the session QER, and a pointer intersection comes out
// empty -- which would have every QER treated as the rule's own, and the session AMBR dropped.
func sessionQERs(node *smfContext.DataPathNode) map[uint32]*smfContext.QER {
	var shared map[uint32]*smfContext.QER

	for _, tunnel := range []*smfContext.GTPTunnel{node.UpLinkTunnel, node.DownLinkTunnel} {
		if tunnel == nil {
			continue
		}

		for _, pdr := range tunnel.PDR {
			carried := make(map[uint32]*smfContext.QER, len(pdr.QER))
			for _, qer := range pdr.QER {
				if qer == nil {
					continue
				}
				if _, ok := shared[qer.QERID]; shared == nil || ok {
					carried[qer.QERID] = qer
				}
			}

			shared = carried
		}
	}

	return shared
}

// addedPccRules names the rules the pending update adds. Their PDRs are built by
// ActivateUlDlTunnel, under the same names.
func addedPccRules(smContext *smfContext.SMContext) map[string]*models.PccRule {
	if len(smContext.SmPolicyUpdates) == 0 || smContext.SmPolicyUpdates[0] == nil ||
		smContext.SmPolicyUpdates[0].PccRuleUpdate == nil {
		return nil
	}

	return smContext.SmPolicyUpdates[0].PccRuleUpdate.GetAddPccRuleUpdate()
}

// requalifiedPccRules names the established rules whose QoS data or traffic control data the pending
// update changes, or which it changes themselves, with the QoS data each refers to. Traffic control
// is where a rule's gate comes from -- CreatePccRuleQer closes the QER for a disabled flow -- so a
// decision that only disables or re-enables a flow reaches the user plane through here too. The second matters when a rule is
// re-pointed at QoS data that already exists: nothing about the QoS data changes, only which of it
// the rule uses -- and undoing a re-pointing is exactly that case. A rule on the default QoS flow is
// included: establishment builds its flow QER from its QoS data like any other rule's, so a change
// to that data has to reach it too.
func requalifiedPccRules(smContext *smfContext.SMContext) map[string]string {
	if len(smContext.SmPolicyUpdates) == 0 || smContext.SmPolicyUpdates[0] == nil {
		return nil
	}

	update := smContext.SmPolicyUpdates[0]
	added := addedPccRules(smContext)
	changed := update.QosFlowUpdate.GetModified()
	requalified := make(map[string]string)

	for name, rule := range update.SmPolicyDecision.GetPccRules() {
		if name == "" || rule.GetPccRuleId() == "" || added[name] != nil || len(rule.RefQosData) == 0 {
			continue
		}

		qosRef := rule.RefQosData[0]
		_, ok := changed[qosRef]
		if !ok {
			_, ok = update.QosFlowUpdate.GetAdded()[qosRef]
		}
		if !ok {
			_, ok = update.PccRuleUpdate.GetModPccRuleUpdate()[name]
		}
		if !ok && len(rule.RefTcData) > 0 {
			_, ok = update.TCUpdate.GetModified()[rule.RefTcData[0]]
		}
		if !ok {
			continue
		}

		requalified[name] = qosRef
	}

	return requalified
}

// releaseRule withdraws a rule's PDRs, FARs and QERs, for a decision that carries no valid rule.
func releaseRule(pfcpParam *pfcpParam, node *smfContext.DataPathNode, ruleid string) {
	for _, tunnel := range []*smfContext.GTPTunnel{node.DownLinkTunnel, node.UpLinkTunnel} {
		pdr, ok := tunnel.PDR[ruleid]
		if !ok {
			continue
		}

		logger.PduSessLog.Infof("[BuildPfcpParam] Marking PDR[%s] ID=%d for removal", ruleid, pdr.PDRID)
		pfcpParam.removePDR = append(pfcpParam.removePDR, pdr)
		if pdr.FAR != nil {
			pfcpParam.removeFAR = append(pfcpParam.removeFAR, pdr.FAR)
		}
		if pdr.QER != nil {
			pfcpParam.removeQER = append(pfcpParam.removeQER, pdr.QER...)
		}
	}
}

// programAddedRule completes the PDRs ActivateUlDlTunnel built for a rule the update adds, and
// queues them for creation. They carry the rule's own flow QER from that build; the session QER is
// added here, since the tunnel build does not attach it.
func programAddedRule(smContext *smfContext.SMContext, pfcpParam *pfcpParam, node *smfContext.DataPathNode,
	name string, sessQERs map[uint32]*smfContext.QER,
) {
	var session []*smfContext.QER
	for _, qer := range sessQERs {
		session = append(session, qer)
	}

	if dlPDR, ok := node.DownLinkTunnel.PDR[name]; ok {
		pfcpParam.qerList = append(pfcpParam.qerList, dlPDR.QER...)
		dlPDR.QER = append(dlPDR.QER, session...)
		if dlPDR.Precedence == 0 {
			dlPDR.Precedence = 1
		}

		// Set PDI fields for core interface
		dlPDR.PDI.SourceInterface = smfContext.SourceInterface{InterfaceValue: smfContext.SourceInterfaceCore}
		dlPDR.PDI.NetworkInstance = nasType.Dnn(smContext.Dnn)

		// Configure FAR for downlink traffic
		if dlFAR := dlPDR.FAR; dlFAR != nil {
			dlFAR.ApplyAction = smfContext.ApplyAction{
				Buff: true, Drop: false, Dupl: false, Forw: false, Nocp: true,
			}
			pfcpParam.farList = append(pfcpParam.farList, dlFAR)
		} else {
			logger.PduSessLog.Errorf("dlPDR.FAR is nil")
		}

		pfcpParam.pdrList = append(pfcpParam.pdrList, dlPDR)
		smContext.PendingUPF[node.GetNodeIP()] = true
	}

	if ulPDR, ok := node.UpLinkTunnel.PDR[name]; ok {
		pfcpParam.qerList = append(pfcpParam.qerList, ulPDR.QER...)
		ulPDR.QER = append(ulPDR.QER, session...)
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
		if ulFAR := ulPDR.FAR; ulFAR != nil {
			ulFAR.ApplyAction = smfContext.ApplyAction{Forw: true}
			ulFAR.ForwardingParameters = &smfContext.ForwardingParameters{
				DestinationInterface: smfContext.DestinationInterface{
					InterfaceValue: smfContext.DestinationInterfaceCore,
				},
				NetworkInstance: []byte(smContext.Dnn),
			}
			pfcpParam.farList = append(pfcpParam.farList, ulFAR)
		} else {
			logger.PduSessLog.Errorf("ulFAR is nil")
		}

		pfcpParam.pdrList = append(pfcpParam.pdrList, ulPDR)
		smContext.PendingUPF[node.GetNodeIP()] = true
		logger.CtxLog.Infof("activate UpLink PDR[%v]:[%v]", name, ulPDR)
	}
}

// requalifyRule gives an established rule's PDRs a flow QER built from its changed QoS data, the
// way the establishment path builds one, and sends them as updates. The superseded flow QER is
// removed; the session QER stays. Nothing else about the PDRs changes: their filters and FARs are
// already programmed, and a downlink FAR rewritten here would stop forwarding an active flow.
func requalifyRule(smContext *smfContext.SMContext, pfcpParam *pfcpParam, node *smfContext.DataPathNode,
	name, qosRef string, sessQERs map[uint32]*smfContext.QER,
) {
	tcRef := ""
	if rule, ok := smContext.SmPolicyUpdates[0].SmPolicyDecision.GetPccRules()[name]; ok && len(rule.RefTcData) > 0 {
		tcRef = rule.RefTcData[0]
	}

	for _, tunnel := range []*smfContext.GTPTunnel{node.DownLinkTunnel, node.UpLinkTunnel} {
		pdr, ok := tunnel.PDR[name]
		if !ok {
			continue
		}

		flowQER, err := node.CreatePccRuleQer(smContext, qosRef, tcRef)
		if err != nil {
			// Left as it is rather than stripped: the old rates still bound the flow.
			logger.PduSessLog.Errorf("PCC rule %s keeps its previous rates: %v", name, err)
			continue
		}

		qers := []*smfContext.QER{flowQER}
		for _, qer := range pdr.QER {
			if qer == nil {
				continue
			}
			if _, session := sessQERs[qer.QERID]; session {
				qers = append(qers, qer)
			} else {
				pfcpParam.removeQER = append(pfcpParam.removeQER, qer)
			}
		}

		pdr.QER = qers
		pdr.State = smfContext.RULE_UPDATE
		pfcpParam.pdrList = append(pfcpParam.pdrList, pdr)
		pfcpParam.qerList = append(pfcpParam.qerList, flowQER)
		smContext.PendingUPF[node.GetNodeIP()] = true
		logger.PduSessLog.Infof("[BuildPfcpParam] PCC rule %s PDR %d now carries QER %d", name, pdr.PDRID, flowQER.QERID)
	}
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
	n2InfoContent := models.NewN2InfoContent(models.RefToBinaryData{ContentId: n2SmInformationContentID})
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

	// Both payloads describe one modification, so they are built under one hold of the lock. The
	// callers reach here without it -- ApplyModification releases before the transfer, and the
	// retransmission runs on the timer's goroutine -- so between the two builds a UE completion
	// could commit and pop the pending update, or another policy update replace it. The command
	// would then carry NAS and NGAP describing different policies, or be built from an update
	// that is no longer there. Neither builder takes the lock itself.
	smContext.SMLock.Lock()

	smNasBuf, nasErr := smfContext.BuildGSMPDUSessionModificationCommand(smContext)

	var (
		n2Pdu   []byte
		ngapErr error
	)

	if nasErr == nil {
		n2Pdu, ngapErr = smfContext.BuildPDUSessionResourceModifyRequestTransfer(smContext)
	}

	smContext.SMLock.Unlock()

	// -------------------------------
	// Build N1 (NAS) PDU Session Modification Command
	// -------------------------------
	if nasErr != nil {
		logger.PduSessLog.Errorf("build GSM BuildGSMPDUSessionModificationCommand failed: %s", nasErr.Error())
		return nasErr
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
	if ngapErr != nil {
		smContext.SubPduSessLog.Errorf("build PDUSessionResourceModifyRequestTransfer failed: %s", ngapErr.Error())
		return ngapErr
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
	lockAfterRevert(smContext)
	smContext.SmPolicyUpdates = append(smContext.SmPolicyUpdates[:0], update)
	// Any update a previous completion retained for a radio answer belongs to a procedure this one
	// replaces. Its flows are either established or long refused, and correcting them from here
	// would withdraw them on the strength of an answer to a different modification.
	smContext.CommittedBeforeRanAnswer = nil
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

	smContext.SMLock.Lock()
	forgetRemovedRules(smContext, pfcpParam)
	smContext.SMLock.Unlock()

	// Expected from before the transfer rather than after it. The radio's answer travels its own
	// path back and can arrive while this HTTP call is still in flight, and a handler finding no
	// expectation set discards it as belonging to no modification -- losing a partial rejection
	// that had a realignment waiting on it. Cleared on every path that gives the modification up.
	smContext.SMLock.Lock()
	smContext.RanAnswerPending = true
	smContext.SMLock.Unlock()

	if err := sendQosN1N2TransferMsg(smContext); err != nil {
		logger.PduSessLog.Errorf("Failed to build/send N1/N2 QoS transfer message: %v", err)
		// The user plane was programmed before this. Leaving it there would have the session
		// enforcing parameters the UE was never told about, which is the divergence this whole
		// path exists to avoid.
		revertModification(smContext, "n1n2_transfer_failed")
		return err
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	smContext.ChangeState(smfContext.SmStateActive)
	smContext.SubCtxLog.Info("PFCP Modify success and N1N2 Msg sent, new state:",
		smContext.SMContextState.String())

	// Armed under the same hold as the state change. Releasing the lock first left a window in
	// which the UE's acknowledgement could stop the timer and commit the update, after which this
	// armed a fresh timer -- and set NwModificationPending back to true -- for a procedure that
	// had already finished. A UE on a short link answers well inside that window.
	// The acknowledgement can arrive before this point: the transfer call above blocks until the
	// AMF answers, and the UE's completion travels its own path. Its handler clears the flag, so
	// finding it clear here means the procedure is already over -- and arming a timer for it would
	// have T3591 retransmit and then abandon a modification the UE has accepted and this SMF has
	// committed.
	if !smContext.NwModificationPending {
		smContext.SubPduSessLog.Infoln("the UE acknowledged the modification before the transfer returned; not arming T3591 for a procedure that is over")
		return nil
	}

	if enabled, maxRetries := effectiveT3591Retries(smContext); enabled {
		startT3591Locked(smContext, maxRetries)

		smContext.SubPduSessLog.Infof("T3591 started at %s with %d retransmissions before abandonment",
			smContext.T3591Value, maxRetries)
	}

	return nil
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
	// A context restored from a record written before T3591Value existed carries zero, because
	// only SetCreateData resolves it and the restore decodes what the record holds. NewTimer
	// would pass that to time.NewTicker, which panics -- ending the process on the first
	// network-initiated modification after a restart. Resolve it here instead, and keep the
	// answer so the next persist carries it. ResolveT3591 always answers with a positive
	// duration, so there is nothing further to guard against here.
	if smContext.T3591Value <= 0 {
		smContext.T3591Value, smContext.T3591Source = smfContext.ResolveT3591(
			factory.SmfConfig.Configuration.T3591, smContext.ExtendedNasSmTimer)

		smContext.SubPduSessLog.Infof("this session carried no T3591 value; resolved %s from %s",
			smContext.T3591Value, smContext.T3591Source)
		// Counted here as well as at creation, or a deployment whose sessions resolve their timer
		// on restore would show no value for that source at all.
		metrics.IncrementNasTimerStats("T3591", string(smContext.T3591Source), smContext.T3591Value.String())
	}

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
			// Queued rather than run on the timer's goroutine. The revert that follows waits on the
			// session's one PFCP response channel, which carries no correlation, so it must not be
			// in flight beside any other exchange for the session -- and a transaction that has
			// already passed its wait for an owed revert, but not yet sent, is one the timer could
			// otherwise overtake.
			queueSessionTask(smContext, func() { abandonIfCurrent(smContext, timer) })
		})
	smContext.T3591 = timer
	// StopT3591 above cleared it; the procedure is still running.
	smContext.NwModificationPending = true
}

// effectiveT3591Retries reports whether the timer is enabled and how many retransmissions it
// allows, so a caller holding SMLock can arm it without re-reading configuration.
//
// Disabling the timer suppresses retransmission and expiry, and nothing else. It used to clear
// NwModificationPending as well, which is a different statement: that flag is what tells the rest
// of the SMF a modification is running. Without it a UE request for the same session stopped
// being a collision to disregard and became one to refuse, and -- worse -- a delivery-failure
// indication was read as belonging to the establishment path, which releases the session instead
// of reverting the modification. Turning off a timer would then have taken down a working data
// path.
//
// So the procedure stays pending until something settles it: the UE's completion or rejection,
// the radio's refusal, or a failure that reverts it. With the timer off and a UE that never
// answers, it stays pending -- which is what disabling the timer asks for.
func effectiveT3591Retries(smContext *smfContext.SMContext) (bool, int) {
	enabled, maxRetries := smfContext.EffectiveT3591(factory.SmfConfig.Configuration.T3591)
	if !enabled {
		smContext.SubPduSessLog.Warnf("T3591 is disabled by configuration; an unacknowledged modification will be neither retransmitted nor abandoned")
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
//
// It returns the update it discarded, taken in the same hold of the lock, so the caller can put the
// user plane back from exactly that one; it does not do so itself, because that waits on the user
// plane.
func abandonModification(smContext *smfContext.SMContext, path, cause string) *qos.PolicyUpdate {
	reportAbandonment(smContext, path, cause)

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	return abandonForRevertLocked(smContext)
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

	// The realignment marker belongs to the procedure being abandoned. Left behind, the next
	// modification's completion would read it, prune flows this abandonment has already given up
	// on, and start a corrective procedure for them.
	smContext.Realign = nil

	// The radio's answer is no longer expected either. It is cleared here and not in StopT3591,
	// which the UE's own completion also calls: the radio can answer after the UE does, and that
	// answer is the one the realignment reads. Only giving up on the modification stops it being
	// an answer to anything.
	smContext.RanAnswerPending = false

	// And with no answer expected, nothing will build a correction from the update a completion
	// retained. Held on to, it would be the update a *later* procedure's answer corrected.
	smContext.CommittedBeforeRanAnswer = nil

	smContext.ChangeState(smfContext.SmStateActive)
}

// abandonIfCurrent abandons the modification only if the expiring timer is still the session's.
//
// Stopping a timer cannot recall an expiry already in flight. The abort is queued as a session
// task and runs when it reaches the front of the session's transaction queue -- behind, most
// likely, the acknowledgement that just arrived and superseded this procedure. Resuming then, it
// would discard whatever modification is pending by then, which after a partial rejection is the
// corrective one started in the meantime.
func abandonIfCurrent(smContext *smfContext.SMContext, timer *smfContext.Timer) {
	// T3591 is the only timer whose expiry abandons a modification, and it expires for one reason.
	const path, cause = "t3591_expiry", "ue_did_not_acknowledge"

	// This starts holding no lock, so it takes SMLock -- and keeps it across the check and the
	// abandonment. Releasing in between put the two on either side of a lock acquisition, so
	// an acknowledgement arriving in the gap could commit and start the next procedure, and this
	// would then discard that newer one on the strength of a check that no longer held.
	smContext.SMLock.Lock()

	if smContext.T3591 != timer {
		smContext.SMLock.Unlock()
		smContext.SubPduSessLog.Infof("a T3591 expiry arrived for a modification that has already finished; ignoring it rather than abandoning the one now in progress")

		return
	}

	abandoned := abandonForRevertLocked(smContext)
	smContext.SMLock.Unlock()

	// Reported outside the lock: it logs and counts, and touches no session state.
	reportAbandonment(smContext, path, cause)

	// The user plane was programmed before the command was first sent, and a UE that never
	// answered never took the new parameters up. This holds no lock here, and runs in the session's
	// transaction slot, so no other exchange for the session is in flight beside the revert.
	restoreUserPlane(smContext, abandoned)
}

// reportAbandonment logs and counts an abandonment without touching session state, so the two
// halves can be used separately by callers that differ only in whether they hold SMLock.
func reportAbandonment(smContext *smfContext.SMContext, path, cause string) {
	smContext.SubPduSessLog.Errorf("abandoning PDU session modification: supi %s, pdu session %d, path %s, cause %s; the session keeps its previous parameters and the change is not retried",
		smContext.Supi, smContext.PDUSessionID, path, cause)
	metrics.IncrementModificationAbandonedStats(path, cause)
}

// abandonModificationUnderLock is abandonModification for a caller that already holds SMLock, for a
// modification whose user plane had been programmed: the UE refusing the command, and the radio
// refusing all of it. The revert runs on its own goroutine, because it waits on the user plane and
// the caller holds the session lock across its whole handler.
func abandonModificationUnderLock(smContext *smfContext.SMContext, path, cause string) {
	reportAbandonment(smContext, path, cause)
	restoreUserPlaneAsync(smContext, abandonForRevertLocked(smContext))
}

// queueSessionTask runs work in the session's transaction queue. The fsm package owns the queue and
// installs the real one at start; this package cannot import it, and until then the work runs on a
// goroutine of its own, as it did before there was a queue to put it in.
var queueSessionTask = func(_ *smfContext.SMContext, task func()) { go task() }

// SetSessionTaskQueue installs the function that queues work for a session. Called once, by the fsm
// package at start.
func SetSessionTaskQueue(queue func(*smfContext.SMContext, func())) {
	queueSessionTask = queue
}

// restoreUserPlaneAsync is behind a seam for the reason applyModification is: the restore runs on
// its own goroutine and reaches the user plane, so a test needs to see that it was issued without
// it outliving the test.
var restoreUserPlaneAsync = func(smContext *smfContext.SMContext, abandoned *qos.PolicyUpdate) {
	go restoreUserPlane(smContext, abandoned)
}

// empty reports whether the parameters change nothing on the user plane.
func (p *pfcpParam) empty() bool {
	return len(p.pdrList) == 0 && len(p.farList) == 0 && len(p.barList) == 0 && len(p.qerList) == 0 &&
		len(p.removePDR) == 0 && len(p.removeFAR) == 0 && len(p.removeQER) == 0
}

// lockAfterRevert takes SMLock once no revert is owed on the session, and returns holding it.
//
// A revert is part of the procedure it undoes: it is computed from the committed rules and the
// update that was abandoned, and programs the committed rules back. A modification built before it
// had finished would be programmed first and then undone -- the revert restores the committed
// rules over whatever the new one had just set -- and the two would wait on the session's one
// response channel at once. Every transaction waits for an owed revert before processing; this is
// the same wait for ApplyModification, which the realignment reaches as a queued task and the
// delivery-failure paths reach from inside a transaction that is already past that point.
func lockAfterRevert(smContext *smfContext.SMContext) {
	for {
		smContext.SMLock.Lock()
		owed := smContext.RevertInFlight
		if owed == nil {
			return
		}
		smContext.SMLock.Unlock()
		<-owed
	}
}

// abandonForRevertLocked abandons the modification in flight and returns what it discarded, so the
// caller can put the user plane back from exactly that update; the caller holds SMLock. When there
// is something to put back, the revert is recorded as owed in the same hold, so nothing can start
// in between: the caller must hand the update to restoreUserPlane, which settles it.
func abandonForRevertLocked(smContext *smfContext.SMContext) *qos.PolicyUpdate {
	abandoned := pendingUpdateLocked(smContext)
	abandonModificationLocked(smContext)
	if abandoned != nil && smContext.RevertInFlight == nil {
		smContext.RevertInFlight = make(chan struct{})
	}

	return abandoned
}

// pendingUpdateLocked is the modification in flight, or nil. The caller holds SMLock, and takes it
// in the same hold as the abandonment that discards it, so what is reverted is what was discarded.
func pendingUpdateLocked(smContext *smfContext.SMContext) *qos.PolicyUpdate {
	if len(smContext.SmPolicyUpdates) == 0 {
		return nil
	}

	return smContext.SmPolicyUpdates[0]
}

// revertModification gives up on a modification that could not be delivered and puts the user
// plane back to the parameters the UE still believes are in force.
//
// The path is always "delivery_failure": that is what reverting means, as distinct from a
// modification abandoned because the UE did not answer or the radio refused it. Only the cause
// varies, by how the delivery failed.
// revertModification reports whether the user plane went back. A false answer means the session is
// running parameters the UE was never told about and the caller must not describe it as recovered.
func revertModification(smContext *smfContext.SMContext, cause string) bool {
	const path = "delivery_failure"

	return restoreUserPlane(smContext, abandonModification(smContext, path, cause))
}

// restoreUserPlane puts the user plane back to the committed policy after abandoned has been
// discarded, and reports whether it went back. The caller must not hold SMLock: this waits on the
// user plane's answer.
//
// The revert is built from the abandoned update rather than by rebuilding from the committed
// policy. The PFCP builder programs what an update changes, so with the abandoned update discarded
// and nothing pending it programs nothing -- which is what this did before, while logging that the
// user plane had been put back. The update abandoned installed is still installed; RevertOf is the
// one that takes it out again.
func restoreUserPlane(smContext *smfContext.SMContext, abandoned *qos.PolicyUpdate) bool {
	if abandoned == nil {
		smContext.SubPduSessLog.Infof("no modification was pending; the user plane has nothing to put back")
		return true
	}

	// Settled however this ends, so a modification waiting in lockAfterRevert is never stranded.
	defer func() {
		smContext.SMLock.Lock()
		if owed := smContext.RevertInFlight; owed != nil {
			close(owed)
			smContext.RevertInFlight = nil
		}
		smContext.SMLock.Unlock()
	}()

	smContext.SMLock.Lock()
	revert := qos.RevertOf(&smContext.SmPolicyData, abandoned)
	// Programmed through the builder as the pending update, and not left pending: it is not a
	// modification of the session, and nothing may commit it or tell the UE about it. Whatever was
	// pending by now -- a modification started since the abandonment -- is put back as it was.
	pending := smContext.SmPolicyUpdates
	smContext.SmPolicyUpdates = []*qos.PolicyUpdate{revert}
	pfcpParam := BuildPfcpParam(smContext)
	smContext.SmPolicyUpdates = pending

	if pfcpParam.empty() {
		smContext.SMLock.Unlock()
		smContext.SubPduSessLog.Infof("the abandoned modification changed nothing the user plane carries; nothing to put back")
		return true
	}

	// The response handler signals the waiting sender only while the session is in PfcpModify,
	// and the abandonment has just moved it to Active. Sent from Active, the UPF's acceptance was
	// never delivered: this waited on SBIPFCPCommunicationChan for good, and the next exchange on
	// the session had its answer taken by this wait instead. Seen on a rig: the revert went out
	// and was accepted, and the SMF never logged it as done.
	settled := smContext.SMContextState
	smContext.ChangeState(smfContext.SmStatePfcpModify)
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

		return false
	}

	smContext.SMLock.Lock()
	forgetRemovedRules(smContext, pfcpParam)
	smContext.ChangeState(settled)
	smContext.SMLock.Unlock()

	smContext.SubPduSessLog.Infof("user plane returned to its pre-modification parameters")

	return true
}

// forgetRemovedRules drops the PDRs the user plane has just accepted removing from the session's
// tunnels and PFCP context, and returns their PDR and FAR identifiers to the pool. The caller holds
// SMLock, and calls this only once the removal has been accepted: until then the rules are still
// installed, and a failed removal has to find them where they were.
//
// Left in the tunnels, a withdrawn rule was still the session's as far as everything reading them
// was concerned. Restoration re-installs a restarted UPF from exactly those maps, so a rule the
// policy had deleted came back with it; and a rule later added under the same name overwrote the
// entry without freeing it, losing a PDR identifier from a pool of 65535 shared by every session on
// the UPF.
//
// QER identifiers are not returned. They come from a pool of 2^32 per UPF, are scoped to the PFCP
// session on the wire, and one per rate change is what a superseded flow QER costs; freeing them
// safely would mean proving no PDR still names one, for a pool that does not run out.
func forgetRemovedRules(smContext *smfContext.SMContext, pfcpParam *pfcpParam) {
	if len(pfcpParam.removePDR) == 0 || smContext.Tunnel == nil {
		return
	}

	removed := make(map[*smfContext.PDR]bool, len(pfcpParam.removePDR))
	for _, pdr := range pfcpParam.removePDR {
		removed[pdr] = true
	}
	removedFAR := make(map[*smfContext.FAR]bool, len(pfcpParam.removeFAR))
	for _, far := range pfcpParam.removeFAR {
		removedFAR[far] = true
	}

	for _, dataPath := range smContext.Tunnel.DataPathPool {
		node := dataPath.FirstDPNode
		if node == nil || node.UPF == nil {
			continue
		}

		nodeIP := node.UPF.NodeID.ResolveNodeIdToIp().String()
		for _, tunnel := range []*smfContext.GTPTunnel{node.UpLinkTunnel, node.DownLinkTunnel} {
			if tunnel == nil {
				continue
			}

			for name, pdr := range tunnel.PDR {
				if !removed[pdr] {
					continue
				}

				delete(tunnel.PDR, name)
				if pfcpCtx := smContext.PFCPContext[nodeIP]; pfcpCtx != nil {
					delete(pfcpCtx.PDRs, pdr.PDRID)
				}
				if err := node.UPF.RemovePDR(pdr); err != nil {
					smContext.SubPduSessLog.Warnf("returning PDR %d to the pool: %v", pdr.PDRID, err)
				}
				if pdr.FAR != nil && removedFAR[pdr.FAR] {
					if err := node.UPF.RemoveFAR(pdr.FAR); err != nil {
						smContext.SubPduSessLog.Warnf("returning FAR %d to the pool: %v", pdr.FAR.FARID, err)
					}
				}
			}
		}
	}
}
