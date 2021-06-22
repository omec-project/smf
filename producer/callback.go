// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package producer

import (
	"net/http"

	"github.com/free5gc/flowdesc"
	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/openapi/models"
	smf_context "github.com/free5gc/smf/context"
	"github.com/free5gc/smf/logger"
	pfcp_message "github.com/free5gc/smf/pfcp/message"
)

func HandleSMPolicyUpdateNotify(smContextRef string, request models.SmPolicyNotification) *http_wrapper.Response {
	logger.PduSessLog.Infoln("In HandleSMPolicyUpdateNotify")
	decision := request.SmPolicyDecision
	smContext := smf_context.GetSMContext(smContextRef)

	if smContext == nil {
		logger.PduSessLog.Errorf("SMContext[%s] not found", smContextRef)
		httpResponse := http_wrapper.NewResponse(http.StatusBadRequest, nil, nil)
		return httpResponse
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	if smContext.SMContextState != smf_context.Active {
		// Wait till the state becomes Active again
		// TODO: implement waiting in concurrent architecture
		logger.PduSessLog.Warnf("SMContext[%s-%02d] should be Active, but actual %s",
			smContext.Supi, smContext.PDUSessionID, smContext.SMContextState.String())
	}

	//TODO: Response data type -
	//[200 OK] UeCampingRep
	//[200 OK] array(PartialSuccessReport)
	//[400 Bad Request] ErrorReport
	httpResponse := http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
	if err := ApplySmPolicyFromDecision(smContext, decision); err != nil {
		logger.PduSessLog.Errorf("apply sm policy decision error: %+v", err)
		// TODO: Fill the error body
		httpResponse.Status = http.StatusBadRequest
	}

	return httpResponse
}

func SelectPSA2DataPathForDelete(flowDesc string, smContext *smf_context.SMContext) *smf_context.DataPath {
	flow_Desc := flowdesc.NewIPFilterRule()
	err := flowdesc.Decode(flowDesc, flow_Desc)
	if err != nil {
		logger.PduSessLog.Errorf("Invalid flow Description: %s\n", err)
	}
	for _, dataPath := range smContext.Tunnel.DataPathPool {
		if dataPath.Destination.DestinationIP == flow_Desc.GetDestinationIP() && dataPath.Destination.DestinationPort == flow_Desc.GetDestinationPorts() {
			return dataPath
		}
	}
	return nil
}

func SendSmPolicyDeleteToUPF(smContext *smf_context.SMContext, PccRule *smf_context.PCCRule) {
	logger.PduSessLog.Infoln("Delete AppSection within the PDU Session...")
	AppID := PccRule.AppID

	// Retrive the policy and flow desc from PFDs in the yaml
	UERoutingConfig := smf_context.SMF_Self().UERoutingConfig

	for _, pfds := range UERoutingConfig.PfdDatas {
		if AppID == pfds.AppID {
			for _, pfd := range pfds.Pfds {
				UPLinkPDR := new(smf_context.PDR)
				DownLinkPDR := new(smf_context.PDR)
				upfNode := new(smf_context.DataPathNode)

				flowDesc := pfd.FlowDescriptions[0]
				// Send Modfication request to the UPF
				if smf_context.SMF_Self().ULCLSupport {
					bpMGR := smContext.BPManager
					//bpMGR.SelectPSA2DataPath(flowDesc, smContext)
					bpMGR.ActivatingPath = SelectPSA2DataPathForDelete(flowDesc, smContext)

					if bpMGR.ActivatingPath == nil {
						logger.PduSessLog.Traceln("Error while getting the datapath")
						return
					}

					smContext.AllocateLocalSEIDForDataPath(bpMGR.ActivatingPath)
					upfNode = bpMGR.ActivatingPath.FirstDPNode

				} else {
					// for Non-ULCL, delete msg to UPF
					dataPath := SelectPSA2DataPathForDelete(flowDesc, smContext)

					if dataPath == nil {
						logger.PduSessLog.Traceln("Error while getting the datapath")
						return
					}
					upfNode = dataPath.FirstDPNode
				}

				/* Get the DownLink and UpLink PDR for delete*/
				UPLinkPDR = upfNode.UpLinkTunnel.PDR
				DownLinkPDR = upfNode.DownLinkTunnel.PDR
				UPLinkPDR.State = smf_context.RULE_REMOVE
				DownLinkPDR.State = smf_context.RULE_REMOVE
				UPLinkPDR.FAR.State = smf_context.RULE_REMOVE
				DownLinkPDR.FAR.State = smf_context.RULE_REMOVE

				pdrList := []*smf_context.PDR{UPLinkPDR, DownLinkPDR}
				farList := []*smf_context.FAR{UPLinkPDR.FAR, DownLinkPDR.FAR}
				barList := []*smf_context.BAR{}
				qerList := UPLinkPDR.QER
				pfcp_message.SendPfcpSessionModificationRequest(upfNode.UPF.NodeID, smContext, pdrList, farList, barList, qerList)
			}
		}
	}
}

func ApplySmPolicyToUPF(smContext *smf_context.SMContext, PccRule *smf_context.PCCRule) {
	logger.PduSessLog.Infoln("In ApplySmPolicyToUPF")
	AppID := PccRule.AppID
	precedence := PccRule.Precedence
	tcData := PccRule.RefTrafficControlData()

	// Retrive tcData
	//	   flowstatus := tcData.FlowStatus
	//	   Dnai := tcData.RouteToLocs[0].Dnai
	RouteId := tcData.RouteToLocs[0].RouteProfId

	// Retrive the policy and flow desc from PFDs in the yaml
	UERoutingConfig := smf_context.SMF_Self().UERoutingConfig
	forwardingPolicyID := UERoutingConfig.RouteProf[RouteId].ForwardingPolicyID

	for _, pfds := range UERoutingConfig.PfdDatas {
		if AppID == pfds.AppID {
			for _, pfd := range pfds.Pfds {
				flowDesc := pfd.FlowDescriptions[0]
				// Send Modfication request to the UPF
				if smf_context.SMF_Self().ULCLSupport {
					bpMGR := smContext.BPManager
					bpMGR.SelectPSA2DataPath(flowDesc, smContext)
					smContext.AllocateLocalSEIDForDataPath(bpMGR.ActivatingPath)
					bpMGR.ActivatingPath.ActivateTunnelAndPDRForIUPF(smContext, forwardingPolicyID)
					EstablishRANTunnelInfo(smContext)
					ULCLModificationRequest(smContext, flowDesc, uint32(precedence))
				} else {
					// for Non-ULCL

					defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
					ANUPF := defaultPath.FirstDPNode

					flow_Desc := flowdesc.NewIPFilterRule()
					err := flowdesc.Decode(flowDesc, flow_Desc)
					if err != nil {
						logger.PduSessLog.Errorf("Invalid flow Description: %s\n", err)
					}

					dataPath := smf_context.GenerateDataPathForIUPF(ANUPF.UPF, smContext)
					dataPath.Destination.DestinationIP = flow_Desc.GetDestinationIP()
					dataPath.Destination.DestinationPort = flow_Desc.GetDestinationPorts()
					dataPath.IsDefaultPath = false
					smContext.Tunnel.AddDataPath(dataPath)
					if defaultPath != nil {
						smContext.Tunnel.AddDataPath(dataPath)
						dataPath.ActivateTunnelAndPDR(smContext, 255)
						SendPFCPRule(smContext, dataPath)
					}
				}
			}
		}
	}
	logger.PduSessLog.Infoln("Exit ApplySmPolicyToUPF")
}

func handlePccRuleDelete(smContext *smf_context.SMContext, decision *models.SmPolicyDecision) {
	for id, pccRule := range smContext.PCCRules {
		// if rule does not exists in the pccrule list from PCF. Delete it
		if _, exist := decision.PccRules[id]; exist {
			if len(decision.SessRules) == 0 {
			  logger.PduSessLog.Debugf("Remove PccRule[%s]", id)
			  SendSmPolicyDeleteToUPF(smContext, pccRule)
			  delete(smContext.PCCRules, id)
		        }
		}
	}
}

func handlePccRule(smContext *smf_context.SMContext, id string, PccRuleModel *models.PccRule, decision *models.SmPolicyDecision) {

	logger.PduSessLog.Infoln("in handlePccRule id:", id)
	if PccRuleModel == nil {
		logger.PduSessLog.Debugf("Delete PccRule[%s]", id)
		delete(smContext.PCCRules, id)
	} else {
		pccRule := smf_context.NewPCCRuleFromModel(PccRuleModel)
		// PCC rule installation
		if oldPccRule, exist := smContext.PCCRules[id]; !exist {
			logger.PduSessLog.Debugf("Install PccRule[%s]", id)
			smContext.PCCRules[id] = pccRule
			for _, idx := range PccRuleModel.RefTcData {
				tcdata := decision.TraffContDecs[idx]
				data := smf_context.NewTrafficControlDataFromModel(tcdata)
				smContext.PCCRules[id].SetRefTrafficControlData(data)
			}
			ApplySmPolicyToUPF(smContext, pccRule)
		} else { // PCC rule modification
			logger.PduSessLog.Debugf("Modify PccRule[%s]... new ID[%s]", oldPccRule.PCCRuleID, id)
			smContext.PCCRules[id] = pccRule
			for _, idx := range PccRuleModel.RefTcData {
				tcdata := decision.TraffContDecs[idx]
				data := smf_context.NewTrafficControlDataFromModel(tcdata)
				smContext.PCCRules[id].SetRefTrafficControlData(data)
			}
			tcdata := smContext.PCCRules[id].RefTrafficControlData()
			oldtcdata := oldPccRule.RefTrafficControlData()
			if oldPccRule.AppID != PccRuleModel.AppId || oldPccRule.Precedence != PccRuleModel.Precedence || tcdata.RouteToLocs[0].Dnai != oldtcdata.RouteToLocs[0].Dnai {
				logger.PduSessLog.Debugf("Got modify request with updated values")
				ApplySmPolicyToUPF(smContext, pccRule)
			}
		}
	}

}

func UpdatePCCRulesSMContext(smContext *smf_context.SMContext, decision *models.SmPolicyDecision) {
	// update PCC rules
	handlePccRuleDelete(smContext, decision)
	for id, pccRuleModel := range decision.PccRules {
		handlePccRule(smContext, id, pccRuleModel, decision)
	}
}

func handleSessionRule(smContext *smf_context.SMContext, id string, sessionRuleModel *models.SessionRule) {
	if sessionRuleModel == nil {
		logger.PduSessLog.Debugf("Delete SessionRule[%s]", id)
		delete(smContext.SessionRules, id)
	} else {
		sessRule := smf_context.NewSessionRuleFromModel(sessionRuleModel)
		// Session rule installation
		if oldSessRule, exist := smContext.SessionRules[id]; !exist {
			logger.PduSessLog.Debugf("Install SessionRule[%s]", id)
			smContext.SessionRules[id] = sessRule
		} else { // Session rule modification
			logger.PduSessLog.Debugf("Modify SessionRule[%s]", oldSessRule.SessionRuleID)
			smContext.SessionRules[id] = sessRule
		}
	}
}

func ApplySmPolicyFromDecision(smContext *smf_context.SMContext, decision *models.SmPolicyDecision) error {
	logger.PduSessLog.Traceln("In ApplySmPolicyFromDecision")
	var err error
	smContext.ChangeState(smf_context.ModificationPending)
	selectedSessionRule := smContext.SelectedSessionRule()
	if selectedSessionRule == nil { // No active session rule
		// Update session rules from decision
		for id, sessRuleModel := range decision.SessRules {
			handleSessionRule(smContext, id, sessRuleModel)
			UpdatePCCRulesSMContext(smContext, decision)
		}
		for id := range smContext.SessionRules {
			// Randomly choose a session rule to activate
			smf_context.SetSessionRuleActivateState(smContext.SessionRules[id], true)
			break
		}
	} else {
		selectedSessionRuleID := selectedSessionRule.SessionRuleID

		if len(decision.SessRules) == 0 {
		  handleSessionRule(smContext, selectedSessionRuleID, nil)
		  UpdatePCCRulesSMContext(smContext, decision)
	        } else {
		  // Update session rules from decision
		  for id, sessRuleModel := range decision.SessRules {
			handleSessionRule(smContext, id, sessRuleModel)
			UpdatePCCRulesSMContext(smContext, decision)
		  }
		}
		if _, exist := smContext.SessionRules[selectedSessionRuleID]; !exist {
			// Original active session rule is deleted; choose again
			for id := range smContext.SessionRules {
				// Randomly choose a session rule to activate
				smf_context.SetSessionRuleActivateState(smContext.SessionRules[id], true)
				break
			}
		} else {
			// Activate original active session rule
			smf_context.SetSessionRuleActivateState(smContext.SessionRules[selectedSessionRuleID], true)
		}
	}

	smContext.SMContextState = smf_context.Active
	logger.PduSessLog.Traceln("End of ApplySmPolicyFromDecision")
	return err
}
