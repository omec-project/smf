// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package producer

import (
	"net/http"

	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/openapi/models"
	smf_context "github.com/free5gc/smf/context"
	"github.com/free5gc/smf/logger"
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

func handlePccRuleDelete(smContext *smf_context.SMContext, decision *models.SmPolicyDecision) {
	for id, pccRule := range smContext.PCCRules {
		// if rule does not exists in the pccrule list from PCF. Delete it
		if _, exist := decision.PccRules[id]; !exist {
			logger.PduSessLog.Debugf("Remove PccRule-id[%s].. PccRules[%s]", id, pccRule)
			delete(smContext.PCCRules, id)
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
				logger.PduSessLog.Debugf("Got modify request. Updated values...")
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
		}
		for id := range smContext.SessionRules {
			// Randomly choose a session rule to activate
			smf_context.SetSessionRuleActivateState(smContext.SessionRules[id], true)
			break
		}
	} else {
		selectedSessionRuleID := selectedSessionRule.SessionRuleID
		// Update session rules from decision
		for id, sessRuleModel := range decision.SessRules {
			handleSessionRule(smContext, id, sessRuleModel)
			UpdatePCCRulesSMContext(smContext, decision)
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

	logger.PduSessLog.Traceln("End of ApplySmPolicyFromDecision")
	return err
}
