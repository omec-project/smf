// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/omec-project/openapi/v2/models"
	nrfCache "github.com/omec-project/openapi/v2/nrfcache"
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
	pcfPolicyDecision := request.SmPolicyDecision

	if smContext.SMContextState != smfContext.SmStateActive {
		// Wait till the state becomes SmStateActive again
		// TODO: implement waiting in concurrent architecture
		logger.PduSessLog.Warnf("SMContext[%s-%02d] should be SmStateActive, but actual %s",
			smContext.Supi, smContext.PDUSessionID, smContext.SMContextState.String())
	}

	//TODO: Response data type -
	//[200 OK] UeCampingRep
	//[200 OK] array(PartialSuccessReport)
	//[400 Bad Request] ErrorReport

	// Derive QoS change(compare existing vs received Policy Decision)
	policyUpdates := qos.BuildSmPolicyUpdate(&smContext.SmPolicyData, pcfPolicyDecision)
	smContext.SmPolicyUpdates = append(smContext.SmPolicyUpdates, policyUpdates)

	// Update UPF
	// TODO

	httpResponse := httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	txn.Rsp = httpResponse

	// Form N1/N2 Msg based on QoS Change and Trigger N1/N2 Msg
	if err := BuildAndSendQosN1N2TransferMsg(smContext); err != nil {
		// smContext.CommitSmPolicyDecision(false)
		// Send error rsp to PCF
		httpResponse.Status = http.StatusBadRequest
		txn.Err = err
		return err
	}

	// N1N2 and UPF update Success
	// Commit SM Policy Decision to SM Context
	// TODO
	// smContext.SMLock.Lock()
	// defer smContext.SMLock.Unlock()
	// smContext.CommitSmPolicyDecision(true)
	return nil
}

func BuildAndSendQosN1N2TransferMsg(smContext *smfContext.SMContext) error {
	// N1N2 Request towards AMF
	n1n2Request := models.N1N2MessageTransferRequest{}
	defer util.CleanupMultipartTempFiles(&n1n2Request)

	// N2 Container Info
	n2InfoContainer := models.N2InfoContainer{
		N2InformationClass: models.N2INFORMATIONCLASS_SM,
		SmInfo: &models.N2SmInformation{
			PduSessionId: smContext.PDUSessionID,
			N2InfoContent: &models.N2InfoContent{
				NgapIeType: models.NGAPIETYPE_PDU_RES_SETUP_REQ.Ptr(),
				NgapData: models.RefToBinaryData{
					ContentId: "N2SmInformation",
				},
			},
			SNssai: smContext.Snssai,
		},
	}

	// N1 Container Info
	n1MessageClass, err := models.NewN1MessageClassFromValue("SM")
	if err != nil {
		smContext.SubPduSessLog.Errorf("failed to create N1 message class: %v", err)
		return err
	}
	n1MessageContent := models.NewRefToBinaryData("GSM_NAS")
	n1MsgContainer := models.NewN1MessageContainer(*n1MessageClass, *n1MessageContent)

	// N1N2 Json Data
	n1n2Request.JsonData = models.NewN1N2MessageTransferReqData()
	n1n2Request.JsonData.SetPduSessionId(smContext.PDUSessionID)

	// N1 Msg
	if smNasBuf, err1 := smfContext.BuildGSMPDUSessionModificationCommand(smContext); err1 != nil {
		logger.PduSessLog.Errorf("build GSM BuildGSMPDUSessionModificationCommand failed: %s", err1.Error())
		return err1
	} else {
		tmpFile, err2 := util.CreatePayloadTempFile(smNasBuf)
		if err2 != nil {
			smContext.SubPduSessLog.Errorf("failed to create temp file: %s", err2.Error())
			return err2
		} else {
			n1n2Request.BinaryDataN1Message = &tmpFile
			n1n2Request.JsonData.N1MessageContainer = n1MsgContainer
		}
	}

	// N2 Msg
	n2Pdu, err := smfContext.BuildPDUSessionResourceModifyRequestTransfer(smContext)
	if err != nil {
		smContext.SubPduSessLog.Errorf("SMPolicyUpdate, build PDUSession Resource Modify Request Transfer Error(%s)", err.Error())
		return err
	} else {
		tmpFile, err1 := util.CreatePayloadTempFile(n2Pdu)
		if err1 != nil {
			smContext.SubPduSessLog.Errorf("error creating temp file (%s)", err1.Error())
			return err1
		} else {
			n1n2Request.BinaryDataN2Information = &tmpFile
			n1n2Request.JsonData.N2InfoContainer = &n2InfoContainer
		}
	}

	smContext.SubPduSessLog.Infoln("QoS N1N2 transfer initiated")
	apiN1N2MessageTransferRequest := smContext.
		CommunicationClient.
		N1N2MessageCollectionCollectionAPI.
		N1N2MessageTransfer(context.Background(), smContext.Supi)
	apiN1N2MessageTransferRequest = apiN1N2MessageTransferRequest.N1N2MessageTransferReqData(n1n2Request.GetJsonData())
	if binaryDataN1Message := n1n2Request.GetBinaryDataN1Message(); binaryDataN1Message != nil {
		apiN1N2MessageTransferRequest = apiN1N2MessageTransferRequest.BinaryDataN1Message(binaryDataN1Message)
	}
	if binaryDataN2Information := n1n2Request.GetBinaryDataN2Information(); binaryDataN2Information != nil {
		apiN1N2MessageTransferRequest = apiN1N2MessageTransferRequest.BinaryDataN2Information(binaryDataN2Information)
	}
	rspData, _, err := smContext.
		CommunicationClient.
		N1N2MessageCollectionCollectionAPI.
		N1N2MessageTransferExecute(apiN1N2MessageTransferRequest)
	if err != nil {
		smContext.SubPfcpLog.Warnf("send N1N2Transfer failed, %v", err.Error())
		return err
	}
	if rspData.GetCause() == models.N1N2MESSAGETRANSFERCAUSE_N1_MSG_NOT_TRANSFERRED {
		smContext.SubPfcpLog.Errorf("N1N2MessageTransfer failure, %v", rspData.Cause)
		return fmt.Errorf("N1N2MessageTransfer failure, %v", rspData.Cause)
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
		problemDetails := models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusBadRequest)
		problemDetails.SetCause("MANDATORY_IE_MISSING") // Defined in TS 29.510 6.1.6.2.17
		problemDetails.SetDetail("Missing IE [Event]/[NfInstanceUri] in NotificationData")
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
