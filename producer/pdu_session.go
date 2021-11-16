// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package producer

import (
	"context"
	"fmt"
	"net/http"

	"github.com/antihax/optional"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/smf/metrics"
	"github.com/free5gc/smf/msgtypes/svcmsgtypes"
	"github.com/free5gc/smf/transaction"

	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/nas"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Namf_Communication"
	"github.com/free5gc/openapi/Nsmf_PDUSession"
	"github.com/free5gc/openapi/Nudm_SubscriberDataManagement"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/smf/consumer"
	smf_context "github.com/free5gc/smf/context"
	"github.com/free5gc/smf/logger"
	pfcp_message "github.com/free5gc/smf/pfcp/message"
)

func formContextCreateErrRsp(httpStatus int, problemBody *models.ProblemDetails, n1SmMsg *models.RefToBinaryData) *http_wrapper.Response {
	return &http_wrapper.Response{
		Header: nil,
		Status: httpStatus,
		Body: models.PostSmContextsErrorResponse{
			JsonData: &models.SmContextCreateError{
				Error:   problemBody,
				N1SmMsg: n1SmMsg,
			},
		},
	}

}

func HandlePduSessionContextReplacement(smCtxtRef string) error {

	smCtxt := smf_context.GetSMContext(smCtxtRef)

	if smCtxt != nil {
		smCtxt.SubPduSessLog.Warn("PDUSessionSMContextCreate, old context exist, purging")
		smCtxt.SMLock.Lock()

		smCtxt.LocalPurged = true

		//Disassociate ctxt from any look-ups(Report-Req from UPF shouldn't get this context)
		smf_context.RemoveSMContext(smCtxt.Ref)

		//check if PCF session set, send release(Npcf_SMPolicyControl_Delete)
		//TODO: not done as part of ctxt release

		//Check if UPF session set, send release
		if smCtxt.Tunnel != nil {
			releaseTunnel(smCtxt)
		}

		smCtxt.SMLock.Unlock()
	}

	return nil
}

func HandlePDUSessionSMContextCreate(eventData interface{}) error {

	txn := eventData.(*transaction.Transaction)
	request := txn.Req.(models.PostSmContextsRequest)
	smContext := txn.Ctxt.(*smf_context.SMContext)

	//GSM State
	//PDU Session Establishment Accept/Reject
	var response models.PostSmContextsResponse
	response.JsonData = new(models.SmContextCreatedData)

	// Check has PDU Session Establishment Request
	m := nas.NewMessage()
	if err := m.GsmMessageDecode(&request.BinaryDataN1SmMessage); err != nil ||
		m.GsmHeader.GetMessageType() != nas.MsgTypePDUSessionEstablishmentRequest {
		logger.PduSessLog.Errorf("PDUSessionSMContextCreate, GsmMessageDecode Error: ", err)

		txn.Rsp = formContextCreateErrRsp(http.StatusForbidden, &Nsmf_PDUSession.N1SmError, nil)
		return fmt.Errorf("GsmMsgDecodeError")
	}

	createData := request.JsonData

	//Create SM context
	//smContext := smf_context.NewSMContext(createData.Supi, createData.PduSessionId)
	smContext.SubPduSessLog.Infof("PDUSessionSMContextCreate, SM context created")
	//smContext.ChangeState(smf_context.SmStateActivePending)
	smContext.SubCtxLog.Traceln("PDUSessionSMContextCreate, SMContextState change state: ", smContext.SMContextState.String())
	smContext.SetCreateData(createData)
	smContext.SmStatusNotifyUri = createData.SmContextStatusUri

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	// DNN Information from config
	smContext.DNNInfo = smf_context.RetrieveDnnInformation(*createData.SNssai, createData.Dnn)
	if smContext.DNNInfo == nil {
		smContext.SubPduSessLog.Errorf("PDUSessionSMContextCreate, S-NSSAI[sst: %d, sd: %s] DNN[%s] not matched DNN Config",
			createData.SNssai.Sst, createData.SNssai.Sd, createData.Dnn)
		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("DnnNotSupported")
		return fmt.Errorf("SnssaiError")
	}

	// Query UDM
	if problemDetails, err := consumer.SendNFDiscoveryUDM(); err != nil {
		smContext.SubPduSessLog.Errorf("PDUSessionSMContextCreate, send NF Discovery Serving UDM Error[%v]", err)
		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("UDMDiscoveryFailure")
		return fmt.Errorf("UdmError")
	} else if problemDetails != nil {
		smContext.SubPduSessLog.Errorf("PDUSessionSMContextCreate, send NF Discovery Serving UDM Problem[%+v]", problemDetails)
		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("UDMDiscoveryFailure")
		return fmt.Errorf("UdmError")
	} else {
		smContext.SubPduSessLog.Infof("PDUSessionSMContextCreate, send NF Discovery Serving UDM Successful")
	}

	// IP Allocation
	if ip, err := smContext.DNNInfo.UeIPAllocator.Allocate(); err != nil {
		smContext.SubPduSessLog.Errorln("PDUSessionSMContextCreate, failed allocate IP address: ", err)
		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("IpAllocError")
		return fmt.Errorf("IpAllocError")
	} else {
		smContext.PDUAddress = ip
		smContext.SubPduSessLog.Infof("PDUSessionSMContextCreate, IP alloc succes IP[%s]",
			smContext.PDUAddress.String())
	}

	//UDM-Fetch Subscription Data
	smPlmnID := createData.Guami.PlmnId
	smDataParams := &Nudm_SubscriberDataManagement.GetSmDataParamOpts{
		Dnn:         optional.NewString(createData.Dnn),
		PlmnId:      optional.NewInterface(smPlmnID.Mcc + smPlmnID.Mnc),
		SingleNssai: optional.NewInterface(openapi.MarshToJsonString(smContext.Snssai)),
	}

	SubscriberDataManagementClient := smf_context.SMF_Self().SubscriberDataManagementClient
	metrics.IncrementSvcUdmMsgStats(smf_context.SMF_Self().NfInstanceID, string(svcmsgtypes.SmSubscriptionDataRetrieval), "Out", "", "")

	if sessSubData, rsp, err := SubscriberDataManagementClient.
		SessionManagementSubscriptionDataRetrievalApi.
		GetSmData(context.Background(), smContext.Supi, smDataParams); err != nil {
		metrics.IncrementSvcUdmMsgStats(smf_context.SMF_Self().NfInstanceID, string(svcmsgtypes.SmSubscriptionDataRetrieval), "In", http.StatusText(rsp.StatusCode), err.Error())
		smContext.SubPduSessLog.Errorln("PDUSessionSMContextCreate, get SessionManagementSubscriptionData error: ", err)
		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("SubscriptionDataFetchError")
		return fmt.Errorf("SubscriptionError")
	} else {
		defer func() {
			if rspCloseErr := rsp.Body.Close(); rspCloseErr != nil {
				smContext.SubPduSessLog.Errorf("PDUSessionSMContextCreate, GetSmData response body cannot close: %+v", rspCloseErr)
			}
		}()
		if len(sessSubData) > 0 {
			metrics.IncrementSvcUdmMsgStats(smf_context.SMF_Self().NfInstanceID, string(svcmsgtypes.SmSubscriptionDataRetrieval), "In", http.StatusText(rsp.StatusCode), "")
			smContext.DnnConfiguration = sessSubData[0].DnnConfigurations[smContext.Dnn]
			smContext.SubPduSessLog.Infof("PDUSessionSMContextCreate, subscription data retrieved from UDM")
		} else {
			metrics.IncrementSvcUdmMsgStats(smf_context.SMF_Self().NfInstanceID, string(svcmsgtypes.SmSubscriptionDataRetrieval), "In", http.StatusText(rsp.StatusCode), "NilSubscriptionData")
			smContext.SubPduSessLog.Errorln("PDUSessionSMContextCreate, SessionManagementSubscriptionData from UDM is nil")
			txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("SubscriptionDataLenError")
			return fmt.Errorf("NoSubscriptionError")
		}
	}

	//Decode UE content(PCO)
	establishmentRequest := m.PDUSessionEstablishmentRequest
	smContext.HandlePDUSessionEstablishmentRequest(establishmentRequest)

	if err := smContext.PCFSelection(); err != nil {
		smContext.SubPduSessLog.Errorln("PDUSessionSMContextCreate, send NF Discovery Serving PCF Error[%v]", err)
		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("PCFDiscoveryFailure")
		return fmt.Errorf("PcfError")
	}
	smContext.SubPduSessLog.Infof("PDUSessionSMContextCreate, send NF Discovery Serving PCF success")

	//PCF Policy Association
	var smPolicyDecision *models.SmPolicyDecision
	metrics.IncrementSvcPcfMsgStats(smf_context.SMF_Self().NfInstanceID, string(svcmsgtypes.SmPolicyAssociationCreate), "Out", "", "")
	if smPolicyDecisionRsp, httpStatus, err := consumer.SendSMPolicyAssociationCreate(smContext); err != nil {
		metrics.IncrementSvcPcfMsgStats(smf_context.SMF_Self().NfInstanceID, string(svcmsgtypes.SmPolicyAssociationCreate), "In", http.StatusText(httpStatus), err.Error())
		smContext.SubPduSessLog.Errorln("PDUSessionSMContextCreate, SMPolicyAssociationCreate error: ", err)
		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("PCFPolicyCreateFailure")
		return fmt.Errorf("PcfAssoError")
	} else if httpStatus != http.StatusCreated {
		metrics.IncrementSvcPcfMsgStats(smf_context.SMF_Self().NfInstanceID, string(svcmsgtypes.SmPolicyAssociationCreate), "In", http.StatusText(httpStatus), "error")
		smContext.SubPduSessLog.Errorln("PDUSessionSMContextCreate, SMPolicyAssociationCreate http status: ", http.StatusText(httpStatus))
		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("PCFPolicyCreateFailure")
		return fmt.Errorf("PcfAssoError")
	} else {
		smContext.SubPduSessLog.Infof("PDUSessionSMContextCreate, Policy association create success")
		smPolicyDecision = smPolicyDecisionRsp
	}

	// dataPath selection
	smContext.Tunnel = smf_context.NewUPTunnel()
	if err := ApplySmPolicyFromDecision(smContext, smPolicyDecision); err != nil {
		smContext.SubPduSessLog.Errorf("PDUSessionSMContextCreate, apply sm policy decision error: %+v", err)
		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("ApplySMPolicyFailure")
		return fmt.Errorf("ApplySmPolicyError")
	}
	var defaultPath *smf_context.DataPath
	upfSelectionParams := &smf_context.UPFSelectionParams{
		Dnn: createData.Dnn,
		SNssai: &smf_context.SNssai{
			Sst: createData.SNssai.Sst,
			Sd:  createData.SNssai.Sd,
		},
	}

	if smf_context.SMF_Self().ULCLSupport && smf_context.CheckUEHasPreConfig(createData.Supi) {
		smContext.SubPduSessLog.Infof("PDUSessionSMContextCreate, SUPI[%s] has pre-config route", createData.Supi)
		uePreConfigPaths := smf_context.GetUEPreConfigPaths(createData.Supi)
		smContext.Tunnel.DataPathPool = uePreConfigPaths.DataPathPool
		smContext.Tunnel.PathIDGenerator = uePreConfigPaths.PathIDGenerator
		defaultPath = smContext.Tunnel.DataPathPool.GetDefaultPath()
		defaultPath.ActivateTunnelAndPDR(smContext, 255)
		smContext.BPManager = smf_context.NewBPManager(createData.Supi)
	} else {
		// UE has no pre-config path.
		// Use default route
		smContext.SubPduSessLog.Infof("PDUSessionSMContextCreate, no pre-config route")
		defaultUPPath := smf_context.GetUserPlaneInformation().GetDefaultUserPlanePathByDNN(upfSelectionParams)
		defaultPath = smf_context.GenerateDataPath(defaultUPPath, smContext)
		if defaultPath != nil {
			defaultPath.IsDefaultPath = true
			smContext.Tunnel.AddDataPath(defaultPath)
			if err := defaultPath.ActivateTunnelAndPDR(smContext, 255); err != nil {
				smContext.SubPduSessLog.Errorf("PDUSessionSMContextCreate, data path error: %v", err.Error())
				txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("UPFDataPathError")
				return fmt.Errorf("DataPathError")
			}
		}
	}

	if defaultPath == nil {
		smContext.ChangeState(smf_context.SmStateInit)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextCreate, SMContextState Change State: ", smContext.SMContextState.String())
		smContext.SubPduSessLog.Errorf("PDUSessionSMContextCreate, data path not found for selection param %v", upfSelectionParams.String())

		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("InsufficientResourceSliceDnn")
		return fmt.Errorf("InsufficientResourceSliceDnn")
	}

	//AMF Selection for SMF -> AMF communication
	if problemDetails, err := consumer.SendNFDiscoveryServingAMF(smContext); err != nil {
		smContext.SubPduSessLog.Errorf("PDUSessionSMContextCreate, send NF Discovery Serving AMF Error[%v]", err)
		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("AMFDiscoveryFailure")
		return fmt.Errorf("AmfError")
	} else if problemDetails != nil {
		smContext.SubPduSessLog.Warnf("PDUSessionSMContextCreate, send NF Discovery Serving AMF Problem[%+v]", problemDetails)
		txn.Rsp = smContext.GeneratePDUSessionEstablishmentReject("AMFDiscoveryFailure")
		return fmt.Errorf("AmfError")
	} else {
		smContext.SubPduSessLog.Traceln("PDUSessionSMContextCreate, Send NF Discovery Serving AMF success")
	}

	for _, service := range *smContext.AMFProfile.NfServices {
		if service.ServiceName == models.ServiceName_NAMF_COMM {
			communicationConf := Namf_Communication.NewConfiguration()
			communicationConf.SetBasePath(service.ApiPrefix)
			smContext.CommunicationClient = Namf_Communication.NewAPIClient(communicationConf)
		}
	}

	response.JsonData = smContext.BuildCreatedData()
	txn.Rsp = &http_wrapper.Response{
		Header: http.Header{
			"Location": {smContext.Ref},
		},
		Status: http.StatusCreated,
		Body:   response,
	}

	smContext.SubPduSessLog.Infof("PDUSessionSMContextCreate, PDU session context create success ")

	return nil
	// TODO: UECM registration
}

func HandlePDUSessionSMContextUpdate(eventData interface{}) error {

	txn := eventData.(*transaction.Transaction)
	body := txn.Req.(models.UpdateSmContextRequest)
	smContext := txn.Ctxt.(*smf_context.SMContext)

	smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, update received")
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	var sendPFCPDelete, sendPFCPModification bool
	var response models.UpdateSmContextResponse
	response.JsonData = new(models.SmContextUpdatedData)

	smContextUpdateData := body.JsonData

	if body.BinaryDataN1SmMessage != nil {
		smContext.SubPduSessLog.Traceln("PDUSessionSMContextUpdate, Binary Data N1 SmMessage isn't nil!")
		m := nas.NewMessage()
		err := m.GsmMessageDecode(&body.BinaryDataN1SmMessage)
		smContext.SubPduSessLog.Traceln("PDUSessionSMContextUpdate, Update SM Context Request N1SmMessage: ", m)
		if err != nil {
			smContext.SubPduSessLog.Error(err)
			txn.Rsp = &http_wrapper.Response{
				Status: http.StatusForbidden,
				Body: models.UpdateSmContextErrorResponse{
					JsonData: &models.SmContextUpdateError{
						Error: &Nsmf_PDUSession.N1SmError,
					},
				}, // Depends on the reason why N4 fail
			}
			return err
		}
		switch m.GsmHeader.GetMessageType() {
		case nas.MsgTypePDUSessionReleaseRequest:
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N1 Msg PDU Session Release Request received")
			if smContext.SMContextState != smf_context.SmStateActive {
				// Wait till the state becomes SmStateActive again
				// TODO: implement sleep wait in concurrent architecture
				smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, SM Context State[%v] should be SmStateActive", smContext.SMContextState.String())
			}

			smContext.HandlePDUSessionReleaseRequest(m.PDUSessionReleaseRequest)
			if buf, err := smf_context.BuildGSMPDUSessionReleaseCommand(smContext); err != nil {
				smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build GSM PDUSessionReleaseCommand failed: %+v", err)
			} else {
				response.BinaryDataN1SmMessage = buf
			}

			response.JsonData.N1SmMsg = &models.RefToBinaryData{ContentId: "PDUSessionReleaseCommand"}

			response.JsonData.N2SmInfo = &models.RefToBinaryData{ContentId: "PDUResourceReleaseCommand"}
			response.JsonData.N2SmInfoType = models.N2SmInfoType_PDU_RES_REL_CMD

			if buf, err := smf_context.BuildPDUSessionResourceReleaseCommandTransfer(smContext); err != nil {
				smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSessionResourceReleaseCommandTransfer failed: %+v", err)
			} else {
				response.BinaryDataN2SmInformation = buf
			}

			if smContext.Tunnel != nil {
				smContext.ChangeState(smf_context.SmStatePfcpModify)
				smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
				//Send release to UPF
				releaseTunnel(smContext)
				sendPFCPDelete = true
			} else {
				smContext.ChangeState(smf_context.SmStateModify)
				smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
			}

		case nas.MsgTypePDUSessionReleaseComplete:
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N1 Msg PDU Session Release Complete received")
			if smContext.SMContextState != smf_context.SmStateInActivePending {
				// Wait till the state becomes SmStateActive again
				// TODO: implement sleep wait in concurrent architecture
				smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, SMContext State[%v] should be SmStateInActivePending State", smContext.SMContextState.String())
			}
			// Send Release Notify to AMF
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, send Update SmContext Response")
			smContext.ChangeState(smf_context.SmStateInit)
			smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
			response.JsonData.UpCnxState = models.UpCnxState_DEACTIVATED
			problemDetails, err := consumer.SendSMContextStatusNotification(smContext.SmStatusNotifyUri)
			if problemDetails != nil || err != nil {
				if problemDetails != nil {
					smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, send SMContext Status Notification Problem[%+v]", problemDetails)
				}

				if err != nil {
					smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, send SMContext Status Notification Error[%v]", err)
				}
			} else {
				smContext.SubPduSessLog.Traceln("PDUSessionSMContextUpdate, sent SMContext Status Notification successfully")
			}
		}
	} else {
		smContext.SubPduSessLog.Traceln("PDUSessionSMContextUpdate, Binary Data N1 SmMessage is nil!")
	}

	tunnel := smContext.Tunnel
	pdrList := []*smf_context.PDR{}
	farList := []*smf_context.FAR{}
	barList := []*smf_context.BAR{}
	qerList := []*smf_context.QER{}

	switch smContextUpdateData.UpCnxState {
	case models.UpCnxState_ACTIVATING:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, UP cnx state %v received", smContextUpdateData.UpCnxState)
		if smContext.SMContextState != smf_context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, SMContext State[%v] should be SmStateActive State", smContext.SMContextState.String())
		}
		smContext.ChangeState(smf_context.SmStateModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		response.JsonData.N2SmInfo = &models.RefToBinaryData{ContentId: "PDUSessionResourceSetupRequestTransfer"}
		response.JsonData.UpCnxState = models.UpCnxState_ACTIVATING
		response.JsonData.N2SmInfoType = models.N2SmInfoType_PDU_RES_SETUP_REQ

		n2Buf, err := smf_context.BuildPDUSessionResourceSetupRequestTransfer(smContext)
		if err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSession Resource Setup Request Transfer Error(%s)", err.Error())
		}
		smContext.UpCnxState = models.UpCnxState_ACTIVATING
		response.BinaryDataN2SmInformation = n2Buf
		response.JsonData.N2SmInfoType = models.N2SmInfoType_PDU_RES_SETUP_REQ
	case models.UpCnxState_DEACTIVATED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, UP cnx state %v received", smContextUpdateData.UpCnxState)
		if smContext.SMContextState != smf_context.SmStateActive {
			// Wait till the state becomes Active again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, SMContext State[%v] should be Active State", smContext.SMContextState.String())
		}
		if smContext.Tunnel != nil {
			smContext.ChangeState(smf_context.SmStateModify)
			smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
			response.JsonData.UpCnxState = models.UpCnxState_DEACTIVATED
			smContext.UpCnxState = body.JsonData.UpCnxState
			smContext.UeLocation = body.JsonData.UeLocation
			// TODO: Deactivate N2 downlink tunnel
			// Set FAR and An, N3 Release Info
			farList = []*smf_context.FAR{}
			smContext.PendingUPF = make(smf_context.PendingUPF)
			for _, dataPath := range smContext.Tunnel.DataPathPool {
				ANUPF := dataPath.FirstDPNode
				DLPDR := ANUPF.DownLinkTunnel.PDR
				if DLPDR == nil {
					smContext.SubPduSessLog.Errorf("AN Release Error")
				} else {
					DLPDR.FAR.State = smf_context.RULE_UPDATE
					DLPDR.FAR.ApplyAction.Forw = false
					DLPDR.FAR.ApplyAction.Buff = true
					DLPDR.FAR.ApplyAction.Nocp = true
					//Set DL Tunnel info to nil
					if DLPDR.FAR.ForwardingParameters != nil {
						DLPDR.FAR.ForwardingParameters.OuterHeaderCreation = nil
					}
					smContext.PendingUPF[ANUPF.GetNodeIP()] = true
					farList = append(farList, DLPDR.FAR)
				}
			}

			sendPFCPModification = true
			smContext.ChangeState(smf_context.SmStatePfcpModify)
			smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		}
	}

	switch smContextUpdateData.N2SmInfoType {
	case models.N2SmInfoType_PDU_RES_SETUP_RSP:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		if smContext.SMContextState != smf_context.SmStateActive {
			// Wait till the state becomes Active again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be Active",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(smf_context.SmStateModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		pdrList = []*smf_context.PDR{}
		farList = []*smf_context.FAR{}

		smContext.PendingUPF = make(smf_context.PendingUPF)
		for _, dataPath := range tunnel.DataPathPool {
			if dataPath.Activated {
				ANUPF := dataPath.FirstDPNode
				DLPDR := ANUPF.DownLinkTunnel.PDR

				DLPDR.FAR.ApplyAction = pfcpType.ApplyAction{Buff: false, Drop: false, Dupl: false, Forw: true, Nocp: false}
				DLPDR.FAR.ForwardingParameters = &smf_context.ForwardingParameters{
					DestinationInterface: pfcpType.DestinationInterface{
						InterfaceValue: pfcpType.DestinationInterfaceAccess,
					},
					NetworkInstance: []byte(smContext.Dnn),
				}

				DLPDR.State = smf_context.RULE_UPDATE
				DLPDR.FAR.State = smf_context.RULE_UPDATE

				pdrList = append(pdrList, DLPDR)
				farList = append(farList, DLPDR.FAR)

				if _, exist := smContext.PendingUPF[ANUPF.GetNodeIP()]; !exist {
					smContext.PendingUPF[ANUPF.GetNodeIP()] = true
				}
			}
		}

		if err := smf_context.
			HandlePDUSessionResourceSetupResponseTransfer(body.BinaryDataN2SmInformation, smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle PDUSessionResourceSetupResponseTransfer failed: %+v", err)
		}
		sendPFCPModification = true
		smContext.ChangeState(smf_context.SmStatePfcpModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
	case models.N2SmInfoType_PDU_RES_SETUP_FAIL:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		if err := smf_context.
			HandlePDUSessionResourceSetupResponseTransfer(body.BinaryDataN2SmInformation, smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle PDUSessionResourceSetupResponseTransfer failed: %+v", err)
		}
	case models.N2SmInfoType_PDU_RES_REL_RSP:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 PDUSession Release Complete ")
		if smContext.PDUSessionRelease_DUE_TO_DUP_PDU_ID {
			if smContext.SMContextState != smf_context.SmStateInActivePending {
				// Wait till the state becomes Active again
				// TODO: implement sleep wait in concurrent architecture
				smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be ActivePending",
					smContext.SMContextState.String())
			}
			smContext.ChangeState(smf_context.SmStateInit)
			smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, send Update SmContext Response")
			response.JsonData.UpCnxState = models.UpCnxState_DEACTIVATED

			smContext.PDUSessionRelease_DUE_TO_DUP_PDU_ID = false
			smf_context.RemoveSMContext(smContext.Ref)
			problemDetails, err := consumer.SendSMContextStatusNotification(smContext.SmStatusNotifyUri)
			if problemDetails != nil || err != nil {
				if problemDetails != nil {
					smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, send SMContext Status Notification Problem[%+v]", problemDetails)
				}

				if err != nil {
					smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, send SMContext Status Notification Error[%v]", err)
				}
			} else {
				smContext.SubPduSessLog.Traceln("PDUSessionSMContextUpdate, send SMContext Status Notification successfully")
			}
		} else { // normal case
			if smContext.SMContextState != smf_context.SmStateInActivePending {
				// Wait till the state becomes Active again
				// TODO: implement sleep wait in concurrent architecture
				smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be ActivePending",
					smContext.SMContextState.String())
			}
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, send Update SmContext Response")
			smContext.ChangeState(smf_context.SmStateInActivePending)
			smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		}
	case models.N2SmInfoType_PATH_SWITCH_REQ:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		smContext.SubPduSessLog.Traceln("PDUSessionSMContextUpdate, handle Path Switch Request")
		if smContext.SMContextState != smf_context.SmStateActive {
			// Wait till the state becomes Active again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be Active",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(smf_context.SmStateModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())

		if err := smf_context.HandlePathSwitchRequestTransfer(body.BinaryDataN2SmInformation, smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle PathSwitchRequestTransfer: %+v", err)
		}

		if n2Buf, err := smf_context.BuildPathSwitchRequestAcknowledgeTransfer(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build Path Switch Transfer Error(%+v)", err)
		} else {
			response.BinaryDataN2SmInformation = n2Buf
		}

		response.JsonData.N2SmInfoType = models.N2SmInfoType_PATH_SWITCH_REQ_ACK
		response.JsonData.N2SmInfo = &models.RefToBinaryData{
			ContentId: "PATH_SWITCH_REQ_ACK",
		}

		smContext.PendingUPF = make(smf_context.PendingUPF)
		for _, dataPath := range tunnel.DataPathPool {
			if dataPath.Activated {
				ANUPF := dataPath.FirstDPNode
				DLPDR := ANUPF.DownLinkTunnel.PDR

				pdrList = append(pdrList, DLPDR)
				farList = append(farList, DLPDR.FAR)

				if _, exist := smContext.PendingUPF[ANUPF.GetNodeIP()]; !exist {
					smContext.PendingUPF[ANUPF.GetNodeIP()] = true
				}
			}
		}

		sendPFCPModification = true
		smContext.ChangeState(smf_context.SmStatePfcpModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
	case models.N2SmInfoType_PATH_SWITCH_SETUP_FAIL:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		if smContext.SMContextState != smf_context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(smf_context.SmStateModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		if err :=
			smf_context.HandlePathSwitchRequestSetupFailedTransfer(body.BinaryDataN2SmInformation, smContext); err != nil {
			smContext.SubPduSessLog.Error()
		}
	case models.N2SmInfoType_HANDOVER_REQUIRED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		if smContext.SMContextState != smf_context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(smf_context.SmStateModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		response.JsonData.N2SmInfo = &models.RefToBinaryData{ContentId: "Handover"}
	}

	switch smContextUpdateData.HoState {
	case models.HoState_PREPARING:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, Ho state %v received", smContextUpdateData.HoState)
		smContext.SubPduSessLog.Traceln("PDUSessionSMContextUpdate, in HoState_PREPARING")
		if smContext.SMContextState != smf_context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(smf_context.SmStateModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		smContext.HoState = models.HoState_PREPARING
		if err := smf_context.HandleHandoverRequiredTransfer(body.BinaryDataN2SmInformation, smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle HandoverRequiredTransfer failed: %+v", err)
		}
		response.JsonData.N2SmInfoType = models.N2SmInfoType_PDU_RES_SETUP_REQ

		if n2Buf, err := smf_context.BuildPDUSessionResourceSetupRequestTransfer(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSession Resource Setup Request Transfer Error(%s)", err.Error())
		} else {
			response.BinaryDataN2SmInformation = n2Buf
		}
		response.JsonData.N2SmInfoType = models.N2SmInfoType_PDU_RES_SETUP_REQ
		response.JsonData.N2SmInfo = &models.RefToBinaryData{
			ContentId: "PDU_RES_SETUP_REQ",
		}
		response.JsonData.HoState = models.HoState_PREPARING
	case models.HoState_PREPARED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, Ho state %v received", smContextUpdateData.HoState)
		smContext.SubPduSessLog.Traceln("PDUSessionSMContextUpdate, in HoState_PREPARED")
		if smContext.SMContextState != smf_context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state [%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(smf_context.SmStateModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		smContext.HoState = models.HoState_PREPARED
		response.JsonData.HoState = models.HoState_PREPARED
		if err :=
			smf_context.HandleHandoverRequestAcknowledgeTransfer(body.BinaryDataN2SmInformation, smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle HandoverRequestAcknowledgeTransfer failed: %+v", err)
		}

		if n2Buf, err := smf_context.BuildHandoverCommandTransfer(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSession Resource Setup Request Transfer Error(%s)", err.Error())
		} else {
			response.BinaryDataN2SmInformation = n2Buf
		}

		response.JsonData.N2SmInfoType = models.N2SmInfoType_HANDOVER_CMD
		response.JsonData.N2SmInfo = &models.RefToBinaryData{
			ContentId: "HANDOVER_CMD",
		}
		response.JsonData.HoState = models.HoState_PREPARING
	case models.HoState_COMPLETED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, Ho state %v received", smContextUpdateData.HoState)
		smContext.SubPduSessLog.Traceln("PDUSessionSMContextUpdate, in HoState_COMPLETED")
		if smContext.SMContextState != smf_context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(smf_context.SmStateModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		smContext.HoState = models.HoState_COMPLETED
		response.JsonData.HoState = models.HoState_COMPLETED
	}

	switch smContextUpdateData.Cause {
	case models.Cause_REL_DUE_TO_DUPLICATE_SESSION_ID:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, update cause %v received", smContextUpdateData.Cause)
		//* release PDU Session Here
		if smContext.SMContextState != smf_context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}

		response.JsonData.N2SmInfo = &models.RefToBinaryData{ContentId: "PDUResourceReleaseCommand"}
		response.JsonData.N2SmInfoType = models.N2SmInfoType_PDU_RES_REL_CMD
		smContext.PDUSessionRelease_DUE_TO_DUP_PDU_ID = true

		buf, err := smf_context.BuildPDUSessionResourceReleaseCommandTransfer(smContext)
		response.BinaryDataN2SmInformation = buf
		if err != nil {
			smContext.SubPduSessLog.Error(err)
		}

		smContext.SubCtxLog.Infof("PDUSessionSMContextUpdate, Cause_REL_DUE_TO_DUPLICATE_SESSION_ID")

		smContext.ChangeState(smf_context.SmStatePfcpModify)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())

		releaseTunnel(smContext)

		sendPFCPDelete = true
	}

	var httpResponse *http_wrapper.Response
	// Check FSM and take corresponding action
	switch smContext.SMContextState {
	case smf_context.SmStatePfcpModify:
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, ctxt in PFCP Modification")

		if sendPFCPModification {
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, send PFCP Modification")
			defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
			ANUPF := defaultPath.FirstDPNode
			pfcp_message.SendPfcpSessionModificationRequest(ANUPF.UPF.NodeID, smContext, pdrList, farList, barList, qerList)
		}

		if sendPFCPDelete {
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, send PFCP Deletion")
		}

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

			releaseTunnel(smContext)

			HandleNwInitiatedPduSessionRelease(smContext.Ref)

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
	case smf_context.SmStateModify:
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, ctxt in Modification Pending")
		smContext.ChangeState(smf_context.SmStateActive)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
		httpResponse = &http_wrapper.Response{
			Status: http.StatusOK,
			Body:   response,
		}
	case smf_context.SmStateInit, smf_context.SmStateInActivePending:
		smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, ctxt in SmStateInit, SmStateInActivePending")
		httpResponse = &http_wrapper.Response{
			Status: http.StatusOK,
			Body:   response,
		}
	default:
		smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SM Context State [%s] shouldn't be here\n", smContext.SMContextState)
		httpResponse = &http_wrapper.Response{
			Status: http.StatusOK,
			Body:   response,
		}
	}

	txn.Rsp = httpResponse
	return nil
}

func HandleNwInitiatedPduSessionRelease(smContextRef string) {
	smContext := smf_context.GetSMContext(smContextRef)
	PFCPResponseStatus := <-smContext.SBIPFCPCommunicationChan

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
}

func HandlePDUSessionSMContextRelease(eventData interface{}) error {
	txn := eventData.(*transaction.Transaction)
	body := txn.Req.(models.ReleaseSmContextRequest)
	smContext := txn.Ctxt.(*smf_context.SMContext)

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	smContext.SubPduSessLog.Infof("PDUSessionSMContextRelease, PDU Session SMContext Release received")

	//Send Policy delete
	metrics.IncrementSvcPcfMsgStats(smf_context.SMF_Self().NfInstanceID, string(svcmsgtypes.SmPolicyAssociationDelete), "Out", "", "")
	if httpStatus, err := consumer.SendSMPolicyAssociationDelete(smContext, &body); err != nil {
		metrics.IncrementSvcPcfMsgStats(smf_context.SMF_Self().NfInstanceID, string(svcmsgtypes.SmPolicyAssociationDelete), "In", http.StatusText(httpStatus), err.Error())
		smContext.SubCtxLog.Errorf("PDUSessionSMContextRelease, SM policy delete error [%v] ", err.Error())
	} else {
		metrics.IncrementSvcPcfMsgStats(smf_context.SMF_Self().NfInstanceID, string(svcmsgtypes.SmPolicyAssociationDelete), "In", http.StatusText(httpStatus), "")
		smContext.SubCtxLog.Infof("PDUSessionSMContextRelease, SM policy delete success with http status [%v] ", httpStatus)
	}

	//Release UE IP-Address
	if ip := smContext.PDUAddress; ip != nil {
		smContext.SubPduSessLog.Infof("Release IP[%s]", smContext.PDUAddress.String())
		smContext.DNNInfo.UeIPAllocator.Release(ip)
	}

	//Initiate PFCP release
	smContext.ChangeState(smf_context.SmStatePfcpModify)
	smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, SMContextState Change State: ", smContext.SMContextState.String())

	var httpResponse *http_wrapper.Response

	//Release User-plane
	if ok := releaseTunnel(smContext); !ok {
		//already released
		httpResponse = &http_wrapper.Response{
			Status: http.StatusNoContent,
			Body:   nil,
		}

		txn.Rsp = httpResponse
		smf_context.RemoveSMContext(smContext.Ref)
		return nil
	}

	PFCPResponseStatus := <-smContext.SBIPFCPCommunicationChan

	switch PFCPResponseStatus {
	case smf_context.SessionReleaseSuccess:
		smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, PFCP SessionReleaseSuccess")
		smContext.ChangeState(smf_context.SmStateInit)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, SMContextState Change State: ", smContext.SMContextState.String())
		httpResponse = &http_wrapper.Response{
			Status: http.StatusNoContent,
			Body:   nil,
		}

	case smf_context.SessionReleaseTimeout:
		smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, PFCP SessionReleaseTimeout")
		smContext.ChangeState(smf_context.SmStateActive)
		httpResponse = &http_wrapper.Response{
			Status: int(http.StatusInternalServerError),
		}

	case smf_context.SessionReleaseFailed:
		// Update SmContext Request(N1 PDU Session Release Request)
		// Send PDU Session Release Reject
		smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, PFCP SessionReleaseFailed")
		problemDetail := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILULE",
		}
		httpResponse = &http_wrapper.Response{
			Status: int(problemDetail.Status),
		}
		smContext.ChangeState(smf_context.SmStateActive)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease,  SMContextState Change State: ", smContext.SMContextState.String())
		errResponse := models.UpdateSmContextErrorResponse{
			JsonData: &models.SmContextUpdateError{
				Error: &problemDetail,
			},
		}
		if buf, err := smf_context.BuildGSMPDUSessionReleaseReject(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextRelease, build GSM PDUSessionReleaseReject failed: %+v", err)
		} else {
			errResponse.BinaryDataN1SmMessage = buf
		}

		errResponse.JsonData.N1SmMsg = &models.RefToBinaryData{ContentId: "PDUSessionReleaseReject"}
		httpResponse.Body = errResponse
	default:
		smContext.SubCtxLog.Warnf("PDUSessionSMContextRelease, The state shouldn't be [%s]\n", PFCPResponseStatus)

		smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, in case Unknown")
		problemDetail := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILULE",
		}
		httpResponse = &http_wrapper.Response{
			Status: int(problemDetail.Status),
		}
		smContext.ChangeState(smf_context.SmStateActive)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, SMContextState Change State: ", smContext.SMContextState.String())
		errResponse := models.UpdateSmContextErrorResponse{
			JsonData: &models.SmContextUpdateError{
				Error: &problemDetail,
			},
		}
		if buf, err := smf_context.BuildGSMPDUSessionReleaseReject(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextRelease, build GSM PDUSessionReleaseReject failed: %+v", err)
		} else {
			errResponse.BinaryDataN1SmMessage = buf
		}

		errResponse.JsonData.N1SmMsg = &models.RefToBinaryData{ContentId: "PDUSessionReleaseReject"}
		httpResponse.Body = errResponse
	}

	txn.Rsp = httpResponse
	smf_context.RemoveSMContext(smContext.Ref)

	return nil
}

func releaseTunnel(smContext *smf_context.SMContext) bool {
	if smContext.Tunnel == nil {
		smContext.SubPduSessLog.Errorf("releaseTunnel, pfcp tunnel already released")
		return false
	}
	deletedPFCPNode := make(map[string]bool)
	smContext.PendingUPF = make(smf_context.PendingUPF)
	for _, dataPath := range smContext.Tunnel.DataPathPool {
		dataPath.DeactivateTunnelAndPDR(smContext)
		for curDataPathNode := dataPath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
			curUPFID, err := curDataPathNode.GetUPFID()
			if err != nil {
				smContext.SubPduSessLog.Error(err)
				continue
			}
			if _, exist := deletedPFCPNode[curUPFID]; !exist {
				pfcp_message.SendPfcpSessionDeletionRequest(curDataPathNode.UPF.NodeID, smContext)
				deletedPFCPNode[curUPFID] = true
				smContext.PendingUPF[curDataPathNode.GetNodeIP()] = true
			}
		}
	}
	smContext.Tunnel = nil
	return true
}

func SendPduSessN1N2Transfer(smContext *smf_context.SMContext, success bool) error {

	//N1N2 Request towards AMF
	n1n2Request := models.N1N2MessageTransferRequest{}

	//N2 Container Info
	n2InfoContainer := models.N2InfoContainer{
		N2InformationClass: models.N2InformationClass_SM,
		SmInfo: &models.N2SmInformation{
			PduSessionId: smContext.PDUSessionID,
			N2InfoContent: &models.N2InfoContent{
				NgapIeType: models.NgapIeType_PDU_RES_SETUP_REQ,
				NgapData: &models.RefToBinaryData{
					ContentId: "N2SmInformation",
				},
			},
			SNssai: smContext.Snssai,
		},
	}

	//N1 Container Info
	n1MsgContainer := models.N1MessageContainer{
		N1MessageClass:   "SM",
		N1MessageContent: &models.RefToBinaryData{ContentId: "GSM_NAS"},
	}

	//N1N2 Json Data
	n1n2Request.JsonData = &models.N1N2MessageTransferReqData{PduSessionId: smContext.PDUSessionID}

	if success {
		if smNasBuf, err := smf_context.BuildGSMPDUSessionEstablishmentAccept(smContext); err != nil {
			logger.PduSessLog.Errorf("Build GSM PDUSessionEstablishmentAccept failed: %s", err)
		} else {
			n1n2Request.BinaryDataN1Message = smNasBuf
			n1n2Request.JsonData.N1MessageContainer = &n1MsgContainer
		}

		if n2Pdu, err := smf_context.BuildPDUSessionResourceSetupRequestTransfer(smContext); err != nil {
			logger.PduSessLog.Errorf("Build PDUSessionResourceSetupRequestTransfer failed: %s", err)
		} else {
			n1n2Request.BinaryDataN2Information = n2Pdu
			n1n2Request.JsonData.N2InfoContainer = &n2InfoContainer
		}
	} else {
		if smNasBuf, err := smf_context.BuildGSMPDUSessionEstablishmentReject(smContext,
			nasMessage.Cause5GSMRequestRejectedUnspecified); err != nil {
			logger.PduSessLog.Errorf("Build GSM PDUSessionEstablishmentReject failed: %s", err)
		} else {
			n1n2Request.BinaryDataN1Message = smNasBuf
			n1n2Request.JsonData.N1MessageContainer = &n1MsgContainer
		}
	}

	smContext.SubPduSessLog.Infof("N1N2 transfer initiated")
	rspData, _, err := smContext.
		CommunicationClient.
		N1N2MessageCollectionDocumentApi.
		N1N2MessageTransfer(context.Background(), smContext.Supi, n1n2Request)
	if err != nil {
		smContext.SubPfcpLog.Warnf("Send N1N2Transfer failed, %v ", err.Error())
		return err
	}
	if rspData.Cause == models.N1N2MessageTransferCause_N1_MSG_NOT_TRANSFERRED {
		smContext.SubPfcpLog.Errorf("N1N2MessageTransfer failure, %v", rspData.Cause)
		return fmt.Errorf("N1N2MessageTransfer failure, %v", rspData.Cause)
	}
	smContext.SubPduSessLog.Infof("N1N2 Transfer completed")
	return nil
}
