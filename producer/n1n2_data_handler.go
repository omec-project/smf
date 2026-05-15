// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/omec-project/nas/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/consumer"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/smferrors"
	"github.com/omec-project/smf/transaction"
	"github.com/omec-project/smf/util"
	"github.com/omec-project/util/httpwrapper"
)

type pfcpAction struct {
	sendPfcpModify, sendPfcpDelete bool
}

type pfcpParam struct {
	pdrList []*context.PDR
	farList []*context.FAR
	barList []*context.BAR
	qerList []*context.QER
}

func buildAccessForwardingParameters(smContext *context.SMContext,
	current *context.ForwardingParameters,
) *context.ForwardingParameters {
	forwardingParameters := &context.ForwardingParameters{
		DestinationInterface: context.DestinationInterface{
			InterfaceValue: context.DestinationInterfaceAccess,
		},
		NetworkInstance: []byte(smContext.Dnn),
	}

	if current != nil {
		forwardingParameters.PFCPSMReqFlags = current.PFCPSMReqFlags
		forwardingParameters.ForwardingPolicyID = current.ForwardingPolicyID
		if current.OuterHeaderCreation != nil {
			outerHeaderCreation := *current.OuterHeaderCreation
			forwardingParameters.OuterHeaderCreation = &outerHeaderCreation
		}
	}

	if forwardingParameters.OuterHeaderCreation == nil &&
		smContext.Tunnel != nil && smContext.Tunnel.ANInformation.IPAddress != nil {
		forwardingParameters.OuterHeaderCreation = &context.OuterHeaderCreation{
			OuterHeaderCreationDescription: context.OuterHeaderCreationGtpUUdpIpv4,
			Teid:                           smContext.Tunnel.ANInformation.TEID,
			Ipv4Address:                    smContext.Tunnel.ANInformation.IPAddress.To4(),
		}
	}

	return forwardingParameters
}

func readBinaryN2SmInformation(file **os.File) ([]byte, error) {
	if file == nil || *file == nil {
		return nil, nil
	}

	if _, err := (*file).Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	return io.ReadAll(*file)
}

func HandleUpdateN1Msg(txn *transaction.Transaction, response *models.UpdateSmContext200Response, pfcpAction *pfcpAction) error {
	body := txn.Req.(models.UpdateSmContextRequest)
	smContext := txn.Ctxt.(*context.SMContext)

	if body.BinaryDataN1SmMessage != nil {
		smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, Binary Data N1 SmMessage isn't nil")
		if *body.BinaryDataN1SmMessage == nil {
			err := fmt.Errorf("binary N1 SM message payload is nil")
			txn.Rsp = &httpwrapper.Response{
				Status: http.StatusForbidden,
				Body: models.UpdateSmContext400Response{
					JsonData: &models.SmContextUpdateError{
						Error: smferrors.N1SmError,
					},
				},
			}
			return err
		}
		m := nas.NewMessage()
		file := *body.BinaryDataN1SmMessage
		_, err := file.Seek(0, io.SeekStart) // Ensure the file pointer is at the beginning
		if err != nil {
			txn.Rsp = &httpwrapper.Response{
				Status: http.StatusForbidden,
				Body: models.UpdateSmContext400Response{
					JsonData: &models.SmContextUpdateError{
						Error: smferrors.N1SmError,
					},
				},
			}
			return err
		}
		fileContents, err := io.ReadAll(file)
		if err != nil {
			smContext.SubPduSessLog.Errorf("read file error: %+v", err)
			txn.Rsp = &httpwrapper.Response{
				Status: http.StatusForbidden,
				Body: models.UpdateSmContext400Response{
					JsonData: &models.SmContextUpdateError{
						Error: smferrors.N1SmError,
					},
				},
			}
			return err
		}
		err = m.GsmMessageDecode(&fileContents)
		smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, Update SM Context Request N1SmMessage:", m)
		if err != nil {
			smContext.SubPduSessLog.Error(err)
			txn.Rsp = &httpwrapper.Response{
				Status: http.StatusForbidden,
				Body: models.UpdateSmContext400Response{
					JsonData: &models.SmContextUpdateError{
						Error: smferrors.N1SmError,
					},
				}, // Depends on the reason why N4 fail
			}
			return err
		}
		switch m.GsmHeader.GetMessageType() {
		case nas.MsgTypePDUSessionReleaseRequest:
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N1 Msg PDU Session Release Request received")
			pduSessIDRelReq := int32(m.PDUSessionReleaseRequest.GetPDUSessionID())
			smContext.SubPduSessLog.Debugln("PDU Session ID in Rel Req:", pduSessIDRelReq)
			pduSessIDSmCxt := smContext.PDUSessionID
			smContext.SubPduSessLog.Debugln("PDU Session ID in SM Context:", pduSessIDSmCxt)
			if smContext.SMContextState != context.SmStateActive {
				// Wait till the state becomes SmStateActive again
				// TODO: implement sleep wait in concurrent architecture
				smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, SM Context State[%v] should be SmStateActive", smContext.SMContextState.String())
			}
			if pduSessIDRelReq == pduSessIDSmCxt {
				smContext.HandlePDUSessionReleaseRequest(m.PDUSessionReleaseRequest)
				if buf, err := context.BuildGSMPDUSessionReleaseCommand(smContext); err != nil {
					smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build GSM PDUSessionReleaseCommand failed: %+v", err)
				} else {
					tmpFile, err := util.CreatePayloadTempFile(buf)
					if err != nil {
						smContext.SubPduSessLog.Errorln(err)
					} else {
						response.BinaryDataN1SmMessage = &tmpFile
						response.JsonData.N1SmMsg = &models.RefToBinaryData{ContentId: "PDUSessionReleaseCommand"}
					}
				}

				if buf, err := context.BuildPDUSessionResourceReleaseCommandTransfer(smContext); err != nil {
					smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSessionResourceReleaseCommandTransfer failed: %+v", err)
				} else {
					tmpFile, err := util.CreatePayloadTempFile(buf)
					if err != nil {
						smContext.SubPduSessLog.Errorln(err)
					} else {
						response.BinaryDataN2SmInformation = &tmpFile
						response.JsonData.N2SmInfo = &models.RefToBinaryData{ContentId: "PDUResourceReleaseCommand"}
						response.JsonData.N2SmInfoType = models.N2SMINFOTYPE_PDU_RES_REL_CMD.Ptr()
					}
				}

				if smContext.Tunnel != nil {
					smContext.ChangeState(context.SmStatePfcpModify)
					smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
					// Send release to UPF
					// releaseTunnel(smContext)
					pfcpAction.sendPfcpDelete = true
				} else {
					smContext.ChangeState(context.SmStateModify)
					smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
				}
			} else {
				smContext.SubPduSessLog.Errorf("Invalid PDU Session ID")
				if buf, err := context.BuildGSMPDUSessionReleaseRejectWithCause(smContext, pduSessIDRelReq, "InvalidPDUSessionIdentity"); err != nil {
					smContext.SubPduSessLog.Errorf("PDUSessionSMContextRelease, build GSM PDUSessionReleaseReject failed: %+v", err)
				} else {
					tmpFile, err := util.CreatePayloadTempFile(buf)
					if err != nil {
						smContext.SubPduSessLog.Errorln(err)
					} else {
						response.BinaryDataN1SmMessage = &tmpFile
						response.JsonData.N1SmMsg = &models.RefToBinaryData{ContentId: "PDUSessionReleaseReject"}
					}
				}
				smContext.ChangeState(context.SmStateModify)
				smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
			}
		case nas.MsgTypePDUSessionReleaseComplete:
			smContext.SubPduSessLog.Infoln("PDUSessionSMContextUpdate, N1 Msg PDU Session Release Complete received")
			if smContext.SMContextState != context.SmStateInActivePending {
				// Wait till the state becomes SmStateActive again
				// TODO: implement sleep wait in concurrent architecture
				smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, SMContext State[%v] should be SmStateInActivePending State", smContext.SMContextState.String())
			}
			// Send Release Notify to AMF
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, send Update SmContext Response")
			smContext.ChangeState(context.SmStateInit)
			smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
			response.JsonData.UpCnxState = models.UPCNXSTATE_DEACTIVATED.Ptr()
			smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, sent SMContext Status Notification successfully")
		}
	} else {
		smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, Binary Data N1 SmMessage is nil")
	}

	return nil
}

func HandleUpCnxState(txn *transaction.Transaction, response *models.UpdateSmContext200Response, pfcpAction *pfcpAction, pfcpParam *pfcpParam) error {
	body := txn.Req.(models.UpdateSmContextRequest)
	smContext := txn.Ctxt.(*context.SMContext)
	smContextUpdateData := body.JsonData

	switch smContextUpdateData.GetUpCnxState() {
	case models.UPCNXSTATE_ACTIVATING:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, UP cnx state %v received", smContextUpdateData.UpCnxState)
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, SMContext State[%v] should be SmStateActive State", smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		response.JsonData.N2SmInfo = &models.RefToBinaryData{ContentId: "PDUSessionResourceSetupRequestTransfer"}
		response.JsonData.UpCnxState = models.UPCNXSTATE_ACTIVATING.Ptr()
		response.JsonData.N2SmInfoType = models.N2SMINFOTYPE_PDU_RES_SETUP_REQ.Ptr()

		n2Buf, err := context.BuildPDUSessionResourceSetupRequestTransfer(smContext)
		if err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSession Resource Setup Request Transfer Error(%s)", err.Error())
			return err
		}
		smContext.UpCnxState = models.UPCNXSTATE_ACTIVATING

		tmpFile, err := util.CreatePayloadTempFile(n2Buf)
		if err != nil {
			smContext.SubPduSessLog.Errorln(err)
			return err
		}
		response.BinaryDataN2SmInformation = &tmpFile
		response.JsonData.N2SmInfoType = models.N2SMINFOTYPE_PDU_RES_SETUP_REQ.Ptr()
	case models.UPCNXSTATE_DEACTIVATED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, UP cnx state %v received", smContextUpdateData.UpCnxState)
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes Active again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, SMContext State[%v] should be Active State", smContext.SMContextState.String())
		}
		if smContext.Tunnel != nil {
			smContext.ChangeState(context.SmStateModify)
			smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
			response.JsonData.UpCnxState = models.UPCNXSTATE_DEACTIVATED.Ptr()
			smContext.UpCnxState = body.JsonData.GetUpCnxState()
			smContext.UeLocation = body.JsonData.UeLocation
			// TODO: Deactivate N2 downlink tunnel
			// Set FAR and An, N3 Release Info
			farList := []*context.FAR{}
			smContext.PendingUPF = make(context.PendingUPF)
			for _, dataPath := range smContext.Tunnel.DataPathPool {
				ANUPF := dataPath.FirstDPNode
				for _, DLPDR := range ANUPF.DownLinkTunnel.PDR {
					if DLPDR == nil {
						smContext.SubPduSessLog.Errorf("AN Release Error")
					} else {
						DLPDR.FAR.State = context.RULE_UPDATE
						DLPDR.FAR.ApplyAction.Forw = false
						DLPDR.FAR.ApplyAction.Buff = true
						DLPDR.FAR.ApplyAction.Nocp = true
						// Set DL Tunnel info to nil
						if DLPDR.FAR.ForwardingParameters != nil {
							DLPDR.FAR.ForwardingParameters.OuterHeaderCreation = nil
						}
						smContext.PendingUPF[ANUPF.GetNodeIP()] = true
						farList = append(farList, DLPDR.FAR)
					}
				}
			}

			pfcpParam.farList = append(pfcpParam.farList, farList...)

			pfcpAction.sendPfcpModify = true
			smContext.ChangeState(context.SmStatePfcpModify)
			smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		}
	}
	return nil
}

func HandleUpdateHoState(txn *transaction.Transaction, response *models.UpdateSmContext200Response) error {
	body := txn.Req.(models.UpdateSmContextRequest)
	smContext := txn.Ctxt.(*context.SMContext)
	smContextUpdateData := body.JsonData

	switch smContextUpdateData.GetHoState() {
	case models.HOSTATE_PREPARING:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, Ho state %v received", smContextUpdateData.HoState)
		smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, in HoState_PREPARING")
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		smContext.HoState = models.HOSTATE_PREPARING
		fileBytes, err := readBinaryN2SmInformation(body.BinaryDataN2SmInformation)
		if err != nil {
			smContext.SubCtxLog.Errorf("failed to read file: %v", err)
			return err
		}
		if err := context.HandleHandoverRequiredTransfer(fileBytes, smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle HandoverRequiredTransfer failed: %+v", err)
		}
		response.JsonData.N2SmInfoType = models.N2SMINFOTYPE_PDU_RES_SETUP_REQ.Ptr()

		if n2Buf, err := context.BuildPDUSessionResourceSetupRequestTransfer(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSession Resource Setup Request Transfer Error(%s)", err.Error())
		} else {
			tmpFile, err := util.CreatePayloadTempFile(n2Buf)
			if err != nil {
				smContext.SubPduSessLog.Errorln(err)
				return err
			}

			response.BinaryDataN2SmInformation = &tmpFile
		}
		response.JsonData.N2SmInfoType = models.N2SMINFOTYPE_PDU_RES_SETUP_REQ.Ptr()
		response.JsonData.N2SmInfo = &models.RefToBinaryData{
			ContentId: "PDU_RES_SETUP_REQ",
		}
		response.JsonData.HoState = models.HOSTATE_PREPARING.Ptr()
	case models.HOSTATE_PREPARED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, Ho state %v received", smContextUpdateData.HoState)
		smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, in HoState_PREPARED")
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state [%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		smContext.HoState = models.HOSTATE_PREPARED
		response.JsonData.HoState = models.HOSTATE_PREPARED.Ptr()
		fileBytes, err := readBinaryN2SmInformation(body.BinaryDataN2SmInformation)
		if err != nil {
			smContext.SubCtxLog.Errorf("failed to read file: %v", err)
			return err
		}
		if err := context.HandleHandoverRequestAcknowledgeTransfer(fileBytes, smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle HandoverRequestAcknowledgeTransfer failed: %+v", err)
		}

		if n2Buf, err := context.BuildHandoverCommandTransfer(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSession Resource Setup Request Transfer Error(%s)", err.Error())
		} else {
			tmpFile, err := util.CreatePayloadTempFile(n2Buf)
			if err != nil {
				smContext.SubPduSessLog.Errorf("failed to create temp file: %v", err)
			} else {
				response.BinaryDataN2SmInformation = &tmpFile
				response.JsonData.N2SmInfoType = models.N2SMINFOTYPE_HANDOVER_CMD.Ptr()
				response.JsonData.N2SmInfo = &models.RefToBinaryData{
					ContentId: "HANDOVER_CMD",
				}
			}
		}
	case models.HOSTATE_COMPLETED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, Ho state %v received", smContextUpdateData.HoState)
		smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, in HoState_COMPLETED")
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		smContext.HoState = models.HOSTATE_COMPLETED
		response.JsonData.HoState = models.HOSTATE_COMPLETED.Ptr()
	}
	return nil
}

func HandleUpdateCause(txn *transaction.Transaction, response *models.UpdateSmContext200Response, pfcpAction *pfcpAction) error {
	body := txn.Req.(models.UpdateSmContextRequest)
	smContext := txn.Ctxt.(*context.SMContext)
	smContextUpdateData := body.JsonData

	switch smContextUpdateData.GetCause() {
	case models.CAUSE_REL_DUE_TO_DUPLICATE_SESSION_ID:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, update cause %v received", smContextUpdateData.Cause)
		//* release PDU Session Here
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}

		response.JsonData.N2SmInfo = &models.RefToBinaryData{ContentId: "PDUResourceReleaseCommand"}
		response.JsonData.N2SmInfoType = models.N2SMINFOTYPE_PDU_RES_REL_CMD.Ptr()
		smContext.PDUSessionRelease_DUE_TO_DUP_PDU_ID = true

		buf, err := context.BuildPDUSessionResourceReleaseCommandTransfer(smContext)
		if err != nil {
			smContext.SubPduSessLog.Errorf("build PDU Session Resource Release Command Transfer failed: %+v", err)
			return err
		}
		tmpFile, err := util.CreatePayloadTempFile(buf)
		if err != nil {
			smContext.SubPduSessLog.Error(err)
			return err
		}
		response.BinaryDataN2SmInformation = &tmpFile

		smContext.SubCtxLog.Infof("PDUSessionSMContextUpdate, Cause_REL_DUE_TO_DUPLICATE_SESSION_ID")

		smContext.ChangeState(context.SmStatePfcpModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())

		// releaseTunnel(smContext)
		pfcpAction.sendPfcpDelete = true
	}

	return nil
}

func HandleUpdateN2Msg(txn *transaction.Transaction, response *models.UpdateSmContext200Response, pfcpAction *pfcpAction, pfcpParam *pfcpParam) error {
	body := txn.Req.(models.UpdateSmContextRequest)
	smContext := txn.Ctxt.(*context.SMContext)
	smContextUpdateData := body.JsonData
	tunnel := smContext.Tunnel

	switch smContextUpdateData.GetN2SmInfoType() {
	case models.N2SMINFOTYPE_PDU_RES_SETUP_RSP:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes Active again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be Active",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		pdrList := []*context.PDR{}
		farList := []*context.FAR{}

		smContext.PendingUPF = make(context.PendingUPF)
		for _, dataPath := range tunnel.DataPathPool {
			if dataPath.Activated {
				ANUPF := dataPath.FirstDPNode
				for _, DLPDR := range ANUPF.DownLinkTunnel.PDR {
					DLPDR.FAR.ApplyAction = context.ApplyAction{Buff: false, Drop: false, Dupl: false, Forw: true, Nocp: false}
					DLPDR.FAR.ForwardingParameters = buildAccessForwardingParameters(
						smContext,
						DLPDR.FAR.ForwardingParameters,
					)

					DLPDR.State = context.RULE_UPDATE
					DLPDR.FAR.State = context.RULE_UPDATE

					pdrList = append(pdrList, DLPDR)
					farList = append(farList, DLPDR.FAR)

					if _, exist := smContext.PendingUPF[ANUPF.GetNodeIP()]; !exist {
						smContext.PendingUPF[ANUPF.GetNodeIP()] = true
					}
				}
			}
		}
		fileBytes, err := readBinaryN2SmInformation(body.BinaryDataN2SmInformation)
		if err != nil {
			smContext.SubCtxLog.Errorf("failed to read file: %v", err)
			return err
		}
		if len(fileBytes) > 0 {
			if err := context.
				HandlePDUSessionResourceSetupResponseTransfer(fileBytes, smContext); err != nil {
				smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle PDUSessionResourceSetupResponseTransfer failed: %+v", err)
			}
		}

		pfcpParam.pdrList = append(pfcpParam.pdrList, pdrList...)
		pfcpParam.farList = append(pfcpParam.farList, farList...)

		pfcpAction.sendPfcpModify = true
		smContext.ChangeState(context.SmStatePfcpModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
	case models.N2SMINFOTYPE_PDU_RES_SETUP_FAIL:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		fileBytes, err := readBinaryN2SmInformation(body.BinaryDataN2SmInformation)
		if err != nil {
			smContext.SubCtxLog.Errorf("failed to read file: %v", err)
			return err
		}
		if len(fileBytes) > 0 {
			if err := context.
				HandlePDUSessionResourceSetupResponseTransfer(fileBytes, smContext); err != nil {
				smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle PDUSessionResourceSetupResponseTransfer failed: %+v", err)
			}
		}
	case models.N2SMINFOTYPE_PDU_RES_REL_RSP:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 PDUSession Release Complete ")
		if smContext.PDUSessionRelease_DUE_TO_DUP_PDU_ID {
			if smContext.SMContextState != context.SmStateInActivePending {
				// Wait till the state becomes Active again
				// TODO: implement sleep wait in concurrent architecture
				smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be ActivePending",
					smContext.SMContextState.String())
			}
			smContext.ChangeState(context.SmStateInit)
			smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, send Update SmContext Response")
			response.JsonData.UpCnxState = models.UPCNXSTATE_DEACTIVATED.Ptr()

			smContext.PDUSessionRelease_DUE_TO_DUP_PDU_ID = false
			context.RemoveSMContext(smContext.Ref)
			problemDetails, err := consumer.SendSMContextStatusNotification(smContext.SmStatusNotifyUri)
			if problemDetails != nil || err != nil {
				if problemDetails != nil {
					smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, send SMContext Status Notification Problem[%+v]", problemDetails)
				}

				if err != nil {
					smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, send SMContext Status Notification Error[%v]", err)
				}
			} else {
				smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, send SMContext Status Notification successfully")
			}
		} else { // normal case
			if smContext.SMContextState != context.SmStateInActivePending {
				// Wait till the state becomes Active again
				// TODO: implement sleep wait in concurrent architecture
				smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be ActivePending",
					smContext.SMContextState.String())
			}
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, send Update SmContext Response")
			smContext.ChangeState(context.SmStateInActivePending)
			smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		}
	case models.N2SMINFOTYPE_PATH_SWITCH_REQ:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, handle Path Switch Request")
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes Active again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be Active",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())

		fileBytes, err := readBinaryN2SmInformation(body.BinaryDataN2SmInformation)
		if err != nil {
			smContext.SubCtxLog.Errorf("failed to read file: %v", err)
			return err
		}
		if len(fileBytes) == 0 {
			return fmt.Errorf("missing PATH_SWITCH_REQ N2 binary payload")
		}
		if err := context.HandlePathSwitchRequestTransfer(fileBytes, smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle PathSwitchRequestTransfer: %+v", err)
			return err
		}

		if n2Buf, err := context.BuildPathSwitchRequestAcknowledgeTransfer(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build Path Switch Transfer Error(%+v)", err)
		} else {
			tmpFile, err := util.CreatePayloadTempFile(n2Buf)
			if err != nil {
				smContext.SubPduSessLog.Errorln(err)
				return err
			}
			response.BinaryDataN2SmInformation = &tmpFile
		}
		response.JsonData.N2SmInfoType = models.N2SMINFOTYPE_PATH_SWITCH_REQ_ACK.Ptr()
		response.JsonData.N2SmInfo = &models.RefToBinaryData{
			ContentId: "PATH_SWITCH_REQ_ACK",
		}

		pdrList := []*context.PDR{}
		farList := []*context.FAR{}
		smContext.PendingUPF = make(context.PendingUPF)
		for _, dataPath := range tunnel.DataPathPool {
			if dataPath.Activated {
				ANUPF := dataPath.FirstDPNode
				for _, DLPDR := range ANUPF.DownLinkTunnel.PDR {
					pdrList = append(pdrList, DLPDR)
					farList = append(farList, DLPDR.FAR)

					if _, exist := smContext.PendingUPF[ANUPF.GetNodeIP()]; !exist {
						smContext.PendingUPF[ANUPF.GetNodeIP()] = true
					}
				}
			}
		}

		pfcpParam.pdrList = append(pfcpParam.pdrList, pdrList...)
		pfcpParam.farList = append(pfcpParam.farList, farList...)

		pfcpAction.sendPfcpModify = true
		smContext.ChangeState(context.SmStatePfcpModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
	case models.N2SMINFOTYPE_PATH_SWITCH_SETUP_FAIL:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		fileBytes, err := readBinaryN2SmInformation(body.BinaryDataN2SmInformation)
		if err != nil {
			smContext.SubCtxLog.Errorf("failed to read file: %v", err)
			return err
		}
		if err := context.HandlePathSwitchRequestSetupFailedTransfer(fileBytes, smContext); err != nil {
			smContext.SubPduSessLog.Error()
		}
	case models.N2SMINFOTYPE_HANDOVER_REQUIRED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.N2SmInfoType)
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		response.JsonData.N2SmInfo = &models.RefToBinaryData{ContentId: "Handover"}
	}

	return nil
}
