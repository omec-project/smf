// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"fmt"
	"io"
	"maps"
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
	pdrList   []*context.PDR
	farList   []*context.FAR
	barList   []*context.BAR
	qerList   []*context.QER
	removePDR []*context.PDR // Add for teardown
	removeFAR []*context.FAR
	removeQER []*context.QER
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

// collectHoFARsForPFCPModify iterates over activated data path DL FARs that are
// marked RULE_UPDATE (set by HandleHandoverRequestAcknowledgeTransfer) and
// accumulates them into param. It returns a PendingUPF map; the caller should
// assign it to smContext.PendingUPF only when a PFCP modify will be sent.
func collectHoFARsForPFCPModify(tunnel *context.UPTunnel, param *pfcpParam) context.PendingUPF {
	pendingUPF := make(context.PendingUPF)
	if tunnel == nil {
		return pendingUPF
	}
	for _, dataPath := range tunnel.DataPathPool {
		if !dataPath.Activated {
			continue
		}
		ANUPF := dataPath.FirstDPNode
		for _, DLPDR := range ANUPF.DownLinkTunnel.PDR {
			if DLPDR.FAR.State != context.RULE_UPDATE {
				continue
			}
			param.pdrList = append(param.pdrList, DLPDR)
			param.farList = append(param.farList, DLPDR.FAR)
			if _, exist := pendingUPF[ANUPF.GetNodeIP()]; !exist {
				pendingUPF[ANUPF.GetNodeIP()] = true
			}
		}
	}
	return pendingUPF
}

func readBinaryN2SmInformation(file *os.File) ([]byte, error) {
	if file == nil {
		return nil, nil
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	return io.ReadAll(file)
}

func HandleUpdateN1Msg(txn *transaction.Transaction, response *models.UpdateSmContext200Response, pfcpAction *pfcpAction) error {
	body := txn.Req.(models.UpdateSmContextRequest)
	smContext := txn.Ctxt.(*context.SMContext)

	if body.HasBinaryDataN1SmMessage() {
		smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, Binary Data N1 SmMessage isn't nil")
		file := body.GetBinaryDataN1SmMessage()
		if file == nil {
			err := fmt.Errorf("binary N1 SM message payload is nil")
			errBody := models.NewUpdateSmContext400Response()
			errBody.SetJsonData(models.SmContextUpdateError{Error: smferrors.N1SmError})
			txn.Rsp = &httpwrapper.Response{
				Status: http.StatusForbidden,
				Body:   errBody,
			}
			return err
		}
		m := nas.NewMessage()
		_, err := file.Seek(0, io.SeekStart) // Ensure the file pointer is at the beginning
		if err != nil {
			errBody := models.NewUpdateSmContext400Response()
			errBody.SetJsonData(models.SmContextUpdateError{Error: smferrors.N1SmError})
			txn.Rsp = &httpwrapper.Response{
				Status: http.StatusForbidden,
				Body:   errBody,
			}
			return err
		}
		fileContents, err := io.ReadAll(file)
		if err != nil {
			smContext.SubPduSessLog.Errorf("read file error: %+v", err)
			errBody := models.NewUpdateSmContext400Response()
			errBody.SetJsonData(models.SmContextUpdateError{Error: smferrors.N1SmError})
			txn.Rsp = &httpwrapper.Response{
				Status: http.StatusForbidden,
				Body:   errBody,
			}
			return err
		}
		err = m.GsmMessageDecode(&fileContents)
		smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, Update SM Context Request N1SmMessage:", m)
		if err != nil {
			smContext.SubPduSessLog.Error(err)
			errBody := models.NewUpdateSmContext400Response()
			errBody.SetJsonData(models.SmContextUpdateError{Error: smferrors.N1SmError})
			txn.Rsp = &httpwrapper.Response{
				Status: http.StatusForbidden,
				Body:   errBody,
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
						response.SetBinaryDataN1SmMessage(tmpFile)
						jsonData := response.GetJsonData()
						jsonData.SetN1SmMsg(models.RefToBinaryData{ContentId: "PDUSessionReleaseCommand"})
						response.SetJsonData(jsonData)
					}
				}

				if buf, err := context.BuildPDUSessionResourceReleaseCommandTransfer(smContext); err != nil {
					smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSessionResourceReleaseCommandTransfer failed: %+v", err)
				} else {
					tmpFile, err := util.CreatePayloadTempFile(buf)
					if err != nil {
						smContext.SubPduSessLog.Errorln(err)
					} else {
						response.SetBinaryDataN2SmInformation(tmpFile)
						jsonData := response.GetJsonData()
						jsonData.SetN2SmInfo(models.RefToBinaryData{ContentId: "PDUResourceReleaseCommand"})
						jsonData.SetN2SmInfoType(models.N2SMINFOTYPE_PDU_RES_REL_CMD)
						response.SetJsonData(jsonData)
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
						response.SetBinaryDataN1SmMessage(tmpFile)
						jsonData := response.GetJsonData()
						jsonData.SetN1SmMsg(models.RefToBinaryData{ContentId: context.PDU_SESS_REL_REJECT})
						response.SetJsonData(jsonData)
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
			jsonData := response.GetJsonData()
			jsonData.SetUpCnxState(models.UPCNXSTATE_DEACTIVATED)
			response.SetJsonData(jsonData)
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
	smContextUpdateData := body.GetJsonData()

	switch smContextUpdateData.GetUpCnxState() {
	case models.UPCNXSTATE_ACTIVATING:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, UP cnx state %v received", smContextUpdateData.GetUpCnxState())
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, SMContext State[%v] should be SmStateActive State", smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		jd := response.GetJsonData()
		jd.SetN2SmInfo(models.RefToBinaryData{ContentId: "PDUSessionResourceSetupRequestTransfer"})
		jd.SetUpCnxState(models.UPCNXSTATE_ACTIVATING)
		jd.SetN2SmInfoType(models.N2SMINFOTYPE_PDU_RES_SETUP_REQ)
		response.SetJsonData(jd)

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
		response.SetBinaryDataN2SmInformation(tmpFile)
	case models.UPCNXSTATE_DEACTIVATED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, UP cnx state %v received", smContextUpdateData.GetUpCnxState())
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes Active again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, SMContext State[%v] should be Active State", smContext.SMContextState.String())
		}
		if smContext.Tunnel != nil {
			smContext.ChangeState(context.SmStateModify)
			smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
			jd := response.GetJsonData()
			jd.SetUpCnxState(models.UPCNXSTATE_DEACTIVATED)
			response.SetJsonData(jd)
			reqJsonData := body.GetJsonData()
			smContext.UpCnxState = reqJsonData.GetUpCnxState()
			smContext.UeLocation = reqJsonData.UeLocation
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

func HandleUpdateHoState(txn *transaction.Transaction, response *models.UpdateSmContext200Response, pfcpAction *pfcpAction, pfcpParam *pfcpParam) error {
	body := txn.Req.(models.UpdateSmContextRequest)
	smContext := txn.Ctxt.(*context.SMContext)
	smContextUpdateData := body.GetJsonData()

	switch smContextUpdateData.GetHoState() {
	case models.HOSTATE_PREPARING:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, Ho state %v received", smContextUpdateData.GetHoState())
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
		fileBytes, err := readBinaryN2SmInformation(body.GetBinaryDataN2SmInformation())
		if err != nil {
			smContext.SubCtxLog.Errorf("failed to read file: %v", err)
			return err
		}
		if err := context.HandleHandoverRequiredTransfer(fileBytes, smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle HandoverRequiredTransfer failed: %+v", err)
		}

		if n2Buf, err := context.BuildPDUSessionResourceSetupRequestTransfer(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSession Resource Setup Request Transfer Error(%s)", err.Error())
		} else {
			tmpFile, err := util.CreatePayloadTempFile(n2Buf)
			if err != nil {
				smContext.SubPduSessLog.Errorln(err)
				return err
			}

			response.SetBinaryDataN2SmInformation(tmpFile)
		}
		jd := response.GetJsonData()
		jd.SetN2SmInfoType(models.N2SMINFOTYPE_PDU_RES_SETUP_REQ)
		jd.SetN2SmInfo(models.RefToBinaryData{ContentId: "PDU_RES_SETUP_REQ"})
		jd.SetHoState(models.HOSTATE_PREPARING)
		response.SetJsonData(jd)
	case models.HOSTATE_PREPARED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, Ho state %v received", smContextUpdateData.GetHoState())
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
		jd := response.GetJsonData()
		jd.SetHoState(models.HOSTATE_PREPARED)
		response.SetJsonData(jd)
		fileBytes, err := readBinaryN2SmInformation(body.GetBinaryDataN2SmInformation())
		if err != nil {
			smContext.SubCtxLog.Errorf("failed to read file: %v", err)
			return err
		}
		if err := context.HandleHandoverRequestAcknowledgeTransfer(fileBytes, smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, handle HandoverRequestAcknowledgeTransfer failed: %+v", err)
		}

		// Trigger PFCP session modification so the UPF DL path is switched to the
		// target gNB (3GPP TS 23.502 §4.9.1.3.3, steps 9a/10a).
		// The FAR OuterHeaderCreation fields were just populated by
		// HandleHandoverRequestAcknowledgeTransfer above.
		pendingUPF := collectHoFARsForPFCPModify(smContext.Tunnel, pfcpParam)
		if len(pendingUPF) > 0 {
			if smContext.PendingUPF == nil {
				smContext.PendingUPF = make(context.PendingUPF)
			}
			maps.Copy(smContext.PendingUPF, pendingUPF)
			pfcpAction.sendPfcpModify = true
			smContext.ChangeState(context.SmStatePfcpModify)
			smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		}

		if n2Buf, err := context.BuildHandoverCommandTransfer(smContext); err != nil {
			smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSession Resource Setup Request Transfer Error(%s)", err.Error())
		} else {
			tmpFile, err := util.CreatePayloadTempFile(n2Buf)
			if err != nil {
				smContext.SubPduSessLog.Errorf("failed to create temp file: %v", err)
			} else {
				response.SetBinaryDataN2SmInformation(tmpFile)
				jd := response.GetJsonData()
				jd.SetN2SmInfoType(models.N2SMINFOTYPE_HANDOVER_CMD)
				jd.SetN2SmInfo(models.RefToBinaryData{ContentId: "HANDOVER_CMD"})
				response.SetJsonData(jd)
			}
		}
	case models.HOSTATE_COMPLETED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, Ho state %v received", smContextUpdateData.GetHoState())
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
		jd := response.GetJsonData()
		jd.SetHoState(models.HOSTATE_COMPLETED)
		response.SetJsonData(jd)
	}
	return nil
}

func HandleUpdateCause(txn *transaction.Transaction, response *models.UpdateSmContext200Response, pfcpAction *pfcpAction) error {
	body := txn.Req.(models.UpdateSmContextRequest)
	smContext := txn.Ctxt.(*context.SMContext)
	smContextUpdateData := body.GetJsonData()

	switch smContextUpdateData.GetCause() {
	case models.CAUSE_REL_DUE_TO_DUPLICATE_SESSION_ID:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, update cause %v received", smContextUpdateData.GetCause())
		//* release PDU Session Here
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}

		jd := response.GetJsonData()
		jd.SetN2SmInfo(models.RefToBinaryData{ContentId: "PDUResourceReleaseCommand"})
		jd.SetN2SmInfoType(models.N2SMINFOTYPE_PDU_RES_REL_CMD)
		response.SetJsonData(jd)
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
		response.SetBinaryDataN2SmInformation(tmpFile)

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
	smContextUpdateData := body.GetJsonData()
	tunnel := smContext.Tunnel

	switch smContextUpdateData.GetN2SmInfoType() {
	case models.N2SMINFOTYPE_PDU_RES_SETUP_RSP:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.GetN2SmInfoType())
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
		fileBytes, err := readBinaryN2SmInformation(body.GetBinaryDataN2SmInformation())
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
			smContextUpdateData.GetN2SmInfoType())
		fileBytes, err := readBinaryN2SmInformation(body.GetBinaryDataN2SmInformation())
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
			smContextUpdateData.GetN2SmInfoType())
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
			jd := response.GetJsonData()
			jd.SetUpCnxState(models.UPCNXSTATE_DEACTIVATED)
			response.SetJsonData(jd)

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
			smContextUpdateData.GetN2SmInfoType())
		smContext.SubPduSessLog.Debugln("PDUSessionSMContextUpdate, handle Path Switch Request")
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes Active again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be Active",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())

		fileBytes, err := readBinaryN2SmInformation(body.GetBinaryDataN2SmInformation())
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
			response.SetBinaryDataN2SmInformation(tmpFile)
		}
		jd := response.GetJsonData()
		jd.SetN2SmInfoType(models.N2SMINFOTYPE_PATH_SWITCH_REQ_ACK)
		jd.SetN2SmInfo(models.RefToBinaryData{ContentId: "PATH_SWITCH_REQ_ACK"})
		response.SetJsonData(jd)

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
			smContextUpdateData.GetN2SmInfoType())
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		fileBytes, err := readBinaryN2SmInformation(body.GetBinaryDataN2SmInformation())
		if err != nil {
			smContext.SubCtxLog.Errorf("failed to read file: %v", err)
			return err
		}
		if err := context.HandlePathSwitchRequestSetupFailedTransfer(fileBytes, smContext); err != nil {
			smContext.SubPduSessLog.Error()
		}
	case models.N2SMINFOTYPE_HANDOVER_REQUIRED:
		smContext.SubPduSessLog.Infof("PDUSessionSMContextUpdate, N2 SM info type %v received",
			smContextUpdateData.GetN2SmInfoType())
		if smContext.SMContextState != context.SmStateActive {
			// Wait till the state becomes SmStateActive again
			// TODO: implement sleep wait in concurrent architecture
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext state[%v] should be SmStateActive",
				smContext.SMContextState.String())
		}
		smContext.ChangeState(context.SmStateModify)
		smContext.SubCtxLog.Debugln("PDUSessionSMContextUpdate, SMContextState Change State:", smContext.SMContextState.String())
		jd := response.GetJsonData()
		jd.SetN2SmInfo(models.RefToBinaryData{ContentId: "Handover"})
		response.SetJsonData(jd)
	}

	return nil
}
