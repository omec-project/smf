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
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/qos"
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
		case nas.MsgTypePDUSessionModificationRequest:
			// TS 23.502 subclause 4.3.3.2 step 3a: the refusal goes back in the UpdateSmContext
			// response. BuildAndSendQosN1N2TransferMsg is the step 3b helper for a
			// network-requested modification and must not be used here.
			pduSessIDModReq := int32(m.PDUSessionModificationRequest.GetPDUSessionID())
			pti := m.PDUSessionModificationRequest.GetPTI()

			// TS 24.501 subclause 6.3.2.5 item d: a UE request for the session the network is
			// already modifying is disregarded, not refused. The network's own procedure carries
			// on as if the request had never arrived — so no reject, no state change, and T3591
			// keeps running. Refusing here would answer a procedure the UE is entitled to have
			// ignored, and the UE would apply the back-off #32 asks for on a session that is
			// about to change anyway.
			// Read directly: HandlePDUSessionSMContextUpdate holds SMLock across this whole
			// function, and taking it again would deadlock the session permanently.
			sessionID, state := smContext.PDUSessionID, smContext.SMContextState
			collision := smContext.NwModificationPending && pduSessIDModReq == sessionID
			if collision {
				// Sub-item i would have the URSP rule enforcement reports IE consumed before
				// ignoring the rest. github.com/omec-project/nas/v2 does not decode that IE — the
				// message struct has no field for it — so no report can reach this point and
				// sub-item ii is the whole of the reachable behaviour.
				smContext.SubPduSessLog.Infof(
					"PDUSessionSMContextUpdate, N1 Msg PDU Session Modification Request received for pdu session %d (pti %d) while the network is modifying it; disregarding it per TS 24.501 subclause 6.3.2.5 item d",
					pduSessIDModReq, pti)
				break
			}

			// Decided from the snapshot taken above rather than re-read: the state is written under
			// SMLock by other goroutines, and choosing the cause from one value while logging
			// another would make the log unusable for exactly the case worth investigating.
			cause := "ModificationNotSupported"
			switch {
			case pduSessIDModReq != sessionID:
				// An identity the SMF does not hold for this context.
				cause = "InvalidPDUSessionIdentity"
			case state == context.SmStateInit, state == context.SmStateInActivePending:
				// Established but on the way out, or never established. TS 24.501 subclause
				// 6.4.2.6 item b: an inactive PDU session identity takes #43, not the refusal.
				cause = "InvalidPDUSessionIdentity"
			}
			smContext.SubPduSessLog.Warnf(
				"PDUSessionSMContextUpdate, N1 Msg PDU Session Modification Request received for pdu session %d (pti %d), state %s; refusing with %s",
				pduSessIDModReq, pti, state.String(), cause)

			if buf, err := context.BuildGSMPDUSessionModificationRejectWithCause(pduSessIDModReq, pti, cause); err != nil {
				smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build GSM PDUSessionModificationReject failed: %+v", err)
			} else {
				tmpFile, err := util.CreatePayloadTempFile(buf)
				if err != nil {
					smContext.SubPduSessLog.Errorln(err)
				} else {
					response.SetBinaryDataN1SmMessage(tmpFile)
					jsonData := response.GetJsonData()
					jsonData.SetN1SmMsg(models.RefToBinaryData{ContentId: "PDUSessionModificationReject"})
					response.SetJsonData(jsonData)
				}
			}

		case nas.MsgTypePDUSessionModificationComplete:
			smContext.SubPduSessLog.Infoln("PDUSessionSMContextUpdate, N1 Msg PDU Session Modification Complete received")
			// The modification is complete only now. Committing on the UE's acknowledgement rather
			// than when the command was sent is what keeps the SMF's record of the session in step
			// with what the UE is actually running, so the next modification computes its delta
			// against the parameters in force.
			//
			// Stopping the timer and taking the realignment marker happen together, under one hold
			// of the lock. Where the radio access network established only part of this
			// modification, what it established is what the session has, so the pending update is
			// pruned to that before it becomes the record — committing the whole of it would record
			// flows that do not exist. Releasing the lock between the two would let a modification
			// starting on another goroutine replace the pending update in the gap, and this would
			// then prune and commit that one instead.
			// SMLock is already held by HandlePDUSessionSMContextUpdate for the whole of this
			// function, so nothing here may take it. Everything below is therefore one atomic
			// section by construction rather than by locking.
			smContext.StopT3591()
			realign := smContext.Realign
			smContext.Realign = nil
			var corrective *qos.PolicyUpdate
			if realign != nil && len(smContext.SmPolicyUpdates) > 0 {
				corrective = smContext.SmPolicyUpdates[0].RemoveFlows(qos.RefusedFlowSet(realign.RefusedQFIs))
			}

			if err := smContext.CommitSmPolicyDecisionLocked(true); err != nil {
				smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, committing the modification failed: %v", err)
			}

			if realign != nil {
				realignSession(smContext, realign, corrective)
			}

		case nas.MsgTypePDUSessionModificationCommandReject:
			cause := m.PDUSessionModificationCommandReject.GetCauseValue()
			smContext.SubPduSessLog.Warnf("PDUSessionSMContextUpdate, N1 Msg PDU Session Modification Command Reject received, 5GSM cause %d", cause)
			smContext.StopT3591()
			// The UE will not apply the parameters it was given. This is an abandonment with its
			// own cause rather than a timeout, and it is reported on the same path as one, so that
			// a modification the network could not apply is countable however it failed.
			abandonModificationUnderLock(smContext, "command_reject", fmt.Sprintf("5gsm_cause_%d", cause))

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

		default:
			// Every unhandled type before this branch existed was decoded, debug-logged and
			// dropped, and the SMF answered 200 with no N1 or N2 content. The UE then retransmits
			// until its timer expires and gives up, which looks like a UE fault. Log loudly so the
			// next missing case is found from a log line rather than from a packet capture.
			smContext.SubPduSessLog.Errorf(
				"PDUSessionSMContextUpdate, unhandled N1 SM message type 0x%02x; the SMF will answer with no N1 content and the UE will retransmit until it gives up",
				m.GsmHeader.GetMessageType())
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
	case models.N2SMINFOTYPE_PDU_RES_MOD_RSP:
		return handleModifyResponse(smContext, body)

	case models.N2SMINFOTYPE_PDU_RES_MOD_FAIL:
		return handleModifyFailure(smContext, body)

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

// handleModifyResponse acts on what the radio access network made of a modification.
//
// A whole refusal means the UE never received the authorized parameters, so the modification is
// abandoned and the user plane is not left carrying it. A partial refusal means the UE was told
// about flows that were not established, and it is owed a further modification saying which are
// actually in force — a distinct procedure, not a retry, because the parameters it carries
// describe what exists rather than what was attempted.
func handleModifyResponse(smContext *context.SMContext, body models.UpdateSmContextRequest) error {
	fileBytes, err := readBinaryN2SmInformation(body.GetBinaryDataN2SmInformation())
	if err != nil {
		smContext.SubPduSessLog.Errorf("reading the modify response failed: %v", err)
		return err
	}

	result, err := context.HandlePDUSessionResourceModifyResponseTransfer(fileBytes, smContext)
	if err != nil {
		smContext.SubPduSessLog.Errorf("decoding the modify response failed: %v", err)
		return err
	}

	switch {
	case result.WhollyRejected():
		smContext.SubPduSessLog.Warnf("radio access network established none of the modified flows %v", result.RejectedQFIs)
		smContext.StopT3591()
		abandonModificationUnderLock(smContext, "ran_whole_rejection", "no_flow_established")

	case result.PartiallyRejected():
		smContext.SubPduSessLog.Warnf("radio access network established flows %v and refused %v; realigning the UE",
			result.AcceptedQFIs, result.RejectedQFIs)
		realignAfterPartialRejection(smContext, result)

	default:
		smContext.SubPduSessLog.Infof("radio access network established all modified flows %v", result.AcceptedQFIs)
	}

	return nil
}

// handleModifyFailure acts on the radio access network refusing a modification outright, which
// it reports as a failure rather than as a response with an empty accepted list.
func handleModifyFailure(smContext *context.SMContext, body models.UpdateSmContextRequest) error {
	fileBytes, err := readBinaryN2SmInformation(body.GetBinaryDataN2SmInformation())
	if err != nil {
		smContext.SubPduSessLog.Errorf("reading the modify failure failed: %v", err)
		return err
	}

	cause, err := context.HandlePDUSessionResourceModifyUnsuccessfulTransfer(fileBytes, smContext)
	if err != nil {
		smContext.SubPduSessLog.Errorf("decoding the modify failure failed: %v", err)
		return err
	}

	smContext.StopT3591()
	abandonModificationUnderLock(smContext, "ran_whole_rejection", fmt.Sprintf("ngap_cause_present_%d", cause.Present))

	return nil
}

// realignAfterPartialRejection records that the UE's view of the session is wider than what the
// radio access network established. The corrective modification runs once the UE has
// acknowledged the first one, per TS 23.502 clause 4.3.3.2, which places it after step 11.
func realignAfterPartialRejection(smContext *context.SMContext, result context.ModifyResponse) {
	smContext.Realign = &context.PendingRealignment{
		EstablishedQFIs: result.AcceptedQFIs,
		RefusedQFIs:     result.RejectedQFIs,
	}
}

// realignSession brings the session into agreement with what the radio access network actually
// established, after a modification it accepted only part of.
//
// The record is already correct by this point: the pending update was pruned to the established
// flows before it was committed. What is left wrong is the UE, which acknowledged a wider set of
// parameters than the session has, and the user plane, which was programmed before the radio
// answered and still carries rules for flows that were never built. A downlink packet matching
// one of those is classified onto a QoS flow with no radio bearer and dropped, rather than
// falling back — so both halves matter.
//
// Both are corrected by one ordinary modification carrying the deletions. TS 23.502 clause
// 4.3.3.2 calls for a further procedure rather than a retry of the one that was partly accepted,
// and a deletion *is* such a procedure — so it goes through ApplyModification like any other
// instead of this function rebuilding the user plane and sending N1N2 itself. It did both by hand
// before, and got both wrong: the rebuild ran after the pruned update had been committed and so
// programmed nothing, and the user-plane call blocked forever on a response the triggering
// transaction had already taken.
//
// It runs on its own goroutine, and acquiring SMLock is what sequences it: the transaction that
// brought the acknowledgement holds the lock for its whole life, so the correction cannot start
// until that has finished and the user plane's response channel is free.
func realignSession(smContext *context.SMContext, realign *context.PendingRealignment, corrective *qos.PolicyUpdate) {
	smContext.SubPduSessLog.Warnf("realigning session: radio access network established %v and refused %v",
		realign.EstablishedQFIs, realign.RefusedQFIs)

	if corrective == nil {
		// Nothing to delete: the refused flows were not in the update being committed, so the
		// record and the UE already agree. Worth saying, because the alternative reading is that
		// the correction was skipped.
		smContext.SubPduSessLog.Infof("no flows to withdraw; the UE's view already matches the session")
		return
	}

	refused := realign.RefusedQFIs
	go func() {
		if err := applyModification(smContext, corrective); err != nil {
			smContext.SubPduSessLog.Errorf("withdrawing the refused flows %v failed: %v; the UE still believes they exist and downlink traffic matching them will be dropped",
				refused, err)
			metrics.IncrementModificationAbandonedStats("realignment", "ue_not_corrected")
			return
		}
		smContext.SubPduSessLog.Infof("corrective modification sent, withdrawing flows %v", refused)
	}()
}
