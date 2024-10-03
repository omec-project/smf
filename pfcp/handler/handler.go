// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"fmt"
	"net"

	"github.com/omec-project/openapi/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/pfcp/ies"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/omec-project/smf/producer"
	mi "github.com/omec-project/util/metricinfo"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func FindUEIPAddress(createdPDRIEs []*ie.IE) net.IP {
	for _, createdPDRIE := range createdPDRIEs {
		ueIPAddress, err := createdPDRIE.UEIPAddress()
		if err == nil {
			return ueIPAddress.IPv4Address
		}
	}
	return nil
}

func HandlePfcpHeartbeatRequest(msg *udp.Message) {
	_, ok := msg.PfcpMessage.(*message.HeartbeatRequest)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for heartbeat request")
		return
	}
	logger.PfcpLog.Infof("handle PFCP Heartbeat Request")
	err := pfcp_message.SendHeartbeatResponse(msg.RemoteAddr, msg.PfcpMessage.Sequence())
	if err != nil {
		logger.PfcpLog.Errorf("failed to send PFCP Heartbeat Response: %+v", err)
	}
}

func HandlePfcpHeartbeatResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.HeartbeatResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for heartbeat response")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Heartbeat Response")

	// Get NodeId from Seq:NodeId Map
	seq := rsp.Sequence()
	nodeID := pfcp_message.FetchPfcpTxn(seq)

	if nodeID == nil {
		logger.PfcpLog.Errorf("no pending pfcp heartbeat response for sequence no: %v", seq)
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, rsp.MessageTypeName(), "In", "Failure", "invalid_seqno")
		return
	}

	logger.PfcpLog.Debugf("handle pfcp heartbeat response seq[%d] with NodeID[%v, %s]", seq, nodeID, nodeID.ResolveNodeIdToIp().String())

	upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can not find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, rsp.MessageTypeName(), "In", "Failure", "unknown_upf")
		return
	}
	upf.UpfLock.Lock()
	defer upf.UpfLock.Unlock()

	rspRecoveryTimeStamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse RecoveryTimeStamp: %+v", err)
		return
	}

	if rspRecoveryTimeStamp != upf.RecoveryTimeStamp.RecoveryTimeStamp {
		// change UPF state to not associated so that
		// PFCP Association can be initiated again
		upf.UPFStatus = smf_context.NotAssociated
		logger.PfcpLog.Warnf("PFCP Heartbeat Response, upf [%v] recovery timestamp changed, previous [%v], new [%v] ", upf.NodeID, upf.RecoveryTimeStamp, *rsp.RecoveryTimeStamp)

		// TODO: Session cleanup required and updated to AMF/PCF
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, rsp.MessageTypeName(), "In", "Failure", "RecoveryTimeStamp_mismatch")
	}

	if *factory.SmfConfig.Configuration.KafkaInfo.EnableKafka {
		// Send Metric event
		upfStatus := mi.MetricEvent{
			EventType: mi.CNfStatusEvt,
			NfStatusData: mi.CNfStatus{
				NfType:   mi.NfTypeUPF,
				NfStatus: mi.NfStatusConnected, NfName: string(upf.NodeID.NodeIdValue),
			},
		}
		err := metrics.StatWriter.PublishNfStatusEvent(upfStatus)
		if err != nil {
			logger.PfcpLog.Errorf("failed to publish NfStatusEvent: %+v", err)
		}
	}

	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
}

func SetUpfInactive(nodeID smf_context.NodeID, msgTypeName string) {
	upf := smf_context.RetrieveUPFNodeByNodeID(nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can not find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, msgTypeName, "In", "Failure", "unknown_upf")
		return
	}

	upf.UpfLock.Lock()
	defer upf.UpfLock.Unlock()
	upf.UPFStatus = smf_context.NotAssociated
	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
}

func HandlePfcpPfdManagementRequest(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP PFD Management Request handling is not implemented")
}

func HandlePfcpPfdManagementResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP PFD Management Response handling is not implemented")
}

func HandlePfcpAssociationSetupRequest(msg *udp.Message) {
	req, ok := msg.PfcpMessage.(*message.AssociationSetupRequest)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for association setup request")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Association Setup Request")

	nodeIDIE := req.NodeID
	if nodeIDIE == nil {
		logger.PfcpLog.Errorln("pfcp association needs NodeID")
		return
	}

	nodeIDStr, err := req.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse NodeID IE: %+v", err)
		return
	}

	logger.PfcpLog.Infof("handle PFCP Association Setup Request with NodeID[%s]", nodeIDStr)

	nodeID := smf_context.NewNodeID(nodeIDStr)

	upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can not find UPF[%s]", nodeIDStr)
		return
	}

	upf.UpfLock.Lock()
	defer upf.UpfLock.Unlock()
	var userPlaneIPResourceInformation *smf_context.UserPlaneIPResourceInformation
	if len(req.UserPlaneIPResourceInformation) != 0 {
		userPlaneIPResourceInformation, err = ies.UnmarshalUEIPInformationBinary(req.UserPlaneIPResourceInformation[0].Payload)
		if err != nil {
			logger.PfcpLog.Errorf("failed to get UserPlaneIPResourceInformation: %+v", err)
			return
		}
		upf.UPIPInfo = *userPlaneIPResourceInformation
	}

	recoveryTimestamp, err := req.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse RecoveryTimeStamp: %+v", err)
		return
	}

	upf.RecoveryTimeStamp = smf_context.RecoveryTimeStamp{
		RecoveryTimeStamp: recoveryTimestamp,
	}
	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0

	// Response with PFCP Association Setup Response
	err = pfcp_message.SendPfcpAssociationSetupResponse(*nodeID, ie.CauseRequestAccepted, upf.Port)
	if err != nil {
		logger.PfcpLog.Errorf("failed to send PFCP Association Setup Response: %+v", err)
	}
}

func HandlePfcpAssociationSetupResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.AssociationSetupResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for association setup response")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Association Setup Response")

	nodeIDIE := rsp.NodeID

	if nodeIDIE == nil {
		logger.PfcpLog.Errorln("pfcp association needs NodeID")
		return
	}

	nodeIDStr, err := rsp.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse NodeID IE: %+v", err)
		return
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse Cause IE: %+v", err)
		return
	}
	if causeValue == ie.CauseRequestAccepted {
		logger.PfcpLog.Infof("handle PFCP Association Setup Response with NodeID[%s]", nodeIDStr)

		// Get NodeId from Seq:NodeId Map
		seq := rsp.Sequence()
		nodeID := pfcp_message.FetchPfcpTxn(seq)

		if nodeID == nil {
			logger.PfcpLog.Errorf("no pending pfcp Assoc req for sequence no: %v", seq)
			metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, rsp.MessageTypeName(), "In", "Failure", "invalid_seqno")
			return
		}

		upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
		if upf == nil {
			logger.PfcpLog.Errorf("can not find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
			return
		}

		var userPlaneIPResourceInformation *smf_context.UserPlaneIPResourceInformation
		if len(rsp.UserPlaneIPResourceInformation) != 0 {
			userPlaneIPResourceInformation, err = ies.UnmarshalUEIPInformationBinary(rsp.UserPlaneIPResourceInformation[0].Payload)
			if err != nil {
				logger.PfcpLog.Errorf("failed to get UserPlaneIPResourceInformation: %+v", err)
				return
			}
		}

		// validate if DNNs served by UPF matches with the one provided by UPF
		if userPlaneIPResourceInformation != nil {
			upfProvidedDnn := string(userPlaneIPResourceInformation.NetworkInstance)
			if !upf.IsDnnConfigured(upfProvidedDnn) {
				logger.PfcpLog.Errorf("handle PFCP Association Setup success Response, DNN mismatch, [%v] is not configured ", upfProvidedDnn)
				return
			}
		}

		upf.UpfLock.Lock()
		defer upf.UpfLock.Unlock()
		upf.UPFStatus = smf_context.AssociatedSetUpSuccess
		recoveryTimestamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
		if err != nil {
			logger.PfcpLog.Errorf("failed to parse RecoveryTimeStamp: %+v", err)
			return
		}
		upf.RecoveryTimeStamp = smf_context.RecoveryTimeStamp{
			RecoveryTimeStamp: recoveryTimestamp,
		}
		upf.NHeartBeat = 0 // reset Heartbeat attempt to 0

		if *factory.SmfConfig.Configuration.KafkaInfo.EnableKafka {
			// Send Metric event
			upfStatus := mi.MetricEvent{
				EventType: mi.CNfStatusEvt,
				NfStatusData: mi.CNfStatus{
					NfType:   mi.NfTypeUPF,
					NfStatus: mi.NfStatusConnected, NfName: string(upf.NodeID.NodeIdValue),
				},
			}
			err := metrics.StatWriter.PublishNfStatusEvent(upfStatus)
			if err != nil {
				logger.PfcpLog.Errorf("failed to publish NfStatusEvent: %+v", err)
			}
		}

		// Supported Features of UPF
		if rsp.UPFunctionFeatures != nil {
			UPFunctionFeatures, err := ies.UnmarshallUserPlaneFunctionFeatures(rsp.UPFunctionFeatures.Payload)
			if err != nil {
				logger.PfcpLog.Warnf("failed to get UPFunctionFeatures: %+v", err)
				return
			}
			logger.PfcpLog.Debugf("handle PFCP Association Setup success Response, received UPFunctionFeatures= %v ", UPFunctionFeatures)
			upf.UPFunctionFeatures = UPFunctionFeatures
		}

		if userPlaneIPResourceInformation != nil {
			upf.UPIPInfo = *userPlaneIPResourceInformation

			if upf.UPIPInfo.Assosi && upf.UPIPInfo.Assoni && upf.UPIPInfo.SourceInterface == ie.SrcInterfaceAccess &&
				upf.UPIPInfo.V4 && !upf.UPIPInfo.Ipv4Address.Equal(net.IPv4zero) {
				logger.PfcpLog.Infof("UPF[%s] received N3 interface IP[%v], network instance[%v] and TEID[%v]",
					upf.NodeID.ResolveNodeIdToIp().String(), upf.UPIPInfo.Ipv4Address,
					string(upf.UPIPInfo.NetworkInstance), upf.UPIPInfo.TeidRange)

				// reset the N3 interface of UPF
				upf.N3Interfaces = make([]smf_context.UPFInterfaceInfo, 0)

				// Insert N3 interface info from UPF
				n3Interface := smf_context.UPFInterfaceInfo{}
				n3Interface.NetworkInstance = string(upf.UPIPInfo.NetworkInstance)
				n3Interface.IPv4EndPointAddresses = append(n3Interface.IPv4EndPointAddresses, upf.UPIPInfo.Ipv4Address)
				upf.N3Interfaces = append(upf.N3Interfaces, n3Interface)
			}

			logger.PfcpLog.Infof("UPF(%s)[%s] setup association success",
				upf.NodeID.ResolveNodeIdToIp().String(), upf.UPIPInfo.NetworkInstance)
		} else {
			logger.PfcpLog.Errorln("pfcp association setup response has no UserPlane IP Resource Information")
		}
	}
}

func HandlePfcpAssociationUpdateRequest(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Association Update Request handling is not implemented")
}

func HandlePfcpAssociationUpdateResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Association Update Response handling is not implemented")
}

func HandlePfcpAssociationReleaseRequest(msg *udp.Message) {
	pfcpMsg, ok := msg.PfcpMessage.(*message.AssociationReleaseRequest)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for association release request")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Association Release Request")

	nodeIDIE := pfcpMsg.NodeID
	if nodeIDIE == nil {
		logger.PfcpLog.Errorln("pfcp association release needs NodeID")
		return
	}

	nodeIDStr, err := pfcpMsg.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse NodeID IE: %+v", err)
		return
	}

	nodeID := smf_context.NewNodeID(nodeIDStr)

	upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can not find UPF[%s]", nodeIDStr)
		return
	}
	smf_context.RemoveUPFNodeByNodeID(*nodeID)
	err = pfcp_message.SendPfcpAssociationReleaseResponse(*nodeID, ie.CauseRequestAccepted, upf.Port)
	if err != nil {
		logger.PfcpLog.Errorf("failed to send PFCP Association Release Response: %+v", err)
	}
}

func HandlePfcpAssociationReleaseResponse(msg *udp.Message) {
	pfcpMsg, ok := msg.PfcpMessage.(*message.AssociationReleaseResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for association release response")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Association Release Response")
	if pfcpMsg.Cause == nil {
		logger.PfcpLog.Errorln("pfcp association release response needs Cause")
		return
	}
	causeValue, err := pfcpMsg.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse Cause IE: %+v", err)
		return
	}
	if causeValue == ie.CauseRequestAccepted {
		nodeIDIE := pfcpMsg.NodeID
		if nodeIDIE == nil {
			logger.PfcpLog.Errorln("pfcp association release needs NodeID")
			return
		}
		nodeIDStr, err := pfcpMsg.NodeID.NodeID()
		if err != nil {
			logger.PfcpLog.Errorf("failed to parse NodeID IE: %+v", err)
			return
		}
		nodeID := smf_context.NewNodeID(nodeIDStr)
		smf_context.RemoveUPFNodeByNodeID(*nodeID)
	}
}

func HandlePfcpVersionNotSupportedResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Version Not Support Response handling is not implemented")
}

func HandlePfcpNodeReportRequest(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Node Report Request handling is not implemented")
}

func HandlePfcpNodeReportResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Node Report Response handling is not implemented")
}

func HandlePfcpSessionSetDeletionRequest(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Session Set Deletion Request handling is not implemented")
}

func HandlePfcpSessionSetDeletionResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Session Set Deletion Response handling is not implemented")
}

func HandlePfcpSessionEstablishmentResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.SessionEstablishmentResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for session establishment response")
		return
	}
	logger.PfcpLog.Infof("handle PFCP Session Establishment Response")

	SEID := rsp.SEID()
	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			logger.PfcpLog.Warnln("PFCP Session Establish Response found invalid event data, response discarded")
			return
		} else {
			SEID = eventData.LSEID
		}
	}
	smContext := smf_context.GetSMContextBySEID(SEID)
	if smContext == nil {
		logger.PfcpLog.Errorf("failed to find SMContext for SEID[%d]", SEID)
		return
	}
	smContext.SMLock.Lock()

	// Get NodeId from Seq:NodeId Map
	seq := rsp.Sequence()
	nodeID := pfcp_message.FetchPfcpTxn(seq)

	if rsp.UPFSEID != nil {
		// NodeIDtoIP := rsp.NodeID.ResolveNodeIdToIp().String()
		NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
		pfcpSessionCtx := smContext.PFCPContext[NodeIDtoIP]
		rspUPFseid, err := rsp.UPFSEID.FSEID()
		if err != nil {
			logger.PfcpLog.Errorf("failed to parse FSEID IE: %+v", err)
			return
		}
		pfcpSessionCtx.RemoteSEID = rspUPFseid.SEID
		smContext.SubPfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse rsp.UPFSEID.Seid [%v] ", rspUPFseid.SEID)
	}

	// UE IP-Addr(only v4 supported)
	if rsp.CreatedPDR != nil {
		ueIPAddress := FindUEIPAddress(rsp.CreatedPDR)
		smContext.SubPfcpLog.Infof("upf provided ue ip address [%v]", ueIPAddress)

		// Release previous locally allocated UE IP-Addr
		err := smContext.ReleaseUeIpAddr()
		if err != nil {
			logger.PfcpLog.Errorf("failed to release UE IP-Addr: %+v", err)
		}

		// Update with one received from UPF
		smContext.PDUAddress.Ip = ueIPAddress
		smContext.PDUAddress.UpfProvided = true
	}
	smContext.SMLock.Unlock()

	// Get N3 interface UPF
	ANUPF := smContext.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode

	if rsp.NodeID == nil {
		logger.PfcpLog.Errorln("PFCP Session Establishment Response missing NodeID")
		return
	}
	rspNodeIDStr, err := rsp.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse NodeID IE: %+v", err)
		return
	}
	rspNodeID := smf_context.NewNodeID(rspNodeIDStr)

	if ANUPF.UPF.NodeID.ResolveNodeIdToIp().Equal(nodeID.ResolveNodeIdToIp()) {
		// UPF Accept
		if rsp.Cause == nil {
			logger.PfcpLog.Errorln("PFCP Session Establishment Response missing Cause")
			return
		}
		causeValue, err := rsp.Cause.Cause()
		if err != nil {
			logger.PfcpLog.Errorf("failed to parse Cause IE: %+v", err)
			return
		}
		if causeValue == ie.CauseRequestAccepted {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionEstablishSuccess
			smContext.SubPfcpLog.Infoln("PFCP Session Establishment accepted")
		} else {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionEstablishFailed
			smContext.SubPfcpLog.Errorf("PFCP Session Establishment rejected with cause [%v]", causeValue)
			if causeValue == ie.CauseNoEstablishedPFCPAssociation {
				SetUpfInactive(*rspNodeID, msg.PfcpMessage.MessageTypeName())
			}
		}
	}

	if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
		if smContext.BPManager.BPStatus == smf_context.AddingPSA {
			smContext.SubPfcpLog.Infoln("keep Adding PSAndULCL")
			producer.AddPDUSessionAnchorAndULCL(smContext, *rspNodeID)
			smContext.BPManager.BPStatus = smf_context.AddingPSA
		}
	}
}

func HandlePfcpSessionModificationResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.SessionModificationResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for session establishment response")
		return
	}

	logger.PfcpLog.Infoln("handle PFCP Session Modification Response")

	SEID := rsp.SEID()

	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			logger.PfcpLog.Warnln("PFCP Session Modification Response found invalid event data, response discarded")
			return
		} else {
			SEID = eventData.LSEID
		}
	}
	smContext := smf_context.GetSMContextBySEID(SEID)

	logger.PfcpLog.Infoln("in HandlePfcpSessionModificationResponse")

	if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
		if smContext.BPManager.BPStatus == smf_context.AddingPSA {
			smContext.SubPfcpLog.Infoln("keep Adding PSAAndULCL")

			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			producer.AddPDUSessionAnchorAndULCL(smContext, upfNodeID)
		}
	}

	if rsp.Cause == nil {
		logger.PfcpLog.Errorln("PFCP Session Modification Response missing Cause")
		return
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse Cause IE: %+v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		smContext.SubPduSessLog.Infoln("PFCP Modification Response Accept")
		if smContext.SMContextState == smf_context.SmStatePfcpModify {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Debugf("delete pending pfcp response: UPF IP [%s]", upfIP)

			if smContext.PendingUPF.IsEmpty() {
				smContext.SBIPFCPCommunicationChan <- smf_context.SessionUpdateSuccess
			}

			if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
				if smContext.BPManager.BPStatus == smf_context.UnInitialized {
					smContext.SubPfcpLog.Infoln("add PSAAndULCL")
					upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
					producer.AddPDUSessionAnchorAndULCL(smContext, upfNodeID)
					smContext.BPManager.BPStatus = smf_context.AddingPSA
				}
			}
		}

		smContext.SubPfcpLog.Infof("PFCP Session Modification Success[%d]", SEID)
	} else {
		smContext.SubPfcpLog.Infof("PFCP Session Modification Failed[%d]", SEID)
		if smContext.SMContextState == smf_context.SmStatePfcpModify {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionUpdateFailed
		}
	}

	smContext.SubCtxLog.Debugln("PFCP Session Context")
	for _, ctx := range smContext.PFCPContext {
		smContext.SubCtxLog.Debugln(ctx.String())
	}
}

func HandlePfcpSessionDeletionResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.SessionDeletionResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for session deletion response")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Session Deletion Response")
	SEID := rsp.SEID()

	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			logger.PfcpLog.Warnln("PFCP Session Deletion Response found invalid event data, response discarded")
			return
		} else {
			SEID = eventData.LSEID
		}
	}
	smContext := smf_context.GetSMContextBySEID(SEID)

	if smContext == nil {
		logger.PfcpLog.Warnln("PFCP Session Deletion Response found SM context nil, response discarded")
		return
		// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
	}

	if rsp.Cause == nil {
		logger.PfcpLog.Errorln("PFCP Session Deletion Response missing Cause")
		return
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse Cause IE: %+v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		if smContext.SMContextState == smf_context.SmStatePfcpRelease {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Debugf("delete pending pfcp response: UPF IP [%s]", upfIP)

			if smContext.PendingUPF.IsEmpty() && !smContext.LocalPurged {
				smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess
			}
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Success[%d]", SEID)
	} else {
		if smContext.SMContextState == smf_context.SmStatePfcpRelease && !smContext.LocalPurged {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Failed[%d]", SEID)
	}
}

func HandlePfcpSessionReportRequest(msg *udp.Message) {
	req, ok := msg.PfcpMessage.(*message.SessionReportRequest)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for session report request")
		return
	}

	logger.PfcpLog.Infoln("handle PFCP Session Report Request")

	SEID := req.SEID()
	smContext := smf_context.GetSMContextBySEID(SEID)
	seqFromUPF := req.Sequence()

	var cause uint8
	var pfcpSRflag smf_context.PFCPSRRspFlags

	if smContext == nil {
		logger.PfcpLog.Warnln("PFCP Session Report Request Found SM Context NULL, Request Rejected")
		cause = ie.CauseRequestRejected

		// Rejecting buffering at UPF since not able to process Session Report Request
		pfcpSRflag.Drobu = true
		// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
		err := pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, pfcpSRflag, seqFromUPF, SEID)
		if err != nil {
			logger.PfcpLog.Errorf("failed to send PFCP Session Report Response: %+v", err)
		}
		return
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	if smContext.UpCnxState == models.UpCnxState_DEACTIVATED {
		if req.ReportType.HasDLDR() {
			downlinkServiceInfo, err := req.DownlinkDataReport.DownlinkDataServiceInformation()
			if err != nil {
				logger.PfcpLog.Warnln("DownlinkDataServiceInformation not found in DownlinkDataReport")
			}

			if downlinkServiceInfo != nil {
				smContext.SubPfcpLog.Warnln("PFCP Session Report Request DownlinkDataServiceInformation handling is not implemented")
			}

			n1n2Request := models.N1N2MessageTransferRequest{}

			// TS 23.502 4.2.3.3 3a. Send Namf_Communication_N1N2MessageTransfer Request, SMF->AMF
			n2SmBuf, err := smf_context.BuildPDUSessionResourceSetupRequestTransfer(smContext)
			if err != nil {
				smContext.SubPduSessLog.Errorln("Build PDUSessionResourceSetupRequestTransfer failed:", err)
			} else {
				n1n2Request.BinaryDataN2Information = n2SmBuf
			}

			// n1n2FailureTxfNotifURI to be added in n1n2 request transfer.
			// It is used as path by AMF to send failure notification message towards SMF
			n1n2FailureTxfNotifURI := "/nsmf-callback/sm-n1n2failnotify/"
			n1n2FailureTxfNotifURI += smContext.Ref

			n1n2Request.JsonData = &models.N1N2MessageTransferReqData{
				PduSessionId: smContext.PDUSessionID,
				SkipInd:      false,
				// Temporarily assign SMF itself, TODO: TS 23.502 4.2.3.3 5. Namf_Communication_N1N2TransferFailureNotification
				N1n2FailureTxfNotifURI: fmt.Sprintf("%s://%s:%d%s",
					smf_context.SMF_Self().URIScheme,
					smf_context.SMF_Self().RegisterIPv4,
					smf_context.SMF_Self().SBIPort,
					n1n2FailureTxfNotifURI),
				N2InfoContainer: &models.N2InfoContainer{
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
				},
			}

			rspData, _, err := smContext.CommunicationClient.
				N1N2MessageCollectionDocumentApi.
				N1N2MessageTransfer(context.Background(), smContext.Supi, n1n2Request)
			if err != nil {
				smContext.SubPfcpLog.Warnf("Send N1N2Transfer failed")
			}
			if rspData.Cause == models.N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE {
				smContext.SubPfcpLog.Infof("Receive %v, AMF is able to page the UE", rspData.Cause)

				pfcpSRflag.Drobu = false
				cause = ie.CauseRequestAccepted
			}
			if rspData.Cause == models.N1N2MessageTransferCause_UE_NOT_RESPONDING {
				smContext.SubPfcpLog.Infof("Receive %v, UE is not responding to N1N2 transfer message", rspData.Cause)
				// TODO: TS 23.502 4.2.3.3 3c. Failure indication

				// Adding Session report flag to drop buffered packet at UPF
				pfcpSRflag.Drobu = true

				// Adding Cause rejected since N1N2 Transfer message got rejected.
				cause = ie.CauseRequestRejected
			}

			// Sending Session Report Response to UPF.
			smContext.SubPfcpLog.Infof("Sending Session Report to UPF with Cause %v", cause)
			err = pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, pfcpSRflag, seqFromUPF, SEID)
			if err != nil {
				logger.PfcpLog.Errorf("failed to send PFCP Session Report Response: %+v", err)
			}
		}
	}

	// TS 23.502 4.2.3.3 2b. Send Data Notification Ack, SMF->UPF
	//	cause.CauseValue = ie.CauseRequestAccepted
	// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
	// pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, seqFromUPF, SEID)
}

func HandlePfcpSessionReportResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Session Report Response handling is not implemented")
}
