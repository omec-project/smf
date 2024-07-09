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

	mi "github.com/omec-project/metricfunc/pkg/metricinfo"
	"github.com/omec-project/openapi/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/producer"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func HandlePfcpHeartbeatRequest(msg message.Message, remoteAddress *net.UDPAddr) {
	_, ok := msg.(*message.HeartbeatRequest)
	if !ok {
		logger.PfcpLog.Errorf("Invalid message type for heartbeat request")
		return
	}

	logger.PfcpLog.Infof("Handle PFCP Heartbeat Request")

	err := pfcp_message.SendHeartbeatResponse(remoteAddress, msg.Sequence())
	if err != nil {
		logger.PfcpLog.Errorf("Failed to send PFCP Heartbeat Response: %+v", err)
	}
}

func HandlePfcpHeartbeatResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	rsp, ok := msg.(*message.HeartbeatResponse)
	if !ok {
		logger.PfcpLog.Errorf("Invalid message type for heartbeat response")
		return
	}

	logger.PfcpLog.Infof("Handle PFCP Heartbeat Response")

	// Get NodeId from Seq:NodeId Map
	seq := msg.Sequence()
	nodeID := pfcp_message.FetchPfcpTxn(seq)

	if nodeID == nil {
		logger.PfcpLog.Errorf("No pending pfcp heartbeat response for sequence no: %v", seq)
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "In", "Failure", "invalid_seqno")
		return
	}

	logger.PfcpLog.Debugf("handle pfcp heartbeat response seq[%d] with NodeID[%v, %s]", seq, nodeID, nodeID.ResolveNodeIdToIp().String())

	upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "In", "Failure", "unknown_upf")
		return
	}
	upf.UpfLock.Lock()
	defer upf.UpfLock.Unlock()

	timeStamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		logger.PfcpLog.Errorf("RecoveryTimeStamp.RecoveryTimeStamp() failed: %+v", err)
		return
	}

	if timeStamp != upf.RecoveryTimeStamp {
		// change UPF state to not associated so that
		// PFCP Association can be initiated again
		upf.UPFStatus = smf_context.NotAssociated
		logger.PfcpLog.Warnf("PFCP Heartbeat Response, upf [%v] recovery timestamp changed, previous [%v], new [%v] ", upf.NodeID, upf.RecoveryTimeStamp, timeStamp)

		// TODO: Session cleanup required and updated to AMF/PCF
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "In", "Failure", "RecoveryTimeStamp_mismatch")
	}

	if *factory.SmfConfig.Configuration.KafkaInfo.EnableKafka {
		// Send Metric event
		upfStatus := mi.MetricEvent{
			EventType: mi.CNfStatusEvt,
			NfStatusData: mi.CNfStatus{
				NfType:   mi.NfTypeUPF,
				NfStatus: mi.NfStatusConnected,
				NfName:   string(upf.NodeID.NodeIdValue),
			},
		}
		metrics.StatWriter.PublishNfStatusEvent(upfStatus)
	}

	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
}

func SetUpfInactive(nodeID smf_context.NodeID, msgTypeName string) {
	upf := smf_context.RetrieveUPFNodeByNodeID(nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, msgTypeName, "In", "Failure", "unknown_upf")
		return
	}

	upf.UpfLock.Lock()
	defer upf.UpfLock.Unlock()
	upf.UPFStatus = smf_context.NotAssociated
	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
}

func HandlePfcpPfdManagementRequest(msg message.Message, remoteAddress *net.UDPAddr) {
	logger.PfcpLog.Warnf("PFCP PFD Management Request handling is not implemented")
}

func HandlePfcpPfdManagementResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	logger.PfcpLog.Warnf("PFCP PFD Management Response handling is not implemented")
}

func HandlePfcpAssociationSetupRequest(msg message.Message, remoteAddress *net.UDPAddr) {
	req, ok := msg.(*message.AssociationSetupRequest)
	if !ok {
		logger.PfcpLog.Errorf("Invalid message type for association setup request")
		return
	}

	logger.PfcpLog.Infof("Handle PFCP Association Setup Request")

	nodeIDString, err := req.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to get NodeID: %+v", err)
		return
	}

	if nodeIDString == "" {
		logger.PfcpLog.Errorln("pfcp association needs NodeID")
		return
	}

	nodeID := smf_context.NewNodeID(nodeIDString)

	logger.PfcpLog.Infof("Handle PFCP Association Setup Request with NodeID[%s]", nodeID.ResolveNodeIdToIp())

	upf := smf_context.RetrieveUPFNodeByNodeID(nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp())
		return
	}

	upf.UpfLock.Lock()
	defer upf.UpfLock.Unlock()

	upIPInfoIE, err := req.UserPlaneIPResourceInformation[0].UserPlaneIPResourceInformation()
	if err != nil {
		logger.PfcpLog.Errorf("failed to get UserPlaneIPResourceInformation: %+v", err)
		return
	}

	upIPInfo := smf_context.UserPlaneIPResourceInformation{
		Ipv4Address:     upIPInfoIE.IPv4Address,
		Ipv6Address:     upIPInfoIE.IPv6Address,
		TeidRange:       upIPInfoIE.TEIDRange,
		NetworkInstance: upIPInfoIE.NetworkInstance,
		SourceInterface: upIPInfoIE.SourceInterface,
	}

	recoveryTimeStamp, err := req.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		logger.PfcpLog.Errorf("failed to get RecoveryTimeStamp: %+v", err)
		return
	}

	upf.UPIPInfo = upIPInfo
	upf.RecoveryTimeStamp = recoveryTimeStamp
	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0

	// Response with PFCP Association Setup Response
	err = pfcp_message.SendPfcpAssociationSetupResponse(remoteAddress, ie.CauseRequestAccepted)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to send PFCP Association Setup Response: %+v", err)
	}
}

func HandlePfcpAssociationSetupResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	rsp, ok := msg.(*message.AssociationSetupResponse)
	if !ok {
		logger.PfcpLog.Errorf("Invalid message type for association setup response")
		return
	}

	logger.PfcpLog.Infof("Handle PFCP Association Setup Response")

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to get Cause: %+v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		nodeIDString, err := rsp.NodeID.NodeID()
		if err != nil {
			logger.PfcpLog.Errorf("failed to get NodeID: %+v", err)
			return
		}
		if nodeIDString == "" {
			logger.PfcpLog.Errorln("pfcp association needs NodeID")
			return
		}
		nodeID := smf_context.NewNodeID(nodeIDString)
		logger.PfcpLog.Infof("Handle PFCP Association Setup Response with NodeID[%s]", nodeID.ResolveNodeIdToIp())

		// Get NodeId from Seq:NodeId Map
		seq := rsp.Sequence()
		pendingTransactionNodeID := pfcp_message.FetchPfcpTxn(seq)

		if pendingTransactionNodeID == nil {
			logger.PfcpLog.Errorf("No pending pfcp Assoc req for sequence no: %v", seq)
			metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, rsp.MessageTypeName(), "In", "Failure", "invalid_seqno")
			return
		}

		upf := smf_context.RetrieveUPFNodeByNodeID(*pendingTransactionNodeID)
		if upf == nil {
			logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp())
			return
		}

		if len(rsp.UserPlaneIPResourceInformation) == 0 {
			logger.PfcpLog.Errorln("pfcp association setup response has no UserPlane IP Resource Information")
			return
		}

		fmt.Println("Length of upIPResourceInformationIE: ", len(rsp.UserPlaneIPResourceInformation))

		upIPResourceInformationIE := rsp.UserPlaneIPResourceInformation[0]

		userPlaneIPResourceInformation, err := UnmarshalUEIPInformationBinary(upIPResourceInformationIE.Payload)
		if err != nil {
			logger.PfcpLog.Errorf("failed to get UserPlaneIPResourceInformation: %+v", err)
			return
		}

		// validate if DNNs served by UPF matches with the one provided by UPF
		if userPlaneIPResourceInformation != nil {
			upfProvidedDnn := userPlaneIPResourceInformation.NetworkInstance
			if !upf.IsDnnConfigured(upfProvidedDnn) {
				logger.PfcpLog.Errorf("Handle PFCP Association Setup success Response, DNN mismatch, [%v] is not configured ", upfProvidedDnn)
				return
			}
		}

		upf.UpfLock.Lock()
		defer upf.UpfLock.Unlock()
		recoveryTimeStamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
		if err != nil {
			logger.PfcpLog.Errorf("failed to get RecoveryTimeStamp: %+v", err)
			return
		}

		upf.UPFStatus = smf_context.AssociatedSetUpSuccess
		upf.RecoveryTimeStamp = recoveryTimeStamp
		upf.NHeartBeat = 0 // reset Heartbeat attempt to 0

		if *factory.SmfConfig.Configuration.KafkaInfo.EnableKafka {
			// Send Metric event
			upfStatus := mi.MetricEvent{
				EventType: mi.CNfStatusEvt,
				NfStatusData: mi.CNfStatus{
					NfType:   mi.NfTypeUPF,
					NfStatus: mi.NfStatusConnected,
					NfName:   string(upf.NodeID.NodeIdValue),
				},
			}
			metrics.StatWriter.PublishNfStatusEvent(upfStatus)
		}

		// Supported Features of UPF
		if rsp.UPFunctionFeatures != nil {
			logger.PfcpLog.Debugf("Handle PFCP Association Setup success Response, received UPFunctionFeatures= %v ", rsp.UPFunctionFeatures)
			upf.UPFunctionFeatures = &smf_context.UPFunctionFeatures{
				UEIPAllocation: rsp.UPFunctionFeatures.HasUEIP(),
			}
		}

		if userPlaneIPResourceInformation != nil {
			newIPIPInfo := smf_context.UserPlaneIPResourceInformation{
				Ipv4Address:     userPlaneIPResourceInformation.IPv4Address,
				Ipv6Address:     userPlaneIPResourceInformation.IPv6Address,
				TeidRange:       userPlaneIPResourceInformation.TEIDRange,
				NetworkInstance: userPlaneIPResourceInformation.NetworkInstance,
				SourceInterface: userPlaneIPResourceInformation.SourceInterface,
				Assosi:          upIPResourceInformationIE.HasASSOSI(),
				Assoni:          upIPResourceInformationIE.HasASSONI(),
				V4:              userPlaneIPResourceInformation.IPv4Address != nil,
				V6:              userPlaneIPResourceInformation.IPv6Address != nil,
			}
			upf.UPIPInfo = newIPIPInfo

			if upf.UPIPInfo.Assosi && upf.UPIPInfo.Assoni && upf.UPIPInfo.SourceInterface == smf_context.SourceInterfaceAccess &&
				upf.UPIPInfo.V4 && !upf.UPIPInfo.Ipv4Address.Equal(net.IPv4zero) {
				logger.PfcpLog.Infof("UPF[%s] received N3 interface IP[%v], network instance[%v] and TEID[%v]",
					upf.NodeID.ResolveNodeIdToIp(), upf.UPIPInfo.Ipv4Address,
					upf.UPIPInfo.NetworkInstance, upf.UPIPInfo.TeidRange)

				// reset the N3 interface of UPF
				upf.N3Interfaces = make([]smf_context.UPFInterfaceInfo, 0)

				// Insert N3 interface info from UPF
				n3Interface := smf_context.UPFInterfaceInfo{}
				n3Interface.NetworkInstance = upf.UPIPInfo.NetworkInstance
				n3Interface.IPv4EndPointAddresses = append(n3Interface.IPv4EndPointAddresses, upf.UPIPInfo.Ipv4Address)
				upf.N3Interfaces = append(upf.N3Interfaces, n3Interface)
			}

			logger.PfcpLog.Infof("UPF(%s)[%s] setup association success",
				upf.NodeID.ResolveNodeIdToIp(), upf.UPIPInfo.NetworkInstance)
		} else {
			logger.PfcpLog.Errorln("pfcp association setup response has no UserPlane IP Resource Information")
		}
	}
}

func HandlePfcpAssociationUpdateRequest(msg message.Message, remoteAddress *net.UDPAddr) {
	logger.PfcpLog.Warnf("PFCP Association Update Request handling is not implemented")
}

func HandlePfcpAssociationUpdateResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	logger.PfcpLog.Warnf("PFCP Association Update Response handling is not implemented")
}

func HandlePfcpAssociationReleaseRequest(msg message.Message, remoteAddress *net.UDPAddr) {
	req, ok := msg.(*message.AssociationReleaseRequest)
	if !ok {
		logger.PfcpLog.Errorf("Invalid message type for association release request")
		return
	}
	logger.PfcpLog.Infof("Handle PFCP Association Release Request")
	nodeIDString, err := req.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to get NodeID: %+v", err)
		return
	}
	nodeID := smf_context.NewNodeID(nodeIDString)
	upf := smf_context.RetrieveUPFNodeByNodeID(nodeID)
	var cause uint8
	if upf != nil {
		smf_context.RemoveUPFNodeByNodeID(nodeID)
		cause = ie.CauseRequestAccepted
	} else {
		cause = ie.CauseNoEstablishedPFCPAssociation
	}

	err = pfcp_message.SendPfcpAssociationReleaseResponse(remoteAddress, nodeID, cause)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to send PFCP Association Release Response: %+v", err)
	}
}

func HandlePfcpAssociationReleaseResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	rsp, ok := msg.(*message.AssociationReleaseResponse)
	if !ok {
		logger.PfcpLog.Errorf("Invalid message type for association release response")
		return
	}
	logger.PfcpLog.Infof("Handle PFCP Association Release Response")
	cause, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to get Cause: %+v", err)
		return
	}

	nodeIdString, err := rsp.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to get NodeID: %+v", err)
		return
	}
	nodeId := smf_context.NewNodeID(nodeIdString)
	if cause == ie.CauseRequestAccepted {
		smf_context.RemoveUPFNodeByNodeID(nodeId)
	}
}

func HandlePfcpVersionNotSupportedResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	logger.PfcpLog.Warnf("PFCP Version Not Support Response handling is not implemented")
}

func HandlePfcpNodeReportRequest(msg message.Message, remoteAddress *net.UDPAddr) {
	logger.PfcpLog.Warnf("PFCP Node Report Request handling is not implemented")
}

func HandlePfcpNodeReportResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	logger.PfcpLog.Warnf("PFCP Node Report Response handling is not implemented")
}

func HandlePfcpSessionSetDeletionRequest(msg message.Message, remoteAddress *net.UDPAddr) {
	logger.PfcpLog.Warnf("PFCP Session Set Deletion Request handling is not implemented")
}

func HandlePfcpSessionSetDeletionResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	logger.PfcpLog.Warnf("PFCP Session Set Deletion Response handling is not implemented")
}

func HandlePfcpSessionEstablishmentResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	rsp, ok := msg.(*message.SessionEstablishmentResponse)
	if !ok {
		logger.PfcpLog.Errorf("Invalid message type for session establishment response")
		return
	}

	logger.PfcpLog.Infof("Handle PFCP Session Establishment Response")

	// Here I got rid of event Data, we should likely set the seid to the local seid when we get 0 in the response
	seid := rsp.SEID()
	if seid == 0 {
		logger.PfcpLog.Warnf("SEID is nil - use Local SEID - not implemented yet")
		return
	}

	smContext := smf_context.GetSMContextBySEID(seid)
	smContext.SMLock.Lock()

	upFSEID, err := rsp.UPFSEID.FSEID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to get UPFSEID: %+v", err)
		return
	}

	// Get NodeId from Seq:NodeId Map
	nodeID := pfcp_message.FetchPfcpTxn(rsp.SequenceNumber)

	if upFSEID != nil {
		NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
		pfcpSessionCtx := smContext.PFCPContext[NodeIDtoIP]
		pfcpSessionCtx.RemoteSEID = upFSEID.SEID
	}
	smContext.SubPfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse rsp.UPFSEID.Seid [%v] ", upFSEID)

	createdPDRIEs := rsp.CreatedPDR
	if len(createdPDRIEs) == 0 {
		logger.PfcpLog.Warnf("No Created PDRs in PFCP Session Establishment Response")
	}

	ueIPAddress := FindUEIPAddress(createdPDRIEs)

	// UE IP-Addr(only v4 supported)
	if ueIPAddress != nil {
		smContext.SubPfcpLog.Infof("upf provided ue ip address [%v]", ueIPAddress)

		// Release previous locally allocated UE IP-Addr
		smContext.ReleaseUeIpAddr()

		// Update with one received from UPF
		smContext.PDUAddress.Ip = ueIPAddress
		smContext.PDUAddress.UpfProvided = true
	}
	smContext.SMLock.Unlock()

	// Get N3 interface UPF
	ANUPF := smContext.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode

	rspNodeIDString, err := rsp.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to get NodeID: %+v", err)
		return
	}

	rspNodeID := smf_context.NewNodeID(rspNodeIDString)

	if ANUPF.UPF.NodeID.ResolveNodeIdToIp().Equal(nodeID.ResolveNodeIdToIp()) {
		// UPF Accept
		cause, err := rsp.Cause.Cause()
		if err != nil {
			logger.PfcpLog.Errorf("failed to get Cause: %+v", err)
			return
		}

		if cause == ie.CauseRequestAccepted {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionEstablishSuccess
			smContext.SubPfcpLog.Infof("PFCP Session Establishment accepted")
		} else {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionEstablishFailed
			smContext.SubPfcpLog.Errorf("PFCP Session Establishment rejected with cause [%v]", cause)
			if cause ==
				ie.CauseNoEstablishedPFCPAssociation {
				SetUpfInactive(rspNodeID, msg.MessageTypeName())
			}
		}
	}

	if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
		if smContext.BPManager.BPStatus == smf_context.AddingPSA {
			smContext.SubPfcpLog.Infoln("Keep Adding PSAndULCL")
			producer.AddPDUSessionAnchorAndULCL(smContext, rspNodeID)
			smContext.BPManager.BPStatus = smf_context.AddingPSA
		}
	}
}

func FindUEIPAddress(createdPDRIEs []*ie.IE) net.IP {
	for _, createdPDRIE := range createdPDRIEs {
		ueIPAddress, err := createdPDRIE.UEIPAddress()
		if err == nil {
			return ueIPAddress.IPv4Address
		}
	}
	return nil
}

func HandlePfcpSessionModificationResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	rsp, ok := msg.(*message.SessionModificationResponse)
	if !ok {
		logger.PfcpLog.Errorf("Invalid message type for session establishment response")
		return
	}

	logger.PfcpLog.Infof("Handle PFCP Session Modification Response")

	SEID := rsp.Header.SEID
	if SEID == 0 {
		logger.PfcpLog.Warnf("SEID is nil - use Local SEID - not implemented yet")
		return
	}
	smContext := smf_context.GetSMContextBySEID(SEID)

	logger.PfcpLog.Infoln("In HandlePfcpSessionModificationResponse")

	if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
		if smContext.BPManager.BPStatus == smf_context.AddingPSA {
			smContext.SubPfcpLog.Infoln("Keep Adding PSAAndULCL")

			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			producer.AddPDUSessionAnchorAndULCL(smContext, upfNodeID)
		}
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to get Cause: %+v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		smContext.SubPduSessLog.Infoln("PFCP Modification Response Accept")
		if smContext.SMContextState == smf_context.SmStatePfcpModify {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Tracef("Delete pending pfcp response: UPF IP [%s]\n", upfIP)

			if smContext.PendingUPF.IsEmpty() {
				smContext.SBIPFCPCommunicationChan <- smf_context.SessionUpdateSuccess
			}

			if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
				if smContext.BPManager.BPStatus == smf_context.UnInitialized {
					smContext.SubPfcpLog.Infoln("Add PSAAndULCL")
					upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
					producer.AddPDUSessionAnchorAndULCL(smContext, upfNodeID)
					smContext.BPManager.BPStatus = smf_context.AddingPSA
				}
			}
		}

		smContext.SubPfcpLog.Infof("PFCP Session Modification Success[%d]\n", SEID)
	} else {
		smContext.SubPfcpLog.Infof("PFCP Session Modification Failed[%d]\n", SEID)
		if smContext.SMContextState == smf_context.SmStatePfcpModify {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionUpdateFailed
		}
	}

	smContext.SubCtxLog.Traceln("PFCP Session Context")
	for _, ctx := range smContext.PFCPContext {
		smContext.SubCtxLog.Traceln(ctx.String())
	}
}

func HandlePfcpSessionDeletionResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	rsp, ok := msg.(*message.SessionDeletionResponse)
	if !ok {
		logger.PfcpLog.Errorf("Invalid message type for session deletion response")
		return
	}

	logger.PfcpLog.Infof("Handle PFCP Session Deletion Response")
	SEID := rsp.Header.SEID

	if SEID == 0 {
		logger.PfcpLog.Warnf("SEID is nil - use Local SEID - not implemented yet")
		return
	}
	smContext := smf_context.GetSMContextBySEID(SEID)

	if smContext == nil {
		logger.PfcpLog.Warnf("PFCP Session Deletion Response found SM context nil, response discarded")
		return
		// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to get Cause: %+v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		if smContext.SMContextState == smf_context.SmStatePfcpRelease {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Tracef("Delete pending pfcp response: UPF IP [%s]\n", upfIP)

			if smContext.PendingUPF.IsEmpty() && !smContext.LocalPurged {
				smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess
			}
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Success[%d]\n", SEID)
	} else {
		if smContext.SMContextState == smf_context.SmStatePfcpRelease && !smContext.LocalPurged {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Failed[%d]\n", SEID)
	}
}

func HandlePfcpSessionReportRequest(msg message.Message, remoteAddress *net.UDPAddr) {
	req, ok := msg.(*message.SessionReportRequest)
	if !ok {
		logger.PfcpLog.Errorf("Invalid message type for session report request")
		return
	}

	logger.PfcpLog.Infof("Handle PFCP Session Report Request")

	SEID := req.Header.SEID
	smContext := smf_context.GetSMContextBySEID(SEID)
	seqFromUPF := req.Header.SequenceNumber

	var cause uint8
	var drobu bool

	if smContext == nil {
		logger.PfcpLog.Warnf("PFCP Session Report Request Found SM Context NULL, Request Rejected")
		cause = ie.CauseRequestRejected

		// Rejecting buffering at UPF since not able to process Session Report Request
		drobu = true

		// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
		err := pfcp_message.SendPfcpSessionReportResponse(remoteAddress, cause, drobu, seqFromUPF, SEID)
		if err != nil {
			logger.PfcpLog.Errorf("Failed to send PFCP Session Report Response: %+v", err)
		}
		return
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	if smContext.UpCnxState == models.UpCnxState_DEACTIVATED {
		if req.ReportType.HasDLDR() {
			downlinkDataReport := req.DownlinkDataReport
			downlinkServiceInfo, err := downlinkDataReport.DownlinkDataServiceInformation()
			if downlinkServiceInfo != nil || err == nil {
				smContext.SubPfcpLog.Warnf("PFCP Session Report Request DownlinkDataServiceInformation handling is not implemented")
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

				drobu = false
				cause = ie.CauseRequestAccepted
			}
			if rspData.Cause == models.N1N2MessageTransferCause_UE_NOT_RESPONDING {
				smContext.SubPfcpLog.Infof("Receive %v, UE is not responding to N1N2 transfer message", rspData.Cause)
				// TODO: TS 23.502 4.2.3.3 3c. Failure indication

				// Adding Session report flag to drop buffered packet at UPF
				drobu = true

				// Adding Cause rejected since N1N2 Transfer message got rejected.
				cause = ie.CauseRequestRejected
			}

			// Sending Session Report Response to UPF.
			smContext.SubPfcpLog.Infof("Sending Session Report to UPF with Cause %v", cause)
			err = pfcp_message.SendPfcpSessionReportResponse(remoteAddress, cause, drobu, seqFromUPF, SEID)
			if err != nil {
				logger.PfcpLog.Errorf("Failed to send PFCP Session Report Response: %+v", err)
			}
		}
	}

	// TS 23.502 4.2.3.3 2b. Send Data Notification Ack, SMF->UPF
	//	cause.CauseValue = smf_context.CauseRequestAccepted
	// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
	// pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, seqFromUPF, SEID)
}

func HandlePfcpSessionReportResponse(msg message.Message, remoteAddress *net.UDPAddr) {
	logger.PfcpLog.Warnf("PFCP Session Report Response handling is not implemented")
}
