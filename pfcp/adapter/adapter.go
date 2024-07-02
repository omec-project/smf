// SPDX-FileCopyrightText: 2022-present Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package adapter

import (
	"net"
	"sync"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func init() {
	PfcpTxns = make(map[uint32]*context.NodeID)
}

var (
	PfcpTxns    map[uint32]*context.NodeID
	PfcpTxnLock sync.Mutex
)

func FetchPfcpTxn(seqNo uint32) (upNodeID *context.NodeID) {
	PfcpTxnLock.Lock()
	defer PfcpTxnLock.Unlock()
	if upNodeID = PfcpTxns[seqNo]; upNodeID != nil {
		delete(PfcpTxns, seqNo)
	}
	return upNodeID
}

func InsertPfcpTxn(seqNo uint32, upNodeID *context.NodeID) {
	PfcpTxnLock.Lock()
	defer PfcpTxnLock.Unlock()
	PfcpTxns[seqNo] = upNodeID
}

/*
This function is called when smf runs with upfadapter and the communication between

	them is sync. smf already holds the lock before calling to the below API, so not required
	upfLock in handler functions
*/
func HandleAdapterPfcpRsp(pfcpMsg message.Message) error {
	switch pfcpMsg.MessageType() {
	case message.MsgTypeAssociationSetupResponse:
		HandlePfcpAssociationSetupResponse(pfcpMsg)
	case message.MsgTypeHeartbeatResponse:
		HandlePfcpHeartbeatResponse(pfcpMsg)
	case message.MsgTypeSessionEstablishmentResponse:
		HandlePfcpSessionEstablishmentResponse(pfcpMsg)
	case message.MsgTypeSessionModificationResponse:
		HandlePfcpSessionModificationResponse(pfcpMsg)
	case message.MsgTypeSessionDeletionResponse:
		HandlePfcpSessionDeletionResponse(pfcpMsg)
	default:
		logger.PfcpLog.Errorf("upf adapter invalid msg type: %v", pfcpMsg)
	}

	return nil
}

func HandlePfcpAssociationSetupResponse(msg message.Message) {
	rsp, ok := msg.(*message.AssociationSetupResponse)
	if !ok {
		logger.PfcpLog.Errorln("Invalid PFCP Association Setup Response")
		return
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("Failed to parse cause from PFCP Association Setup Response, error: %+v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		nodeIDValue, err := rsp.NodeID.NodeID()
		if err != nil {
			logger.PfcpLog.Errorf("Failed to parse NodeID from PFCP Association Setup Response, error: %+v", err)
			return
		}

		if nodeIDValue == "" {
			logger.PfcpLog.Errorln("pfcp association needs NodeID")
			return
		}
		nodeID := context.NewNodeID(nodeIDValue)
		logger.PfcpLog.Infof("Handle PFCP Association Setup Response with NodeID[%s]", nodeID.ResolveNodeIdToIp().String())

		upf := context.RetrieveUPFNodeByNodeID(nodeID)
		if upf == nil {
			logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
			return
		}

		if rsp.UserPlaneIPResourceInformation == nil {
			logger.PfcpLog.Errorln("pfcp association setup response has no UserPlane IP Resource Information")
			return
		}

		userPlaneIpResourceInfo, err := rsp.UserPlaneIPResourceInformation[0].UserPlaneIPResourceInformation()
		if err != nil {
			logger.PfcpLog.Errorf("Failed to parse UserPlaneIPResourceInformation from PFCP Association Setup Response, error: %+v", err)
			return
		}

		if !upf.IsDnnConfigured(userPlaneIpResourceInfo.NetworkInstance) {
			logger.PfcpLog.Errorf("Handle PFCP Association Setup Response, DNN mismatch, [%v] is not configured ", userPlaneIpResourceInfo.NetworkInstance)
			return
		}

		recoveryTimeStamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
		if err != nil {
			logger.PfcpLog.Errorf("Failed to parse RecoveryTimeStamp from PFCP Association Setup Response, error: %+v", err)
			return
		}
		upf.UPFStatus = context.AssociatedSetUpSuccess
		upf.RecoveryTimeStamp = recoveryTimeStamp
		upf.NHeartBeat = 0 // reset Heartbeat attempt to 0

		upf.UPIPInfo = context.UserPlaneIPResourceInformation{
			NetworkInstance: userPlaneIpResourceInfo.NetworkInstance,
			Ipv4Address:     userPlaneIpResourceInfo.IPv4Address,
			Ipv6Address:     userPlaneIpResourceInfo.IPv6Address,
			Assosi:          rsp.UserPlaneIPResourceInformation[0].HasASSOSI(),
			Assoni:          rsp.UserPlaneIPResourceInformation[0].HasASSONI(),
			SourceInterface: userPlaneIpResourceInfo.SourceInterface,
			TeidRange:       userPlaneIpResourceInfo.TEIDRange,
			V4:              userPlaneIpResourceInfo.IPv4Address != nil,
			V6:              userPlaneIpResourceInfo.IPv6Address != nil,
		}

		if upf.UPIPInfo.Assosi && upf.UPIPInfo.Assoni && upf.UPIPInfo.SourceInterface == context.SourceInterfaceAccess &&
			upf.UPIPInfo.V4 && !upf.UPIPInfo.Ipv4Address.Equal(net.IPv4zero) {
			logger.PfcpLog.Infof("UPF[%s] received N3 interface IP[%v], network instance[%v] and TEID[%v]",
				upf.NodeID.ResolveNodeIdToIp().String(), upf.UPIPInfo.Ipv4Address,
				upf.UPIPInfo.NetworkInstance, upf.UPIPInfo.TeidRange)

			// reset the N3 interface of UPF
			upf.N3Interfaces = make([]context.UPFInterfaceInfo, 0)

			// Insert N3 interface info from UPF
			n3Interface := context.UPFInterfaceInfo{}
			n3Interface.NetworkInstance = upf.UPIPInfo.NetworkInstance
			n3Interface.IPv4EndPointAddresses = append(n3Interface.IPv4EndPointAddresses, upf.UPIPInfo.Ipv4Address)
			upf.N3Interfaces = append(upf.N3Interfaces, n3Interface)
		}

		logger.PfcpLog.Infof("UPF(%s)[%s] setup association",
			upf.NodeID.ResolveNodeIdToIp().String(), upf.UPIPInfo.NetworkInstance)
	}
}

func HandlePfcpHeartbeatResponse(msg message.Message) {
	rsp, ok := msg.(*message.HeartbeatResponse)
	if !ok {
		logger.PfcpLog.Errorln("Invalid PFCP Heartbeat Response")
		return
	}

	// Get NodeId from Seq:NodeId Map
	seq := msg.Sequence()
	nodeID := FetchPfcpTxn(seq)

	if nodeID == nil {
		logger.PfcpLog.Errorf("No pending pfcp heartbeat response for sequence no: %v", seq)
		// metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, pfcpmsgtypes.PfcpMsgTypeString(msg.PfcpMessage.Header.MessageType), "In", "Failure", "invalid_seqno")
		return
	}

	logger.PfcpLog.Debugf("handle pfcp heartbeat response seq[%d] with NodeID[%v, %s]", seq, nodeID, nodeID.ResolveNodeIdToIp().String())

	upf := context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		// metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, pfcpmsgtypes.PfcpMsgTypeString(msg.PfcpMessage.Header.MessageType), "In", "Failure", "unknown_upf")
		return
	}

	recoveryTimeStamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		logger.PfcpLog.Errorf("Failed to parse RecoveryTimeStamp from PFCP Heartbeat Response, error: %+v", err)
		return
	}

	if recoveryTimeStamp != upf.RecoveryTimeStamp {
		// change UPF state to not associated so that
		// PFCP Association can be initiated again
		upf.UPFStatus = context.NotAssociated
		logger.PfcpLog.Warnf("PFCP Heartbeat Response, upf [%v] recovery timestamp changed", upf.NodeID)

		// TODO: Session cleanup required and updated to AMF/PCF
		// metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, pfcpmsgtypes.PfcpMsgTypeString(msg.PfcpMessage.Header.MessageType), "In", "Failure", "RecoveryTimeStamp_mismatch")
	}

	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
}

func HandlePfcpSessionEstablishmentResponse(msg message.Message) {
	rsp, ok := msg.(*message.SessionEstablishmentResponse)
	if !ok {
		logger.PfcpLog.Errorln("Invalid PFCP Session Establishment Response")
		return
	}

	logger.PfcpLog.Infoln("In HandlePfcpSessionEstablishmentResponse")

	SEID := rsp.SEID()
	if SEID == 0 {
		// Let's validate that it was ok to remove this
		logger.PfcpLog.Warnf("PFCP Session Establish Response found invalid event data, response discarded")
		return
	}
	smContext := context.GetSMContextBySEID(SEID)
	logger.PfcpLog.Infof("In HandlePfcpSessionEstablishmentResponse SEID %v", SEID)
	logger.PfcpLog.Infof("In HandlePfcpSessionEstablishmentResponse smContext %+v", smContext)

	// Get NodeId from Seq:NodeId Map
	seq := rsp.Sequence()
	nodeID := FetchPfcpTxn(seq)

	UPFSEID, err := rsp.UPFSEID.FSEID()
	if err != nil {
		logger.PfcpLog.Errorf("Failed to parse UPFSEID from PFCP Session Establishment Response, error: %+v", err)
		return
	}

	if UPFSEID != nil {
		NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
		pfcpSessionCtx := smContext.PFCPContext[NodeIDtoIP]
		pfcpSessionCtx.RemoteSEID = UPFSEID.SEID
		smContext.SubPfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse rsp.UPFSEID.Seid [%v] ", UPFSEID.SEID)
	}

	// Get N3 interface UPF
	ANUPF := smContext.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("Failed to parse cause from PFCP Session Establishment Response, error: %+v", err)
		return
	}
	rspNodeID, err := rsp.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("Failed to parse NodeID from PFCP Session Establishment Response, error: %+v", err)
		return
	}

	rspNodeIDObj := context.NewNodeID(rspNodeID)
	if ANUPF.UPF.NodeID.ResolveNodeIdToIp().Equal(nodeID.ResolveNodeIdToIp()) {
		// UPF Accept
		if causeValue == ie.CauseRequestAccepted {
			smContext.SBIPFCPCommunicationChan <- context.SessionEstablishSuccess
			smContext.SubPfcpLog.Infof("PFCP Session Establishment accepted")
		} else {
			smContext.SBIPFCPCommunicationChan <- context.SessionEstablishFailed
			smContext.SubPfcpLog.Errorf("PFCP Session Establishment rejected with cause [%v]", causeValue)
			if causeValue ==
				ie.CauseNoEstablishedPFCPAssociation {
				SetUpfInactive(rspNodeIDObj)
			}
		}
	}
}

func HandlePfcpSessionModificationResponse(msg message.Message) {
	rsp, ok := msg.(*message.SessionModificationResponse)
	if !ok {
		logger.PfcpLog.Errorln("Invalid PFCP Session Modification Response")
		return
	}

	logger.PfcpLog.Infoln("In HandlePfcpSessionModificationResponse")

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("Failed to parse cause from PFCP Session Modification Response, error: %+v", err)
		return
	}

	logger.PfcpLog.Infof("In HandlePfcpSessionModificationResponse pfcpRsp.Cause.CauseValue = [%v], accepted?? %v", causeValue, causeValue == ie.CauseRequestAccepted)

	SEID := rsp.SEID()
	logger.PfcpLog.Infof("In HandlePfcpSessionModificationResponse SEID %v", SEID)

	smContext := context.GetSMContextBySEID(SEID)
	logger.PfcpLog.Infof("In HandlePfcpSessionModificationResponse smContext found by SEID %v", smContext)

	if SEID == 0 {
		// Let's validate that it was ok to remove this
		logger.PfcpLog.Warnf("PFCP Session Modification Response found invalid event data, response discarded")
		return
	}
	// smContext := context.GetSMContextBySEID(SEID)

	if causeValue == ie.CauseRequestAccepted {
		smContext.SubPduSessLog.Infoln("PFCP Modification Response Accept")
		if smContext.SMContextState == context.SmStatePfcpModify {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Tracef("Delete pending pfcp response: UPF IP [%s]\n", upfIP)

			if smContext.PendingUPF.IsEmpty() {
				smContext.SBIPFCPCommunicationChan <- context.SessionUpdateSuccess
			}
		}

		smContext.SubPfcpLog.Infof("PFCP Session Modification Success[%d]\n", SEID)
	} else {
		smContext.SubPfcpLog.Infof("PFCP Session Modification Failed[%d]\n", SEID)
		if smContext.SMContextState == context.SmStatePfcpModify {
			smContext.SBIPFCPCommunicationChan <- context.SessionUpdateFailed
		}
	}

	smContext.SubCtxLog.Traceln("PFCP Session Context")
	for _, ctx := range smContext.PFCPContext {
		smContext.SubCtxLog.Traceln(ctx.String())
	}
}

func HandlePfcpSessionDeletionResponse(msg message.Message) {
	rsp, ok := msg.(*message.SessionDeletionResponse)
	if !ok {
		logger.PfcpLog.Errorln("Invalid PFCP Session Deletion Response")
		return
	}

	logger.PfcpLog.Infof("Handle PFCP Session Deletion Response")
	SEID := rsp.SEID()

	if SEID == 0 {
		// Let's validate that it was ok to remove this
		logger.PfcpLog.Warnf("PFCP Session Deletion Response found invalid event data, response discarded")
		return
	}
	smContext := context.GetSMContextBySEID(SEID)

	if smContext == nil {
		logger.PfcpLog.Warnf("PFCP Session Deletion Response found SM context nil, response discarded")
		return
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("Failed to parse cause from PFCP Session Deletion Response, error: %+v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		if smContext.SMContextState == context.SmStatePfcpRelease {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Tracef("Delete pending pfcp response: UPF IP [%s]\n", upfIP)

			if smContext.PendingUPF.IsEmpty() && !smContext.LocalPurged {
				smContext.SBIPFCPCommunicationChan <- context.SessionReleaseSuccess
			}
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Success[%d]\n", SEID)
	} else {
		if smContext.SMContextState == context.SmStatePfcpRelease && !smContext.LocalPurged {
			smContext.SBIPFCPCommunicationChan <- context.SessionReleaseSuccess
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Failed[%d]\n", SEID)
	}
}

func SetUpfInactive(nodeID context.NodeID) {
	upf := context.RetrieveUPFNodeByNodeID(nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		// metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID,
		//	pfcpmsgtypes.PfcpMsgTypeString(msgType),
		//	"In", "Failure", "unknown_upf")
		return
	}

	upf.UPFStatus = context.NotAssociated
	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
}
