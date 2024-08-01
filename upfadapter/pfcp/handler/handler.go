// SPDX-FileCopyrightText: 2022-present Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package handler

import (
	"fmt"

	"upf-adapter/config"
	"upf-adapter/logger"
	"upf-adapter/types"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func HandlePfcpSendError(msg message.Message, pfcpErr error) {
	msgType := msg.MessageType()
	logger.PfcpLog.Errorf("send of PFCP msg [%v] failed with error [%v] ",
		msgType, pfcpErr.Error())
	switch msgType {
	case message.MsgTypeAssociationSetupRequest:
		handleSendPfcpAssoSetReqError(msg, pfcpErr)
	case message.MsgTypeHeartbeatRequest:
		handleSendPfcpHeartbeatReqError(msg, pfcpErr)
	case message.MsgTypeSessionEstablishmentRequest:
		handleSendPfcpSessEstReqError(msg, pfcpErr)
	case message.MsgTypeSessionModificationRequest:
		handleSendPfcpSessModReqError(msg, pfcpErr)
	case message.MsgTypeSessionDeletionRequest:
		handleSendPfcpSessRelReqError(msg, pfcpErr)
	default:
		logger.PfcpLog.Errorf("unable to send PFCP packet type [%v] and content [%v]",
			msgType, msg)
	}
}

func handleSendPfcpAssoSetReqError(msg message.Message, pfcpErr error) {
	logger.PfcpLog.Debugf("send association setup request error [%v] ", pfcpErr.Error())
	// send Error
	sendErrRsp(msg, pfcpErr)
}

func handleSendPfcpHeartbeatReqError(msg message.Message, pfcpErr error) {
	logger.PfcpLog.Debugf("send heartbeat request error [%v]", pfcpErr.Error())
	// send Error
	sendErrRsp(msg, pfcpErr)
}

func handleSendPfcpSessEstReqError(msg message.Message, pfcpErr error) {
	logger.PfcpLog.Debugf("send session establishment request error [%v] ", pfcpErr.Error())
	// send Error
	sendErrRsp(msg, pfcpErr)
}

func handleSendPfcpSessModReqError(msg message.Message, pfcpErr error) {
	logger.PfcpLog.Debugf("send session modification request error [%v]", pfcpErr.Error())
	// send Error
	sendErrRsp(msg, pfcpErr)
}

func handleSendPfcpSessRelReqError(msg message.Message, pfcpErr error) {
	logger.PfcpLog.Debugf("send session release request error [%v]", pfcpErr.Error())
	// send Error
	sendErrRsp(msg, pfcpErr)
}

func sendErrRsp(msg message.Message, err error) {
	// Get the PFCP Txn
	pfcpTxnChan := config.GetUpfPfcpTxn(msg.Sequence())

	// Send Rsp back to http txn
	pfcpTxnChan <- config.PfcpHttpRsp{Rsp: nil, Err: err}
}

func encodeAndSendRsp(msg message.Message) error {
	buf := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(buf)
	if err != nil {
		return err
	}

	// Get the PFCP Txn
	pfcpTxnChan := config.GetUpfPfcpTxn(msg.Sequence())

	// Send Rsp back to http txn
	pfcpTxnChan <- config.PfcpHttpRsp{Rsp: buf, Err: nil}

	return nil
}

func HandlePfcpAssociationSetupResponse(msg message.Message) {
	rsp, ok := msg.(*message.AssociationSetupResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Association Setup Response")
		return
	}

	recoveryTimeStamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse recovery timestamp: %v", err)
		return
	}

	logger.PfcpLog.Debugf("HandlePfcpAssociationSetupResponse, recovery timestamp [%v] ", recoveryTimeStamp)

	cause, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse cause: %v", err)
		return
	}

	if cause == ie.CauseRequestAccepted {

		// UPF's node ID
		nodeIDstr, err := rsp.NodeID.NodeID()
		if err != nil {
			logger.PfcpLog.Errorf("failed to parse node id: %v", err)
			return
		}
		// Add UPF as active
		logger.PfcpLog.Debugf("node id from pfcp association response [%v] ", nodeIDstr)
		nodeId := types.NewNodeID(nodeIDstr)
		upf := config.ActivateUpfNode(nodeId)

		// Preserve success Asso Rsp
		upf.PreservePfcpAssociationRsp(*rsp)
	}

	// Encode pfcp rsp to byte and send to http txn
	if err := encodeAndSendRsp(msg); err != nil {
		logger.PfcpLog.Errorf("handle pfcp association response error [%v] ", err)
	}
}

func HandlePfcpHeartbeatResponse(msg message.Message) {
	heartbeatResp, ok := msg.(*message.HeartbeatResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Heartbeat Response")
		return
	}
	recoveryTimestamp, err := heartbeatResp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse recovery timestamp: %v", err)
		return
	}
	logger.PfcpLog.Debugf("pfcp heartbeat response recovery timestamp [%v] ", recoveryTimestamp)
	// Encode pfcp rsp to byte and send to http txn
	if err := encodeAndSendRsp(msg); err != nil {
		logger.PfcpLog.Errorf("handle pfcp heartbeat response error [%v] ", err)
	}
}

func HandlePfcpSessionEstablishmentResponse(msg message.Message) {
	_, ok := msg.(*message.SessionEstablishmentResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Session Establishment Response")
		return
	}
	// Encode pfcp rsp to byte and send to http txn
	if err := encodeAndSendRsp(msg); err != nil {
		logger.PfcpLog.Errorf("handle pfcp session establishment response error [%v] ", err)
	}
}

func HandlePfcpSessionModificationResponse(msg message.Message) {
	_, ok := msg.(*message.SessionModificationResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Session Modification Response")
		return
	}
	// Encode pfcp rsp to byte and send to http txn
	if err := encodeAndSendRsp(msg); err != nil {
		logger.PfcpLog.Errorf("handle pfcp session modify response error [%v] ", err)
	}
}

func HandlePfcpSessionDeletionResponse(msg message.Message) {
	_, ok := msg.(*message.SessionDeletionResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Session Deletion Response")
		return
	}
	// Encode pfcp rsp to byte and send to http txn
	if err := encodeAndSendRsp(msg); err != nil {
		logger.PfcpLog.Errorf("handle pfcp session delete response error [%v] ", err)
	}
}

func BuildPfcpAssociationResponse(nodeId *types.NodeID, seqNo uint32) (*message.AssociationSetupResponse, error) {
	logger.AppLog.Debugf("building pfcp association response for upf [%v], seqNo [%v]", nodeId, seqNo)
	if upf := config.GetUpfFromNodeId(nodeId); upf != nil {
		lastAssociationRsp := upf.LastAssoRsp
		logger.AppLog.Debugf("stored association response recovery timestamp: %v", lastAssociationRsp.RecoveryTimeStamp)
		lastAssociationRsp.Header.SequenceNumber = seqNo
		return &lastAssociationRsp, nil
	}

	logger.AppLog.Errorf("upf [%v] not found", string(nodeId.NodeIdValue))
	return nil, fmt.Errorf("upf not found : %v", string(nodeId.NodeIdValue))
}

func BuildPfcpHeartBeatResponse(nodeId *types.NodeID, seqNo uint32) (*message.HeartbeatResponse, error) {
	logger.PfcpLog.Debugf("building pfcp heartbeat response for upf:[%v], seqNo:[%v]", nodeId, seqNo)
	if upf := config.GetUpfFromNodeId(nodeId); upf != nil {
		pfcpMsg := upf.LastHBRsp
		logger.PfcpLog.Debugf("stored heartbeat rsp recovery timestamp: %v", pfcpMsg.RecoveryTimeStamp)
		pfcpMsg.Header.SequenceNumber = seqNo
		return &pfcpMsg, nil
	}

	return nil, fmt.Errorf("upf not found : %v", string(nodeId.NodeIdValue))
}
