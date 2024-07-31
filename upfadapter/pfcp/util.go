// SPDX-FileCopyrightText: 2022-present Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package pfcp

import (
	"fmt"

	"upf-adapter/config"
	"upf-adapter/logger"
	"upf-adapter/pfcp/handler"
	"upf-adapter/pfcp/message"
	"upf-adapter/types"

	"github.com/wmnsk/go-pfcp/ie"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
)

func ForwardPfcpMsgToUpf(pfcpMessage pfcp_message.Message, upNodeID types.NodeID) ([]byte, error) {
	pfcpTxnChan := make(config.PfcpTxnChan)
	var err error

	// identify msg type
	msgType := pfcpMessage.MessageType()
	switch msgType {
	case pfcp_message.MsgTypeAssociationSetupRequest:
		// if UPF is already associated then send Asso rsp
		if config.IsUpfAssociated(upNodeID) {

			logger.AppLog.Debugf("upf[%v] already associated", upNodeID)
			// form and send Assoc rsp
			pfcpAssociationRsp, err := handler.BuildPfcpAssociationResponse(&upNodeID, pfcpMessage.Sequence())
			if err != nil {
				return nil, fmt.Errorf("error building association response: %v", err)
			}
			buf := make([]byte, pfcpAssociationRsp.MarshalLen())
			err = pfcpAssociationRsp.MarshalTo(buf)
			if err != nil {
				return nil, err
			}
			return buf, nil
		}

		config.InsertUpfNode(upNodeID)

		associationReq, ok := pfcpMessage.(*pfcp_message.AssociationSetupRequest)
		if !ok {
			return nil, fmt.Errorf("invalid association setup request")
		}

		// replace smf time-stamp with UPF-Adapters timestamp
		associationReq.RecoveryTimeStamp = ie.NewRecoveryTimeStamp(config.UpfServerStartTime)

		// replace SMF NodeId with of upf-adapter's one
		associationReq.NodeID = ie.NewNodeID(config.UpfAdapterIp.String(), "", "")
		logger.AppLog.Debugf("association request, existing node id replaced by [%v]", config.UpfAdapterIp)

		// store txn in seq:chan map
		config.InsertUpfPfcpTxn(associationReq.Sequence(), pfcpTxnChan)
		err = message.SendPfcpAssociationSetupRequest(upNodeID, associationReq)
		if err != nil {
			return nil, err
		}
	case pfcp_message.MsgTypeHeartbeatRequest:

		heartbeatReq, ok := pfcpMessage.(*pfcp_message.HeartbeatRequest)
		if !ok {
			return nil, fmt.Errorf("invalid heartbeat request")
		}

		// replace smf time-stamp with UPF-Adapters timestamp
		heartbeatReq.RecoveryTimeStamp = ie.NewRecoveryTimeStamp(config.UpfServerStartTime)

		// store txn in seq:chan map
		config.InsertUpfPfcpTxn(heartbeatReq.Sequence(), pfcpTxnChan)
		err = message.SendHeartbeatRequest(upNodeID, heartbeatReq)
		if err != nil {
			return nil, err
		}
	case pfcp_message.MsgTypeSessionEstablishmentRequest:
		sessionEstablishmentReq, ok := pfcpMessage.(*pfcp_message.SessionEstablishmentRequest)
		if !ok {
			return nil, fmt.Errorf("invalid session establishment request")
		}
		// replace SMF NodeId with of upf-adapter's one
		sessionEstablishmentReq.NodeID = ie.NewNodeID(config.UpfAdapterIp.String(), "", "")

		// Replace SMF FSEID v4 Addr with UPF Adapter's IP
		existingCPFSEID, err := sessionEstablishmentReq.CPFSEID.FSEID()
		if err != nil {
			return nil, fmt.Errorf("error getting FSEID from session establishment request")
		}
		sessionEstablishmentReq.CPFSEID = ie.NewFSEID(
			existingCPFSEID.SEID,
			config.UpfAdapterIp,
			nil,
		)
		// store txn in seq:chan map
		config.InsertUpfPfcpTxn(sessionEstablishmentReq.Sequence(), pfcpTxnChan)

		err = message.SendPfcpSessionEstablishmentRequest(upNodeID, sessionEstablishmentReq)
		if err != nil {
			return nil, err
		}
	case pfcp_message.MsgTypeSessionModificationRequest:
		sessionModificationReq, ok := pfcpMessage.(*pfcp_message.SessionModificationRequest)
		if !ok {
			return nil, fmt.Errorf("invalid session modification request")
		}

		// store txn in seq:chan map
		config.InsertUpfPfcpTxn(sessionModificationReq.Sequence(), pfcpTxnChan)
		err = message.SendPfcpSessionModificationRequest(upNodeID, sessionModificationReq)
		if err != nil {
			return nil, err
		}
	case pfcp_message.MsgTypeSessionDeletionRequest:
		sessionDeletionReq, ok := pfcpMessage.(*pfcp_message.SessionDeletionRequest)
		if !ok {
			return nil, fmt.Errorf("invalid session deletion request")
		}

		// store txn in seq:chan map
		config.InsertUpfPfcpTxn(sessionDeletionReq.Sequence(), pfcpTxnChan)
		message.SendPfcpSessionDeletionRequest(upNodeID, sessionDeletionReq)
	default:
		return nil, fmt.Errorf("invalid msg type [%v] from smf", msgType)
	}

	// wait for response from UPF
	pfcpRsp := <-pfcpTxnChan

	return pfcpRsp.Rsp, pfcpRsp.Err
}
