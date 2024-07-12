// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package pfcp

import (
	"net"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/pfcp/handler"
	"github.com/wmnsk/go-pfcp/message"
)

func Dispatch(msg message.Message, remoteAddress *net.UDPAddr) {
	messageType := msg.MessageType()
	switch messageType {
	case message.MsgTypeHeartbeatRequest:
		handler.HandlePfcpHeartbeatRequest(msg, remoteAddress)
	case message.MsgTypeHeartbeatResponse:
		handler.HandlePfcpHeartbeatResponse(msg, remoteAddress)
	case message.MsgTypePFDManagementRequest:
		handler.HandlePfcpPfdManagementRequest(msg, remoteAddress)
	case message.MsgTypePFDManagementResponse:
		handler.HandlePfcpPfdManagementResponse(msg, remoteAddress)
	case message.MsgTypeAssociationSetupRequest:
		handler.HandlePfcpAssociationSetupRequest(msg, remoteAddress)
	case message.MsgTypeAssociationSetupResponse:
		handler.HandlePfcpAssociationSetupResponse(msg, remoteAddress)
	case message.MsgTypeAssociationUpdateRequest:
		handler.HandlePfcpAssociationUpdateRequest(msg, remoteAddress)
	case message.MsgTypeAssociationUpdateResponse:
		handler.HandlePfcpAssociationUpdateResponse(msg, remoteAddress)
	case message.MsgTypeAssociationReleaseRequest:
		handler.HandlePfcpAssociationReleaseRequest(msg, remoteAddress)
	case message.MsgTypeAssociationReleaseResponse:
		handler.HandlePfcpAssociationReleaseResponse(msg, remoteAddress)
	case message.MsgTypeVersionNotSupportedResponse:
		handler.HandlePfcpVersionNotSupportedResponse(msg, remoteAddress)
	case message.MsgTypeNodeReportRequest:
		handler.HandlePfcpNodeReportRequest(msg, remoteAddress)
	case message.MsgTypeNodeReportResponse:
		handler.HandlePfcpNodeReportResponse(msg, remoteAddress)
	case message.MsgTypeSessionSetDeletionRequest:
		handler.HandlePfcpSessionSetDeletionRequest(msg, remoteAddress)
	case message.MsgTypeSessionSetDeletionResponse:
		handler.HandlePfcpSessionSetDeletionResponse(msg, remoteAddress)
	case message.MsgTypeSessionEstablishmentResponse:
		handler.HandlePfcpSessionEstablishmentResponse(msg, remoteAddress)
	case message.MsgTypeSessionModificationResponse:
		handler.HandlePfcpSessionModificationResponse(msg, remoteAddress)
	case message.MsgTypeSessionDeletionResponse:
		handler.HandlePfcpSessionDeletionResponse(msg, remoteAddress)
	case message.MsgTypeSessionReportRequest:
		handler.HandlePfcpSessionReportRequest(msg, remoteAddress)
	case message.MsgTypeSessionReportResponse:
		handler.HandlePfcpSessionReportResponse(msg, remoteAddress)
	default:
		logger.PfcpLog.Errorf("Unknown PFCP message type: %d", messageType)
		return
	}

	// stats
	metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "In", "", "")
}
