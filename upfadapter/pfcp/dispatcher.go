// SPDX-FileCopyrightText: 2022-present Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package pfcp

import (
	"upf-adapter/logger"
	"upf-adapter/pfcp/handler"

	"github.com/wmnsk/go-pfcp/message"
)

func Dispatch(msg message.Message) {
	// TODO: Add return status to all handlers
	msgType := msg.MessageType()
	switch msgType {
	/*
		case pfcp.PFCP_HEARTBEAT_REQUEST:
			handler.HandlePfcpHeartbeatRequest(msg)
	*/
	case message.MsgTypeHeartbeatResponse:
		handler.HandlePfcpHeartbeatResponse(msg)
	/*
		case pfcp.PFCP_PFD_MANAGEMENT_REQUEST:
			handler.HandlePfcpPfdManagementRequest(msg)
		case pfcp.PFCP_PFD_MANAGEMENT_RESPONSE:
			handler.HandlePfcpPfdManagementResponse(msg)
		case pfcp.PFCP_ASSOCIATION_SETUP_REQUEST:
			handler.HandlePfcpAssociationSetupRequest(msg)
	*/
	case message.MsgTypeAssociationSetupResponse:
		handler.HandlePfcpAssociationSetupResponse(msg)
		/*
			case pfcp.PFCP_ASSOCIATION_UPDATE_REQUEST:
				handler.HandlePfcpAssociationUpdateRequest(msg)
			case pfcp.PFCP_ASSOCIATION_UPDATE_RESPONSE:
				handler.HandlePfcpAssociationUpdateResponse(msg)
			case pfcp.PFCP_ASSOCIATION_RELEASE_REQUEST:
				handler.HandlePfcpAssociationReleaseRequest(msg)
			case pfcp.PFCP_ASSOCIATION_RELEASE_RESPONSE:
				handler.HandlePfcpAssociationReleaseResponse(msg)
			case pfcp.PFCP_VERSION_NOT_SUPPORTED_RESPONSE:
				handler.HandlePfcpVersionNotSupportedResponse(msg)
			case pfcp.PFCP_NODE_REPORT_REQUEST:
				handler.HandlePfcpNodeReportRequest(msg)
			case pfcp.PFCP_NODE_REPORT_RESPONSE:
				handler.HandlePfcpNodeReportResponse(msg)
			case pfcp.PFCP_SESSION_SET_DELETION_REQUEST:
				handler.HandlePfcpSessionSetDeletionRequest(msg)
			case pfcp.PFCP_SESSION_SET_DELETION_RESPONSE:
				handler.HandlePfcpSessionSetDeletionResponse(msg)
		*/
	case message.MsgTypeSessionEstablishmentResponse:
		handler.HandlePfcpSessionEstablishmentResponse(msg)
	case message.MsgTypeSessionModificationResponse:
		handler.HandlePfcpSessionModificationResponse(msg)
	case message.MsgTypeSessionDeletionResponse:
		handler.HandlePfcpSessionDeletionResponse(msg)
		/*
			case pfcp.PFCP_SESSION_REPORT_REQUEST:
				handler.HandlePfcpSessionReportRequest(msg)
			case pfcp.PFCP_SESSION_REPORT_RESPONSE:
				handler.HandlePfcpSessionReportResponse(msg)
		*/
	default:
		logger.PfcpLog.Errorf("unknown pfcp message type [%d]: %s", msgType, msg.MessageTypeName())
		return
	}
}
