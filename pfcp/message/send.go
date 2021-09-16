// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package message

import (
	"context"
	"net"
	"net/http"
	"sync"

	"sync/atomic"

	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/pfcp/pfcpUdp"
	smf_context "github.com/free5gc/smf/context"
	"github.com/free5gc/smf/logger"
	"github.com/free5gc/smf/metrics"
	"github.com/free5gc/smf/msgtypes/pfcpmsgtypes"
	"github.com/free5gc/smf/pfcp/udp"
)

var seq uint32

func getSeqNumber() uint32 {
	return atomic.AddUint32(&seq, 1)
}

func init() {
	PfcpTxns = make(map[uint32]*pfcpType.NodeID)
}

var (
	PfcpTxns    map[uint32]*pfcpType.NodeID
	PfcpTxnLock sync.Mutex
)

func FetchPfcpTxn(seqNo uint32) (upNodeID *pfcpType.NodeID) {
	PfcpTxnLock.Lock()
	defer PfcpTxnLock.Unlock()
	if upNodeID = PfcpTxns[seqNo]; upNodeID != nil {
		delete(PfcpTxns, seqNo)
	}
	return upNodeID
}

func InsertPfcpTxn(seqNo uint32, upNodeID *pfcpType.NodeID) {
	PfcpTxnLock.Lock()
	defer PfcpTxnLock.Unlock()
	PfcpTxns[seqNo] = upNodeID
}

func SendHeartbeatRequest(upNodeID pfcpType.NodeID) error {
	pfcpMsg, err := BuildPfcpHeartbeatRequest()
	if err != nil {
		logger.PfcpLog.Errorf("Build PFCP Heartbeat Request failed: %v", err)
		return err
	}

	message := pfcp.Message{
		Header: pfcp.Header{
			Version:        pfcp.PfcpVersion,
			MP:             0,
			S:              pfcp.SEID_NOT_PRESENT,
			MessageType:    pfcp.PFCP_HEARTBEAT_REQUEST,
			SequenceNumber: getSeqNumber(),
		},
		Body: pfcpMsg,
	}

	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: pfcpUdp.PFCP_PORT,
	}

	InsertPfcpTxn(message.Header.SequenceNumber, &upNodeID)
	if err := udp.SendPfcp(message, addr, nil); err != nil {
		FetchPfcpTxn(message.Header.SequenceNumber)
		return err
	}
	logger.PfcpLog.Infof("Sent PFCP Heartbeat Request Seq[%d] to NodeID[%s]", message.Header.SequenceNumber,
		upNodeID.ResolveNodeIdToIp().String())
	return nil
}

func SendPfcpAssociationSetupRequest(upNodeID pfcpType.NodeID) {
	if net.IP.Equal(upNodeID.ResolveNodeIdToIp(), net.IPv4zero) {
		logger.PfcpLog.Errorf("PFCP Association Setup Request failed, invalid NodeId: %v", string(upNodeID.NodeIdValue))
		return
	}

	pfcpMsg, err := BuildPfcpAssociationSetupRequest()
	if err != nil {
		logger.PfcpLog.Errorf("Build PFCP Association Setup Request failed: %v", err)
		return
	}

	message := pfcp.Message{
		Header: pfcp.Header{
			Version:        pfcp.PfcpVersion,
			MP:             0,
			S:              pfcp.SEID_NOT_PRESENT,
			MessageType:    pfcp.PFCP_ASSOCIATION_SETUP_REQUEST,
			SequenceNumber: getSeqNumber(),
		},
		Body: pfcpMsg,
	}

	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: pfcpUdp.PFCP_PORT,
	}

	udp.SendPfcp(message, addr, nil)
	logger.PfcpLog.Infof("Sent PFCP Association Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
}

func SendPfcpAssociationSetupResponse(upNodeID pfcpType.NodeID, cause pfcpType.Cause) {
	pfcpMsg, err := BuildPfcpAssociationSetupResponse(cause)
	if err != nil {
		logger.PfcpLog.Errorf("Build PFCP Association Setup Response failed: %v", err)
		return
	}

	message := pfcp.Message{
		Header: pfcp.Header{
			Version:        pfcp.PfcpVersion,
			MP:             0,
			S:              pfcp.SEID_NOT_PRESENT,
			MessageType:    pfcp.PFCP_ASSOCIATION_SETUP_RESPONSE,
			SequenceNumber: 1,
		},
		Body: pfcpMsg,
	}

	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: pfcpUdp.PFCP_PORT,
	}

	udp.SendPfcp(message, addr, nil)
	logger.PfcpLog.Infof("Sent PFCP Association Response to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
}

func SendPfcpAssociationReleaseRequest(upNodeID pfcpType.NodeID) {
	pfcpMsg, err := BuildPfcpAssociationReleaseRequest()
	if err != nil {
		logger.PfcpLog.Errorf("Build PFCP Association Release Request failed: %v", err)
		return
	}

	message := pfcp.Message{
		Header: pfcp.Header{
			Version:        pfcp.PfcpVersion,
			MP:             0,
			S:              pfcp.SEID_NOT_PRESENT,
			MessageType:    pfcp.PFCP_ASSOCIATION_RELEASE_REQUEST,
			SequenceNumber: 1,
		},
		Body: pfcpMsg,
	}

	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: pfcpUdp.PFCP_PORT,
	}

	udp.SendPfcp(message, addr, nil)
	logger.PfcpLog.Infof("Sent PFCP Association Release Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
}

func SendPfcpAssociationReleaseResponse(upNodeID pfcpType.NodeID, cause pfcpType.Cause) {
	pfcpMsg, err := BuildPfcpAssociationReleaseResponse(cause)
	if err != nil {
		logger.PfcpLog.Errorf("Build PFCP Association Release Response failed: %v", err)
		return
	}

	message := pfcp.Message{
		Header: pfcp.Header{
			Version:        pfcp.PfcpVersion,
			MP:             0,
			S:              pfcp.SEID_NOT_PRESENT,
			MessageType:    pfcp.PFCP_ASSOCIATION_RELEASE_RESPONSE,
			SequenceNumber: 1,
		},
		Body: pfcpMsg,
	}

	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: pfcpUdp.PFCP_PORT,
	}

	udp.SendPfcp(message, addr, nil)
	logger.PfcpLog.Infof("Sent PFCP Association Release Response to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
}

func SendPfcpSessionEstablishmentRequest(
	upNodeID pfcpType.NodeID,
	ctx *smf_context.SMContext,
	pdrList []*smf_context.PDR, farList []*smf_context.FAR, barList []*smf_context.BAR, qerList []*smf_context.QER) {
	pfcpMsg, err := BuildPfcpSessionEstablishmentRequest(upNodeID, ctx, pdrList, farList, barList, qerList)
	if err != nil {
		ctx.SubPfcpLog.Errorf("Build PFCP Session Establishment Request failed: %v", err)
		return
	}

	ip := upNodeID.ResolveNodeIdToIp()

	message := pfcp.Message{
		Header: pfcp.Header{
			Version:         pfcp.PfcpVersion,
			MP:              1,
			S:               pfcp.SEID_PRESENT,
			MessageType:     pfcp.PFCP_SESSION_ESTABLISHMENT_REQUEST,
			SEID:            0,
			SequenceNumber:  getSeqNumber(),
			MessagePriority: 0,
		},
		Body: pfcpMsg,
	}

	upaddr := &net.UDPAddr{
		IP:   ip,
		Port: pfcpUdp.PFCP_PORT,
	}
	ctx.SubPduSessLog.Traceln("[SMF] Send SendPfcpSessionEstablishmentRequest")
	ctx.SubPduSessLog.Traceln("Send to addr ", upaddr.String())

	eventData := pfcpUdp.PfcpEventData{LSEID: ctx.PFCPContext[ip.String()].LocalSEID, ErrHandler: HandlePfcpSendError}
	udp.SendPfcp(message, upaddr, eventData)
	ctx.SubPfcpLog.Infof("Sent PFCP Session Establish Request to NodeID[%s]", ip.String())
}

// Deprecated: PFCP Session Establishment Procedure should be initiated by the CP function
func SendPfcpSessionEstablishmentResponse(addr *net.UDPAddr) {
	pfcpMsg, err := BuildPfcpSessionEstablishmentResponse()
	if err != nil {
		logger.PfcpLog.Errorf("Build PFCP Session Establishment Response failed: %v", err)
		return
	}

	message := pfcp.Message{
		Header: pfcp.Header{
			Version:         pfcp.PfcpVersion,
			MP:              1,
			S:               pfcp.SEID_PRESENT,
			MessageType:     pfcp.PFCP_SESSION_ESTABLISHMENT_RESPONSE,
			SEID:            123456789123456789,
			SequenceNumber:  1,
			MessagePriority: 12,
		},
		Body: pfcpMsg,
	}

	udp.SendPfcp(message, addr, nil)
}

func SendPfcpSessionModificationRequest(upNodeID pfcpType.NodeID,
	ctx *smf_context.SMContext,
	pdrList []*smf_context.PDR, farList []*smf_context.FAR, barList []*smf_context.BAR, qerList []*smf_context.QER) (seqNum uint32) {
	pfcpMsg, err := BuildPfcpSessionModificationRequest(upNodeID, ctx, pdrList, farList, barList, qerList)
	if err != nil {
		ctx.SubPfcpLog.Errorf("Build PFCP Session Modification Request failed: %v", err)
		return
	}

	seqNum = getSeqNumber()
	nodeIDtoIP := upNodeID.ResolveNodeIdToIp().String()
	remoteSEID := ctx.PFCPContext[nodeIDtoIP].RemoteSEID
	message := pfcp.Message{
		Header: pfcp.Header{
			Version:         pfcp.PfcpVersion,
			MP:              1,
			S:               pfcp.SEID_PRESENT,
			MessageType:     pfcp.PFCP_SESSION_MODIFICATION_REQUEST,
			SEID:            remoteSEID,
			SequenceNumber:  seqNum,
			MessagePriority: 12,
		},
		Body: pfcpMsg,
	}

	upaddr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: pfcpUdp.PFCP_PORT,
	}

	eventData := pfcpUdp.PfcpEventData{LSEID: ctx.PFCPContext[nodeIDtoIP].LocalSEID, ErrHandler: HandlePfcpSendError}

	udp.SendPfcp(message, upaddr, eventData)
	ctx.SubPfcpLog.Infof("Sent PFCP Session Modify Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
	return seqNum
}

// Deprecated: PFCP Session Modification Procedure should be initiated by the CP function
func SendPfcpSessionModificationResponse(addr *net.UDPAddr) {
	pfcpMsg, err := BuildPfcpSessionModificationResponse()
	if err != nil {
		logger.PfcpLog.Errorf("Build PFCP Session Modification Response failed: %v", err)
		return
	}

	message := pfcp.Message{
		Header: pfcp.Header{
			Version:         pfcp.PfcpVersion,
			MP:              1,
			S:               pfcp.SEID_PRESENT,
			MessageType:     pfcp.PFCP_SESSION_MODIFICATION_RESPONSE,
			SEID:            123456789123456789,
			SequenceNumber:  1,
			MessagePriority: 12,
		},
		Body: pfcpMsg,
	}

	udp.SendPfcp(message, addr, nil)
}

func SendPfcpSessionDeletionRequest(upNodeID pfcpType.NodeID, ctx *smf_context.SMContext) (seqNum uint32) {
	pfcpMsg, err := BuildPfcpSessionDeletionRequest(upNodeID, ctx)
	if err != nil {
		ctx.SubPfcpLog.Errorf("Build PFCP Session Deletion Request failed: %v", err)
		return
	}
	seqNum = getSeqNumber()
	nodeIDtoIP := upNodeID.ResolveNodeIdToIp().String()
	remoteSEID := ctx.PFCPContext[nodeIDtoIP].RemoteSEID
	message := pfcp.Message{
		Header: pfcp.Header{
			Version:         pfcp.PfcpVersion,
			MP:              1,
			S:               pfcp.SEID_PRESENT,
			MessageType:     pfcp.PFCP_SESSION_DELETION_REQUEST,
			SEID:            remoteSEID,
			SequenceNumber:  seqNum,
			MessagePriority: 12,
		},
		Body: pfcpMsg,
	}

	upaddr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: pfcpUdp.PFCP_PORT,
	}

	eventData := pfcpUdp.PfcpEventData{LSEID: ctx.PFCPContext[nodeIDtoIP].LocalSEID, ErrHandler: HandlePfcpSendError}

	udp.SendPfcp(message, upaddr, eventData)

	ctx.SubPfcpLog.Infof("Sent PFCP Session Delete Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
	return seqNum
}

// Deprecated: PFCP Session Deletion Procedure should be initiated by the CP function
func SendPfcpSessionDeletionResponse(addr *net.UDPAddr) {
	pfcpMsg, err := BuildPfcpSessionDeletionResponse()
	if err != nil {
		logger.PfcpLog.Errorf("Build PFCP Session Deletion Response failed: %v", err)
		return
	}

	message := pfcp.Message{
		Header: pfcp.Header{
			Version:         pfcp.PfcpVersion,
			MP:              1,
			S:               pfcp.SEID_PRESENT,
			MessageType:     pfcp.PFCP_SESSION_DELETION_RESPONSE,
			SEID:            123456789123456789,
			SequenceNumber:  1,
			MessagePriority: 12,
		},
		Body: pfcpMsg,
	}

	udp.SendPfcp(message, addr, nil)
}

func SendPfcpSessionReportResponse(addr *net.UDPAddr, cause pfcpType.Cause, seqFromUPF uint32, SEID uint64) {
	pfcpMsg, err := BuildPfcpSessionReportResponse(cause)
	if err != nil {
		logger.PfcpLog.Errorf("Build PFCP Session Report Response failed: %v", err)
		return
	}

	message := pfcp.Message{
		Header: pfcp.Header{
			Version:        pfcp.PfcpVersion,
			MP:             0,
			S:              pfcp.SEID_PRESENT,
			MessageType:    pfcp.PFCP_SESSION_REPORT_RESPONSE,
			SequenceNumber: seqFromUPF,
			SEID:           SEID,
		},
		Body: pfcpMsg,
	}

	udp.SendPfcp(message, addr, nil)
	logger.PfcpLog.Infof("Sent PFCP Session Report Response Seq[%d] to NodeID[%s]", seqFromUPF, addr.IP.String())
}

func SendHeartbeatResponse(addr *net.UDPAddr, seq uint32) {
	pfcpMsg := pfcp.HeartbeatResponse{
		RecoveryTimeStamp: &pfcpType.RecoveryTimeStamp{
			RecoveryTimeStamp: udp.ServerStartTime,
		},
	}

	message := pfcp.Message{
		Header: pfcp.Header{
			Version:        pfcp.PfcpVersion,
			MP:             0,
			S:              pfcp.SEID_NOT_PRESENT,
			MessageType:    pfcp.PFCP_HEARTBEAT_RESPONSE,
			SequenceNumber: seq,
		},
		Body: pfcpMsg,
	}

	udp.SendPfcp(message, addr, nil)
	logger.PfcpLog.Infof("Sent PFCP Heartbeat Response Seq[%d] to NodeID[%s]", seq, addr.IP.String())
}

func HandlePfcpSendError(msg *pfcp.Message, pfcpErr error) {

	logger.PfcpLog.Errorf("send of PFCP msg [%v] failed, %v",
		pfcpmsgtypes.PfcpMsgTypeString(msg.Header.MessageType), pfcpErr.Error())
	metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID,
		pfcpmsgtypes.PfcpMsgTypeString(msg.Header.MessageType), "Out", "Failure", pfcpErr.Error())

	//Refresh SMF DNS Cache incase of any send failure(includes timeout)
	pfcpType.RefreshDnsHostIpCache()

	switch msg.Header.MessageType {
	case pfcp.PFCP_SESSION_ESTABLISHMENT_REQUEST:
		handleSendPfcpSessEstReqError(msg, pfcpErr)
	case pfcp.PFCP_SESSION_MODIFICATION_REQUEST:
		handleSendPfcpSessModReqError(msg, pfcpErr)
	case pfcp.PFCP_SESSION_DELETION_REQUEST:
		handleSendPfcpSessRelReqError(msg, pfcpErr)
	default:
		logger.PfcpLog.Errorf("Unable to send PFCP packet type [%v] and content [%v]",
			pfcpmsgtypes.PfcpMsgTypeString(msg.Header.MessageType), msg)
	}
}

func handleSendPfcpSessEstReqError(msg *pfcp.Message, pfcpErr error) {
	//Lets decode the PDU request
	pfcpEstReq, _ := msg.Body.(pfcp.PFCPSessionEstablishmentRequest)

	SEID := pfcpEstReq.CPFSEID.Seid
	smContext := smf_context.GetSMContextBySEID(SEID)
	smContext.SubPfcpLog.Errorf("PFCP Session Establishment send failure, %v", pfcpErr.Error())
	//N1N2 Request towards AMF
	n1n2Request := models.N1N2MessageTransferRequest{}

	//N1 Container Info
	n1MsgContainer := models.N1MessageContainer{
		N1MessageClass:   "SM",
		N1MessageContent: &models.RefToBinaryData{ContentId: "GSM_NAS"},
	}

	//N1N2 Json Data
	n1n2Request.JsonData = &models.N1N2MessageTransferReqData{PduSessionId: smContext.PDUSessionID}

	if smNasBuf, err := smf_context.BuildGSMPDUSessionEstablishmentReject(smContext,
		nasMessage.Cause5GSMRequestRejectedUnspecified); err != nil {
		smContext.SubPduSessLog.Errorf("Build GSM PDUSessionEstablishmentReject failed: %s", err)
	} else {
		n1n2Request.BinaryDataN1Message = smNasBuf
		n1n2Request.JsonData.N1MessageContainer = &n1MsgContainer
	}

	//Send N1N2 Reject request
	rspData, _, err := smContext.
		CommunicationClient.
		N1N2MessageCollectionDocumentApi.
		N1N2MessageTransfer(context.Background(), smContext.Supi, n1n2Request)
	smContext.ChangeState(smf_context.InActive)
	smContext.SubCtxLog.Traceln("SMContextState Change State: ", smContext.SMContextState.String())
	if err != nil {
		smContext.SubPfcpLog.Warnf("Send N1N2Transfer failed")
	}
	if rspData.Cause == models.N1N2MessageTransferCause_N1_MSG_NOT_TRANSFERRED {
		smContext.SubPfcpLog.Warnf("%v", rspData.Cause)
	}
	smContext.SubPfcpLog.Errorf("PFCP send N1N2Transfer Reject initiated for id[%v], pduSessId[%v]", smContext.Identifier, smContext.PDUSessionID)

	//clear subscriber
	smf_context.RemoveSMContext(smContext.Ref)
}

func handleSendPfcpSessRelReqError(msg *pfcp.Message, pfcpErr error) {
	//Lets decode the PDU request
	pfcpRelReq, _ := msg.Body.(pfcp.PFCPSessionDeletionRequest)

	SEID := pfcpRelReq.CPFSEID.Seid
	smContext := smf_context.GetSMContextBySEID(SEID)
	smContext.SubPfcpLog.Errorf("PFCP Session Delete send failure, %v", pfcpErr.Error())

	smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseTimeout
}

func handleSendPfcpSessModReqError(msg *pfcp.Message, pfcpErr error) {
	//Lets decode the PDU request
	pfcpModReq, _ := msg.Body.(pfcp.PFCPSessionModificationRequest)

	SEID := pfcpModReq.CPFSEID.Seid
	smContext := smf_context.GetSMContextBySEID(SEID)
	smContext.SubPfcpLog.Errorf("PFCP Session Modification send failure, %v", pfcpErr.Error())

	smContext.SBIPFCPCommunicationChan <- smf_context.SessionUpdateTimeout
}

func ReleaseTunnel(smContext *smf_context.SMContext) {
	deletedPFCPNode := make(map[string]bool)
	smContext.PendingUPF = make(smf_context.PendingUPF)
	for _, dataPath := range smContext.Tunnel.DataPathPool {
		dataPath.DeactivateTunnelAndPDR(smContext)
		for curDataPathNode := dataPath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
			curUPFID, err := curDataPathNode.GetUPFID()
			if err != nil {
				smContext.SubPduSessLog.Error(err)
				continue
			}
			if _, exist := deletedPFCPNode[curUPFID]; !exist {
				SendPfcpSessionDeletionRequest(curDataPathNode.UPF.NodeID, smContext)
				deletedPFCPNode[curUPFID] = true
				smContext.PendingUPF[curDataPathNode.GetNodeIP()] = true
			}
		}
	}
}

func HandleNwInitiatedPduSessionRelease(smContextRef string) {
	smContext := smf_context.GetSMContext(smContextRef)
	PFCPResponseStatus := <-smContext.SBIPFCPCommunicationChan

	switch PFCPResponseStatus {
	case smf_context.SessionReleaseSuccess:
		smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, PFCP SessionReleaseSuccess")
		smContext.ChangeState(smf_context.InActivePending)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, SMContextState Change State: ", smContext.SMContextState.String())
	case smf_context.SessionReleaseTimeout:
		fallthrough
	case smf_context.SessionReleaseFailed:
		smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease, PFCP SessionReleaseFailed")
		smContext.ChangeState(smf_context.InActivePending)
		smContext.SubCtxLog.Traceln("PDUSessionSMContextRelease,  SMContextState Change State: ", smContext.SMContextState.String())
	}

	smf_context.RemoveSMContext(smContext.Ref)
}

//HandlePfcpResponse : Handles PFCP Responses received from UPF
func HandlePfcpResponse(smContext *smf_context.SMContext,
	response models.UpdateSmContextResponse,
	smContextRef string) *http_wrapper.Response {

	var httpResponse *http_wrapper.Response

	PFCPResponseStatus := <-smContext.SBIPFCPCommunicationChan

	smContext.SubPfcpLog.Infoln("In HandlePfcpResp, Received PFCP Response : ", PFCPResponseStatus.String())

	switch PFCPResponseStatus {
	case smf_context.SessionUpdateSuccess:

		httpResponse = HandlePfcpUpdateSuccess(response, smContext)
		smContext.SubPfcpLog.Infoln("Received Successful PFCP modification response from UPF")

	case smf_context.SessionUpdateFailed:

		httpResponse = HandlePfcpUpdateFailure(smContext)
		smContext.SubPfcpLog.Errorln("Request rejected for PFCP modification from UPF,sending modify reject to AMF")

	case smf_context.SessionUpdateTimeout:

		httpResponse = HandlePfcpUpdateTimeout(smContext, smContextRef)
		smContext.SubPfcpLog.Errorln("PFCP modification Request timed out for UPF,sending modify reject to AMF")

	case smf_context.SessionReleaseSuccess:
		httpResponse = HandlePfcpReleaseSuccess(response, smContext)
		smContext.SubPfcpLog.Infoln("Received Successful PFCP deletion response from UPF")

	case smf_context.SessionReleaseTimeout:
		fallthrough
	case smf_context.SessionReleaseFailed:
		smContext.SubPfcpLog.Errorln("PFCP Deletion Request failure for UPF,sending reject response to AMF")
		httpResponse = HandlePfcpReleaseFailure(smContext)
	}

	smContext.SubPfcpLog.Traceln("Out HandlePFCPResp")
	return httpResponse

}

//HandlePfcpUpdateSuccess : Handles PFCP Modification success from UPF
func HandlePfcpUpdateSuccess(response models.UpdateSmContextResponse,
	smContext *smf_context.SMContext) *http_wrapper.Response {

	var httpResponse *http_wrapper.Response
	smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, PFCP Session Update Success")
	smContext.ChangeState(smf_context.Active)
	smContext.SubCtxLog.Traceln("SMContextState Change State: ", smContext.SMContextState.String())
	httpResponse = &http_wrapper.Response{
		Status: http.StatusOK,
		Body:   response,
	}
	return httpResponse
}

//HandlePfcpReleaseSuccess : Handles PFCP Deletion success from UPF
func HandlePfcpReleaseSuccess(response models.UpdateSmContextResponse,
	smContext *smf_context.SMContext) *http_wrapper.Response {

	var httpResponse *http_wrapper.Response
	smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, PFCP Session Release Success")
	smContext.ChangeState(smf_context.InActivePending)
	smContext.SubCtxLog.Traceln("SMContextState Change State: ", smContext.SMContextState.String())
	httpResponse = &http_wrapper.Response{
		Status: http.StatusOK,
		Body:   response,
	}
	return httpResponse
}

//HandlePfcpUpdateFailure : Handles PFCP Modification failure from UPF
func HandlePfcpUpdateFailure(smContext *smf_context.SMContext) *http_wrapper.Response {

	var httpResponse *http_wrapper.Response
	smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, PFCP Session Update Failed")
	smContext.ChangeState(smf_context.Active)
	smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())

	problemDetail := models.ProblemDetails{
		Title:  "PFCP Session Modification Failure",
		Status: http.StatusForbidden,
		Detail: "PFCP Session Modification Failure",
		Cause:  "PFCP_REQUEST_REJECTED",
	}
	// It is just a template
	httpResponse = &http_wrapper.Response{
		Status: http.StatusForbidden,
		Body: models.UpdateSmContextErrorResponse{
			JsonData: &models.SmContextUpdateError{
				Error: &problemDetail,
			},
		}, // Depends on the reason why N4 fail
	}

	return httpResponse
}

//HandlePfcpUpdateTimeout : Handles PFCP Modification timeout from UPF
func HandlePfcpUpdateTimeout(smContext *smf_context.SMContext,
	smContextRef string) *http_wrapper.Response {

	var httpResponse *http_wrapper.Response
	smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, PFCP Session Modification Timeout")

	/* TODO: exact http error response code for this usecase is 504, so relevant cause for
	   this usecase is 500. If it gets added in spec 29.502 new release that can be added
	*/
	problemDetail := models.ProblemDetails{
		Title:  "PFCP Session Modification Timeout",
		Status: http.StatusInternalServerError,
		Detail: "PFCP Session Modification Timeout",
		Cause:  "UPF_NOT_RESPONDING",
	}
	var n1buf, n2buf []byte
	var err error
	if n1buf, err = smf_context.BuildGSMPDUSessionReleaseCommand(smContext); err != nil {
		smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build GSM PDUSessionReleaseCommand failed: %+v", err)
	}

	if n2buf, err = smf_context.BuildPDUSessionResourceReleaseCommandTransfer(smContext); err != nil {
		smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build PDUSessionResourceReleaseCommandTransfer failed: %+v", err)
	}

	smContext.ChangeState(smf_context.PFCPModification)
	smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())

	// It is just a template
	httpResponse = &http_wrapper.Response{
		Status: http.StatusServiceUnavailable,
		Body: models.UpdateSmContextErrorResponse{
			JsonData: &models.SmContextUpdateError{
				Error:        &problemDetail,
				N1SmMsg:      &models.RefToBinaryData{ContentId: smf_context.PDU_SESS_REL_CMD},
				N2SmInfo:     &models.RefToBinaryData{ContentId: smf_context.PDU_SESS_REL_CMD},
				N2SmInfoType: models.N2SmInfoType_PDU_RES_REL_CMD,
			},
			BinaryDataN1SmMessage:     n1buf,
			BinaryDataN2SmInformation: n2buf,
		}, // Depends on the reason why N4 fail
	}

	//Initiating PFCP Deletion request
	ReleaseTunnel(smContext)

	//Deleting SmContext
	HandleNwInitiatedPduSessionRelease(smContextRef)

	return httpResponse
}

//HandlePfcpReleaseFailure : Handles PFCP deletion failure from UPF
func HandlePfcpReleaseFailure(smContext *smf_context.SMContext) *http_wrapper.Response {

	var httpResponse *http_wrapper.Response
	// Update SmContext Request(N1 PDU Session Release Request)
	// Send PDU Session Release Reject
	smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, PFCP Session Release Failed")
	problemDetail := models.ProblemDetails{
		Status: http.StatusInternalServerError,
		Cause:  "SYSTEM_FAILULE",
	}
	httpResponse = &http_wrapper.Response{
		Status: int(problemDetail.Status),
	}
	smContext.ChangeState(smf_context.Active)
	smContext.SubCtxLog.Traceln("PDUSessionSMContextUpdate, SMContextState Change State: ", smContext.SMContextState.String())
	errResponse := models.UpdateSmContextErrorResponse{
		JsonData: &models.SmContextUpdateError{
			Error: &problemDetail,
		},
	}
	if buf, err := smf_context.BuildGSMPDUSessionReleaseReject(smContext); err != nil {
		smContext.SubPduSessLog.Errorf("PDUSessionSMContextUpdate, build GSM PDUSessionReleaseReject failed: %+v", err)
	} else {
		errResponse.BinaryDataN1SmMessage = buf
	}

	errResponse.JsonData.N1SmMsg = &models.RefToBinaryData{ContentId: "PDUSessionReleaseReject"}
	httpResponse.Body = errResponse
	return httpResponse
}
