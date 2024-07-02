// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	mi "github.com/omec-project/metricfunc/pkg/metricinfo"
	"github.com/omec-project/nas/nasMessage"
	"github.com/omec-project/openapi/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
)

var seq uint32

func getSeqNumber() uint32 {
	smfCount := 1
	if smfCountStr, ok := os.LookupEnv("SMF_COUNT"); ok {
		smfCount, _ = strconv.Atoi(smfCountStr)
	}

	seqNum := atomic.AddUint32(&seq, 1) + uint32((smfCount-1)*5000)
	logger.PfcpLog.Debugf("unique seq num: smfCount from os: %v; seqNum %v\n", smfCount, seqNum)
	return seqNum
}

func init() {
	PfcpTxns = make(map[uint32]*smf_context.NodeID)
}

var (
	PfcpTxns    map[uint32]*smf_context.NodeID
	PfcpTxnLock sync.Mutex
)

func FetchPfcpTxn(seqNo uint32) (upNodeID *smf_context.NodeID) {
	PfcpTxnLock.Lock()
	defer PfcpTxnLock.Unlock()
	if upNodeID = PfcpTxns[seqNo]; upNodeID != nil {
		delete(PfcpTxns, seqNo)
	}
	return upNodeID
}

func InsertPfcpTxn(seqNo uint32, upNodeID *smf_context.NodeID) {
	PfcpTxnLock.Lock()
	defer PfcpTxnLock.Unlock()
	PfcpTxns[seqNo] = upNodeID
}

func SendHeartbeatRequest(remoteAddress *net.UDPAddr, upNodeID smf_context.NodeID) error {
	message := BuildPfcpHeartbeatRequest()
	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		sendHeartbeatRequestToAdapter(remoteAddress, message, message.Sequence(), upNodeID)
	} else {
		InsertPfcpTxn(message.Sequence(), &upNodeID)
		if err := udp.SendPfcp(message, remoteAddress); err != nil {
			FetchPfcpTxn(message.Sequence())
			return err
		}
	}
	logger.PfcpLog.Debugf("sent pfcp heartbeat request seq[%d] to NodeID[%s]", message.Sequence(),
		upNodeID.ResolveNodeIdToIp().String())
	return nil
}

func sendHeartbeatRequestToAdapter(remoteAddress *net.UDPAddr, message pfcp_message.Message, sequenceNumber uint32, upNodeID smf_context.NodeID) {
	adapter.InsertPfcpTxn(message.Sequence(), &upNodeID)
	rsp, err := SendPfcpMsgToAdapter(upNodeID, message, remoteAddress)
	if err != nil {
		logger.PfcpLog.Errorf("send pfcp heartbeat msg to upf-adapter error [%v] ", err.Error())
		return
	}
	logger.PfcpLog.Debugf("send pfcp heartbeat response [%v] ", rsp)
	defer rsp.Body.Close()
	if rsp.StatusCode == http.StatusOK {
		pfcpMsgBytes, err := io.ReadAll(rsp.Body)
		if err != nil {
			logger.PfcpLog.Fatalln(err)
		}
		pfcpMsgString := string(pfcpMsgBytes)
		logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)

		pfcpRspMsg, err := pfcp_message.Parse(pfcpMsgBytes)
		if err != nil {
			logger.PfcpLog.Errorf("Parse PFCP message failed: %v", err)
			return
		}
		adapter.HandleAdapterPfcpRsp(pfcpRspMsg)
	}
}

func SendPfcpAssociationSetupRequest(remoteAddress *net.UDPAddr, upNodeID smf_context.NodeID) {
	if *factory.SmfConfig.Configuration.KafkaInfo.EnableKafka {
		// Send Metric event
		upfStatus := mi.MetricEvent{
			EventType: mi.CNfStatusEvt,
			NfStatusData: mi.CNfStatus{
				NfType:   mi.NfTypeUPF,
				NfStatus: mi.NfStatusDisconnected,
				NfName:   string(upNodeID.NodeIdValue),
			},
		}
		metrics.StatWriter.PublishNfStatusEvent(upfStatus)
	}

	if net.IP.Equal(upNodeID.ResolveNodeIdToIp(), net.IPv4zero) {
		logger.PfcpLog.Errorf("PFCP Association Setup Request failed, invalid NodeId: %v", string(upNodeID.NodeIdValue))
		return
	}

	pfcpMsg := BuildPfcpAssociationSetupRequest()

	logger.PfcpLog.Infof("Sent PFCP Association Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())

	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		sendAssociationSetupRequestToAdapter(remoteAddress, pfcpMsg, pfcpMsg.Sequence(), upNodeID)
	} else {
		InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		udp.SendPfcp(pfcpMsg, remoteAddress)
	}
}

func sendAssociationSetupRequestToAdapter(remoteAddress *net.UDPAddr, message pfcp_message.Message, sequenceNumber uint32, upNodeID smf_context.NodeID) {
	rsp, err := SendPfcpMsgToAdapter(upNodeID, message, remoteAddress)
	if err != nil {
		logger.PfcpLog.Errorf("send pfcp association msg to upf-adapter error [%v] ", err.Error())
		return
	}
	logger.PfcpLog.Debugf("send pfcp association response [%v] ", rsp)
	if rsp.StatusCode == http.StatusOK {
		pfcpMsgBytes, err := io.ReadAll(rsp.Body)
		if err != nil {
			logger.PfcpLog.Fatalln(err)
		}
		pfcpMsgString := string(pfcpMsgBytes)
		logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)
		pfcpRspMsg, err := pfcp_message.Parse(pfcpMsgBytes)
		if err != nil {
			logger.PfcpLog.Errorf("Parse PFCP message failed: %v", err)
			return
		}
		adapter.HandleAdapterPfcpRsp(pfcpRspMsg)
	}
}

func SendPfcpAssociationSetupResponse(remoteAddress *net.UDPAddr, cause uint8) {
	pfcpMsg := BuildPfcpAssociationSetupResponse(cause)
	udp.SendPfcp(pfcpMsg, remoteAddress)
	logger.PfcpLog.Infof("Sent PFCP Association Response to NodeID[%s]", remoteAddress.IP.String())
}

func SendPfcpAssociationReleaseResponse(remoteAddress *net.UDPAddr, upNodeID smf_context.NodeID, cause uint8) {
	pfcpMsg := BuildPfcpAssociationReleaseResponse(cause)
	udp.SendPfcp(pfcpMsg, remoteAddress)
	logger.PfcpLog.Infof("Sent PFCP Association Release Response to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
}

func SendPfcpSessionEstablishmentRequest(
	remoteAddress *net.UDPAddr,
	upNodeID smf_context.NodeID,
	ctx *smf_context.SMContext,
	pdrList []*smf_context.PDR,
	farList []*smf_context.FAR,
	barList []*smf_context.BAR,
	qerList []*smf_context.QER,
) {
	message, err := BuildPfcpSessionEstablishmentRequest(upNodeID, ctx, pdrList, farList, barList, qerList)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to build PFCP Session Establishment Request: %v", err)
		return
	}
	logger.PfcpLog.Debugf("in SendPfcpSessionEstablishmentRequest pfcpMsg.CPFSEID.Seid %v\n", message.SEID())
	ip := upNodeID.ResolveNodeIdToIp()

	ctx.SubPduSessLog.Traceln("[SMF] Send SendPfcpSessionEstablishmentRequest")
	ctx.SubPduSessLog.Traceln("Send to addr ", remoteAddress.String())
	logger.PfcpLog.Infof("in SendPfcpSessionEstablishmentRequest fseid %v\n", message.SEID())

	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		sendSessionEstablishmentRequestToAdapter(remoteAddress, message, message.Sequence(), upNodeID)
	} else {
		// What am I loosing by getting rid of this eventData? To validate
		InsertPfcpTxn(message.Sequence(), &upNodeID)
		udp.SendPfcp(message, remoteAddress)
	}
	ctx.SubPfcpLog.Infof("Sent PFCP Session Establish Request to NodeID[%s]", ip.String())
}

func sendSessionEstablishmentRequestToAdapter(remoteAddress *net.UDPAddr, message pfcp_message.Message, sequenceNumber uint32, upNodeID smf_context.NodeID) {
	adapter.InsertPfcpTxn(sequenceNumber, &upNodeID)
	rsp, err := SendPfcpMsgToAdapter(upNodeID, message, remoteAddress)
	if err != nil {
		logger.PfcpLog.Errorf("send pfcp session establish msg to upf-adapter error [%v] ", err.Error())
		HandlePfcpSendError(message, err)
		return
	}
	logger.PfcpLog.Debugf("send pfcp session establish response [%v] ", rsp)
	if rsp.StatusCode == http.StatusOK {
		pfcpMsgBytes, err := io.ReadAll(rsp.Body)
		if err != nil {
			logger.PfcpLog.Fatalln(err)
		}
		pfcpMsgString := string(pfcpMsgBytes)
		logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)
		rspmsg, err := pfcp_message.Parse(pfcpMsgBytes)
		if err != nil {
			logger.PfcpLog.Errorf("Parse PFCP message failed: %v", err)
			return
		}
		adapter.HandleAdapterPfcpRsp(rspmsg)
	} else {
		HandlePfcpSendError(message, fmt.Errorf("send error to upf-adapter [%v]", rsp.StatusCode))
	}
}

func SendPfcpSessionModificationRequest(
	remoteAddress *net.UDPAddr,
	upNodeID smf_context.NodeID,
	ctx *smf_context.SMContext,
	pdrList []*smf_context.PDR,
	farList []*smf_context.FAR,
	barList []*smf_context.BAR,
	qerList []*smf_context.QER,
) (seqNum uint32) {
	pfcpMsg, err := BuildPfcpSessionModificationRequest(upNodeID, ctx, pdrList, farList, barList, qerList)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to build PFCP Session Modification Request: %v", err)
		return 0
	}
	seqNum = getSeqNumber()
	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		sendSessionModificationRequestToAdapter(upNodeID, pfcpMsg, remoteAddress)
	} else {
		InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		udp.SendPfcp(pfcpMsg, remoteAddress) // Again, be careful of what we are getting rid of here
	}
	ctx.SubPfcpLog.Infof("Sent PFCP Session Modify Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
	return seqNum
}

func sendSessionModificationRequestToAdapter(upNodeID smf_context.NodeID, message pfcp_message.Message, upaddr *net.UDPAddr) {
	if rsp, err := SendPfcpMsgToAdapter(upNodeID, message, upaddr); err != nil {
		logger.PfcpLog.Errorf("send pfcp session modify msg to upf-adapter error [%v] ", err.Error())
		return
	} else {
		logger.PfcpLog.Debugf("send pfcp session modify response [%v] ", rsp)
		if rsp.StatusCode == http.StatusOK {
			pfcpMsgBytes, err := io.ReadAll(rsp.Body)
			if err != nil {
				logger.PfcpLog.Fatalln(err)
			}
			pfcpMsgString := string(pfcpMsgBytes)
			logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)
			pfcpRspMsg, err := pfcp_message.Parse(pfcpMsgBytes)
			if err != nil {
				logger.PfcpLog.Errorf("Parse PFCP message failed: %v", err)
				return
			}
			adapter.HandleAdapterPfcpRsp(pfcpRspMsg)
		}
	}
}

func SendPfcpSessionDeletionRequest(upNodeID smf_context.NodeID, ctx *smf_context.SMContext, upfPort uint16) (seqNum uint32) {
	pfcpMsg, err := BuildPfcpSessionDeletionRequest(upNodeID, ctx)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to build PFCP Session Deletion Request: %v", err)
		return 0
	}
	seqNum = getSeqNumber()
	upaddr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: int(upfPort),
	}
	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		sendSessionDeletionRequestToAdapter(upNodeID, pfcpMsg, upaddr)
	} else {
		InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		udp.SendPfcp(pfcpMsg, upaddr) // Again, to validate that we can get rid of eventData
	}
	ctx.SubPfcpLog.Infof("Sent PFCP Session Delete Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
	return seqNum
}

func sendSessionDeletionRequestToAdapter(upNodeID smf_context.NodeID, message pfcp_message.Message, upaddr *net.UDPAddr) {
	rsp, err := SendPfcpMsgToAdapter(upNodeID, message, upaddr)
	if err != nil {
		logger.PfcpLog.Errorf("send pfcp session delete msg to upf-adapter error [%v] ", err.Error())
		return
	}
	logger.PfcpLog.Debugf("send pfcp session delete response [%v] ", rsp)
	if rsp.StatusCode == http.StatusOK {
		pfcpMsgBytes, err := io.ReadAll(rsp.Body)
		if err != nil {
			logger.PfcpLog.Fatalln(err)
		}
		pfcpMsgString := string(pfcpMsgBytes)
		logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)
		pfcpRspMsg, err := pfcp_message.Parse(pfcpMsgBytes)
		if err != nil {
			logger.PfcpLog.Errorf("Parse PFCP message failed: %v", err)
			return
		}
		adapter.HandleAdapterPfcpRsp(pfcpRspMsg)
	}
}

func SendPfcpSessionReportResponse(addr *net.UDPAddr, cause uint8, drobu bool, seqFromUPF uint32, SEID uint64) {
	pfcpMsg := BuildPfcpSessionReportResponse(cause, drobu, seqFromUPF, SEID)
	udp.SendPfcp(pfcpMsg, addr)
	logger.PfcpLog.Infof("Sent PFCP Session Report Response Seq[%d] to NodeID[%s]", seqFromUPF, addr.IP.String())
}

func SendHeartbeatResponse(addr *net.UDPAddr, seq uint32) {
	msg := pfcp_message.NewHeartbeatResponse(
		seq,
		ie.NewRecoveryTimeStamp(udp.ServerStartTime),
	)
	udp.SendPfcp(msg, addr)
	logger.PfcpLog.Infof("Sent PFCP Heartbeat Response Seq[%d] to NodeID[%s]", seq, addr.IP.String())
}

func HandlePfcpSendError(msg pfcp_message.Message, pfcpErr error) {
	logger.PfcpLog.Errorf("send of PFCP msg [%v] failed, %v", msg.MessageTypeName(), pfcpErr.Error())
	metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "Out", "Failure", pfcpErr.Error())

	// Refresh SMF DNS Cache incase of any send failure(includes timeout)
	smf_context.RefreshDnsHostIpCache()

	switch msg.MessageType() {
	case pfcp_message.MsgTypeSessionEstablishmentRequest:
		handleSendPfcpSessEstReqError(msg, pfcpErr)
	case pfcp_message.MsgTypeSessionModificationRequest:
		handleSendPfcpSessModReqError(msg, pfcpErr)
	case pfcp_message.MsgTypeSessionDeletionRequest:
		handleSendPfcpSessRelReqError(msg, pfcpErr)
	default:
		logger.PfcpLog.Errorf("Unable to send PFCP packet type [%v] and content [%v]",
			msg.MessageTypeName(), msg)
	}
}

func handleSendPfcpSessEstReqError(msg pfcp_message.Message, pfcpErr error) {
	// Lets decode the PDU request
	message, ok := msg.(*pfcp_message.SessionEstablishmentRequest)
	if !ok {
		logger.PfcpLog.Errorf("Unable to decode PFCP Session Establishment Request")
		return
	}

	SEID := message.SEID()
	smContext := smf_context.GetSMContextBySEID(SEID)
	smContext.SubPfcpLog.Errorf("PFCP Session Establishment send failure, %v", pfcpErr.Error())
	// N1N2 Request towards AMF
	n1n2Request := models.N1N2MessageTransferRequest{}

	// N1 Container Info
	n1MsgContainer := models.N1MessageContainer{
		N1MessageClass:   "SM",
		N1MessageContent: &models.RefToBinaryData{ContentId: "GSM_NAS"},
	}

	// N1N2 Json Data
	n1n2Request.JsonData = &models.N1N2MessageTransferReqData{PduSessionId: smContext.PDUSessionID}

	if smNasBuf, err := smf_context.BuildGSMPDUSessionEstablishmentReject(smContext,
		nasMessage.Cause5GSMRequestRejectedUnspecified); err != nil {
		smContext.SubPduSessLog.Errorf("Build GSM PDUSessionEstablishmentReject failed: %s", err)
	} else {
		n1n2Request.BinaryDataN1Message = smNasBuf
		n1n2Request.JsonData.N1MessageContainer = &n1MsgContainer
	}

	// Send N1N2 Reject request
	rspData, _, err := smContext.
		CommunicationClient.
		N1N2MessageCollectionDocumentApi.
		N1N2MessageTransfer(context.Background(), smContext.Supi, n1n2Request)
	smContext.ChangeState(smf_context.SmStateInit)
	smContext.SubCtxLog.Traceln("SMContextState Change State: ", smContext.SMContextState.String())
	if err != nil {
		smContext.SubPfcpLog.Warnf("Send N1N2Transfer failed")
	}
	if rspData.Cause == models.N1N2MessageTransferCause_N1_MSG_NOT_TRANSFERRED {
		smContext.SubPfcpLog.Warnf("%v", rspData.Cause)
	}
	smContext.SubPfcpLog.Errorf("PFCP send N1N2Transfer Reject initiated for id[%v], pduSessId[%v]", smContext.Identifier, smContext.PDUSessionID)

	// clear subscriber
	smf_context.RemoveSMContext(smContext.Ref)
}

func handleSendPfcpSessRelReqError(msg pfcp_message.Message, pfcpErr error) {
	message, ok := msg.(*pfcp_message.SessionDeletionRequest)
	if !ok {
		logger.PfcpLog.Errorf("Unable to decode PFCP Session Deletion Request")
		return
	}

	SEID := message.SEID()
	smContext := smf_context.GetSMContextBySEID(SEID)
	if smContext != nil {
		smContext.SubPfcpLog.Errorf("PFCP Session Delete send failure, %v", pfcpErr.Error())
		// Always send success
		smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess
	}
}

func handleSendPfcpSessModReqError(msg pfcp_message.Message, pfcpErr error) {
	message, ok := msg.(*pfcp_message.SessionModificationRequest)
	if !ok {
		logger.PfcpLog.Errorf("Unable to decode PFCP Session Modification Request")
		return
	}

	SEID := message.SEID()
	smContext := smf_context.GetSMContextBySEID(SEID)
	smContext.SubPfcpLog.Errorf("PFCP Session Modification send failure, %v", pfcpErr.Error())

	smContext.SBIPFCPCommunicationChan <- smf_context.SessionUpdateTimeout
}

type UdpPodPfcpMsg struct {
	// message type contains in Msg.Header
	Msg      pfcp_message.Message `json:"pfcpMsg"`
	Addr     *net.UDPAddr         `json:"addr"`
	SmfIp    string               `json:"smfIp"`
	UpNodeID smf_context.NodeID   `json:"upNodeID"`
}

type UdpPodPfcpRspMsg struct {
	// message type contains in Msg.Header
	Msg pfcp_message.Message `json:"msg"`
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

// SendPfcpMsgToAdapter send pfcp msg to upf-adapter in http/json encoded format
func SendPfcpMsgToAdapter(upNodeID smf_context.NodeID, msg pfcp_message.Message, addr *net.UDPAddr) (*http.Response, error) {
	// get IP
	ip_str := GetLocalIP()
	udpPodMsg := &UdpPodPfcpMsg{
		UpNodeID: upNodeID,
		SmfIp:    ip_str,
		Msg:      msg,
		Addr:     addr,
	}
	upfAdpPort := 8090

	udpPodMsgJson, _ := json.Marshal(udpPodMsg)

	logger.PfcpLog.Debugf("json encoded udpPodMsg [%s] ", udpPodMsgJson)

	// change the IP here
	logger.PfcpLog.Debugf("send to http://upf-adapter:%d\n", upfAdpPort)
	requestURL := fmt.Sprintf("http://upf-adapter:%d", upfAdpPort)
	jsonBody := udpPodMsgJson

	bodyReader := bytes.NewReader(jsonBody)
	req, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		logger.PfcpLog.Errorf("client: could not create request: %s\n", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := http.Client{
		Timeout: 30 * time.Second,
	}
	// waiting for http response
	rsp, err := client.Do(req)
	if err != nil {
		logger.PfcpLog.Errorf("client: error making http request: %s\n", err)
		return nil, err
	}

	return rsp, nil
}
