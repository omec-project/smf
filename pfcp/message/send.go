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
	"strconv"
	"sync"
	"time"

	"sync/atomic"

	mi "github.com/omec-project/metricfunc/pkg/metricinfo"
	"github.com/omec-project/nas/nasMessage"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/pfcp"
	"github.com/omec-project/pfcp/pfcpType"
	"github.com/omec-project/pfcp/pfcpUdp"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/msgtypes/pfcpmsgtypes"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/udp"

	// "github.com/omec-project/MongoDBLibrary"
	"os"
)

var seq uint32

func getSeqNumber() uint32 {
	// smfCount := MongoDBLibrary.GetSmfCountFromDb()

	smfCount := 1
	if smfCountStr, ok := os.LookupEnv("SMF_COUNT"); ok {
		smfCount, _ = strconv.Atoi(smfCountStr)
	}

	seqNum := atomic.AddUint32(&seq, 1) + uint32((smfCount-1)*5000)
	logger.PfcpLog.Debugf("unique seq num: smfCount from os: %v; seqNum %v\n", smfCount, seqNum)
	return seqNum
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

func SendHeartbeatRequest(upNodeID pfcpType.NodeID, upfPort uint16) error {
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
		Port: int(upfPort),
	}

	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		adapter.InsertPfcpTxn(message.Header.SequenceNumber, &upNodeID)
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, message, addr, nil); err != nil {
			logger.PfcpLog.Errorf("send pfcp heartbeat msg to upf-adapter error [%v] ", err.Error())
			return err
		} else {
			logger.PfcpLog.Debugf("send pfcp heartbeat response [%v] ", rsp)
			defer rsp.Body.Close()
			if rsp.StatusCode == http.StatusOK {
				pfcpMsgBytes, err := io.ReadAll(rsp.Body)
				if err != nil {
					logger.PfcpLog.Fatalln(err)
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, ", pfcpMsgString)
				pfcpRspMsg := pfcp.Message{}
				json.Unmarshal(pfcpMsgBytes, &pfcpRspMsg)
				adapter.HandleAdapterPfcpRsp(pfcpRspMsg, nil)
			}
		}
	} else {
		InsertPfcpTxn(message.Header.SequenceNumber, &upNodeID)
		if err := udp.SendPfcp(message, addr, nil); err != nil {
			FetchPfcpTxn(message.Header.SequenceNumber)
			return err
		}
	}
	logger.PfcpLog.Debugf("sent pfcp heartbeat request seq[%d] to NodeID[%s]", message.Header.SequenceNumber,
		upNodeID.ResolveNodeIdToIp().String())
	return nil
}

func SendPfcpAssociationSetupRequest(upNodeID pfcpType.NodeID, upfPort uint16) {

	//Send Metric event
	upfStatus := mi.MetricEvent{EventType: mi.CNfStatusEvt,
		NfStatusData: mi.CNfStatus{NfType: mi.NfTypeUPF,
			NfStatus: mi.NfStatusDisconnected, NfName: string(upNodeID.NodeIdValue)}}
	metrics.StatWriter.PublishNfStatusEvent(upfStatus)

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
		Port: int(upfPort),
	}

	logger.PfcpLog.Infof("Sent PFCP Association Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())

	if factory.SmfConfig.Configuration.EnableUpfAdapter {

		if rsp, err := SendPfcpMsgToAdapter(upNodeID, message, addr, nil); err != nil {
			logger.PfcpLog.Errorf("send pfcp association msg to upf-adapter error [%v] ", err.Error())
			return
		} else {
			logger.PfcpLog.Debugf("send pfcp association response [%v] ", rsp)
			if rsp.StatusCode == http.StatusOK {
				pfcpMsgBytes, err := io.ReadAll(rsp.Body)
				if err != nil {
					logger.PfcpLog.Fatalln(err)
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, ", pfcpMsgString)
				pfcpRspMsg := pfcp.Message{}
				json.Unmarshal(pfcpMsgBytes, &pfcpRspMsg)
				adapter.HandleAdapterPfcpRsp(pfcpRspMsg, nil)
			}
		}
	} else {
		InsertPfcpTxn(message.Header.SequenceNumber, &upNodeID)
		udp.SendPfcp(message, addr, nil)
	}
}

func SendPfcpAssociationSetupResponse(upNodeID pfcpType.NodeID, cause pfcpType.Cause, upfPort uint16) {
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
		Port: int(upfPort),
	}

	udp.SendPfcp(message, addr, nil)
	logger.PfcpLog.Infof("Sent PFCP Association Response to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
}

func SendPfcpAssociationReleaseRequest(upNodeID pfcpType.NodeID, upfPort uint16) {
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
		Port: int(upfPort),
	}

	udp.SendPfcp(message, addr, nil)
	logger.PfcpLog.Infof("Sent PFCP Association Release Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
}

func SendPfcpAssociationReleaseResponse(upNodeID pfcpType.NodeID, cause pfcpType.Cause, upfPort uint16) {
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
		Port: int(upfPort),
	}

	udp.SendPfcp(message, addr, nil)
	logger.PfcpLog.Infof("Sent PFCP Association Release Response to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
}

func SendPfcpSessionEstablishmentRequest(
	upNodeID pfcpType.NodeID,
	ctx *smf_context.SMContext,
	pdrList []*smf_context.PDR, farList []*smf_context.FAR, barList []*smf_context.BAR, qerList []*smf_context.QER, upfPort uint16) {
	pfcpMsg, err := BuildPfcpSessionEstablishmentRequest(upNodeID, ctx, pdrList, farList, barList, qerList)
	if err != nil {
		ctx.SubPfcpLog.Errorf("Build PFCP Session Establishment Request failed: %v", err)
		return
	}
	logger.PfcpLog.Debugf("in SendPfcpSessionEstablishmentRequest pfcpMsg.CPFSEID.Seid %v\n", pfcpMsg.CPFSEID.Seid)
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
		Port: int(upfPort),
	}
	ctx.SubPduSessLog.Traceln("[SMF] Send SendPfcpSessionEstablishmentRequest")
	ctx.SubPduSessLog.Traceln("Send to addr ", upaddr.String())
	logger.PfcpLog.Infof("in SendPfcpSessionEstablishmentRequest fseid %v\n", pfcpMsg.CPFSEID.Seid)

	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		adapter.InsertPfcpTxn(message.Header.SequenceNumber, &upNodeID)
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, message, upaddr, nil); err != nil {
			logger.PfcpLog.Errorf("send pfcp session establish msg to upf-adapter error [%v] ", err.Error())
			HandlePfcpSendError(&message, err)
			return
		} else {
			logger.PfcpLog.Debugf("send pfcp session establish response [%v] ", rsp)
			if rsp.StatusCode == http.StatusOK {
				pfcpMsgBytes, err := io.ReadAll(rsp.Body)
				if err != nil {
					logger.PfcpLog.Fatalln(err)
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, ", pfcpMsgString)
				pfcpRspMsg := pfcp.Message{}
				json.Unmarshal(pfcpMsgBytes, &pfcpRspMsg)
				eventData := pfcpUdp.PfcpEventData{LSEID: ctx.PFCPContext[ip.String()].LocalSEID, ErrHandler: HandlePfcpSendError}
				adapter.HandleAdapterPfcpRsp(pfcpRspMsg, &eventData)
			} else {
				//http status !OK
				HandlePfcpSendError(&message, fmt.Errorf("send error to upf-adapter [%v]", rsp.StatusCode))
			}
		}
	} else {
		InsertPfcpTxn(message.Header.SequenceNumber, &upNodeID)
		eventData := pfcpUdp.PfcpEventData{LSEID: ctx.PFCPContext[ip.String()].LocalSEID, ErrHandler: HandlePfcpSendError}
		udp.SendPfcp(message, upaddr, eventData)
	}
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
	pdrList []*smf_context.PDR, farList []*smf_context.FAR, barList []*smf_context.BAR, qerList []*smf_context.QER, upfPort uint16) (seqNum uint32) {
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
		Port: int(upfPort),
	}

	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, message, upaddr, nil); err != nil {
			logger.PfcpLog.Errorf("send pfcp session modify msg to upf-adapter error [%v] ", err.Error())
			return 0
		} else {
			logger.PfcpLog.Debugf("send pfcp session modify response [%v] ", rsp)
			if rsp.StatusCode == http.StatusOK {
				pfcpMsgBytes, err := io.ReadAll(rsp.Body)
				if err != nil {
					logger.PfcpLog.Fatalln(err)
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, ", pfcpMsgString)
				pfcpRspMsg := pfcp.Message{}
				json.Unmarshal(pfcpMsgBytes, &pfcpRspMsg)
				eventData := pfcpUdp.PfcpEventData{LSEID: ctx.PFCPContext[nodeIDtoIP].LocalSEID, ErrHandler: HandlePfcpSendError}
				adapter.HandleAdapterPfcpRsp(pfcpRspMsg, &eventData)
			}
		}
	} else {
		InsertPfcpTxn(message.Header.SequenceNumber, &upNodeID)
		eventData := pfcpUdp.PfcpEventData{LSEID: ctx.PFCPContext[nodeIDtoIP].LocalSEID, ErrHandler: HandlePfcpSendError}

		udp.SendPfcp(message, upaddr, eventData)
	}
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

func SendPfcpSessionDeletionRequest(upNodeID pfcpType.NodeID, ctx *smf_context.SMContext, upfPort uint16) (seqNum uint32) {
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
		Port: int(upfPort),
	}

	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, message, upaddr, nil); err != nil {
			logger.PfcpLog.Errorf("send pfcp session delete msg to upf-adapter error [%v] ", err.Error())
			return 0
		} else {

			logger.PfcpLog.Debugf("send pfcp session delete response [%v] ", rsp)
			if rsp.StatusCode == http.StatusOK {
				pfcpMsgBytes, err := io.ReadAll(rsp.Body)
				if err != nil {
					logger.PfcpLog.Fatalln(err)
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, ", pfcpMsgString)
				pfcpRspMsg := pfcp.Message{}
				json.Unmarshal(pfcpMsgBytes, &pfcpRspMsg)
				eventData := pfcpUdp.PfcpEventData{LSEID: ctx.PFCPContext[nodeIDtoIP].LocalSEID, ErrHandler: HandlePfcpSendError}
				adapter.HandleAdapterPfcpRsp(pfcpRspMsg, &eventData)
			}
		}
	} else {
		InsertPfcpTxn(message.Header.SequenceNumber, &upNodeID)
		eventData := pfcpUdp.PfcpEventData{LSEID: ctx.PFCPContext[nodeIDtoIP].LocalSEID, ErrHandler: HandlePfcpSendError}

		udp.SendPfcp(message, upaddr, eventData)
	}

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

func SendPfcpSessionReportResponse(addr *net.UDPAddr, cause pfcpType.Cause, pfcpSRflag pfcpType.PFCPSRRspFlags, seqFromUPF uint32, SEID uint64) {
	pfcpMsg, err := BuildPfcpSessionReportResponse(cause, pfcpSRflag)
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
	smContext.ChangeState(smf_context.SmStateInit)
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
	if smContext != nil {
		smContext.SubPfcpLog.Errorf("PFCP Session Delete send failure, %v", pfcpErr.Error())
		//Always send success
		smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess
	}
}

func handleSendPfcpSessModReqError(msg *pfcp.Message, pfcpErr error) {
	//Lets decode the PDU request
	pfcpModReq, _ := msg.Body.(pfcp.PFCPSessionModificationRequest)

	SEID := pfcpModReq.CPFSEID.Seid
	smContext := smf_context.GetSMContextBySEID(SEID)
	smContext.SubPfcpLog.Errorf("PFCP Session Modification send failure, %v", pfcpErr.Error())

	smContext.SBIPFCPCommunicationChan <- smf_context.SessionUpdateTimeout
}

type UdpPodPfcpMsg struct {
	SmfIp    string          `json:"smfIp"`
	UpNodeID pfcpType.NodeID `json:"upNodeID"`
	// message type contains in Msg.Header
	Msg  pfcp.Message `json:"pfcpMsg"`
	Addr *net.UDPAddr `json:"addr"`
}

type UdpPodPfcpRspMsg struct {
	// message type contains in Msg.Header
	Msg pfcp.Message `json:"msg"`
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
func SendPfcpMsgToAdapter(upNodeID pfcpType.NodeID, msg pfcp.Message, addr *net.UDPAddr, eventData interface{}) (*http.Response, error) {

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
	jsonBody := []byte(udpPodMsgJson)

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
