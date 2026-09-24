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

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/consumer"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/omec-project/smf/util"
	mi "github.com/omec-project/util/metricinfo"
	"github.com/wmnsk/go-pfcp/message"
)

var seq uint32

const UPFAdapterURL = "http://upf-adapter:8090"

func getSeqNumber() uint32 {
	smfCount := 1
	var err error
	if smfCountStr, ok := os.LookupEnv("SMF_COUNT"); ok {
		smfCount, err = strconv.Atoi(smfCountStr)
		if err != nil {
			logger.PfcpLog.Errorf("SMF_COUNT env variable is not a number: %v", smfCountStr)
		}
	}

	seqNum := atomic.AddUint32(&seq, 1) + uint32((smfCount-1)*5000)
	logger.PfcpLog.Debugf("unique seq num: smfCount from os: %v; seqNum %v", smfCount, seqNum)
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

func SendHeartbeatRequest(upNodeID smf_context.NodeID, upfPort uint16) error {
	msg := BuildPfcpHeartbeatRequest(getSeqNumber(), udp.GetServerStartTime())
	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: int(upfPort),
	}
	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		adapter.InsertPfcpTxn(msg.Sequence(), &upNodeID)
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, msg, addr, nil, UPFAdapterURL); err != nil {
			logger.PfcpLog.Errorf("send pfcp heartbeat msg to upf-adapter error [%v] ", err.Error())
			return err
		} else {
			logger.PfcpLog.Debugf("send pfcp heartbeat response [%v] ", rsp)
			defer func() {
				if err = rsp.Body.Close(); err != nil {
					logger.PfcpLog.Errorf("close response body failed: %v", err)
				}
			}()
			if rsp.StatusCode == http.StatusOK {
				pfcpMsgBytes, err := io.ReadAll(rsp.Body)
				if err != nil {
					logger.PfcpLog.Fatalln(err)
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)

				pfcpRspMsg, err := message.Parse(pfcpMsgBytes)
				if err != nil {
					logger.PfcpLog.Errorf("parse pfcp heartbeat response failed: %v", err)
					return err
				}
				err = adapter.HandleAdapterPfcpRsp(pfcpRspMsg, nil)
				if err != nil {
					logger.PfcpLog.Errorf("handle adapter pfcp response failed: %v", err)
				}
			}
		}
	} else {
		InsertPfcpTxn(msg.Sequence(), &upNodeID)
		if err := udp.SendPfcp(msg, addr, nil); err != nil {
			FetchPfcpTxn(msg.Sequence())
			return err
		}
	}
	logger.PfcpLog.Debugf("sent pfcp heartbeat request seq[%d] to NodeID[%s]", msg.Sequence(),
		upNodeID.ResolveNodeIdToIp().String())
	return nil
}

func SendPfcpAssociationSetupRequest(upNodeID smf_context.NodeID, upfPort uint16) error {
	if *factory.SmfConfig.Configuration.KafkaInfo.EnableKafka {
		// Send Metric event
		upfStatus := mi.MetricEvent{
			EventType: mi.CNfStatusEvt,
			NfStatusData: mi.CNfStatus{
				NfType:   mi.NfTypeUPF,
				NfStatus: mi.NfStatusDisconnected, NfName: string(upNodeID.NodeIdValue),
			},
		}
		err := metrics.StatWriter.PublishNfStatusEvent(upfStatus)
		if err != nil {
			logger.PfcpLog.Errorf("failed to publish UPF status event: %v", err)
		}
	}

	if net.IP.Equal(upNodeID.ResolveNodeIdToIp(), net.IPv4zero) {
		return fmt.Errorf("PFCP Association Setup Request failed, invalid NodeId: %v", string(upNodeID.NodeIdValue))
	}

	pfcpMsg := BuildPfcpAssociationSetupRequest(getSeqNumber(), udp.GetServerStartTime(), smf_context.SMF_Self().CPNodeID.ResolveNodeIdToIp().String())
	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: int(upfPort),
	}
	logger.PfcpLog.Infof("sent PFCP Association Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())

	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, pfcpMsg, addr, nil, UPFAdapterURL); err != nil {
			logger.PfcpLog.Errorf("send pfcp association msg to upf-adapter error [%v]", err.Error())
			return err
		} else {
			defer func() {
				if closeErr := rsp.Body.Close(); closeErr != nil {
					logger.PfcpLog.Errorf("close response body failed: %v", closeErr)
				}
			}()
			logger.PfcpLog.Debugf("send pfcp association response [%v]", rsp)
			if rsp.StatusCode == http.StatusOK {
				pfcpMsgBytes, err := io.ReadAll(rsp.Body)
				if err != nil {
					logger.PfcpLog.Fatalln(err)
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)
				pfcpRspMsg, err := message.Parse(pfcpMsgBytes)
				if err != nil {
					logger.PfcpLog.Errorf("parse pfcp association response failed: %v", err)
					return err
				}
				err = adapter.HandleAdapterPfcpRsp(pfcpRspMsg, nil)
				if err != nil {
					logger.PfcpLog.Errorf("handle adapter pfcp response failed: %v", err)
				}
			}
		}
	} else {
		InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		err := udp.SendPfcp(pfcpMsg, addr, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func SendPfcpAssociationSetupResponse(upNodeID smf_context.NodeID, cause uint8, upfPort uint16) error {
	pfcpMsg := BuildPfcpAssociationSetupResponse(cause, udp.GetServerStartTime(), smf_context.SMF_Self().CPNodeID.ResolveNodeIdToIp().String())
	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: int(upfPort),
	}
	err := udp.SendPfcp(pfcpMsg, addr, nil)
	if err != nil {
		return err
	}
	logger.PfcpLog.Infof("sent PFCP Association Response to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
	return nil
}

func SendPfcpAssociationReleaseResponse(upNodeID smf_context.NodeID, cause uint8, upfPort uint16) error {
	pfcpMsg := BuildPfcpAssociationReleaseResponse(cause, smf_context.SMF_Self().CPNodeID.ResolveNodeIdToIp().String())
	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: int(upfPort),
	}
	err := udp.SendPfcp(pfcpMsg, addr, nil)
	if err != nil {
		return err
	}
	logger.PfcpLog.Infof("sent PFCP Association Release Response to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
	return nil
}

func SendPfcpSessionEstablishmentRequest(
	upNodeID smf_context.NodeID,
	ctx *smf_context.SMContext,
	pdrList []*smf_context.PDR,
	farList []*smf_context.FAR,
	barList []*smf_context.BAR,
	qerList []*smf_context.QER,
	upfPort uint16,
) error {
	upNodeIDStr := upNodeID.ResolveNodeIdToIp().String()
	pfcpContext, ok := ctx.PFCPContext[upNodeIDStr]
	if !ok {
		return fmt.Errorf("PFCP Context not found for NodeID[%v]", upNodeID)
	}

	nodeIDIPAddress := smf_context.SMF_Self().CPNodeID.ResolveNodeIdToIp()

	pfcpMsg, err := BuildPfcpSessionEstablishmentRequest(
		getSeqNumber(),
		nodeIDIPAddress.String(),
		nodeIDIPAddress,
		pfcpContext.LocalSEID,
		pdrList,
		farList,
		qerList,
	)
	if err != nil {
		return err
	}
	logger.PfcpLog.Debugf("in SendPfcpSessionEstablishmentRequest pfcpMsg.CPFSEID.Seid %v\n", pfcpMsg.SEID())
	ip := upNodeID.ResolveNodeIdToIp()

	upaddr := &net.UDPAddr{
		IP:   ip,
		Port: int(upfPort),
	}
	ctx.SubPduSessLog.Debugln("[SMF] Send SendPfcpSessionEstablishmentRequest")
	ctx.SubPduSessLog.Debugln("send to addr", upaddr.String())
	logger.PfcpLog.Infof("in SendPfcpSessionEstablishmentRequest fseid %v", pfcpMsg.SEID())

	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		adapter.InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, pfcpMsg, upaddr, nil, UPFAdapterURL); err != nil {
			logger.PfcpLog.Errorf("send pfcp session establish msg to upf-adapter error [%v]", err.Error())
			HandlePfcpSendError(pfcpMsg, err)
			return err
		} else {
			defer func() {
				if closeErr := rsp.Body.Close(); closeErr != nil {
					logger.PfcpLog.Errorf("close response body failed: %v", closeErr)
				}
			}()
			logger.PfcpLog.Debugf("send pfcp session establish response [%v]", rsp)
			if rsp.StatusCode == http.StatusOK {
				pfcpMsgBytes, err := io.ReadAll(rsp.Body)
				if err != nil {
					logger.PfcpLog.Fatalln(err)
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)
				pfcpRspMsg, err := message.Parse(pfcpMsgBytes)
				if err != nil {
					logger.PfcpLog.Errorf("parse pfcp session establish response failed: %v", err)
					return err
				}
				eventData := udp.PfcpEventData{LSEID: ctx.PFCPContext[ip.String()].LocalSEID, ErrHandler: HandlePfcpSendError}
				err = adapter.HandleAdapterPfcpRsp(pfcpRspMsg, &eventData)
				if err != nil {
					logger.PfcpLog.Errorf("handle adapter pfcp response failed: %v", err)
				}
			} else {
				// http status !OK
				HandlePfcpSendError(pfcpMsg, fmt.Errorf("send error to upf-adapter [%v]", rsp.StatusCode))
			}
		}
	} else {
		InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		eventData := udp.PfcpEventData{LSEID: ctx.PFCPContext[ip.String()].LocalSEID, ErrHandler: HandlePfcpSendError}
		err := udp.SendPfcp(pfcpMsg, upaddr, eventData)
		if err != nil {
			return err
		}
	}
	ctx.SubPfcpLog.Infof("sent PFCP Session Establish Request to NodeID[%s]", ip.String())
	return nil
}

// SendPfcpSessionModificationRequest sends a modification nothing waits on: an unanswered one is
// logged against its session, and no verdict is queued for it.
func SendPfcpSessionModificationRequest(
	upNodeID smf_context.NodeID,
	ctx *smf_context.SMContext,
	pdrList []*smf_context.PDR,
	farList []*smf_context.FAR,
	barList []*smf_context.BAR,
	qerList []*smf_context.QER,
	removePDR []*smf_context.PDR,
	removeFAR []*smf_context.FAR,
	removeQER []*smf_context.QER,
	upfPort uint16,
) error {
	return sendPfcpSessionModificationRequest(upNodeID, ctx, pdrList, farList, qerList,
		removePDR, removeFAR, removeQER, upfPort, false)
}

// SendAwaitedPfcpSessionModificationRequest sends a modification whose caller then waits on the
// session's PFCP channel, and on the native datapath binds the timeout that answers that wait.
//
// Which sends are awaited is the caller's to say, because the session's state cannot say it.
// Restoration reissues rules to every user plane of a session without waiting, and it can do so
// while a policy update holds the session in SmStatePfcpModify waiting for its own answer; a
// handler that took that state to mean "this request is awaited" answered the policy update with
// the timeout of restoration's request.
func SendAwaitedPfcpSessionModificationRequest(
	upNodeID smf_context.NodeID,
	ctx *smf_context.SMContext,
	pdrList []*smf_context.PDR,
	farList []*smf_context.FAR,
	barList []*smf_context.BAR,
	qerList []*smf_context.QER,
	removePDR []*smf_context.PDR,
	removeFAR []*smf_context.FAR,
	removeQER []*smf_context.QER,
	upfPort uint16,
) error {
	return sendPfcpSessionModificationRequest(upNodeID, ctx, pdrList, farList, qerList,
		removePDR, removeFAR, removeQER, upfPort, true)
}

// The request carries no BARs, so the barList the exported senders accept goes no further.
func sendPfcpSessionModificationRequest(
	upNodeID smf_context.NodeID,
	ctx *smf_context.SMContext,
	pdrList []*smf_context.PDR,
	farList []*smf_context.FAR,
	qerList []*smf_context.QER,
	removePDR []*smf_context.PDR,
	removeFAR []*smf_context.FAR,
	removeQER []*smf_context.QER,
	upfPort uint16,
	awaited bool,
) error {
	seqNum := getSeqNumber()
	upNodeIDStr := upNodeID.ResolveNodeIdToIp().String()
	pfcpContext, ok := ctx.PFCPContext[upNodeIDStr]
	if !ok {
		return fmt.Errorf("PFCP Context not found for NodeID[%s]", upNodeIDStr)
	}
	pfcpMsg, err := BuildPfcpSessionModificationRequest(seqNum, pfcpContext.LocalSEID, pfcpContext.RemoteSEID, smf_context.SMF_Self().CPNodeID.ResolveNodeIdToIp(), pdrList, farList, qerList, removePDR, removeFAR, removeQER)
	if err != nil {
		return err
	}
	nodeIDtoIP := upNodeID.ResolveNodeIdToIp().String()
	upaddr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: int(upfPort),
	}

	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, pfcpMsg, upaddr, nil, UPFAdapterURL); err != nil {
			logger.PfcpLog.Errorf("send pfcp session modify msg to upf-adapter error [%v]", err.Error())
			return err
		} else {
			defer func() {
				if closeErr := rsp.Body.Close(); closeErr != nil {
					logger.PfcpLog.Errorf("close response body failed: %v", closeErr)
				}
			}()
			logger.PfcpLog.Debugf("send pfcp session modify response [%v]", rsp)
			if rsp.StatusCode == http.StatusOK {
				pfcpMsgBytes, err := io.ReadAll(rsp.Body)
				if err != nil {
					logger.PfcpLog.Fatalln(err)
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)
				pfcpRspMsg, err := message.Parse(pfcpMsgBytes)
				if err != nil {
					logger.PfcpLog.Errorf("parse pfcp session modify response failed: %v", err)
					return err
				}
				eventData := udp.PfcpEventData{LSEID: ctx.PFCPContext[nodeIDtoIP].LocalSEID, ErrHandler: HandlePfcpSendError}
				err = adapter.HandleAdapterPfcpRsp(pfcpRspMsg, &eventData)
				if err != nil {
					logger.PfcpLog.Errorf("handle adapter pfcp response failed: %v", err)
				}
			}
		}
	} else {
		InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		eventData := udp.PfcpEventData{LSEID: ctx.PFCPContext[nodeIDtoIP].LocalSEID, ErrHandler: sessionSendErrorHandler(ctx.PFCPContext[nodeIDtoIP].LocalSEID, awaited)}
		err := udp.SendPfcp(pfcpMsg, upaddr, eventData)
		if err != nil {
			logger.PfcpLog.Errorf("send pfcp session modify msg to upf error [%v]", err.Error())
		}
	}
	ctx.SubPfcpLog.Infof("sent PFCP Session Modify Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
	return nil
}

func SendPfcpSessionDeletionRequest(upNodeID smf_context.NodeID, ctx *smf_context.SMContext, upfPort uint16) error {
	seqNum := getSeqNumber()
	upNodeIDStr := upNodeID.ResolveNodeIdToIp().String()
	pfcpContext, ok := ctx.PFCPContext[upNodeIDStr]
	if !ok {
		return fmt.Errorf("PFCP Context not found for NodeID[%s]", upNodeIDStr)
	}
	pfcpMsg := BuildPfcpSessionDeletionRequest(seqNum, pfcpContext.LocalSEID, pfcpContext.RemoteSEID, smf_context.SMF_Self().CPNodeID.ResolveNodeIdToIp())

	upaddr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: int(upfPort),
	}

	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, pfcpMsg, upaddr, nil, UPFAdapterURL); err != nil {
			logger.PfcpLog.Errorf("send pfcp session delete msg to upf-adapter error [%v]", err.Error())
			return err
		} else {
			defer func() {
				if closeErr := rsp.Body.Close(); closeErr != nil {
					logger.PfcpLog.Errorf("close response body failed: %v", closeErr)
				}
			}()
			logger.PfcpLog.Debugf("send pfcp session delete response [%v]", rsp)
			if rsp.StatusCode == http.StatusOK {
				pfcpMsgBytes, err := io.ReadAll(rsp.Body)
				if err != nil {
					logger.PfcpLog.Fatalln(err)
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)
				pfcpRspMsg, err := message.Parse(pfcpMsgBytes)
				if err != nil {
					logger.PfcpLog.Errorf("parse pfcp session delete response failed: %v", err)
					return err
				}
				eventData := udp.PfcpEventData{LSEID: pfcpContext.LocalSEID, ErrHandler: HandlePfcpSendError}
				err = adapter.HandleAdapterPfcpRsp(pfcpRspMsg, &eventData)
				if err != nil {
					logger.PfcpLog.Errorf("handle adapter pfcp response failed: %v", err)
				}
			}
		}
	} else {
		InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		eventData := udp.PfcpEventData{LSEID: pfcpContext.LocalSEID, ErrHandler: sessionSendErrorHandler(pfcpContext.LocalSEID, true)}
		err := udp.SendPfcp(pfcpMsg, upaddr, eventData)
		if err != nil {
			return err
		}
	}

	ctx.SubPfcpLog.Infof("sent PFCP Session Delete Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
	return nil
}

func SendPfcpSessionReportResponse(addr *net.UDPAddr, cause uint8, pfcpSRflag smf_context.PFCPSRRspFlags, seqFromUPF uint32, SEID uint64) error {
	pfcpMsg := BuildPfcpSessionReportResponse(cause, pfcpSRflag.Drobu, seqFromUPF, SEID)
	err := udp.SendPfcp(pfcpMsg, addr, nil)
	if err != nil {
		return err
	}
	logger.PfcpLog.Infof("sent PFCP Session Report Response Seq[%d] to NodeID[%s]", seqFromUPF, addr.IP.String())
	return nil
}

func SendHeartbeatResponse(addr *net.UDPAddr, sequenceNumber uint32) error {
	pfcpMsg := BuildPfcpHeartbeatResponse(sequenceNumber, udp.GetServerStartTime())
	err := udp.SendPfcp(pfcpMsg, addr, nil)
	if err != nil {
		return err
	}
	logger.PfcpLog.Infof("sent PFCP Heartbeat Response Seq[%d] to NodeID[%s]", sequenceNumber, addr.IP.String())
	return nil
}

// sessionSendErrorHandler returns the error handler for a modification or deletion request, bound
// to the session the request was sent for.
//
// The UDP layer reports a failure that happens after the send has returned -- a request that went
// unanswered through every retry, or a write that failed on the transaction's own goroutine -- with
// nothing but the message. These requests carry the user plane's SEID in their header, and
// sessions are found by the SMF's own, so looked up by the header the handler found nothing: the
// exchange waiting on the session's channel was never answered, and a user plane that stopped
// responding left that modification or release waiting for good.
//
// Establishment is deliberately not bound. Its handler, once it can find a session, sends the UE a
// reject and removes the context. That is right for a create that failed and wrong for
// restoration, which reissues establishments for sessions already running -- and for a create the
// procedure's own failure path already does both, so the handler would do them twice. Which of
// those an establishment failure should do is a question for a change of its own.
// sessionSendErrorHandler binds a failed request to its session. awaited says whether the request's
// sender waits on the session's channel for its verdict; a deletion always is.
func sessionSendErrorHandler(localSEID uint64, awaited bool) func(message.Message, error) {
	return func(msg message.Message, err error) {
		handlePfcpSendError(msg, err, localSEID, true, awaited)
	}
}

func HandlePfcpSendError(msg message.Message, pfcpErr error) {
	handlePfcpSendError(msg, pfcpErr, 0, false, true)
}

// handlePfcpSendError reports a failed send. When sessionKnown, localSEID names the session the
// request belonged to; otherwise the handlers find it from the message, as before. A flag rather
// than a zero sentinel, because zero is a SEID the DRSM allocator can hand out.
func handlePfcpSendError(msg message.Message, pfcpErr error, localSEID uint64, sessionKnown, awaited bool) {
	logger.PfcpLog.Errorf("send of PFCP msg [%v] failed, %v",
		msg.MessageTypeName(), pfcpErr.Error())
	metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID,
		msg.MessageTypeName(), "Out", "Failure", pfcpErr.Error())

	// Refresh SMF DNS Cache incase of any send failure(includes timeout)
	smf_context.RefreshDnsHostIpCache()

	switch msg.MessageType() {
	case message.MsgTypeSessionEstablishmentRequest:
		handleSendPfcpSessEstReqError(msg, pfcpErr)
	case message.MsgTypeSessionModificationRequest:
		handleSendPfcpSessModReqError(msg, pfcpErr, localSEID, sessionKnown, awaited)
	case message.MsgTypeSessionDeletionRequest:
		handleSendPfcpSessRelReqError(msg, pfcpErr, localSEID, sessionKnown)
	default:
		logger.PfcpLog.Errorf("unable to send PFCP packet type [%v] and content [%v]",
			msg.MessageTypeName(), msg)
	}
}

func handleSendPfcpSessEstReqError(msg message.Message, pfcpErr error) {
	// Lets decode the PDU request
	pfcpEstReq, ok := msg.(*message.SessionEstablishmentRequest)
	if !ok {
		logger.PfcpLog.Errorf("unable to decode PFCP Session Establishment Request")
		return
	}

	SEID := pfcpEstReq.SEID()
	smContext := smf_context.GetSMContextBySEID(SEID)
	if smContext == nil {
		logger.PfcpLog.Errorf("SMContext not found for SEID[%v]", SEID)
		return
	}
	smContext.SubPfcpLog.Errorf("PFCP Session Establishment send failure, %v", pfcpErr.Error())
	// N1N2 Request towards AMF
	n1n2Request := models.NewN1N2MessageTransferRequest()

	// N1 Container Info
	n1MsgContainer := models.NewN1MessageContainer("SM", models.RefToBinaryData{ContentId: "GSM_NAS"})

	// N1N2 Json Data
	jsonData := models.NewN1N2MessageTransferReqData()
	jsonData.SetPduSessionId(smContext.PDUSessionID)
	n1n2Request.SetJsonData(*jsonData)
	defer util.CleanupMultipartTempFiles(n1n2Request)

	if smNasBuf, err := smf_context.BuildGSMPDUSessionEstablishmentReject(smContext,
		nasMessage.Cause5GSMRequestRejectedUnspecified); err != nil {
		smContext.SubPduSessLog.Errorf("Build GSM PDUSessionEstablishmentReject failed: %s", err)
		smContext.ChangeState(smf_context.SmStateInit)
		smContext.SubCtxLog.Debugln("SMContextState Change State:", smContext.SMContextState.String())
		smf_context.RemoveSMContext(smContext.Ref)
		return
	} else {
		tmpFile, fileErr := util.CreatePayloadTempFile(smNasBuf)
		if fileErr != nil {
			smContext.SubPduSessLog.Errorf("failed to create temp file: %v", fileErr)
			smContext.ChangeState(smf_context.SmStateInit)
			smContext.SubCtxLog.Debugln("SMContextState Change State:", smContext.SMContextState.String())
			smf_context.RemoveSMContext(smContext.Ref)
			return
		} else {
			n1n2Request.SetBinaryDataN1Message(tmpFile)
			jsonData := n1n2Request.GetJsonData()
			jsonData.SetN1MessageContainer(*n1MsgContainer)
			n1n2Request.SetJsonData(jsonData)
		}
	}

	// Send N1N2 Reject request. Hold SMLock across the transfer (AMF re-discovery may
	// mutate AMFProfile/ServingNfId/CommunicationClient) and the state transition so the
	// SMContext stays consistent against concurrent users.
	smContext.SMLock.Lock()
	rspData, err := consumer.SendN1N2TransferWithRediscovery(context.Background(), smContext, n1n2Request)
	smContext.ChangeState(smf_context.SmStateInit)
	smContext.SubCtxLog.Debugln("SMContextState Change State:", smContext.SMContextState.String())
	smContext.SMLock.Unlock()
	if err != nil {
		smContext.SubPfcpLog.Warnln("send N1N2Transfer failed")
	}
	if err == nil && rspData != nil && rspData.GetCause() == models.N1N2MESSAGETRANSFERCAUSE_N1_MSG_NOT_TRANSFERRED {
		smContext.SubPfcpLog.Warnf("%v", rspData.GetCause())
	}
	smContext.SubPfcpLog.Errorf("PFCP send N1N2Transfer Reject initiated for id[%v], pduSessId[%v]", smContext.Identifier, smContext.PDUSessionID)

	// clear subscriber
	smf_context.RemoveSMContext(smContext.Ref)
}

// sessionForFailedRequest finds the session a failed request belonged to: by the SMF's own SEID when
// the caller knew it, and otherwise by the header, which for a modification or deletion carries the
// user plane's and so finds nothing.
func sessionForFailedRequest(msg message.Message, localSEID uint64, sessionKnown bool) *smf_context.SMContext {
	if sessionKnown {
		return smf_context.GetSMContextBySEID(localSEID)
	}

	return smf_context.GetSMContextBySEID(msg.SEID())
}

// answerFailedRequest puts a verdict on the session's channel for a request that will never be
// answered -- if an exchange is waiting for one, and without blocking.
//
// Both halves are the rules the response handlers already follow, and they matter here for the
// first time: these handlers could not find their session before, so whatever they wrote never
// reached anyone. Requests are sent that nobody waits for -- restoration's, and the establishment
// of a second user plane on a session that already has one -- and a verdict written for one of
// those is read by the next unrelated exchange as its own. A blocking write with nobody reading
// parks the UDP goroutine that reported the failure.
func answerFailedRequest(smContext *smf_context.SMContext, waiting bool, verdict smf_context.PFCPSessionResponseStatus) {
	if !waiting {
		smContext.SubPfcpLog.Infof("no exchange is waiting on the PFCP channel; not queueing %v", verdict)

		return
	}

	select {
	case smContext.SBIPFCPCommunicationChan <- verdict:
	default:
		smContext.SubPfcpLog.Warnf("a verdict is already waiting to be read; not queueing %v", verdict)
	}
}

func handleSendPfcpSessRelReqError(msg message.Message, pfcpErr error, localSEID uint64, sessionKnown bool) {
	// Lets decode the PDU request
	if _, ok := msg.(*message.SessionDeletionRequest); !ok {
		logger.PfcpLog.Errorln("unable to decode PFCP Session Deletion Request")
		return
	}

	smContext := sessionForFailedRequest(msg, localSEID, sessionKnown)
	if smContext == nil {
		logger.PfcpLog.Errorf("SMContext not found for failed deletion (local SEID[%v], header SEID[%v])", localSEID, msg.SEID())
		return
	}

	smContext.SubPfcpLog.Errorf("PFCP Session Delete send failure, %v", pfcpErr.Error())

	// Success, as the response handler reports a refused deletion too: a session whose user plane
	// will not confirm the deletion still has to be released here, or it is never released at all.
	answerFailedRequest(smContext,
		smContext.SMContextState == smf_context.SmStatePfcpRelease && !smContext.LocalPurged,
		smf_context.SessionReleaseSuccess)
}

func handleSendPfcpSessModReqError(msg message.Message, pfcpErr error, localSEID uint64, sessionKnown, awaited bool) {
	// Lets decode the PDU request
	if _, ok := msg.(*message.SessionModificationRequest); !ok {
		logger.PfcpLog.Errorln("unable to decode PFCP Session Modification Request")
		return
	}

	smContext := sessionForFailedRequest(msg, localSEID, sessionKnown)
	if smContext == nil {
		logger.PfcpLog.Errorf("SMContext not found for failed modification (local SEID[%v], header SEID[%v])", localSEID, msg.SEID())
		return
	}

	smContext.SubPfcpLog.Errorf("PFCP Session Modification send failure, %v", pfcpErr.Error())

	// Only for a request its sender waits on, and only while the session still waits: the state
	// alone is shared by every modification in flight on the session, awaited or not.
	answerFailedRequest(smContext, awaited && smContext.SMContextState == smf_context.SmStatePfcpModify,
		smf_context.SessionUpdateTimeout)
}

type adapterMessage struct {
	Body []byte `json:"body"`
}

type UdpPodPfcpMsg struct {
	// message type contains in Msg.Header
	Msg      adapterMessage     `json:"pfcpMsg"`
	Addr     *net.UDPAddr       `json:"addr"`
	SmfIp    string             `json:"smfIp"`
	UpNodeID smf_context.NodeID `json:"upNodeID"`
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
func SendPfcpMsgToAdapter(upNodeID smf_context.NodeID, msg message.Message, addr *net.UDPAddr, eventData interface{}, url string) (*http.Response, error) {
	// get IP
	ip_str := GetLocalIP()

	buf := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(buf)
	if err != nil {
		logger.PfcpLog.Errorf("marshal failed: %v", err)
		return nil, err
	}

	udpPodMsg := &UdpPodPfcpMsg{
		UpNodeID: upNodeID,
		SmfIp:    ip_str,
		Msg:      adapterMessage{Body: buf},
		Addr:     addr,
	}

	udpPodMsgJson, err := json.Marshal(udpPodMsg)
	if err != nil {
		logger.PfcpLog.Errorf("json marshal failed: %v", err)
		return nil, err
	}

	logger.PfcpLog.Debugf("json encoded udpPodMsg [%s]", udpPodMsgJson)
	// change the IP here
	logger.PfcpLog.Debugf("send to: %s", url)

	bodyReader := bytes.NewReader(udpPodMsgJson)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bodyReader)
	if err != nil {
		logger.PfcpLog.Errorf("client: could not create request: %s", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := http.Client{
		Timeout: 30 * time.Second,
	}
	// waiting for http response
	rsp, err := client.Do(req)
	if err != nil {
		logger.PfcpLog.Errorf("client: error making http request: %s", err)
		return nil, err
	}

	return rsp, nil
}
