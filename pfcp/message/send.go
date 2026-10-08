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

func SendHeartbeatRequest(upNodeID smf_context.NodeID, upfPort uint16) (err error) {
	msg := BuildPfcpHeartbeatRequest(getSeqNumber(), udp.GetServerStartTime())
	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: int(upfPort),
	}
	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		adapter.InsertPfcpTxn(msg.Sequence(), &upNodeID)

		// The entry is consumed by the response handler, so a heartbeat that fails before one is
		// dispatched takes it back here. The native branch does the same with FetchPfcpTxn; this
		// one left an entry behind on every failing exit, one per heartbeat period for as long as
		// the adapter kept refusing.
		defer func() {
			if err != nil {
				adapter.FetchPfcpTxn(msg.Sequence())
			}
		}()

		if rsp, err := SendPfcpMsgToAdapter(upNodeID, msg, addr, nil, UPFAdapterURL); err != nil {
			logger.PfcpLog.Errorf("send pfcp heartbeat msg to upf-adapter error [%v] ", err.Error())
			// Counted here as on the native branch: in adapter mode the exchange is synchronous, so
			// there is no transaction goroutine to report an asynchronous failure, and nothing else
			// books this one. Without it, removing the aggregate heartbeat metric in heartbeatUpf
			// would leave adapter-mode heartbeat failures uncounted entirely.
			reportSendFailure(msg, err)
			return err
		} else {
			logger.PfcpLog.Debugf("send pfcp heartbeat response [%v] ", rsp)
			defer func() {
				if closeErr := rsp.Body.Close(); closeErr != nil {
					logger.PfcpLog.Errorf("close response body failed: %v", closeErr)
				}
			}()
			pfcpRspMsg, err := adapterReply(rsp, "heartbeat")
			if err != nil {
				logger.PfcpLog.Errorf("pfcp heartbeat not answered: %v", err)
				reportSendFailure(msg, err)

				return err
			}

			if err = adapter.HandleAdapterPfcpRsp(pfcpRspMsg, nil); err != nil {
				logger.PfcpLog.Errorf("handle adapter pfcp response failed: %v", err)
				reportSendFailure(msg, err)

				return fmt.Errorf("handling the adapter's response: %w", err)
			}
		}
	} else {
		InsertPfcpTxn(msg.Sequence(), &upNodeID)
		if err := udp.SendPfcp(msg, addr, nil); err != nil {
			// Counted here: a synchronous send failure never reaches startTxLifeCycle, so nothing
			// else calls this for it.
			reportSendFailure(msg, err)

			FetchPfcpTxn(msg.Sequence())
			return err
		}
	}
	logger.PfcpLog.Debugf("sent pfcp heartbeat request seq[%d] to NodeID[%s]", msg.Sequence(),
		upNodeID.ResolveNodeIdToIp().String())
	return nil
}

// adapterReply takes the user plane's answer out of the adapter's reply to a node-level request.
//
// Separated from the sends for the same reason handleAdapterModificationResponse is: the refusal
// is otherwise reachable only through a live adapter. A status other than OK means the adapter did
// not deliver the request, so nothing reached the user plane and no answer is coming -- which is a
// failure to report, not a message to dispatch. Both the heartbeat and the association setup fell
// through to their success return on one. And the heartbeat caller counts only failures it is told
// about toward declaring a user plane lost, so a refusal reported as success was also one the
// liveness check never saw.
//
// A reply that stops early is returned, not fatal: it is one request's failure, and ending the
// process takes every other session with it.
func adapterReply(rsp *http.Response, what string) (message.Message, error) {
	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upf adapter refused the %s: %s", what, rsp.Status)
	}

	pfcpMsgBytes, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading the adapter's %s reply: %w", what, err)
	}

	logger.PfcpLog.Debugf("pfcp rsp status ok, %s", string(pfcpMsgBytes))

	pfcpRspMsg, err := message.Parse(pfcpMsgBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the adapter's %s reply: %w", what, err)
	}

	return pfcpRspMsg, nil
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
			// Counted here as on the native branch and the heartbeat adapter path: the adapter
			// exchange is synchronous, so no transaction goroutine reports it, and nothing else does.
			reportSendFailure(pfcpMsg, err)
			return err
		} else {
			defer func() {
				if closeErr := rsp.Body.Close(); closeErr != nil {
					logger.PfcpLog.Errorf("close response body failed: %v", closeErr)
				}
			}()
			logger.PfcpLog.Debugf("send pfcp association response [%v]", rsp)
			// A refusal used to be reported as a sent request, so the caller marked the user plane
			// as setting up and waited the full association timeout for a response that could not
			// come. As an error it stays NotAssociated and is retried on the next probe.
			pfcpRspMsg, err := adapterReply(rsp, "association setup")
			if err != nil {
				logger.PfcpLog.Errorf("pfcp association setup not answered: %v", err)
				reportSendFailure(pfcpMsg, err)

				return err
			}

			if err = adapter.HandleAdapterPfcpRsp(pfcpRspMsg, nil); err != nil {
				logger.PfcpLog.Errorf("handle adapter pfcp response failed: %v", err)
				reportSendFailure(pfcpMsg, err)

				return fmt.Errorf("handling the adapter's response: %w", err)
			}
		}
	} else {
		InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		err := udp.SendPfcp(pfcpMsg, addr, nil)
		if err != nil {
			reportSendFailure(pfcpMsg, err)

			// A synchronous send failure never reaches startTxLifeCycle, so nothing will ever consume
			// the txn inserted above; remove it here as the heartbeat and session request paths do, so
			// a failed association attempt does not leak one PfcpTxns entry per try.
			FetchPfcpTxn(pfcpMsg.Sequence())
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
		reportSendFailure(pfcpMsg, err)

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
		reportSendFailure(pfcpMsg, err)

		return err
	}
	logger.PfcpLog.Infof("sent PFCP Association Release Response to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
	return nil
}

func SendPfcpSessionEstablishmentRequest(
	upNodeID smf_context.NodeID,
	ctx *smf_context.SMContext,
	pendingKey string,
	pdrList []*smf_context.PDR,
	farList []*smf_context.FAR,
	barList []*smf_context.BAR,
	qerList []*smf_context.QER,
	upfPort uint16,
) (err error) {
	// The request either goes out -- in which case a response handler answers the session -- or it
	// does not, and nothing else will. The caller waits on the session's PFCP channel whatever this
	// returns, so every failing exit is answered here. Registered before the first of them, which is
	// the guard below: a deferred call does not run for a return that precedes it.
	//
	// For a create, this UPF is one entry of a PendingUPF batch, so a failure is folded into that
	// batch and the SessionEstablishFailed verdict queued only once the batch drains -- never
	// immediately. A synchronous failure on one UPF of a multi-UPF create must not roll the whole
	// create back while the other establishment requests are still in flight: an accepted branch
	// would then be stranded, its UPF session never deleted. This mirrors establishmentSendErrorHandler,
	// which folds an asynchronous (transaction-timeout) failure into the same batch.
	//
	// Before the local SEID is known -- the PFCPContext lookup below failed -- the failure cannot be
	// keyed by SEID, but SendPFCPRules added this UPF to PendingUPF under the same missing-context
	// condition, so the batch entry is drained by pendingKey (the exact key the caller registered)
	// instead. Only if that key is in no batch (a lone create-pending session, or a restoration that
	// never populated PendingUPF) is the waiter answered directly, so a missing-context failure can no
	// longer wake the create FSM before the rest of the batch completes.
	var localSEID uint64
	var haveLocalSEID bool
	defer func() {
		if err == nil {
			return
		}
		if haveLocalSEID {
			foldEstablishmentFailureIntoBatch(ctx, localSEID)
		} else if !foldEstablishmentFailureByKey(ctx, pendingKey) {
			answerTheWaitingSession(ctx, awaitingEstablishment, smf_context.SessionEstablishFailed)
		}
	}()

	upNodeIDStr := upNodeID.ResolveNodeIdToIp().String()
	pfcpContext, ok := ctx.PFCPContext[upNodeIDStr]
	if !ok {
		return fmt.Errorf("PFCP Context not found for NodeID[%v]", upNodeID)
	}
	localSEID = pfcpContext.LocalSEID
	haveLocalSEID = true

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

		// Consumed by the response handler; taken back here when no response is dispatched, as
		// on the heartbeat path. A handler that fetched it and then failed leaves nothing to take.
		defer func() {
			if err != nil {
				adapter.FetchPfcpTxn(pfcpMsg.Sequence())
			}
		}()

		// Failures on this branch are reported through reportSendFailure, not HandlePfcpSendError.
		// Its session handling finds the session by the request's header SEID, and an establishment
		// carries zero there -- a local SEID the allocator can hand out, so it could reject and
		// remove a different, live session. The deferred answer above tells this session, and the
		// procedure's own failure path sends the reject and removes the context.
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, pfcpMsg, upaddr, nil, UPFAdapterURL); err != nil {
			logger.PfcpLog.Errorf("send pfcp session establish msg to upf-adapter error [%v]", err.Error())
			reportSendFailure(pfcpMsg, err)
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
					// Returned, not fatal. A reply that stops early is one request's failure, and
					// ending the process takes every other session with it -- including, on the
					// session paths, the deferred answer that would have released this one. Counted
					// here as the other adapter reply failures are.
					readErr := fmt.Errorf("reading the adapter's reply: %w", err)
					reportSendFailure(pfcpMsg, readErr)
					return readErr
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)
				pfcpRspMsg, err := message.Parse(pfcpMsgBytes)
				if err != nil {
					logger.PfcpLog.Errorf("parse pfcp session establish response failed: %v", err)
					reportSendFailure(pfcpMsg, err)
					return err
				}
				eventData := udp.PfcpEventData{LSEID: localSEID, ErrHandler: HandlePfcpSendError}
				if err = adapter.HandleAdapterPfcpRsp(pfcpRspMsg, &eventData); err != nil {
					// Dispatching is what puts the verdict on the session's PFCP channel, so a
					// dispatch that failed is a request with no answer coming. Returned, and the
					// session answered by the deferred call above.
					logger.PfcpLog.Errorf("handle adapter pfcp response failed: %v", err)
					reportSendFailure(pfcpMsg, err)

					return fmt.Errorf("handling the adapter's response: %w", err)
				}
			} else {
				// The adapter refused the request, so it never reached the user plane. Reported as
				// a failure rather than returning nil: this said the establishment had been sent,
				// and the session then waited for a response to a request that does not exist.
				sendErr := fmt.Errorf("send error to upf-adapter [%v]", rsp.StatusCode)
				reportSendFailure(pfcpMsg, sendErr)

				return sendErr
			}
		}
	} else {
		InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		// Bound to this session's local SEID so an asynchronous establishment failure (a transaction
		// timeout) can drain this UPF from the create's PendingUPF batch -- the request header SEID is 0,
		// so nothing else can identify the session on timeout. See establishmentSendErrorHandler. Taken
		// from the context validated at function entry, not re-indexed by a freshly resolved IP: for an
		// FQDN UPF the periodic DNS refresh can move the address between resolutions, and PFCPContext
		// keyed by the new address returns nil -- dereferencing it for LocalSEID would panic.
		eventData := udp.PfcpEventData{LSEID: localSEID, ErrHandler: establishmentSendErrorHandler(localSEID)}
		err := udp.SendPfcp(pfcpMsg, upaddr, eventData)
		if err != nil {
			// Counted here: a synchronous send failure never reaches startTxLifeCycle, so nothing
			// else calls this for it.
			reportSendFailure(pfcpMsg, err)

			// The entry is consumed by the response, and a request that never went out has none.
			FetchPfcpTxn(pfcpMsg.Sequence())

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

	// The builder marks every rule it is handed as applied while it builds, so a request that then
	// fails to leave the SMF is put back through this. Without it, "not sent" was true of the wire
	// and false of the session: the rules read as applied, the user plane had never received them,
	// and the next modification -- which sends only rules not yet applied -- skipped them for good.
	restoreRuleStates := snapshotRuleStates(pdrList, farList, qerList)

	pfcpMsg, err := BuildPfcpSessionModificationRequest(seqNum, pfcpContext.LocalSEID, pfcpContext.RemoteSEID, smf_context.SMF_Self().CPNodeID.ResolveNodeIdToIp(), pdrList, farList, qerList, removePDR, removeFAR, removeQER)
	if err != nil {
		restoreRuleStates()

		return err
	}
	upaddr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: int(upfPort),
	}

	// The local SEID is taken from the context validated above, not re-indexed by a freshly resolved
	// IP: for an FQDN UPF the periodic DNS refresh can move the address between resolutions, and
	// PFCPContext keyed by the new address returns nil -- dereferencing it for LocalSEID would panic.
	localSEID := pfcpContext.LocalSEID

	if factory.SmfConfig.Configuration.EnableUpfAdapter {
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, pfcpMsg, upaddr, nil, UPFAdapterURL); err != nil {
			logger.PfcpLog.Errorf("send pfcp session modify msg to upf-adapter error [%v]", err.Error())
			// Counted here as on the native branch: the adapter POST failed, so the request never
			// reached the user plane and no transaction goroutine will report it.
			reportSendFailure(pfcpMsg, err)
			return err
		} else {
			defer func() {
				if closeErr := rsp.Body.Close(); closeErr != nil {
					logger.PfcpLog.Errorf("close response body failed: %v", closeErr)
				}
			}()
			logger.PfcpLog.Debugf("send pfcp session modify response [%v]", rsp)

			if err := handleAdapterModificationResponse(rsp, localSEID); err != nil {
				// The adapter accepted the POST but rejected the status/body/message or could not
				// dispatch the response, so this N4 exchange failed with no response coming. Counted
				// here, as the heartbeat/association adapter paths count their reply failures.
				reportSendFailure(pfcpMsg, err)
				return err
			}
		}
	} else {
		InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		eventData := udp.PfcpEventData{LSEID: localSEID, ErrHandler: sessionSendErrorHandler(localSEID, awaited)}
		if err := udp.SendPfcp(pfcpMsg, upaddr, eventData); err != nil {
			// Reported here, not just logged: a synchronous send failure never reaches
			// startTxLifeCycle, so nothing else counts it as a failure or refreshes the DNS cache.
			reportSendFailure(pfcpMsg, err)

			// The timeout that would otherwise end the caller's wait is raised by the transaction
			// this send failed to create, so there is nothing left to answer with. The bookkeeping
			// entry goes with it -- though only for tidiness: the modification response handler
			// correlates by SEID and never reads this map, so the entry the line above makes is
			// unread on the success path too.
			FetchPfcpTxn(pfcpMsg.Sequence())
			restoreRuleStates()

			return err
		}
	}
	ctx.SubPfcpLog.Infof("sent PFCP Session Modify Request to NodeID[%s]", upNodeID.ResolveNodeIdToIp().String())
	return nil
}

// handleAdapterModificationResponse takes the user plane's answer out of the adapter's reply and
// dispatches it.
//
// Separated from the send so that the refusal below can be exercised: in this mode the user
// plane's response arrives in the body, so a status other than OK is not a slow answer -- it is
// the only answer there will be. Returning nil there left the caller waiting on
// SBIPFCPCommunicationChan for a response nothing would deliver.
func handleAdapterModificationResponse(rsp *http.Response, localSEID uint64) error {
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("upf adapter did not accept the session modification: %s", rsp.Status)
	}

	pfcpMsgBytes, err := io.ReadAll(rsp.Body)
	if err != nil {
		// Returned, not fatal. A body that stops early is a failed request, and the SMF has other
		// sessions: ending the process over one truncated read takes them all down with it. The
		// caller answers this the same way it answers a refusal.
		logger.PfcpLog.Errorf("reading the adapter's session modify response failed: %v", err)

		return fmt.Errorf("reading the adapter's session modify response: %w", err)
	}

	logger.PfcpLog.Debugf("pfcp rsp status ok, %s", string(pfcpMsgBytes))

	pfcpRspMsg, err := message.Parse(pfcpMsgBytes)
	if err != nil {
		logger.PfcpLog.Errorf("parse pfcp session modify response failed: %v", err)

		return err
	}

	eventData := udp.PfcpEventData{LSEID: localSEID, ErrHandler: HandlePfcpSendError}
	if err = adapter.HandleAdapterPfcpRsp(pfcpRspMsg, &eventData); err != nil {
		// Returned, not just logged. Dispatching the response is what eventually puts the verdict
		// on the session's PFCP channel, so a dispatch that failed leaves nothing to signal it --
		// and the caller, which waits on that channel, would wait for an answer that cannot come.
		// Its callers already treat a send that did not happen as a failed modification rather
		// than waiting, and this is the same thing one step later.
		//
		// What that makes an error here mean, for anyone changing HandleAdapterPfcpRsp: no verdict
		// is coming. A handler that signalled the channel and then failed would break that -- the
		// caller would report the modification failed while its answer sat in a channel of
		// capacity one, for the next exchange on that session to read as its own.
		logger.PfcpLog.Errorf("handle adapter pfcp response failed: %v", err)

		return fmt.Errorf("handling the adapter's session modify response: %w", err)
	}

	return nil
}

func SendPfcpSessionDeletionRequest(upNodeID smf_context.NodeID, ctx *smf_context.SMContext, upfPort uint16) (err error) {
	// As on the establishment path: a failing exit is a request no response handler will answer,
	// and the release waits on the session's PFCP channel whatever this returns. Registered before
	// the guard below, which is one of those exits.
	defer func() {
		if err != nil {
			answerTheWaitingSession(ctx, awaitingRelease, smf_context.SessionReleaseSuccess)
		}
	}()

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
		// As on the establishment path, failures here are reported without HandlePfcpSendError:
		// a deletion's header carries the user plane's SEID, and the handler looks it up among the
		// SMF's own, so it could answer another session's release. The deferred answer above
		// answers this one.
		if rsp, err := SendPfcpMsgToAdapter(upNodeID, pfcpMsg, upaddr, nil, UPFAdapterURL); err != nil {
			logger.PfcpLog.Errorf("send pfcp session delete msg to upf-adapter error [%v]", err.Error())
			// Counted here, as the other adapter failure exits of this function already are: the
			// adapter POST failed, so nothing else books it. The deferred answer above releases the
			// waiting session; this only records the metric.
			reportSendFailure(pfcpMsg, err)
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
					// Returned, not fatal. A reply that stops early is one request's failure, and
					// ending the process takes every other session with it -- including, on the
					// session paths, the deferred answer that would have released this one. Counted
					// here as the other adapter reply failures are.
					readErr := fmt.Errorf("reading the adapter's reply: %w", err)
					reportSendFailure(pfcpMsg, readErr)
					return readErr
				}
				pfcpMsgString := string(pfcpMsgBytes)
				logger.PfcpLog.Debugf("pfcp rsp status ok, %s", pfcpMsgString)
				pfcpRspMsg, err := message.Parse(pfcpMsgBytes)
				if err != nil {
					logger.PfcpLog.Errorf("parse pfcp session delete response failed: %v", err)
					reportSendFailure(pfcpMsg, err)
					return err
				}
				eventData := udp.PfcpEventData{LSEID: pfcpContext.LocalSEID, ErrHandler: HandlePfcpSendError}
				if err = adapter.HandleAdapterPfcpRsp(pfcpRspMsg, &eventData); err != nil {
					// Dispatching is what puts the verdict on the session's PFCP channel, so a
					// dispatch that failed is a request with no answer coming. Returned, and the
					// session answered by the deferred call above.
					logger.PfcpLog.Errorf("handle adapter pfcp response failed: %v", err)
					reportSendFailure(pfcpMsg, err)

					return fmt.Errorf("handling the adapter's response: %w", err)
				}
			} else {
				// The adapter refused the request. There was no branch here at all, so a refusal
				// fell through to the success return: the release reported that the deletion had
				// been sent and then waited for a response to a request that does not exist.
				sendErr := fmt.Errorf("send error to upf-adapter [%v]", rsp.StatusCode)
				reportSendFailure(pfcpMsg, sendErr)

				return sendErr
			}
		}
	} else {
		InsertPfcpTxn(pfcpMsg.Sequence(), &upNodeID)
		eventData := udp.PfcpEventData{LSEID: pfcpContext.LocalSEID, ErrHandler: sessionSendErrorHandler(pfcpContext.LocalSEID, true)}
		err := udp.SendPfcp(pfcpMsg, upaddr, eventData)
		if err != nil {
			// Counted here: a synchronous send failure never reaches startTxLifeCycle, so nothing
			// else calls this for it.
			reportSendFailure(pfcpMsg, err)

			// Taken back as on the modification path. No response handler reads this entry, for a
			// deletion that was answered either, so this only stops a failing send adding to it.
			FetchPfcpTxn(pfcpMsg.Sequence())

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
		reportSendFailure(pfcpMsg, err)

		return err
	}
	logger.PfcpLog.Infof("sent PFCP Session Report Response Seq[%d] to NodeID[%s]", seqFromUPF, addr.IP.String())
	return nil
}

func SendHeartbeatResponse(addr *net.UDPAddr, sequenceNumber uint32) error {
	pfcpMsg := BuildPfcpHeartbeatResponse(sequenceNumber, udp.GetServerStartTime())
	err := udp.SendPfcp(pfcpMsg, addr, nil)
	if err != nil {
		reportSendFailure(pfcpMsg, err)

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
// sessionSendErrorHandler binds a failed request to its session. awaited says whether the request's
// sender waits on the session's channel for its verdict; a deletion always is.
func sessionSendErrorHandler(localSEID uint64, awaited bool) func(message.Message, error) {
	return func(msg message.Message, err error) {
		handlePfcpSendError(msg, err, localSEID, true, awaited)
	}
}

// establishmentSendErrorHandler binds a create's establishment request to its session by the SMF's
// own local SEID, so an asynchronous send failure -- a transaction timeout, or a write that failed on
// the transaction goroutine -- can be folded into the create's PendingUPF batch as this UPF's failed
// verdict. BuildPfcpSessionEstablishmentRequest sets the header SEID to 0, so the request carries no
// session identity of its own (this is why establishment cannot use sessionSendErrorHandler, which
// finds a modification/deletion by that header SEID); without the bound local SEID the handler could
// not find the context, and without feeding the batch, the entry SendPFCPRules added for this UPF
// would never clear and the create FSM's blocking receive on SBIPFCPCommunicationChan would hang
// forever if this UPF stopped responding.
//
// It reports the N4 Out/Failure metric (and DNS refresh) through reportSendFailure, then aggregates a
// failed response for this UPF and, when that drains the batch, queues the SessionEstablishFailed
// verdict. It deliberately does not reject the UE or remove the context: once the verdict is read the
// create procedure's own failure path (the FSM's create-failure handler) does both, and doing them
// here too would double them -- the reason establishment was previously left unbound. For a
// restoration establishment, which reuses this send path for a session already running and is not
// tracked in PendingUPF, AggregateEstablishmentResponse returns tracked=false, so this reports the
// failure and changes no batch or channel state.
//
// It also consumes the seq->NodeID entry InsertPfcpTxn added for this request, exactly as the
// synchronous failure path in SendPfcpSessionEstablishmentRequest does. The UDP transaction has
// already been removed by the time this asynchronous handler runs, so no later response will arrive
// to consume the entry through FetchPfcpTxn; without this, every establishment to an unreachable UPF
// would leak one PfcpTxns entry.
func establishmentSendErrorHandler(localSEID uint64) func(message.Message, error) {
	return func(msg message.Message, err error) {
		reportSendFailure(msg, err)

		// The response that would have consumed this entry is never coming on a send timeout.
		FetchPfcpTxn(msg.Sequence())

		smContext := smf_context.GetSMContextBySEID(localSEID)
		if smContext == nil {
			logger.PfcpLog.Errorf("SMContext not found for failed establishment (local SEID[%v])", localSEID)
			return
		}
		smContext.SubPfcpLog.Errorf("PFCP Session Establishment send failure, %v", err.Error())

		foldEstablishmentFailureIntoBatch(smContext, localSEID)
	}
}

// foldEstablishmentFailureIntoBatch records one UPF's establishment failure in the create's PendingUPF
// batch and queues the aggregate SessionEstablishFailed verdict only once that drains the batch. Both
// an asynchronous failure (establishmentSendErrorHandler, on a transaction timeout) and a synchronous
// one (the deferred failure path of SendPfcpSessionEstablishmentRequest) fold through here, so a
// failure on one UPF of a multi-UPF create never answers -- and rolls back -- the create while the
// other establishment requests are still in flight. The N4 Out/Failure metric and DNS refresh are
// reported by the caller's reportSendFailure, not here.
//
// It deliberately does not reject the UE or remove the context: once the verdict is read the create
// procedure's own failure path (the FSM's create-failure handler) does both, and doing them here too
// would double them.
func foldEstablishmentFailureIntoBatch(smContext *smf_context.SMContext, localSEID uint64) {
	// The stable key this UPF is tracked by in PendingUPF, recovered from the bound local SEID rather
	// than by re-resolving the NodeID: reportSendFailure may have refreshed the DNS cache, so an FQDN
	// UPF can now resolve to a different address than the one SendPFCPRules recorded in PendingUPF at
	// dispatch, and a re-resolved key would miss the batch and leave the create waiting forever. An
	// absent entry (e.g. a restoration establishment, not tracked) is nothing to drain.
	upfKey, known := smContext.GetPFCPContextKeyByLocalSEID(localSEID)
	if !known {
		return
	}

	foldEstablishmentFailureByKey(smContext, upfKey)
}

// foldEstablishmentFailureByKey is the shared tail of both fold paths: it drains the UPF tracked by
// upfKey from the create's PendingUPF batch as a failed verdict and, once that empties the batch,
// queues the aggregate SessionEstablishFailed on the session's PFCP channel. It returns whether the
// UPF belonged to the batch (tracked), so a caller holding a dispatch-time key the batch never
// recorded can answer its lone waiter directly instead.
//
// upfKey is the dispatch-time PendingUPF key: the local SEID-derived key when the failure handler
// had one (foldEstablishmentFailureIntoBatch), or the key the caller registered in PendingUPF
// otherwise (the deferred failure path of SendPfcpSessionEstablishmentRequest). Either way it is the
// key PendingUPF was keyed by, never a fresh NodeID re-resolution that the periodic DNS refresh
// could have moved off the batch.
func foldEstablishmentFailureByKey(smContext *smf_context.SMContext, upfKey string) (tracked bool) {
	// Only a create waits on PendingUPF as an establishment batch. Gate on that state before touching
	// the map, exactly as the response handler and its failPendingEstablishment sibling do: PendingUPF
	// is shared with the awaited modification and release flows, so draining a UPF here for a
	// restoration establishment (which reuses this send path for a session already running, outside any
	// create) could corrupt a modify/release batch that happens to track the same UPF.
	if upfKey == "" || smContext.SMContextState != smf_context.SmStatePfcpCreatePending {
		return false
	}

	// Not under SMLock: PendingUPF is serialized by its own PendingUPFLock (AggregateEstablishmentResponse
	// takes it), and the state read above follows the same lock-free convention the deferred failure
	// handler in SendPfcpSessionEstablishmentRequest already uses.
	//
	// A tracked response that drains the batch belongs to the initial create by definition, so the
	// verdict is written straight to the channel, exactly as the response handler and
	// failPendingEstablishment do -- not routed through awaitingEstablishment, which additionally
	// returns false while BPManager is AddingPSA. A PSA/ULCL branch addition can overlap a
	// still-create-pending context; if the last initial-batch result is a send failure during that
	// overlap, gating the send on awaitingEstablishment here would suppress the only verdict and block
	// the create FSM forever. The non-blocking send keeps the sender off a channel nobody reads.
	tracked, signal, verdict := smContext.AggregateEstablishmentResponse(upfKey, false)
	if tracked && signal {
		select {
		case smContext.SBIPFCPCommunicationChan <- verdict:
		default:
			smContext.SubPfcpLog.Warnf("an establishment verdict is already waiting; not queueing %v", verdict)
		}
	}
	return tracked
}

// answerTheWaitingSession puts a verdict on the session's PFCP channel when the request was not
// dispatched and no response will be.
//
// The exchange that sent the request waits on that channel whatever the send function returned, so
// an error alone leaves the goroutine holding the session parked. Reporting the failure to the UE
// does not release it either.
//
// awaited says whether anything is listening, and it is not optional. Every other write of this
// channel is gated the same way, because restoration issues an establishment without ever waiting
// on it: an ungated write leaves a verdict behind for whichever unrelated modification or release
// reads the channel next, which is the fault this would cause rather than fix.
//
// The write is non-blocking. The channel holds one verdict, and a session nothing is reading must
// not wedge the goroutine that sends.
func answerTheWaitingSession(smContext *smf_context.SMContext, awaited func(*smf_context.SMContext) bool, verdict smf_context.PFCPSessionResponseStatus) {
	// Logged through the package logger rather than the session's own: a context this function is
	// handed may be one that never reached NewSMContext, and a nil sub-logger here would turn a
	// failed send into a panic.
	if !awaited(smContext) {
		logger.PfcpLog.Infof("no exchange on session [%s] is waiting on the PFCP channel; not queueing %v",
			smContext.Supi, verdict)

		return
	}

	select {
	case smContext.SBIPFCPCommunicationChan <- verdict:
	default:
		logger.PfcpLog.Warnf("session [%s] already has a verdict waiting to be read; not queueing %v",
			smContext.Supi, verdict)
	}
}

// awaitingEstablishment and awaitingRelease are the states in which an exchange is waiting on a
// session's PFCP channel, and they are the gates the response handlers use: create-pending for an
// establishment, release-and-not-purged for a deletion. The second can resume the waiter while
// deletions to other user planes are still in flight -- the rejected-deletion branch of the
// response handler answers on the same terms, and a waiter resumed early beats one never resumed.
func awaitingEstablishment(smContext *smf_context.SMContext) bool {
	// A session adding a second anchor is not one waiting for its first establishment. The uplink
	// classifier issues that establishment from inside the response handler that has just answered
	// the create exchange, and the goroutine it answered may not have changed the state yet -- so
	// the state alone would call this a waiting session and leave a verdict behind for the next
	// exchange to read as its own.
	if smContext.BPManager != nil && smContext.BPManager.BPStatus == smf_context.AddingPSA {
		return false
	}

	return smContext.SMContextState == smf_context.SmStatePfcpCreatePending
}

func awaitingRelease(smContext *smf_context.SMContext) bool {
	return smContext.SMContextState == smf_context.SmStatePfcpRelease && !smContext.LocalPurged.Load()
}

// snapshotRuleStates records the states of the rules a request is about to be built from, and
// returns what puts them back. Only for a request that provably never left the SMF: once one has,
// what the user plane holds is not known, and restoring the SMF's view would be guessing.
func snapshotRuleStates(pdrs []*smf_context.PDR, fars []*smf_context.FAR, qers []*smf_context.QER) func() {
	pdrStates := make([]smf_context.RuleState, len(pdrs))
	for i, pdr := range pdrs {
		if pdr != nil {
			pdrStates[i] = pdr.State
		}
	}

	farStates := make([]smf_context.RuleState, len(fars))
	for i, far := range fars {
		if far != nil {
			farStates[i] = far.State
		}
	}

	qerStates := make([]smf_context.RuleState, len(qers))
	for i, qer := range qers {
		if qer != nil {
			qerStates[i] = qer.State
		}
	}

	return func() {
		for i, pdr := range pdrs {
			if pdr != nil {
				pdr.State = pdrStates[i]
			}
		}

		for i, far := range fars {
			if far != nil {
				far.State = farStates[i]
			}
		}

		for i, qer := range qers {
			if qer != nil {
				qer.State = qerStates[i]
			}
		}
	}
}

// reportSendFailure is the part of a send failure that concerns no session: the log, the bounded N4
// failure count and the DNS refresh. The adapter paths, which answer their own session, report
// through this alone. It is a thin wrapper over udp.ReportSendFailure, which owns the reporting so
// that callers of the exported udp.SendPfcp in any package can report a synchronous failure without
// an import cycle; this keeps the familiar name for pfcp/message's own call sites.
func reportSendFailure(msg message.Message, pfcpErr error) {
	udp.ReportSendFailure(msg, pfcpErr)
}

func HandlePfcpSendError(msg message.Message, pfcpErr error) {
	handlePfcpSendError(msg, pfcpErr, 0, false, true)
}

// handlePfcpSendError reports a failed send. When sessionKnown, localSEID names the session the
// request belonged to; otherwise the handlers find it from the message, as before. A flag rather
// than a zero sentinel, because zero is a SEID the DRSM allocator can hand out.
func handlePfcpSendError(msg message.Message, pfcpErr error, localSEID uint64, sessionKnown, awaited bool) {
	reportSendFailure(msg, pfcpErr)

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
		smContext.SMContextState == smf_context.SmStatePfcpRelease && !smContext.LocalPurged.Load(),
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
func SendPfcpMsgToAdapter(upNodeID smf_context.NodeID, msg message.Message, addr *net.UDPAddr, eventData any, url string) (*http.Response, error) {
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
