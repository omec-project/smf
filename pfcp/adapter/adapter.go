// SPDX-FileCopyrightText: 2022-present Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package adapter

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/omec-project/smf/consumer"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/pfcp/ies"
	"github.com/omec-project/smf/pfcp/lisequence"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func init() {
	PfcpTxns = make(map[uint32]*context.NodeID)
}

// POIRestarted is the Lawful Interception hook this package calls when a UPF stops answering.
// Nil unless LI is wired, and nil-checked at every call site. A detected restart does not call
// it: it calls context.OnRestart, which the LI wiring wraps so the same discard is settled
// before any session is restored (lawfulintercept.GateRestoration).
//
// **A package variable rather than a direct call, because this package may not import
// lawfulintercept.** pfcp/message imports this one, and lawfulintercept's own tests import
// pfcp/message, so the direct call is an import cycle. The same shape the producer's
// teardown hooks take, for the same reason, and it is assigned once by the service wiring
// that already builds the LI subsystem.
var POIRestarted func(node context.NodeID)

// LIModificationAnswered is the Lawful Interception hook this package calls with the
// outcome of a modification the interception subsystem sent. Nil unless LI is wired, and
// assigned by the same service wiring that assigns POIRestarted, for the same reason: this
// package may not import lawfulintercept.
var LIModificationAnswered func(req lisequence.Request, cause uint8, answered bool)

// notifyLIModificationAnswered calls the hook if one is wired.
func notifyLIModificationAnswered(req lisequence.Request, cause uint8, answered bool) {
	if LIModificationAnswered != nil {
		LIModificationAnswered(req, cause, answered)
	}
}

// ReportEstablishment, ApplyCCAfterEstablishment and TriggerCC are the Lawful Interception hooks
// this package raises when a PFCP session establishment response completes. They are assigned by
// the same service wiring that assigns POIRestarted, for the same reason: this package may not
// import lawfulintercept.
//
// **They exist because only one of the native and adapter handlers runs in a deployment.** The
// native handler in pfcp/handler raises the same three. Without them here, with enableUPFAdapter
// set — the chart's default — the SMF would send the UPF a DUPL FAR and never send the
// ActivateTask that authorises it: the CC-POI would hold no task for the session and drop every
// copy as unattributable, the establishment record would never be produced, and nothing would
// raise a fault, because from the SMF's side nothing failed.
var (
	ReportEstablishment       func(sc *context.SMContext)
	ApplyCCAfterEstablishment func(sc *context.SMContext)
	TriggerCC                 func(sc *context.SMContext)
)

// notifyReportEstablishment calls the hook if one is wired.
func notifyReportEstablishment(sc *context.SMContext) {
	if ReportEstablishment != nil {
		ReportEstablishment(sc)
	}
}

// notifyApplyCCAfterEstablishment calls the hook if one is wired.
func notifyApplyCCAfterEstablishment(sc *context.SMContext) {
	if ApplyCCAfterEstablishment != nil {
		ApplyCCAfterEstablishment(sc)
	}
}

// notifyTriggerCC calls the hook if one is wired.
//
// One helper per hook, named for it, rather than one that raises both: the call site is what a
// reader and a parity check both look at, and a helper that groups two hooks hides their names
// from it, and the parity guard in this package fails until each hook is named here.
func notifyTriggerCC(sc *context.SMContext) {
	if TriggerCC != nil {
		TriggerCC(sc)
	}
}

// notifyPOIRestarted calls the hook if one is wired. Written once so a new call site cannot
// forget the nil check — a nil function value panics, and these are PFCP message handlers.
func notifyPOIRestarted(node context.NodeID) {
	if POIRestarted != nil {
		POIRestarted(node)
	}
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
func HandleAdapterPfcpRsp(pfcpMsg message.Message, evtData *udp.PfcpEventData) error {
	switch pfcpMsg.MessageType() {
	case message.MsgTypeAssociationSetupResponse:
		msg := udp.Message{PfcpMessage: pfcpMsg}
		HandlePfcpAssociationSetupResponse(&msg)
	case message.MsgTypeHeartbeatResponse:
		msg := udp.Message{PfcpMessage: pfcpMsg}
		HandlePfcpHeartbeatResponse(&msg)
	// The session handlers report a reply they could not use rather than dropping it. Here the reply
	// is the only answer there will be -- the request was one HTTP call, with no transaction left to
	// time out -- so a reply dropped in silence left the session waiting on its channel for good.
	// What stays silent is what should: a reply for a session in no state that awaits it, and one
	// that is one of several the session is still collecting.
	case message.MsgTypeSessionEstablishmentResponse:
		msg := udp.Message{PfcpMessage: pfcpMsg, EventData: *evtData}
		return HandlePfcpSessionEstablishmentResponse(&msg)
	case message.MsgTypeSessionModificationResponse:
		msg := udp.Message{PfcpMessage: pfcpMsg, EventData: *evtData}
		return HandlePfcpSessionModificationResponse(&msg)
	case message.MsgTypeSessionDeletionResponse:
		msg := udp.Message{PfcpMessage: pfcpMsg, EventData: *evtData}
		return HandlePfcpSessionDeletionResponse(&msg)
	default:
		return fmt.Errorf("upf adapter returned an unexpected message type: %v", pfcpMsg.MessageTypeName())
	}
	return nil
}

func FindUEIPAddress(createdPDRIEs []*ie.IE) net.IP {
	for _, createdPDRIE := range createdPDRIEs {
		ueIPAddress, err := createdPDRIE.UEIPAddress()
		if err == nil {
			return ueIPAddress.IPv4Address
		}
	}
	return nil
}

func FindFTEID(createdPDRIEs []*ie.IE) (*ie.FTEIDFields, error) {
	for _, createdPDRIE := range createdPDRIEs {
		teid, err := createdPDRIE.FTEID()
		if err == nil {
			return teid, nil
		}
	}
	return nil, fmt.Errorf("FTEID not found in CreatedPDR")
}

// HandlePfcpAssociationSetupResponse runs synchronously inside the association send and takes no
// lock of its own: every caller holds the UPF's UpfLock across that send (see HandleAdapterPfcpRsp).
// That is what makes the associated status and the new recovery timestamp visible together, which
// the acknowledging-incarnation record restoration reads depends on. Taking the lock here instead
// deadlocks probeUpf, which already holds it.
func HandlePfcpAssociationSetupResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.AssociationSetupResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Association Setup Response")
		return
	}

	nodeIDIE := rsp.NodeID
	if nodeIDIE == nil {
		logger.PfcpLog.Errorln("pfcp association setup response has no NodeID")
		return
	}

	nodeIDStr, err := nodeIDIE.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("pfcp association setup response NodeID error: %v", err)
		return
	}

	nodeID := context.NewNodeID(nodeIDStr)

	if rsp.Cause == nil {
		logger.PfcpLog.Errorln("pfcp association setup response has no cause")
		return
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("pfcp association setup response cause error: %v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		logger.PfcpLog.Infof("handle PFCP Association Setup Response with NodeID[%s]", nodeID.ResolveNodeIdToIp().String())

		upf := context.RetrieveUPFNodeByNodeID(*nodeID)
		if upf == nil {
			logger.PfcpLog.Errorf("can not find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
			return
		}

		upf.UPFStatus = context.AssociatedSetUpSuccess
		upf.SessionsRetained = rsp.PFCPASRspFlags != nil && rsp.PFCPASRspFlags.HasPSREI()
		logger.PfcpLog.Debugln("upf status updated to associated: %+v", upf.UPFStatus)
		if rsp.RecoveryTimeStamp == nil {
			logger.PfcpLog.Errorln("pfcp association setup response has no RecoveryTimeStamp")
			return
		}
		recoveryTimestamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
		if err != nil {
			logger.PfcpLog.Errorf("pfcp association setup response RecoveryTimeStamp error: %v", err)
			return
		}
		// Compared before the overwrite below, for the same reason as on the native path: once the
		// held value has been replaced the evidence of the restart is gone, and what remains is the
		// state that hides it.
		if upf.HasRestarted(recoveryTimestamp) {
			logger.PfcpLog.Warnf("PFCP Association Setup Response, upf [%v] recovery timestamp changed", upf.NodeID)
			if context.OnRestart != nil {
				context.OnRestart(upf.NodeID, recoveryTimestamp)
			}
		}

		upf.RecoveryTimeStamp = context.RecoveryTimeStamp{
			RecoveryTimeStamp: recoveryTimestamp,
		}
		upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
	}
}

func HandlePfcpHeartbeatResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.HeartbeatResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Heartbeat Response")
		return
	}

	// Get NodeId from Seq:NodeId Map
	seq := rsp.Sequence()
	nodeID := FetchPfcpTxn(seq)

	if nodeID == nil {
		logger.PfcpLog.Errorf("no pending pfcp heartbeat response for sequence no: %v", seq)
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

	if rsp.RecoveryTimeStamp == nil {
		logger.PfcpLog.Errorln("pfcp heartbeat response has no RecoveryTimeStamp")
		return
	}

	recoveryTimestamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		logger.PfcpLog.Errorf("pfcp heartbeat response RecoveryTimeStamp error: %v", err)
		return
	}

	if upf.HasRestarted(recoveryTimestamp) {
		// change UPF state to not associated so that
		// PFCP Association can be initiated again
		upf.UPFStatus = context.NotAssociated
		logger.PfcpLog.Warnf("PFCP Heartbeat Response, upf [%v] recovery timestamp changed", upf.NodeID)

		if context.OnRestart != nil {
			context.OnRestart(upf.NodeID, recoveryTimestamp)
		}
	}

	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
}

func HandlePfcpSessionEstablishmentResponse(msg *udp.Message) error {
	rsp, ok := msg.PfcpMessage.(*message.SessionEstablishmentResponse)
	if !ok {
		return errors.New("invalid PFCP Session Establishment Response")
	}
	logger.PfcpLog.Infoln("in HandlePfcpSessionEstablishmentResponse")

	SEID := rsp.SEID()
	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			return errors.New("PFCP Session Establish Response found invalid event data, response discarded")
		} else {
			SEID = eventData.LSEID
		}
	}
	smContext := context.GetSMContextBySEID(SEID)
	if smContext == nil {
		return errors.New("PFCP Session Establish Response found SM context nil, response discarded")
	}
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	logger.PfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse SEID %v", SEID)
	// The session's reference, not the context: the context's text carries the subscriber's
	// identities and every FAR's apply action, including the duplication that marks an
	// intercepted session.
	logger.PfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse smContext Ref %s", smContext.Ref)

	// Get NodeId from Seq:NodeId Map
	seq := rsp.Sequence()
	nodeID := FetchPfcpTxn(seq)
	if nodeID == nil {
		return fmt.Errorf("no pending pfcp session establishment response for sequence no: %v", seq)
	}

	upfKey, _ := smContext.GetPFCPContextKeyByLocalSEID(SEID)

	if rsp.Cause == nil {
		return errors.New("pfcp session establishment response has no cause")
	}
	causeValue, causeErr := rsp.Cause.Cause()
	if causeErr != nil {
		return fmt.Errorf("pfcp session establishment response cause error: %v", causeErr)
	}
	var rspUPFseid *ie.FSEIDFields
	if causeValue == ie.CauseRequestAccepted && rsp.UPFSEID != nil {
		var fseidErr error
		if rspUPFseid, fseidErr = rsp.UPFSEID.FSEID(); fseidErr != nil {
			logger.PfcpLog.Errorf("failed to parse FSEID IE: %+v", fseidErr)
			rspUPFseid = nil
		}
	}
	accepted := causeValue == ie.CauseRequestAccepted

	if accepted {
		pfcpSessionCtx := smContext.PFCPContext[upfKey]
		if pfcpSessionCtx == nil {
			return fmt.Errorf("PFCP Session Establishment accepted but its PFCP context is gone for UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		}
		if rspUPFseid != nil {
			pfcpSessionCtx.RemoteSEID = rspUPFseid.SEID
			smContext.SubPfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse rsp.UPFSEID.Seid [%v] ", rspUPFseid.SEID)
		}
		if upf := context.RetrieveUPFNodeByNodeID(*nodeID); upf != nil {
			pfcpSessionCtx.AcknowledgedAtRecovery = upf.HeldRecovery()
		}
	}

	// Get N3 interface UPF
	defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
	if defaultPath == nil {
		return errors.New("failed to get default path")
	}
	ANUPF := smContext.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode

	if accepted && rsp.CreatedPDR != nil {
		ueIPAddress := FindUEIPAddress(rsp.CreatedPDR)
		if ueIPAddress != nil {
			smContext.SubPfcpLog.Infof("upf provided ue ip address [%v]", ueIPAddress)

			// Before the release, not after. Releasing first puts the old address back in
			// the pool, and another session can take it while this report is in flight --
			// leaving the PCF holding that address as this session's binding key at the
			// moment it becomes another subscriber's, which is the collision this reports
			// to prevent.
			consumer.ReportUeIpChange(smContext, ueIPAddress)

			// Release previous locally allocated UE IP-Addr
			err := smContext.ReleaseUeIpAddr()
			if err != nil {
				logger.PfcpLog.Errorf("failed to release UE IP-Addr: %+v", err)
			}

			// Update with one received from UPF
			smContext.PDUAddress.Ip = ueIPAddress
			smContext.PDUAddress.UpfProvided = true
		}

		// Store F-TEID created by UPF
		fteid, err := FindFTEID(rsp.CreatedPDR)
		if err != nil {
			return fmt.Errorf("failed to parse TEID IE: %+v", err)
		}
		logger.PfcpLog.Infof("created PDR FTEID: %+v", fteid)
		if err = ies.CheckOneFTEID(rsp.CreatedPDR); err != nil {
			smContext.SubPfcpLog.Errorf("UPF[%s]: %v; the RAN is told TEID %#x",
				nodeID.ResolveNodeIdToIp().String(), err, fteid.TEID)
		}

		// Applied to the node each F-TEID belongs to, not to ANUPF: a response can come from any UPF
		// on any of the session's data paths. See DataPathPool.FindNode and ies.ApplyCreatedFTEIDs.
		advertised, err := ies.ApplyCreatedFTEIDs(smContext.Tunnel.DataPathPool, *nodeID, ies.CreatedFTEIDs(rsp.CreatedPDR))
		if err != nil {
			return err
		}
		upf := context.RetrieveUPFNodeByNodeID(*nodeID)
		if upf == nil {
			return fmt.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		}
		upf.N3Interfaces = make([]context.UPFInterfaceInfo, 0)
		n3Interface := context.UPFInterfaceInfo{}
		n3Interface.IPv4EndPointAddresses = append(n3Interface.IPv4EndPointAddresses, advertised.IPv4Address)
		upf.N3Interfaces = append(upf.N3Interfaces, n3Interface)
	}

	if rsp.NodeID == nil {
		return errors.New("PFCP Session Establishment Response missing NodeID")
	}
	rspNodeIDStr, err := rsp.NodeID.NodeID()
	if err != nil {
		return fmt.Errorf("failed to parse NodeID IE: %+v", err)
	}
	rspNodeID := context.NewNodeID(rspNodeIDStr)

	if ANUPF.UPF == nil {
		return errors.New("failed to get UPF from default path")
	}

	// Gated on the state, like the modification and release handlers. Restoration issues an
	// establishment without waiting on this channel, so an unconditional send here would leave a
	// stale value for whichever unrelated modification or release next waits on it.
	awaited := smContext.SMContextState == context.SmStatePfcpCreatePending

	if !accepted {
		smContext.SubPfcpLog.Errorf("PFCP Session Establishment rejected with cause [%v]", causeValue)
		if causeValue == ie.CauseNoEstablishedPFCPAssociation {
			SetUpfInactive(*rspNodeID)
		}
	} else {
		// Lawful Interception IRI-POI: the session now exists on the UPF, so its F-SEID
		// (the X2 correlation identifier) and F-TEID are known — both were set above from
		// this response. At most once per session; silent no-op unless LI is configured.
		// SMLock is held for the whole handler.
		//
		// Only on the anchor's response, as in the native handler: the record's correlation
		// identifier is the *default path's* F-SEID, so emitting it on some other UPF's
		// response would produce the one record describing the session with nothing to
		// join it to.
		if ANUPF.UPF.NodeID.ResolveNodeIdToIp().Equal(nodeID.ResolveNodeIdToIp()) {
			notifyReportEstablishment(smContext)
		}
		smContext.SubPfcpLog.Infof("PFCP Session Establishment accepted")
	}

	if awaited {
		tracked, signal, verdict := smContext.AggregateEstablishmentResponse(upfKey, accepted)
		if !tracked {
			smContext.SubPfcpLog.Warnf("PFCP Session Establishment Response from UPF[%s] was not pending; not counted toward the establishment verdict", nodeID.ResolveNodeIdToIp().String())
		} else if signal {
			select {
			case smContext.SBIPFCPCommunicationChan <- verdict:
			default:
				smContext.SubPfcpLog.Warnf("an establishment verdict is already waiting; not queueing %v", verdict)
			}
		}
	}

	// Lawful Interception CC-TF: task the CC-POI of the UPF that has just created this session.
	// The trigger's packet detection criterion is the F-SEID that response assigns, so this is
	// the earliest point it can be sent — the duplication instruction itself rode out with the
	// request.
	//
	// Not gated on the anchor, as in the native handler, because a session can be served by
	// more than one UPF. Gated on the anchor, an additional PSA got its DUPL FAR but never its
	// trigger, so it duplicated the target's traffic into content the CC-POI could not
	// attribute and correctly dropped. Triggering is idempotent per (warrant, session, UPF).
	if accepted {
		// Re-derive duplication before tasking: a warrant that activated while this session was
		// being established has not been applied to its FARs by anyone, and this is the first
		// point ordered after the session exists. Under the same lock, so it cannot race the
		// rules it reads.
		notifyApplyCCAfterEstablishment(smContext)
		notifyTriggerCC(smContext)
	}
	return nil
}

func HandlePfcpSessionModificationResponse(msg *udp.Message) error {
	pfcpRsp, ok := msg.PfcpMessage.(*message.SessionModificationResponse)
	if !ok {
		return errors.New("invalid PFCP Session Modification Response")
	}
	logger.PfcpLog.Infoln("in HandlePfcpSessionModificationResponse")

	// A modification this element sent for Lawful Interception, not one the session's
	// own procedures sent — the same guard the native handler applies, on the path
	// taken when enableUPFAdapter is set. sendSessionModification routes the response
	// through HandleAdapterPfcpRsp in that mode. Without it, an LI modification's
	// response landing during SmStatePfcpModify would clear the pending-UPF entry the
	// subscriber's own concurrent modification is waiting on and complete that procedure
	// on an answer never sent to it. The correlation below — SEID, serving UPF, procedure
	// state — cannot tell the two apart, which is why the sequence number is what answers
	// it.
	//
	// Take closes the record; it stays as a tombstone for a bounded time, so a repeated
	// answer is still recognised as LI.
	//
	// **And the answer is read.** Keeping it out of the subscriber's procedure is one
	// obligation and reading it is a second: the Cause says whether the datapath applied
	// the duplication this element had already recorded as applied, and with it discarded
	// a refused activation would never be retried — the element holding a task it reports
	// as intercepting and a datapath that declined it, with nothing left to re-send and
	// nothing reported. A refused withdrawal would leave duplication running while the
	// element believed it was off.
	//
	// Ahead of the Cause checks below, as the native handler's is: an answer with no Cause
	// this element can read is treated as not applied, and so retried, rather than
	// discarded.
	//
	// Only the first answer to a sequence number is read, as in the native handler; a repeat
	// is still LI, and dropped.
	if req, ok, first := lisequence.Take(pfcpRsp.Sequence()); ok {
		if !first {
			return nil
		}
		var (
			liCause  uint8
			answered bool
		)
		if pfcpRsp.Cause != nil {
			if value, causeErr := pfcpRsp.Cause.Cause(); causeErr == nil {
				liCause, answered = value, true
			}
		}
		notifyLIModificationAnswered(req, liCause, answered)

		return nil
	}

	cause := pfcpRsp.Cause
	if cause == nil {
		return errors.New("PFCP Session Modification Response found invalid cause, response discarded")
	}
	causeValue, err := cause.Cause()
	if err != nil {
		return fmt.Errorf("PFCP Session Modification Response cause error: %v", err)
	}

	logger.PfcpLog.Infof("in HandlePfcpSessionModificationResponse pfcpRsp.Cause.CauseValue = [%v], accepted?? %v", causeValue, causeValue == ie.CauseRequestAccepted)

	SEID := pfcpRsp.SEID()
	logger.PfcpLog.Infof("in HandlePfcpSessionModificationResponse SEID %v", SEID)

	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			return errors.New("PFCP Session Modification Response found invalid event data, response discarded")
		} else {
			SEID = eventData.LSEID
		}
	}

	smContext := context.GetSMContextBySEID(SEID)

	// After the interception block, as in the native handler: that block answers a
	// modification this element sent itself, keyed on the sequence number alone, and it must
	// still run when the session has since been released.
	if smContext == nil {
		return fmt.Errorf("PFCP Session Modification Response found SM context nil for SEID %d, response discarded", SEID)
	}
	// The session's reference, not the context: see HandlePfcpSessionEstablishmentResponse.
	logger.PfcpLog.Infof("in HandlePfcpSessionModificationResponse smContext Ref %s found by SEID %d", smContext.Ref, SEID)

	if causeValue == ie.CauseRequestAccepted {
		smContext.SubPduSessLog.Infoln("PFCP Modification Response Accept")
		if smContext.SMContextState == context.SmStatePfcpModify || smContext.RevertOwed.Load() {
			// The dispatch-time PFCPContext key (recovered from the response's local SEID), not a
			// re-resolution of the NodeID: an FQDN UPF's address can move under the DNS refresh while
			// the modification is in flight, and a re-resolved key would miss PendingUPF and leave the
			// awaited modify blocked on SBIPFCPCommunicationChan. An absent entry is nothing to drain.
			upfKey, known := smContext.GetPFCPContextKeyByLocalSEID(SEID)
			// DeletePendingUPF: see SMContext.PendingUPFLock's declaration.
			pendingEmpty := known && smContext.DeletePendingUPF(upfKey)
			smContext.SubPduSessLog.Debugf("delete pending pfcp response: UPF [%s]", upfKey)

			if pendingEmpty {
				smContext.SBIPFCPCommunicationChan <- context.SessionUpdateSuccess
			}
		}

		smContext.SubPfcpLog.Infof("PFCP Session Modification Success[%d]", SEID)
	} else {
		smContext.SubPfcpLog.Infof("PFCP Session Modification Failed[%d]", SEID)
		if smContext.SMContextState == context.SmStatePfcpModify || smContext.RevertOwed.Load() {
			smContext.SBIPFCPCommunicationChan <- context.SessionUpdateFailed
		}
	}

	// No debug dump of PFCPContext here: this handler does not hold SMLock, so iterating the map
	// would race -- fatally -- a concurrent AllocateLocalSEIDForDataPath insert (e.g. a PSA/ULCL
	// branch activation). See SMContext.seidToPFCPCtx.
	return nil
}

func HandlePfcpSessionDeletionResponse(msg *udp.Message) error {
	pfcpRsp, ok := msg.PfcpMessage.(*message.SessionDeletionResponse)
	if !ok {
		return errors.New("invalid PFCP Session Deletion Response")
	}
	logger.PfcpLog.Infoln("handle PFCP Session Deletion Response")
	SEID := pfcpRsp.SEID()

	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			return errors.New("PFCP Session Deletion Response found invalid event data, response discarded")
		} else {
			SEID = eventData.LSEID
		}
	}
	smContext := context.GetSMContextBySEID(SEID)

	if smContext == nil {
		return errors.New("PFCP Session Deletion Response found SM context nil, response discarded")
	}

	cause := pfcpRsp.Cause
	if cause == nil {
		return errors.New("PFCP Session Deletion Response found invalid cause, response discarded")
	}

	causeValue, err := cause.Cause()
	if err != nil {
		return fmt.Errorf("PFCP Session Deletion Response cause error: %v", err)
	}

	if causeValue == ie.CauseRequestAccepted {
		if smContext.SMContextState == context.SmStatePfcpRelease {
			// The dispatch-time PFCPContext key (recovered from the response's local SEID), not a
			// re-resolution of the NodeID: an FQDN UPF's address can move under the DNS refresh while
			// the deletion is in flight, and a re-resolved key would miss PendingUPF and leave the
			// awaited release blocked on SBIPFCPCommunicationChan. An absent entry is nothing to drain.
			upfKey, known := smContext.GetPFCPContextKeyByLocalSEID(SEID)
			// DeletePendingUPF: releaseTunnel rebuilds this same map under SMLock, which this
			// handler cannot take (see SMContext.PendingUPFLock's declaration).
			pendingEmpty := known && smContext.DeletePendingUPF(upfKey)
			smContext.SubPduSessLog.Debugf("delete pending pfcp response: UPF [%s]", upfKey)

			if pendingEmpty && !smContext.LocalPurged.Load() {
				smContext.QueuePFCPVerdict(context.SessionReleaseSuccess)
			}
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Success[%d]", SEID)
	} else {
		if smContext.SMContextState == context.SmStatePfcpRelease {
			// A refusal is the answer of one node, so it drains that node from the pending batch
			// the way an acceptance does, and resumes the waiter only once the batch is empty.
			// Resuming per refusal queued a second verdict behind the first, and with the verdict
			// slot taken the send blocked: in adapter mode this runs inline in the goroutine that
			// reads the slot, with SMLock held. An answer from a session this element holds no
			// context for (unknown SEID key) has no entry to drain and resumes the waiter outright.
			upfKey, known := smContext.GetPFCPContextKeyByLocalSEID(SEID)
			pendingEmpty := !known || smContext.DeletePendingUPF(upfKey)
			if pendingEmpty && !smContext.LocalPurged.Load() {
				smContext.QueuePFCPVerdict(context.SessionReleaseSuccess)
			}
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Failed[%d]", SEID)
	}
	return nil
}

func SetUpfInactive(nodeID context.NodeID) {
	upf := context.RetrieveUPFNodeByNodeID(nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can not find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		// metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID,
		//	pfcpmsgtypes.PfcpMsgTypeString(msgType),
		//	"In", "Failure", "unknown_upf")
		return
	}

	upf.UPFStatus = context.NotAssociated
	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0

	// Lawful Interception: this UPF has stopped answering, so what it holds is no longer
	// knowable and the claims this element keeps for it are worse than useless — they make
	// the planning path skip every triple as already claimed, and they keep this element
	// telling a POI it may not be reaching that its triggering function is present, which is
	// what disables that POI's own fail-safe.
	notifyPOIRestarted(upf.NodeID)
}
