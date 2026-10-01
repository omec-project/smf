// SPDX-FileCopyrightText: 2022-present Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package adapter

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func init() {
	PfcpTxns = make(map[uint32]*context.NodeID)
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
	logger.PfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse smContext %+v", smContext)

	// Get NodeId from Seq:NodeId Map
	seq := rsp.Sequence()
	nodeID := FetchPfcpTxn(seq)
	if nodeID == nil {
		return fmt.Errorf("no pending pfcp session establishment response for sequence no: %v", seq)
	}

	if rsp.Cause == nil {
		return errors.New("pfcp session establishment response has no cause")
	}
	causeValue, causeErr := rsp.Cause.Cause()
	if causeErr != nil {
		return fmt.Errorf("pfcp session establishment response cause error: %v", causeErr)
	}
	// F-SEID only matters for an accepted response, so it is parsed only for one: a rejected
	// response must still reach the failure branch below on its Cause alone, regardless of whether
	// this unrelated IE is present, malformed, or absent. A parse failure on an accepted response is
	// handled the same way as a missing F-SEID rather than by returning an error, so that case still
	// reaches the rejection logic below instead of silently dropping the verdict.
	var rspUPFseid *ie.FSEIDFields
	if causeValue == ie.CauseRequestAccepted && rsp.UPFSEID != nil {
		var fseidErr error
		if rspUPFseid, fseidErr = rsp.UPFSEID.FSEID(); fseidErr != nil {
			logger.PfcpLog.Errorf("failed to parse FSEID IE: %+v", fseidErr)
			rspUPFseid = nil
		}
	}
	// An accepted response with no UP F-SEID, or a zero-valued one, leaves no usable SEID the SMF
	// can address this session's PFCP session with at the UPF -- SendPFCPRules (producer/datapath.go)
	// treats RemoteSEID == 0 as not yet established and would keep reissuing an establishment
	// request instead of a modification. Both are treated as a rejection rather than the silent
	// success they would otherwise be. Validated up front, before any response-derived state is
	// applied below, so a rejected response can never leave establishment state (RemoteSEID, UE
	// address, TEID, N3 interface) partially applied.
	acceptedWithNoSeid := causeValue == ie.CauseRequestAccepted && (rspUPFseid == nil || rspUPFseid.SEID == 0)
	accepted := causeValue == ie.CauseRequestAccepted && !acceptedWithNoSeid

	if accepted {
		NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
		pfcpSessionCtx := smContext.PFCPContext[NodeIDtoIP]
		pfcpSessionCtx.RemoteSEID = rspUPFseid.SEID
		// Which incarnation of the node acknowledged it, so a restoration after a restart can tell a
		// session the restarted node lost from one it already holds. See AcknowledgedAtRecovery.
		if upf := context.RetrieveUPFNodeByNodeID(*nodeID); upf != nil {
			pfcpSessionCtx.AcknowledgedAtRecovery = upf.HeldRecovery()
		}
		smContext.SubPfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse rsp.UPFSEID.Seid [%v] ", rspUPFseid.SEID)
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
		ANUPF.UpLinkTunnel.TEID = fteid.TEID
		upf := context.RetrieveUPFNodeByNodeID(*nodeID)
		if upf == nil {
			return fmt.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		}
		upf.N3Interfaces = make([]context.UPFInterfaceInfo, 0)
		n3Interface := context.UPFInterfaceInfo{}
		n3Interface.IPv4EndPointAddresses = append(n3Interface.IPv4EndPointAddresses, fteid.IPv4Address)
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
		if acceptedWithNoSeid {
			smContext.SubPfcpLog.Errorf("PFCP Session Establishment rejected: accepted with no usable UP F-SEID")
		} else {
			smContext.SubPfcpLog.Errorf("PFCP Session Establishment rejected with cause [%v]", causeValue)
		}
		if causeValue == ie.CauseNoEstablishedPFCPAssociation {
			SetUpfInactive(*rspNodeID)
		}
	} else {
		smContext.SubPfcpLog.Infof("PFCP Session Establishment accepted")
	}

	if awaited {
		// A branching data path sends an establishment request to every UPF on it (SendPFCPRules,
		// producer/datapath.go), which populates PendingUPF with all of them before any request goes
		// out. The single verdict the create procedure reads must reflect every one of those
		// responses, not just whichever UPF this handler happens to be invoked for first -- SendPFCPRules
		// iterates an unordered map, so the AN UPF's acceptance must not be able to win a race against a
		// secondary UPF's rejection merely by being visited first. EstablishmentFailed latches a
		// rejection seen from any UPF until the verdict is queued, so a failure from one UPF is never
		// erased by a later acceptance from another.
		upfIP := nodeID.ResolveNodeIdToIp().String()
		if _, pending := smContext.PendingUPF[upfIP]; pending {
			delete(smContext.PendingUPF, upfIP)
		} else {
			smContext.SubPfcpLog.Warnf("PFCP Session Establishment Response from UPF[%s] was not pending; not counted toward the establishment verdict", upfIP)
		}
		if !accepted {
			smContext.EstablishmentFailed = true
		}
		if smContext.PendingUPF.IsEmpty() {
			verdict := context.SessionEstablishSuccess
			if smContext.EstablishmentFailed {
				verdict = context.SessionEstablishFailed
			}
			smContext.EstablishmentFailed = false
			// Not a blocking send. The response is dispatched inline, on the goroutine that reads the
			// channel afterwards -- so a blocking write here would park the sender behind its own
			// reader. The first verdict stands and a later, stale one (e.g. a response this call was
			// not actually waiting for) is dropped rather than queued behind it.
			select {
			case smContext.SBIPFCPCommunicationChan <- verdict:
			default:
				smContext.SubPfcpLog.Warnf("an establishment verdict is already waiting; not queueing %v", verdict)
			}
		}
	}
	return nil
}

func HandlePfcpSessionModificationResponse(msg *udp.Message) error {
	pfcpRsp, ok := msg.PfcpMessage.(*message.SessionModificationResponse)
	if !ok {
		return errors.New("invalid PFCP Session Modification Response")
	}
	logger.PfcpLog.Infoln("in HandlePfcpSessionModificationResponse")

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
	logger.PfcpLog.Infof("in HandlePfcpSessionModificationResponse smContext found by SEID %v", smContext)
	if smContext == nil {
		return fmt.Errorf("PFCP Session Modification Response found SM context nil for SEID %d, response discarded", SEID)
	}

	if causeValue == ie.CauseRequestAccepted {
		smContext.SubPduSessLog.Infoln("PFCP Modification Response Accept")
		if smContext.SMContextState == context.SmStatePfcpModify {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Debugf("delete pending pfcp response: UPF IP [%s]", upfIP)

			if smContext.PendingUPF.IsEmpty() {
				smContext.SBIPFCPCommunicationChan <- context.SessionUpdateSuccess
			}
		}

		smContext.SubPfcpLog.Infof("PFCP Session Modification Success[%d]", SEID)
	} else {
		smContext.SubPfcpLog.Infof("PFCP Session Modification Failed[%d]", SEID)
		if smContext.SMContextState == context.SmStatePfcpModify {
			smContext.SBIPFCPCommunicationChan <- context.SessionUpdateFailed
		}
	}

	smContext.SubCtxLog.Debugln("PFCP Session Context")
	for _, ctx := range smContext.PFCPContext {
		smContext.SubCtxLog.Debugln(ctx.String())
	}
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
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Debugf("delete pending pfcp response: UPF IP [%s]", upfIP)

			if smContext.PendingUPF.IsEmpty() && !smContext.LocalPurged {
				smContext.SBIPFCPCommunicationChan <- context.SessionReleaseSuccess
			}
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Success[%d]", SEID)
	} else {
		if smContext.SMContextState == context.SmStatePfcpRelease && !smContext.LocalPurged {
			smContext.SBIPFCPCommunicationChan <- context.SessionReleaseSuccess
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
}
