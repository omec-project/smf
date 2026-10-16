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

	// The stable key this response's UPF is tracked by in PendingUPF/PFCPContext, recovered from the
	// response's local SEID rather than by re-resolving the NodeID: an FQDN UPF's address can move
	// under the periodic DNS refresh while the request is in flight, and a re-resolved key would miss
	// the create batch and strand it. Used for every PendingUPF correlation and PFCPContext lookup
	// below.
	upfKey, _ := smContext.GetPFCPContextKeyByLocalSEID(SEID)

	if rsp.Cause == nil {
		return errors.New("pfcp session establishment response has no cause")
	}
	causeValue, causeErr := rsp.Cause.Cause()
	if causeErr != nil {
		return fmt.Errorf("pfcp session establishment response cause error: %v", causeErr)
	}
	// F-SEID only matters for an accepted response, so it is parsed only for one. A parse failure
	// leaves rspUPFseid nil, which records no RemoteSEID below (the session stays not-yet-established).
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
			// The PFCP session this acceptance belongs to is already gone (upfKey empty, or its entry
			// removed): record nothing rather than dereference a nil entry.
			return fmt.Errorf("PFCP Session Establishment accepted but its PFCP context is gone for UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		}
		if rspUPFseid != nil {
			pfcpSessionCtx.RemoteSEID = rspUPFseid.SEID
			smContext.SubPfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse rsp.UPFSEID.Seid [%v] ", rspUPFseid.SEID)
		}
		// Which incarnation of the node acknowledged it, so a restoration after a restart can tell a
		// session the restarted node lost from one it already holds. See AcknowledgedAtRecovery.
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
		if err := ies.CheckOneFTEID(rsp.CreatedPDR); err != nil {
			smContext.SubPfcpLog.Errorf("UPF[%s]: %v; the RAN is told TEID %#x",
				nodeID.ResolveNodeIdToIp().String(), err, fteid.TEID)
		}
		// The CreatedPDR F-TEID is the responding UPF's own uplink endpoint, so it belongs on that
		// UPF's data path node -- not unconditionally on the access node (ANUPF). Now that the create
		// verdict waits for every UPF, a secondary UPF's acceptance reaches this handler before N1N2
		// setup, so a blind write to ANUPF.UpLinkTunnel.TEID would pair the access UPF's N3 address
		// with the secondary UPF's TEID in the RAN's UL tunnel info
		// (BuildPDUSessionResourceSetupRequestTransfer reads GetDefaultPath().FirstDPNode.UpLinkTunnel.TEID),
		// breaking uplink despite an aggregate success. Apply it to the node that actually responded.
		if respNode := defaultPath.FindNode(*nodeID); respNode != nil {
			respNode.UpLinkTunnel.TEID = fteid.TEID
		} else {
			smContext.SubPfcpLog.Warnf("establishment F-TEID from UPF[%s] matches no node on the default path; not applied", nodeID.ResolveNodeIdToIp().String())
		}
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
		smContext.SubPfcpLog.Errorf("PFCP Session Establishment rejected with cause [%v]", causeValue)
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
		//
		// A PSA/ULCL branch addition (BPManager.PendingUPF, a separate map) can establish further
		// sessions while this context is still create-pending, and its responses reach this same
		// handler. Only a response found in this map belongs to the batch the create verdict tracks;
		// aggregating and emitting on any other response would let it poison or preempt that verdict.
		//
		// The map and the EstablishmentFailed latch are read and mutated through
		// AggregateEstablishmentResponse, which takes PendingUPFLock. This handler holds SMLock, but
		// the modification and deletion response handlers mutate PendingUPF without it (see
		// SMContext.PendingUPFLock's declaration), so SMLock here does not serialize against them --
		// only the shared PendingUPFLock does. A direct map access here would be the concurrent
		// read/write that lock exists to prevent.
		//
		// upfKey is the dispatch-time PFCPContext key, not a re-resolution of the NodeID: for an FQDN
		// UPF the DNS refresh can change the resolved address while the request is in flight, and a
		// re-resolved key would miss PendingUPF and leave the batch pending forever.
		tracked, signal, verdict := smContext.AggregateEstablishmentResponse(upfKey, accepted)
		if !tracked {
			smContext.SubPfcpLog.Warnf("PFCP Session Establishment Response from UPF[%s] was not pending; not counted toward the establishment verdict", nodeID.ResolveNodeIdToIp().String())
		} else if signal {
			// Not a blocking send, and made outside PendingUPFLock. The response is dispatched inline,
			// on the goroutine that reads the channel afterwards -- so a blocking write here would park
			// the sender behind its own reader. The first verdict stands and a later, stale one (e.g. a
			// response this call was not actually waiting for) is dropped rather than queued behind it.
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
		if smContext.SMContextState == context.SmStatePfcpModify {
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
				smContext.SBIPFCPCommunicationChan <- context.SessionReleaseSuccess
			}
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Success[%d]", SEID)
	} else {
		if smContext.SMContextState == context.SmStatePfcpRelease && !smContext.LocalPurged.Load() {
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
