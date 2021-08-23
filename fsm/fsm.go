// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package fsm

import (
	"github.com/free5gc/pfcp/pfcpType"
	smf_context "github.com/free5gc/smf/context"
	"github.com/free5gc/smf/logger"
	pfcp_message "github.com/free5gc/smf/pfcp/message"
)

type fsmEvent int
type fsmState int

const (
	PFCPSessModify fsmEvent = iota
	PFCPSessDelete
	MaxSubsEvents
)

const (
	UpCnxDeactivated fsmState = iota
	N2SmInfoTypePduResSetupRsp
	N2SmInfoTypePathSwitchReq
	MsgTypePDUSessionReleaseRequest
	RelDueToDuplicateSessionId
	MaxSubsState
)

type EventData struct {
	Data interface{}
}

type PfcpModEventData struct {
	PdrList   []*smf_context.PDR
	FarList   []*smf_context.FAR
	QerList   []*smf_context.QER
	BarList   []*smf_context.BAR
	UpNodeID  pfcpType.NodeID
	SmContext *smf_context.SMContext
}

type PfcpDeleteEventData struct {
	SmContext *smf_context.SMContext
}

func init() {
	InitFSM()
}

type FSM [MaxSubsState][MaxSubsEvents]func(evtData EventData) error

var fsm FSM

func InitFSM() {
	fsm[UpCnxDeactivated][PFCPSessModify] = fsmActiveHandlePfcpModifySess
	fsm[N2SmInfoTypePduResSetupRsp][PFCPSessModify] = fsmActiveHandlePfcpModifySess
	fsm[N2SmInfoTypePathSwitchReq][PFCPSessModify] = fsmActiveHandlePfcpModifySess
	fsm[MsgTypePDUSessionReleaseRequest][PFCPSessDelete] = fsmActiveHandlePfcpDeleteSess
	fsm[RelDueToDuplicateSessionId][PFCPSessDelete] = fsmActiveHandlePfcpDeleteSess
}

func EventHandler(s fsmState, e fsmEvent, evtData EventData) {
	logger.FsmLog.Traceln("In FSM Event Handler ")

	if fsm[s][e] != nil {
		err := fsm[s][e](evtData)

		if err != nil {
			// FSM(nextErrState)
		}
	}
	logger.FsmLog.Traceln("Out FSM Event Handler ")
}

func fsmActiveHandlePfcpModifySess(evtData EventData) error {
	logger.FsmLog.Traceln("In fsmActiveHandlePfcpModifySess")
	pfcpModEvent := evtData.Data.(*PfcpModEventData)

	pfcpModEvent.SmContext.ChangeState(smf_context.PFCPModification)

	pfcp_message.SendPfcpSessionModificationRequest(pfcpModEvent.UpNodeID, pfcpModEvent.SmContext,
		pfcpModEvent.PdrList, pfcpModEvent.FarList, pfcpModEvent.BarList, pfcpModEvent.QerList)

	logger.FsmLog.Traceln("Out fsmActiveHandlePfcpModifySess")
	return nil
}

func fsmActiveHandlePfcpDeleteSess(evtData EventData) error {
	logger.FsmLog.Traceln("In fsmActiveHandlePfcpDeleteSess")

	pfcpDeleteEvent := evtData.Data.(*PfcpDeleteEventData)

	pfcpDeleteEvent.SmContext.ChangeState(smf_context.PFCPDeletion)
	pfcp_message.ReleaseTunnel(pfcpDeleteEvent.SmContext)

	logger.FsmLog.Traceln("Out fsmActiveHandlePfcpDeleteSess")

	return nil
}
