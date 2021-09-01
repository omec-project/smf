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

type FSM [smf_context.MaxSmContextStates][MaxSubsEvents]func(evtData EventData) error

var fsm FSM

func InitFSM() {
	fsm[smf_context.ModificationPending][PFCPSessModify] = fsmHandlePfcpModifySess
	fsm[smf_context.Active][PFCPSessDelete] = fsmHandlePfcpDeleteSess
}

func EventHandler(smContext *smf_context.SMContext, event fsmEvent, evtData EventData) {
	logger.FsmLog.Traceln("In FSM Event Handler ")

	if fsm[smContext.SMContextState][event] != nil {
		logger.FsmLog.Infoln("Received State [%v] and Event [%v] ", smContext.SMContextState.String(),
			event.String())
		err := fsm[smContext.SMContextState][event](evtData)

		if err != nil {
			// FSM(nextErrState)
		}
	} else {
		logger.FsmLog.Infoln("No Handler defined for State [%v] and Event [%v]", smContext.SMContextState.String(),
			event.String())
	}
	logger.FsmLog.Traceln("Out FSM Event Handler ")
}

func fsmHandlePfcpModifySess(evtData EventData) error {
	logger.FsmLog.Traceln("In fsmHandlePfcpModifySess")
	pfcpModEvent := evtData.Data.(*PfcpModEventData)

	pfcpModEvent.SmContext.ChangeState(smf_context.PFCPModification)

	pfcp_message.SendPfcpSessionModificationRequest(pfcpModEvent.UpNodeID, pfcpModEvent.SmContext,
		pfcpModEvent.PdrList, pfcpModEvent.FarList, pfcpModEvent.BarList, pfcpModEvent.QerList)

	logger.FsmLog.Traceln("Out fsmHandlePfcpModifySess")
	return nil
}

func fsmHandlePfcpDeleteSess(evtData EventData) error {
	logger.FsmLog.Traceln("In fsmHandlePfcpDeleteSess")

	pfcpDeleteEvent := evtData.Data.(*PfcpDeleteEventData)

	pfcpDeleteEvent.SmContext.ChangeState(smf_context.PFCPDeletion)
	pfcp_message.ReleaseTunnel(pfcpDeleteEvent.SmContext)

	logger.FsmLog.Traceln("Out fsmHandlePfcpDeleteSess")

	return nil
}

func PreparePfcpModEventData(pdrList []*smf_context.PDR,
	farList []*smf_context.FAR, qerList []*smf_context.QER,
	barList []*smf_context.BAR, UpNodeID pfcpType.NodeID,
	smContext *smf_context.SMContext) EventData {

	evtData := EventData{
		Data: &PfcpModEventData{PdrList: pdrList, FarList: farList, QerList: qerList, BarList: barList, UpNodeID: UpNodeID, SmContext: smContext},
	}
	return evtData
}

func PreparePfcpDeleteEventData(smContext *smf_context.SMContext) EventData {

	evtData := EventData{
		Data: &PfcpDeleteEventData{SmContext: smContext},
	}
	return evtData
}

func (event fsmEvent) String() string {
	switch event {
	case PFCPSessModify:
		return "PFCPSessModify"
	case PFCPSessDelete:
		return "PFCPSessDelete"
	default:
		return "Unknown Event"
	}
}
