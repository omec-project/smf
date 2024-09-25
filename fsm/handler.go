// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"fmt"

	mi "github.com/omec-project/metricfunc/pkg/metricinfo"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	stats "github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/producer"
	"github.com/omec-project/smf/transaction"
)

// Define SM Context level Events
type SmEvent uint

const (
	SmEventInvalid SmEvent = iota
	SmEventPduSessCreate
	SmEventPduSessModify
	SmEventPduSessRelease
	SmEventPfcpSessCreate
	SmEventPfcpSessCreateFailure
	SmEventPfcpSessModify
	SmEventPfcpSessRelease
	SmEventPduSessN1N2Transfer
	SmEventPduSessN1N2TransferFailureIndication
	SmEventPolicyUpdateNotify
	SmEventMax
)

type SmEventData struct {
	Txn interface{}
}

// Define FSM Func Point Struct here
type eventHandler func(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error)

var SmfFsmHandler [smf_context.SmStateMax][SmEventMax]eventHandler

func init() {
	// Initilise with default invalid handler
	for state := smf_context.SmStateInit; state < smf_context.SmStateMax; state++ {
		for event := SmEventInvalid; event < SmEventMax; event++ {
			SmfFsmHandler[state][event] = EmptyEventHandler
		}
	}

	InitFsm()
	transaction.InitTxnFsm(SmfTxnFsmHandle)
}

// Override with specific handler
func InitFsm() {
	SmfFsmHandler[smf_context.SmStateInit][SmEventPduSessCreate] = HandleStateInitEventPduSessCreate
	SmfFsmHandler[smf_context.SmStatePfcpCreatePending][SmEventPfcpSessCreate] = HandleStatePfcpCreatePendingEventPfcpSessCreate
	SmfFsmHandler[smf_context.SmStatePfcpCreatePending][SmEventPfcpSessCreateFailure] = HandleStatePfcpCreatePendingEventPfcpSessCreateFailure
	SmfFsmHandler[smf_context.SmStateN1N2TransferPending][SmEventPduSessN1N2Transfer] = HandleStateN1N2TransferPendingEventN1N2Transfer
	SmfFsmHandler[smf_context.SmStateActive][SmEventPduSessModify] = HandleStateActiveEventPduSessModify
	SmfFsmHandler[smf_context.SmStateActive][SmEventPduSessRelease] = HandleStateActiveEventPduSessRelease
	SmfFsmHandler[smf_context.SmStateActive][SmEventPduSessN1N2TransferFailureIndication] = HandleStateActiveEventPduSessN1N2TransFailInd
	SmfFsmHandler[smf_context.SmStateActive][SmEventPolicyUpdateNotify] = HandleStateActiveEventPolicyUpdateNotify
}

func HandleEvent(smContext *smf_context.SMContext, event SmEvent, eventData SmEventData) error {
	ctxtState := smContext.SMContextState
	smContext.SubFsmLog.Debugf("handle fsm event[%v], state[%v] ", event.String(), ctxtState.String())
	if nextState, err := SmfFsmHandler[smContext.SMContextState][event](event, &eventData); err != nil {
		smContext.SubFsmLog.Errorf("fsm state[%v] event[%v], next-state[%v] error, %v",
			smContext.SMContextState.String(), event.String(), nextState.String(), err.Error())
		return err
	} else {
		smContext.ChangeState(nextState)
	}

	return nil
}

type SmfTxnFsm struct{}

var SmfTxnFsmHandle SmfTxnFsm

func EmptyEventHandler(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)
	smCtxt.SubFsmLog.Errorf("unhandled event[%s] ", event.String())
	return smCtxt.SMContextState, fmt.Errorf("fsm error, unhandled event[%s] and event data[%s] ", event.String(), eventData.String())
}

func HandleStateInitEventPduSessCreate(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	if err := producer.HandlePDUSessionSMContextCreate(eventData.Txn); err != nil {
		err := stats.PublishMsgEvent(mi.Smf_msg_type_pdu_sess_create_rsp_failure)
		var errorMessage string = ""
		if err != nil {
			logger.FsmLog.Errorf("error while publishing pdu session create response failure, %v ", err.Error())
			errorMessage = err.Error()
		}
		txn := eventData.Txn.(*transaction.Transaction)
		txn.Err = err
		return smf_context.SmStateInit, fmt.Errorf("pdu session create error, %v ", errorMessage)
	}

	err := stats.PublishMsgEvent(mi.Smf_msg_type_pdu_sess_create_rsp_success)
	if err != nil {
		logger.FsmLog.Errorf("error while publishing pdu session create response success, %v ", err.Error())
	}
	return smf_context.SmStatePfcpCreatePending, nil
}

func HandleStatePfcpCreatePendingEventPfcpSessCreate(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)

	producer.SendPFCPRules(smCtxt)
	smCtxt.SubFsmLog.Debug("waiting for pfcp session establish response")
	switch <-smCtxt.SBIPFCPCommunicationChan {
	case smf_context.SessionEstablishSuccess:
		smCtxt.SubFsmLog.Debug("pfcp session establish response success")
		return smf_context.SmStateN1N2TransferPending, nil
	case smf_context.SessionEstablishFailed:
		fallthrough
	default:
		smCtxt.SubFsmLog.Errorf("pfcp session establish response failure")
		return smf_context.SmStatePfcpCreatePending, fmt.Errorf("pfcp establishment failure")
	}
}

func HandleStateN1N2TransferPendingEventN1N2Transfer(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)

	if err := producer.SendPduSessN1N2Transfer(smCtxt, true); err != nil {
		err := stats.PublishMsgEvent(mi.Smf_msg_type_pdu_sess_modify_rsp_failure)
		if err != nil {
			smCtxt.SubFsmLog.Errorf("error while publishing pdu session modify response failure, %v ", err.Error())
		}
		smCtxt.SubFsmLog.Errorf("N1N2 transfer failure error, %v ", err.Error())
		return smf_context.SmStateN1N2TransferPending, fmt.Errorf("N1N2 Transfer failure error, %v ", err.Error())
	}
	err := stats.PublishMsgEvent(mi.Smf_msg_type_pdu_sess_modify_rsp_success)
	if err != nil {
		smCtxt.SubFsmLog.Errorf("error while publishing pdu session modify response success, %v ", err.Error())
	}
	return smf_context.SmStateActive, nil
}

func HandleStatePfcpCreatePendingEventPfcpSessCreateFailure(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)

	// sending n1n2 transfer failure to amf
	if err := producer.SendPduSessN1N2Transfer(smCtxt, false); err != nil {
		smCtxt.SubFsmLog.Errorf("N1N2 transfer failure error, %v ", err.Error())
		return smf_context.SmStateN1N2TransferPending, fmt.Errorf("N1N2 Transfer failure error, %v ", err.Error())
	}
	return smf_context.SmStateInit, nil
}

func HandleStateActiveEventPduSessCreate(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	// Context Replacement
	return smf_context.SmStateActive, nil
}

func HandleStateActiveEventPduSessModify(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)

	if err := producer.HandlePDUSessionSMContextUpdate(eventData.Txn); err != nil {
		smCtxt.SubFsmLog.Errorf("sm context update error, %v ", err.Error())
		return smf_context.SmStateActive, err
	}
	return smf_context.SmStateActive, nil
}

func HandleStateActiveEventPduSessRelease(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)

	if err := producer.HandlePDUSessionSMContextRelease(eventData.Txn); err != nil {
		err := stats.PublishMsgEvent(mi.Smf_msg_type_pdu_sess_release_rsp_failure)
		if err != nil {
			smCtxt.SubFsmLog.Errorf("error while publishing pdu session release response failure, %v ", err.Error())
		}
		smCtxt.SubFsmLog.Errorf("sm context release error, %v ", err.Error())
		return smf_context.SmStateInit, err
	}
	err := stats.PublishMsgEvent(mi.Smf_msg_type_pdu_sess_release_rsp_success)
	if err != nil {
		smCtxt.SubFsmLog.Errorf("error while publishing pdu session release response success, %v ", err.Error())
	}
	return smf_context.SmStateInit, nil
}

func HandleStateActiveEventPduSessN1N2TransFailInd(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)

	if err := producer.HandlePduSessN1N2TransFailInd(eventData.Txn); err != nil {
		smCtxt.SubFsmLog.Errorf("error while processing HandlePduSessN1N2TransferFailureIndication, %v ", err.Error())
		return smf_context.SmStateInit, err
	}
	return smf_context.SmStateInit, nil
}

func HandleStateActiveEventPolicyUpdateNotify(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)

	if err := producer.HandleSMPolicyUpdateNotify(eventData.Txn); err != nil {
		txn.Err = err
		smCtxt.SubFsmLog.Errorf("sm policy update error, %v ", err.Error())
		return smf_context.SmStateActive, fmt.Errorf("pdu session create error, %v ", err.Error())
	}

	return smf_context.SmStateActive, nil
}
