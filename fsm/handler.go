// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"fmt"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
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
	Txn any
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
	producer.SetSessionTaskQueue(queueSessionTask)
}

// Override with specific handler
func InitFsm() {
	SmfFsmHandler[smf_context.SmStateInit][SmEventPduSessCreate] = HandleStateInitEventPduSessCreate
	SmfFsmHandler[smf_context.SmStatePfcpCreatePending][SmEventPfcpSessCreate] = HandleStatePfcpCreatePendingEventPfcpSessCreate
	SmfFsmHandler[smf_context.SmStatePfcpCreatePending][SmEventPfcpSessCreateFailure] = HandleStatePfcpCreatePendingEventPfcpSessCreateFailure
	SmfFsmHandler[smf_context.SmStateN1N2TransferPending][SmEventPduSessN1N2Transfer] = HandleStateN1N2TransferPendingEventN1N2Transfer
	SmfFsmHandler[smf_context.SmStateActive][SmEventPduSessModify] = HandleStateActiveEventPduSessModify
	// The UE's acknowledgement of a network-requested modification can arrive while the session is
	// still in PfcpModify: the state changes only after the N1/N2 transfer call returns, and on a
	// short link the UE can answer before the AMF has answered us. Without this the acknowledgement
	// met EmptyEventHandler and was dropped, after which T3591 retransmitted a command the UE had
	// already accepted and eventually abandoned a modification that had succeeded.
	SmfFsmHandler[smf_context.SmStatePfcpModify][SmEventPduSessModify] = HandleStateActiveEventPduSessModify
	// A UE-requested modification can also arrive for a context that was never established or is
	// being torn down: TS 24.501 subclause 6.4.2.6 item b still requires the #43 reject. Before this,
	// the event met EmptyEventHandler, HandleUpdateN1Msg's refusal was never reached, and the AMF got
	// a bare 500 with no N1 answer. HandleStateActiveEventPduSessModify is not reused here because it
	// returns SmStateActive on success, which would reactivate a session this refusal does not.
	SmfFsmHandler[smf_context.SmStateInit][SmEventPduSessModify] = HandleInactiveStateEventPduSessModify
	SmfFsmHandler[smf_context.SmStateInActivePending][SmEventPduSessModify] = HandleInactiveStateEventPduSessModify
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
		txn := eventData.Txn.(*transaction.Transaction)
		txn.Err = err
		return smf_context.SmStateInit, fmt.Errorf("pdu session create: %v", err)
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
		smCtxt.SubFsmLog.Errorf("N1N2 transfer failure error, %v ", err.Error())
		return smf_context.SmStateN1N2TransferPending, fmt.Errorf("N1N2 Transfer failure error, %v ", err.Error())
	}
	return smf_context.SmStateActive, nil
}

func HandleStatePfcpCreatePendingEventPfcpSessCreateFailure(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)

	// The create never finished establishing on the UPF, so nothing survives this rollback:
	// remove the context instead of leaving it parked in SmStatePfcpCreatePending or
	// SmStateN1N2TransferPending forever with no terminal Kafka event. Deferred so the
	// removal runs whether the N1N2 transfer failure notification to the AMF succeeds or
	// errors out; HandleEvent's follow-up ChangeState is a no-op once this has already moved
	// the context to the terminal SmStateRelease.
	defer smf_context.RemoveSMContext(smCtxt.Ref)

	// sending n1n2 transfer failure to amf
	if err := producer.SendPduSessN1N2Transfer(smCtxt, false); err != nil {
		smCtxt.SubFsmLog.Errorf("N1N2 transfer failure error, %v ", err.Error())
		return smf_context.SmStateN1N2TransferPending, fmt.Errorf("N1N2 Transfer failure error, %v ", err.Error())
	}
	return smf_context.SmStateInit, nil
}

// HandleStateActiveEventPduSessModify runs the update pipeline and returns the state
// HandlePDUSessionSMContextUpdate's own dispatch already left the context in, rather than assuming
// success always means SmStateActive: a UE-initiated release (TS 24.501 clause 6.3.3) moves the
// context to SmStatePfcpRelease then SmStateInActivePending internally before returning, and a
// hardcoded SmStateActive here would have HandleEvent's unconditional ChangeState stomp that back
// to Active immediately after -- reactivating a session whose user plane was just torn down and
// hiding the isSmContextInactive guards in n1n2_data_handler.go from ever seeing the real state on
// a subsequent retransmission.
func HandleStateActiveEventPduSessModify(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)

	if err := producer.HandlePDUSessionSMContextUpdate(eventData.Txn); err != nil {
		smCtxt.SubFsmLog.Errorf("sm context update error, %v ", err.Error())
		return smCtxt.SMContextState, err
	}
	return smCtxt.SMContextState, nil
}

// HandleInactiveStateEventPduSessModify runs the update pipeline for a context that is not active,
// without assuming it becomes active on success: HandlePDUSessionSMContextUpdate's own
// SmStateInit/SmStateInActivePending/SmStateRelease branch already answers 200 OK without changing
// state, and leaves the next state at whatever the call left it (e.g. SmStateRelease if the N1
// message it answered was a PDUSessionReleaseComplete).
func HandleInactiveStateEventPduSessModify(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)

	if err := producer.HandlePDUSessionSMContextUpdate(eventData.Txn); err != nil {
		smCtxt.SubFsmLog.Errorf("sm context update error, %v ", err.Error())
		return smCtxt.SMContextState, err
	}
	return smCtxt.SMContextState, nil
}

func HandleStateActiveEventPduSessRelease(event SmEvent, eventData *SmEventData) (smf_context.SMContextState, error) {
	txn := eventData.Txn.(*transaction.Transaction)
	smCtxt := txn.Ctxt.(*smf_context.SMContext)

	if err := producer.HandlePDUSessionSMContextRelease(eventData.Txn); err != nil {
		smCtxt.SubFsmLog.Errorf("sm context release error, %v ", err.Error())
		return smf_context.SmStateInit, err
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

	// A paging failure does not end a network-requested modification. The AMF reports it when its
	// paging gives up, which says nothing about a Command already sent: T3591 retransmits it, and the
	// UE's answer can still come. That answer is handled only in an update-capable state, so in
	// SmStateInit it was dropped while T3591 ran on, and the modification was abandoned although the
	// UE had applied it. The same holds once the UE has completed and the radio has not answered
	// (RanAnswerPending): its answer comes on the same update path, and in SmStateInit a refusal would
	// go uncorrected and a held decision be dropped. A paging failure that started a release
	// (SmStatePfcpRelease), or one with no modification pending, still ends in SmStateInit, as it did
	// before.
	smCtxt.SMLock.Lock()
	modifying := (smCtxt.NwModificationPending || smCtxt.RanAnswerPending) &&
		smCtxt.SMContextState == smf_context.SmStateActive
	smCtxt.SMLock.Unlock()
	if modifying {
		return smf_context.SmStateActive, nil
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

// queueSessionTask runs task as a transaction in the session's queue: after whatever the session is
// doing now, and before whatever arrives for it later.
func queueSessionTask(smContext *smf_context.SMContext, task func()) {
	txn := transaction.NewTransaction(task, nil, svcmsgtypes.SessionTask)
	txn.Ctxt = smContext
	go txn.StartTxnLifeCycle(SmfTxnFsmHandle)
}
