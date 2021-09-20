package fsm

import (
	"fmt"
	"net/http"

	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/openapi/models"
	smf_context "github.com/free5gc/smf/context"
	"github.com/free5gc/smf/logger"
	"github.com/free5gc/smf/msgtypes/svcmsgtypes"
	"github.com/free5gc/smf/producer"
	"github.com/free5gc/smf/transaction"
)

func (SmfTxnFsm) TxnInit(txn *transaction.Transaction) (transaction.TxnEvent, error) {
	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventInit.String())
	return transaction.TxnEventDecode, nil
}

func (SmfTxnFsm) TxnDecode(txn *transaction.Transaction) (transaction.TxnEvent, error) {

	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventDecode.String())
	return transaction.TxnEventLoadCtxt, nil
}

func (SmfTxnFsm) TxnLoadCtxt(txn *transaction.Transaction) (transaction.TxnEvent, error) {

	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventLoadCtxt.String())
	switch txn.MsgType {
	case svcmsgtypes.NsmfPDUSessionCreate:
		req := txn.Req.(models.PostSmContextsRequest)
		createData := req.JsonData
		if smCtxtRef, err := smf_context.ResolveRef(createData.Supi, createData.PduSessionId); err == nil {
			//Previous context exist
			producer.HandlePduSessionContextReplacement(smCtxtRef)
		}
		//Create fresh context
		txn.Ctxt = smf_context.NewSMContext(createData.Supi, createData.PduSessionId)

	case svcmsgtypes.NsmfPDUSessionUpdateSmContext:
		//req := txn.Req.(models.UpdateSmContextRequest)
		fallthrough
	case svcmsgtypes.NsmfPDUSessionReleaseSmContext:
		txn.Ctxt = smf_context.GetSMContext(txn.CtxtKey)
		//req := txn.Req.(models.ReleaseSmContextRequest)
	case svcmsgtypes.SmEventPfcpSessCreate:
		fallthrough
	case svcmsgtypes.NamfCommunicationN1N2MessageTransfer:
		//Pre-loaded- No action
	default:
		txn.TxnFsmLog.Errorf("handle event[%v], next-event[%v], unknown msgtype [%v] ",
			transaction.TxnEventInit.String(), transaction.TxnEventFailure.String(), txn.MsgType)
		return transaction.TxnEventFailure, fmt.Errorf("invalid Msg to load Txn")
	}

	if txn.Ctxt == nil {
		txn.TxnFsmLog.Errorf("handle event[%v], ctxt [%v] not found", transaction.TxnEventInit.String(), txn.CtxtKey)
		return transaction.TxnEventFailure, fmt.Errorf("ctxt not found")
	}

	return transaction.TxnEventCtxtPost, nil
}

func (SmfTxnFsm) TxnCtxtPost(txn *transaction.Transaction) (transaction.TxnEvent, error) {

	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventCtxtPost.String())
	smContext := txn.Ctxt.(*smf_context.SMContext)

	//If already Active Txn running then post it to SMF Txn Bus
	if smContext.ActiveTxn != nil {
		//Lock the bus before modifying
		smContext.SMTxnBusLock.Lock()
		defer smContext.SMTxnBusLock.Unlock()
		smContext.TxnBus = smContext.TxnBus.AddTxn(txn)

		//Txn has been posted and shall be scheduled later
		txn.TxnFsmLog.Debugf("event[%v], next-event[%v], txn queued ", transaction.TxnEventCtxtPost.String(), transaction.TxnEventExit.String())
		return transaction.TxnEventExit, nil
	}

	//No other Txn running, lets proceed with current Txn

	return transaction.TxnEventRun, nil
}

func (SmfTxnFsm) TxnCtxtRun(txn *transaction.Transaction) (transaction.TxnEvent, error) {

	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventRun.String())
	smContext := txn.Ctxt.(*smf_context.SMContext)

	//There shouldn't be any active Txn if current Txn has reached to Run state
	//Probably, abort it
	if smContext.ActiveTxn != nil {
		logger.TxnFsmLog.Errorf("active transaction [%v] not completed", smContext.ActiveTxn)
	}

	//make current txn as Active now, move it to processing
	smContext.ActiveTxn = txn
	return transaction.TxnEventProcess, nil
}

func (SmfTxnFsm) TxnProcess(txn *transaction.Transaction) (transaction.TxnEvent, error) {
	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventProcess.String())
	smContext := txn.Ctxt.(*smf_context.SMContext)
	if smContext == nil {
		txn.TxnFsmLog.Errorf("event[%v], next-event[%v], SM context invalid ", transaction.TxnEventProcess.String(), transaction.TxnEventFailure.String())
		return transaction.TxnEventFailure, fmt.Errorf("TxnProcess, invalid SM Ctxt")
	}

	var event SmEvent

	switch txn.MsgType {
	case svcmsgtypes.NsmfPDUSessionCreate:
		event = SmEventPduSessCreate
	case svcmsgtypes.NsmfPDUSessionUpdateSmContext:
		event = SmEventPduSessModify
		//req := txn.Req.(models.UpdateSmContextRequest)
	case svcmsgtypes.NsmfPDUSessionReleaseSmContext:
		event = SmEventPduSessRelease
	case svcmsgtypes.SmEventPfcpSessCreate:
		event = SmEventPfcpSessCreate
	case svcmsgtypes.NamfCommunicationN1N2MessageTransfer:
		event = SmEventPduSessN1N2Transfer
	default:
		event = SmEventInvalid

	}

	eventData := SmEventData{Txn: txn}

	if err := HandleEvent(smContext, event, eventData); err != nil {
		smContext.SubFsmLog.Errorf("handle event[%v], err [%s]", transaction.TxnEventProcess.String(), err.Error())
		return transaction.TxnEventFailure, err
	}
	return transaction.TxnEventSuccess, nil
}

func (SmfTxnFsm) TxnSuccess(txn *transaction.Transaction) (transaction.TxnEvent, error) {
	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventSuccess.String())

	switch txn.MsgType {
	case svcmsgtypes.SmEventPfcpSessCreate:

		nextTxn := transaction.NewTransaction(nil, nil, svcmsgtypes.SmfMsgType(svcmsgtypes.NamfCommunicationN1N2MessageTransfer))
		nextTxn.Ctxt = txn.Ctxt
		smContext := txn.Ctxt.(*smf_context.SMContext)
		smContext.SMTxnBusLock.Lock()
		smContext.TxnBus = smContext.TxnBus.AddTxn(nextTxn)
		smContext.SMTxnBusLock.Unlock()
		go func(nextTxn *transaction.Transaction) {
			//Initiate N1N2 Transfer

			//nextTxn.StartTxnLifeCycle(SmfTxnFsmHandle)
			<-nextTxn.Status
		}(nextTxn)
	}

	//put Success Rsp
	txn.Status <- true
	return transaction.TxnEventEnd, nil
}

func (SmfTxnFsm) TxnFailure(txn *transaction.Transaction) (transaction.TxnEvent, error) {
	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventFailure.String())

	//Put Failure Rsp
	switch txn.MsgType {
	case svcmsgtypes.NsmfPDUSessionUpdateSmContext:
		if txn.Ctxt == nil {
			logger.PduSessLog.Warnf("PDUSessionSMContextUpdate, SMContext[%s] is not found", txn.CtxtKey)

			httpResponse := &http_wrapper.Response{
				Header: nil,
				Status: http.StatusNotFound,
				Body: models.UpdateSmContextErrorResponse{
					JsonData: &models.SmContextUpdateError{
						UpCnxState: models.UpCnxState_DEACTIVATED,
						Error: &models.ProblemDetails{
							Type:   "Resource Not Found",
							Title:  "SMContext Ref is not found",
							Status: http.StatusNotFound,
						},
					},
				},
			}
			txn.Rsp = httpResponse
		}

	case svcmsgtypes.NsmfPDUSessionReleaseSmContext:
		if txn.Ctxt == nil {
			logger.PduSessLog.Warnf("PDUSessionSMContextRelease [%s] is not found", txn.CtxtKey)

			httpResponse := &http_wrapper.Response{
				Header: nil,
				Status: http.StatusNotFound,
				Body: models.UpdateSmContextErrorResponse{
					JsonData: &models.SmContextUpdateError{
						UpCnxState: models.UpCnxState_DEACTIVATED,
						Error: &models.ProblemDetails{
							Type:   "Resource Not Found",
							Title:  "SMContext Ref is not found",
							Status: http.StatusNotFound,
						},
					},
				},
			}
			txn.Rsp = httpResponse
		}
	}
	txn.Status <- false
	return transaction.TxnEventEnd, nil
}

func (SmfTxnFsm) TxnAbort(txn *transaction.Transaction) (transaction.TxnEvent, error) {
	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventAbort.String())
	return transaction.TxnEventEnd, nil
}

func (SmfTxnFsm) TxnSave(txn *transaction.Transaction) (transaction.TxnEvent, error) {
	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventSave.String())
	return transaction.TxnEventEnd, nil
}

func (SmfTxnFsm) TxnTimeout(txn *transaction.Transaction) (transaction.TxnEvent, error) {
	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventTimeout.String())
	return transaction.TxnEventEnd, nil
}

func (SmfTxnFsm) TxnCollision(txn *transaction.Transaction) (transaction.TxnEvent, error) {
	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventCollision.String())
	return transaction.TxnEventEnd, nil
}

func (SmfTxnFsm) TxnEnd(txn *transaction.Transaction) (transaction.TxnEvent, error) {

	txn.TxnFsmLog.Debugf("handle event[%v] ", transaction.TxnEventEnd.String())
	smContext := txn.Ctxt.(*smf_context.SMContext)
	txn.TransactionEnd()
	smContext.ActiveTxn = nil

	var nextTxn *transaction.Transaction
	//Active Txn is over, now Pull out head Txn and Run it
	if len(smContext.TxnBus) > 0 {
		//Lock txnbus to access
		smContext.SMTxnBusLock.Lock()
		defer smContext.SMTxnBusLock.Unlock()
		nextTxn, smContext.TxnBus = smContext.TxnBus.PopTxn()
		txn.NextTxn = nextTxn
		return transaction.TxnEventRun, nil
	}

	return transaction.TxnEventExit, nil
}

/// Suggestions
//1. Global pipeline for txns
//2. Memory alloc pool for txns
