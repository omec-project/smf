// Copyright 2019 free5GC.org
// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package udp

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/omec-project/smf/logger"
	"github.com/wmnsk/go-pfcp/message"
)

type TransactionType uint8

type TxTable struct {
	m sync.Map // map[uint32]*Transaction
}

func (t *TxTable) Store(sequenceNumber uint32, tx *Transaction) {
	t.m.Store(sequenceNumber, tx)
}

func (t *TxTable) Load(sequenceNumber uint32) (*Transaction, bool) {
	if t == nil {
		logger.PfcpLog.Warnf("TxTable is nil")
		return nil, false
	}

	tx, ok := t.m.Load(sequenceNumber)
	if ok {
		return tx.(*Transaction), ok
	}
	return nil, false
}

func (t *TxTable) Delete(sequenceNumber uint32) {
	t.m.Delete(sequenceNumber)
}

const (
	SendingRequest TransactionType = iota
	SendingResponse
)

// Kept as untyped-int constants, seconds-based, for API/source compatibility: they were exported
// this way before, and a caller doing e.g. time.Duration(ResendRequestTimeOutPeriod) * time.Second
// must keep working and NumOfResend must stay usable wherever a constant is required.
const (
	NumOfResend                 = 3
	ResendRequestTimeOutPeriod  = 3
	ResendResponseTimeOutPeriod = 15
)

// numOfResend, resendRequestTimeout and resendResponseTimeout are what Start actually reads. They
// default to the public constants above but, unlike them, can be overridden at runtime -- see
// SetRetryTimingForTest. A transaction goroutine started by SendPfcp is not tied to any test's
// lifecycle, and at the production values above it can easily outlive the sub-second test that
// spawned it, later touching memory the runtime has since reused for an unrelated test's stack --
// a real race the detector will report between two logically unrelated tests.
//
// They are atomics, rather than plain package vars, so SetRetryTimingForTest can be called
// concurrently with Start without racing; Start additionally reads them once into local variables
// at the top of a run, so a single transaction always retries with one consistent timing even if
// SetRetryTimingForTest is called again while it is in flight.
var (
	numOfResend           atomic.Int32
	resendRequestTimeout  atomic.Int64
	resendResponseTimeout atomic.Int64
)

func init() {
	numOfResend.Store(NumOfResend)
	resendRequestTimeout.Store(int64(ResendRequestTimeOutPeriod * time.Second))
	resendResponseTimeout.Store(int64(ResendResponseTimeOutPeriod * time.Second))
}

// SetRetryTimingForTest overrides the resend count and timeout periods Start uses. It exists so
// tests can bound how long a leaked transaction goroutine survives without changing the public,
// seconds-based NumOfResend/ResendRequestTimeOutPeriod/ResendResponseTimeOutPeriod constants that
// callers may already depend on. Production code must not call this.
func SetRetryTimingForTest(retries int, requestTimeout, responseTimeout time.Duration) {
	numOfResend.Store(int32(retries))
	resendRequestTimeout.Store(int64(requestTimeout))
	resendResponseTimeout.Store(int64(responseTimeout))
}

type Transaction struct {
	EventChannel   chan EventType
	Conn           *net.UDPConn
	DestAddr       *net.UDPAddr
	ConsumerAddr   string
	ErrHandler     func(*message.Message, error)
	EventData      interface{}
	SendMsg        []byte
	SequenceNumber uint32
	MessageType    uint8
	TxType         TransactionType
}

func NewTransaction(pfcpMSG message.Message, binaryMSG []byte, Conn *net.UDPConn, DestAddr *net.UDPAddr, eventData interface{}) *Transaction {
	tx := &Transaction{
		SendMsg:        binaryMSG,
		SequenceNumber: pfcpMSG.Sequence(),
		MessageType:    pfcpMSG.MessageType(),
		EventChannel:   make(chan EventType, 1),
		Conn:           Conn,
		DestAddr:       DestAddr,
		EventData:      eventData,
	}

	if IsRequest(pfcpMSG) {
		tx.TxType = SendingRequest
		tx.ConsumerAddr = Conn.LocalAddr().String()
	} else if IsResponse(pfcpMSG) {
		tx.TxType = SendingResponse
		tx.ConsumerAddr = DestAddr.String()
	}
	logger.PfcpLog.Debugf("new Transaction SEQ[%d] DestAddr[%s]", tx.SequenceNumber, DestAddr.String())
	return tx
}

func (transaction *Transaction) Start() error {
	logger.PfcpLog.Debugf("start transaction [%d]", transaction.SequenceNumber)

	// Snapshotting once here, rather than reading the atomics on every iteration below, keeps a
	// single transaction's retries consistent even if SetRetryTimingForTest changes the timing
	// concurrently (e.g. between test cases).
	retries := int(numOfResend.Load())
	requestTimeout := time.Duration(resendRequestTimeout.Load())
	responseTimeout := time.Duration(resendResponseTimeout.Load())

	if transaction.TxType == SendingRequest {
		for iter := 0; iter < retries; iter++ {
			timer := time.NewTimer(requestTimeout)
			_, err := transaction.Conn.WriteToUDP(transaction.SendMsg, transaction.DestAddr)
			if err != nil {
				logger.PfcpLog.Warnf("request transaction [%d]: %s", transaction.SequenceNumber, err)
				return err
			}

			select {
			case event := <-transaction.EventChannel:

				if event == ReceiveValidResponse {
					logger.PfcpLog.Debugf("request transaction [%d]: receive valid response", transaction.SequenceNumber)
					return nil
				}
			case <-timer.C:
				logger.PfcpLog.Debugf("request transaction [%d]: timeout expire", transaction.SequenceNumber)
				logger.PfcpLog.Debugf("request transaction [%d]: Resend packet", transaction.SequenceNumber)
				continue
			}
		}
		// Num of retries exhausted, send failure back to app
		return fmt.Errorf("request timeout, seq [%d]", transaction.SequenceNumber)
	} else if transaction.TxType == SendingResponse {
		// Todo :Implement SendingResponse type of reliable delivery
		timer := time.NewTimer(responseTimeout)
		for iter := 0; iter < retries; iter++ {
			_, err := transaction.Conn.WriteToUDP(transaction.SendMsg, transaction.DestAddr)
			if err != nil {
				logger.PfcpLog.Warnf("response transaction [%d]: sending error", transaction.SequenceNumber)
				return err
			}

			select {
			case event := <-transaction.EventChannel:

				if event == ReceiveResendRequest {
					logger.PfcpLog.Debugf("response transaction [%d]: receive resend request", transaction.SequenceNumber)
					logger.PfcpLog.Debugf("response transaction [%d]: Resend packet", transaction.SequenceNumber)
					continue
				}
			case <-timer.C:
				logger.PfcpLog.Debugf("response transaction [%d]: timeout expire", transaction.SequenceNumber)
				return fmt.Errorf("response timeout, seq [%d]", transaction.SequenceNumber)
			}
		}
	}
	return nil
}
