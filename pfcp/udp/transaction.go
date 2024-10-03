// Copyright 2019 free5GC.org
// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package udp

import (
	"net"
	"sync"
	"time"

	"github.com/omec-project/smf/logger"
	"github.com/pkg/errors"
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

const (
	NumOfResend                 = 3
	ResendRequestTimeOutPeriod  = 3
	ResendResponseTimeOutPeriod = 15
)

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

	if transaction.TxType == SendingRequest {
		for iter := 0; iter < NumOfResend; iter++ {
			timer := time.NewTimer(ResendRequestTimeOutPeriod * time.Second)
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
		return errors.Errorf("request timeout, seq [%d]", transaction.SequenceNumber)
	} else if transaction.TxType == SendingResponse {
		// Todo :Implement SendingResponse type of reliable delivery
		timer := time.NewTimer(ResendResponseTimeOutPeriod * time.Second)
		for iter := 0; iter < NumOfResend; iter++ {
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
				return errors.Errorf("response timeout, seq [%d]", transaction.SequenceNumber)
			}
		}
	}
	return nil
}
