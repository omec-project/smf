// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package udp

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/wmnsk/go-pfcp/message"
)

const PFCP_MAX_UDP_LEN = 2048

type ConsumerTable struct {
	m sync.Map // map[string]TxTable
}

type PfcpEventData struct {
	ErrHandler func(message.Message, error)
	LSEID      uint64
}

type PfcpServer struct {
	Addr *net.UDPAddr
	Conn *net.UDPConn
	// Consumer Table
	// Map Consumer IP to its tx table
	ConsumerTable ConsumerTable
	// Done is closed once the background read loop started by Run for this server has returned.
	// Closing Conn ends the loop, but that happens on another goroutine; callers that need the loop
	// to have actually exited (mainly tests restarting the server between iterations) should wait on
	// this rather than assuming Conn.Close returning means the loop is gone.
	Done chan struct{}
}

var Server *PfcpServer

var ServerStartTime time.Time

var serverMu sync.RWMutex

// txWG tracks the transaction goroutines started by SendPfcp so their lifetime can be awaited --
// see WaitForAllTransactions.
var txWG sync.WaitGroup

func GetServer() *PfcpServer {
	serverMu.RLock()
	defer serverMu.RUnlock()
	return Server
}

func SetServer(server *PfcpServer) {
	serverMu.Lock()
	defer serverMu.Unlock()
	Server = server
}

func GetServerStartTime() time.Time {
	serverMu.RLock()
	defer serverMu.RUnlock()
	return ServerStartTime
}

func SetServerStartTime(startTime time.Time) {
	serverMu.Lock()
	defer serverMu.Unlock()
	ServerStartTime = startTime
}

func (t *ConsumerTable) Load(consumerAddr string) (*TxTable, bool) {
	txTable, ok := t.m.Load(consumerAddr)
	if ok {
		return txTable.(*TxTable), ok
	}
	return nil, false
}

func (t *ConsumerTable) Store(consumerAddr string, txTable *TxTable) {
	t.m.Store(consumerAddr, txTable)
}

func Run(Dispatch func(*Message)) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(context.SMF_Self().CPNodeID.ResolveNodeIdToIp().String()),
		Port: context.SMF_Self().PFCPPort,
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to listen on %s: %v", addr.String(), err)
		return
	}
	server := &PfcpServer{
		Addr: addr,
		Conn: conn,
		Done: make(chan struct{}),
	}
	SetServer(server)
	logger.PfcpLog.Infof("Listen on %s", addr.String())

	go func() {
		// Bound to this call's own server/conn rather than re-fetching the (mutable) global on every
		// iteration: otherwise a later Run() call (e.g. a test restarting the server) rebinds the
		// global and this stale goroutine starts reading the new conn too, racing the new reader for
		// the same packets. A closed conn also ends the loop instead of spinning forever on it.
		defer close(server.Done)
		for {
			remoteAddr, pfcpMessage, eventData, err := readPfcpMessage(server)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					logger.PfcpLog.Infof("PFCP connection closed, stopping read loop")
					return
				}
				if err.Error() == "Receive resend PFCP request" {
					logger.PfcpLog.Infoln(err)
				} else {
					logger.PfcpLog.Warnf("Read PFCP error: %v", err)
				}
				continue
			}
			msg := NewMessage(remoteAddr, pfcpMessage, eventData)
			go Dispatch(&msg)
		}
	}()

	SetServerStartTime(time.Now())
}

func WaitForServer() error {
	timeout := 10 * time.Second
	t0 := time.Now()
	for {
		if time.Since(t0) > timeout {
			return fmt.Errorf("timeout waiting for PFCP server to start")
		}
		server := GetServer()
		if server != nil && server.Conn != nil {
			return nil
		}
		logger.PfcpLog.Infof("Waiting for PFCP server to start...")
		time.Sleep(1 * time.Second)
	}
}

// SendPfcp marshals msg and hands it to the transaction layer. On success it counts one N4
// "Out/Success" and returns nil; the transaction goroutine then reports any later, asynchronous
// failure (an unanswered request or a write that failed on its own goroutine) through the
// eventData error handler.
//
// A synchronous failure here -- marshalling, a missing server, or a duplicate-sequence
// PutTransaction error -- returns an error and is NOT counted at this layer: the goroutine that
// would report it is never started. Every caller must report that returned error through the
// exported ReportSendFailure (pfcp/message's reportSendFailure and handlePfcpSendError are thin
// wrappers over it) so the N4 "Out/Failure" count and DNS refresh still happen. Reporting lives in
// this package, not pfcp/message, precisely so a caller in any package can satisfy this contract
// without an import cycle. The counting was kept out of this function so the two failure paths
// (synchronous at the caller, asynchronous in the goroutine) are each reported exactly once.
func SendPfcp(msg message.Message, addr *net.UDPAddr, eventData any) error {
	server := GetServer()
	if server == nil {
		return fmt.Errorf("PFCP server is not initialized")
	}
	if server.Conn == nil {
		return fmt.Errorf("PFCP server is not listening")
	}

	buf := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(buf)
	if err != nil {
		return err
	}

	tx := NewTransaction(msg, buf, server.Conn, addr, eventData)
	err = PutTransaction(tx)
	if err != nil {
		logger.PfcpLog.Errorf("Failed to send PFCP message: %v", err)
		return err
	}
	txWG.Go(func() {
		startTxLifeCycle(tx)
	})
	metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, msg.MessageTypeName(), "Out", "Success", "")
	return nil
}

// WaitForAllTransactions blocks until every transaction goroutine started by SendPfcp has returned,
// including its error handler. It exists for tests: such a goroutine is not tied to the lifecycle
// of the test whose send started it, and its error handler reads shared state (e.g.
// factory.SmfConfig) that a later, unrelated test may rewrite -- a race the detector reports
// between the two. Draining before a test returns keeps a goroutine from outliving it. Production
// code has no reason to call this.
func WaitForAllTransactions() {
	txWG.Wait()
}

func readPfcpMessage(server *PfcpServer) (*net.UDPAddr, message.Message, any, error) {
	if server == nil {
		return nil, nil, nil, fmt.Errorf("PFCP server is not initialized")
	}
	if server.Conn == nil {
		return nil, nil, nil, fmt.Errorf("PFCP server is not listening")
	}

	buf := make([]byte, PFCP_MAX_UDP_LEN)
	n, addr, err := server.Conn.ReadFromUDP(buf)
	if err != nil {
		return addr, nil, nil, err
	}

	msg, err := message.Parse(buf[:n])
	if err != nil {
		logger.PfcpLog.Errorf("error parsing PFCP message: %v", err)
		return addr, nil, nil, err
	}

	var eventData any
	if IsRequest(msg) {
		// Todo: Implement SendingResponse type of reliable delivery
		tx, err := findTransaction(server, msg, addr)
		if err != nil {
			return addr, msg, nil, err
		} else if tx != nil {
			// err == nil && tx != nil => Resend Request
			err = fmt.Errorf("receive resend PFCP request")
			tx.EventChannel <- ReceiveResendRequest
			return addr, msg, nil, err
		} else {
			// err == nil && tx == nil => New Request
			return addr, msg, nil, nil
		}
	} else if IsResponse(msg) {
		tx, err := findTransaction(server, msg, server.Addr)
		if err != nil {
			return addr, msg, nil, err
		}
		eventData = tx.EventData
		tx.EventChannel <- ReceiveValidResponse
	}

	return addr, msg, eventData, nil
}

func findTransaction(server *PfcpServer, msg message.Message, addr *net.UDPAddr) (*Transaction, error) {
	var tx *Transaction
	consumerAddr := addr.String()

	if server == nil {
		return nil, fmt.Errorf("PFCP server is not initialized")
	}

	if IsResponse(msg) {
		if _, exist := server.ConsumerTable.Load(consumerAddr); !exist {
			return nil, fmt.Errorf("txTable not found")
		}

		txTable, _ := server.ConsumerTable.Load(consumerAddr)
		seqNum := msg.Sequence()

		if _, exist := txTable.Load(seqNum); !exist {
			return nil, fmt.Errorf("sequence number [%d] not found", seqNum)
		}

		tx, _ = txTable.Load(seqNum)
	} else if IsRequest(msg) {
		if _, exist := server.ConsumerTable.Load(consumerAddr); !exist {
			return nil, nil
		}
		txTable, _ := server.ConsumerTable.Load(consumerAddr)
		seqNum := msg.Sequence()
		if _, exist := txTable.Load(seqNum); !exist {
			return nil, nil
		}
		tx, _ = txTable.Load(seqNum)
	}
	return tx, nil
}

func PutTransaction(tx *Transaction) error {
	server := GetServer()
	consumerAddr := tx.ConsumerAddr
	if server == nil {
		return fmt.Errorf("PFCP server is not initialized")
	}
	if _, exist := server.ConsumerTable.Load(consumerAddr); !exist {
		server.ConsumerTable.Store(consumerAddr, &TxTable{})
	}
	txTable, _ := server.ConsumerTable.Load(consumerAddr)
	if _, exist := txTable.Load(tx.SequenceNumber); !exist {
		txTable.Store(tx.SequenceNumber, tx)
	} else {
		return fmt.Errorf("insert tx error: duplicate sequence number %d", tx.SequenceNumber)
	}
	return nil
}

// The bounded vocabulary for the N4 "Out/Failure" metric's reason label. Kept as named constants so
// the set stays small and explicit -- a Prometheus label with unbounded values (an error string
// carrying a sequence number or peer address) would spawn a time series per attempt.
const (
	ReasonTimeout    = "Timeout"
	ReasonWriteError = "WriteError"
	ReasonSendError  = "SendError"
)

// OutFailureReason maps a send failure to a bounded reason label for the N4 "Out/Failure" metric.
// The raw error must never be used as the label: a request timeout carries the sequence number (see
// ErrRequestTimeout) and a socket write error the peer address, so err.Error() would create a new
// n4_messages_total time series per attempt (unbounded Prometheus cardinality). The returned set is
// fixed to the Reason* constants (and "" for no error) while the full error stays in the logs for
// diagnosis.
func OutFailureReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrRequestTimeout):
		return ReasonTimeout
	case errors.Is(err, ErrWriteFailed):
		return ReasonWriteError
	default:
		return ReasonSendError
	}
}

// ReportSendFailure records a PFCP send failure that concerns no particular session: it logs the
// failure, counts exactly one bounded N4 "Out/Failure" (OutFailureReason, never err.Error()), and
// refreshes the SMF DNS cache so the next resolve can pick up a user plane that has moved.
//
// It lives in this layer, not pfcp/message, so the exported SendPfcp's synchronous-failure contract
// can be honoured by any caller: pfcp/message cannot be imported here (cycle), and reaching for an
// unexported reporter left callers outside pfcp/message unable to count a synchronous SendPfcp error.
// The asynchronous fallback below and pfcp/message's own reportSendFailure wrapper both route through
// this, so a failure is reported through exactly one path.
func ReportSendFailure(msg message.Message, err error) {
	logger.PfcpLog.Errorf("send of PFCP msg [%v] failed, %v", msg.MessageTypeName(), err)
	metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID,
		msg.MessageTypeName(), "Out", "Failure", OutFailureReason(err))

	// Refresh SMF DNS Cache in case of any send failure (includes timeout).
	context.RefreshDnsHostIpCache()
}

func startTxLifeCycle(tx *Transaction) {
	sendErr := tx.Start()

	err := removeTransaction(tx)
	if err != nil {
		logger.PfcpLog.Warnln(err)
	}

	if sendErr == nil {
		return
	}

	// An asynchronous send failure -- a request that exhausted its retries without a response, or a
	// write that failed on this goroutine -- must be counted as one N4 "Out/Failure" to balance the
	// "Out/Success" SendPfcp optimistically counted when it handed the message off. A session send
	// supplies a PfcpEventData error handler that reports it (and drives the session's own recovery),
	// so when one is present it is the single reporter. A native send with nil event data (a
	// heartbeat/association request, or any response) carries no handler, so without the fallback
	// below its failure would be left counted only as Out/Success -- exactly the native send failure
	// this change set out to count.
	msg, parseErr := message.Parse(tx.SendMsg)
	if parseErr != nil {
		logger.PfcpLog.Warnf("Parse message error: %v", parseErr)
		return
	}

	if eventData, ok := tx.EventData.(PfcpEventData); ok && eventData.ErrHandler != nil {
		eventData.ErrHandler(msg, sendErr)
		return
	}

	// Native send (nil event data: a heartbeat/association request, or any response) with no handler
	// to report it -- count it here, exactly once, as the single reporter for this transaction.
	ReportSendFailure(msg, sendErr)
}

func removeTransaction(tx *Transaction) error {
	server := GetServer()
	if server == nil {
		return fmt.Errorf("PFCP server is not initialized")
	}
	consumerAddr := tx.ConsumerAddr
	txTable, _ := server.ConsumerTable.Load(consumerAddr)

	if txTmp, exist := txTable.Load(tx.SequenceNumber); exist {
		tx = txTmp
		switch tx.TxType {
		case SendingRequest:
			logger.PfcpLog.Debugf("Remove Request Transaction [%d]", tx.SequenceNumber)
		case SendingResponse:
			logger.PfcpLog.Debugf("Remove Response Transaction [%d]", tx.SequenceNumber)
		default:
			logger.PfcpLog.Debugf("Remove Transaction [%d]", tx.SequenceNumber)
		}

		txTable.Delete(tx.SequenceNumber)
	} else {
		return fmt.Errorf("remove tx error: transaction [%d] doesn't exist", tx.SequenceNumber)
	}
	return nil
}
