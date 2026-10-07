// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package udp

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// n4OutFailures reads the current n4_messages_total counter for Out/Failure of msgType. When reason
// is "" it sums across every reason label; otherwise it matches that one reason. Reading through the
// default gatherer (not the unexported CounterVec) keeps the test at the real metric boundary.
func n4OutFailures(t *testing.T, msgType, reason string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	var total float64
	for _, mf := range mfs {
		if mf.GetName() != "n4_messages_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["msg_type"] != msgType || labels["direction"] != "Out" || labels["result"] != "Failure" {
				continue
			}
			if reason != "" && labels["reason"] != reason {
				continue
			}
			total += m.GetCounter().GetValue()
		}
	}
	return total
}

// heartbeatRequestBytes builds a real, parseable Heartbeat Request so startTxLifeCycle's
// message.Parse(tx.SendMsg) succeeds and reaches the failure-reporting logic under test. Returns the
// wire bytes and the message type name used as the metric label.
func heartbeatRequestBytes(t *testing.T) ([]byte, string) {
	t.Helper()
	msg := message.NewHeartbeatRequest(1, ie.NewRecoveryTimeStamp(time.Now()), nil)
	buf := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(buf); err != nil {
		t.Fatalf("marshal heartbeat request: %v", err)
	}
	return buf, msg.MessageTypeName()
}

// loopbackSocket opens a loopback UDP socket a transaction can write to; the datagram goes nowhere
// useful, so a SendingRequest transaction never sees a response and times out.
func loopbackSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("open loopback UDP socket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// TestFallbackCountsNativeTimeoutExactlyOnce covers the no-handler path: a native send (nil event
// data) that times out must be counted as exactly one N4 Out/Failure, with the bounded Timeout
// reason -- this is the "exactly once" behavior the change set exists for.
func TestFallbackCountsNativeTimeoutExactlyOnce(t *testing.T) {
	retries, reqTimeout, rspTimeout := GetRetryTimingForTest()
	t.Cleanup(func() { SetRetryTimingForTest(retries, reqTimeout, rspTimeout) })
	SetRetryTimingForTest(1, time.Millisecond, time.Millisecond)

	conn := loopbackSocket(t)
	buf, msgType := heartbeatRequestBytes(t)

	beforeTimeout := n4OutFailures(t, msgType, ReasonTimeout)
	beforeAll := n4OutFailures(t, msgType, "")

	tx := &Transaction{
		Conn:         conn,
		DestAddr:     conn.LocalAddr().(*net.UDPAddr),
		EventChannel: make(chan EventType, 1),
		SendMsg:      buf,
		TxType:       SendingRequest,
		EventData:    nil, // native send: no error handler, so the fallback is the sole reporter
	}
	startTxLifeCycle(tx)

	if got := n4OutFailures(t, msgType, ReasonTimeout) - beforeTimeout; got != 1 {
		t.Errorf("Out/Failure[%s] delta = %v, want 1 (exactly-once fallback count)", ReasonTimeout, got)
	}
	if got := n4OutFailures(t, msgType, "") - beforeAll; got != 1 {
		t.Errorf("total Out/Failure delta = %v, want 1 (no extra reason series)", got)
	}
}

// TestFallbackDefersToHandlerWithoutDoubleCounting covers the handler path: when a PfcpEventData
// error handler is present, it is the single reporter. The fallback must NOT also increment the
// metric, or a session send failure would be counted twice.
func TestFallbackDefersToHandlerWithoutDoubleCounting(t *testing.T) {
	retries, reqTimeout, rspTimeout := GetRetryTimingForTest()
	t.Cleanup(func() { SetRetryTimingForTest(retries, reqTimeout, rspTimeout) })
	SetRetryTimingForTest(1, time.Millisecond, time.Millisecond)

	conn := loopbackSocket(t)
	buf, msgType := heartbeatRequestBytes(t)

	before := n4OutFailures(t, msgType, "")

	var handlerCalled bool
	var handlerErr error
	tx := &Transaction{
		Conn:         conn,
		DestAddr:     conn.LocalAddr().(*net.UDPAddr),
		EventChannel: make(chan EventType, 1),
		SendMsg:      buf,
		TxType:       SendingRequest,
		EventData: PfcpEventData{ErrHandler: func(_ message.Message, err error) {
			handlerCalled = true
			handlerErr = err
		}},
	}
	startTxLifeCycle(tx)

	if !handlerCalled {
		t.Error("error handler was not invoked on an asynchronous timeout")
	}
	if !errors.Is(handlerErr, ErrRequestTimeout) {
		t.Errorf("handler received %v, want a wrapped ErrRequestTimeout", handlerErr)
	}
	if got := n4OutFailures(t, msgType, "") - before; got != 0 {
		t.Errorf("fallback incremented Out/Failure by %v although a handler was present; want 0 (the handler is the sole reporter)", got)
	}
}

// TestFallbackCountsNoFailureForResponseRetentionExpiry covers the response path: a SendingResponse
// transaction whose retention window expires wrote its datagram successfully, so Start returns nil
// and startTxLifeCycle must count no failure at all.
func TestFallbackCountsNoFailureForResponseRetentionExpiry(t *testing.T) {
	retries, reqTimeout, rspTimeout := GetRetryTimingForTest()
	t.Cleanup(func() { SetRetryTimingForTest(retries, reqTimeout, rspTimeout) })
	SetRetryTimingForTest(1, time.Millisecond, time.Millisecond)

	conn := loopbackSocket(t)
	buf, msgType := heartbeatRequestBytes(t)

	before := n4OutFailures(t, msgType, "")

	tx := &Transaction{
		Conn:         conn,
		DestAddr:     conn.LocalAddr().(*net.UDPAddr),
		EventChannel: make(chan EventType, 1),
		SendMsg:      buf,
		TxType:       SendingResponse,
		EventData:    nil,
	}
	startTxLifeCycle(tx)

	if got := n4OutFailures(t, msgType, "") - before; got != 0 {
		t.Errorf("response-retention expiry counted %v Out/Failure, want 0 (a written response is not a send failure)", got)
	}
}
