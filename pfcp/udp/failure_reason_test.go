// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package udp

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestOutFailureReasonIsBounded pins the N4 "Out/Failure" reason label to a fixed set. The label is
// a Prometheus dimension, so it must never carry per-attempt data: a request timeout wraps the
// sequence number and a socket write error the peer address. Two timeouts with different sequence
// numbers must therefore collapse to the one "Timeout" label, or the metric gains a time series per
// heartbeat/association attempt (unbounded cardinality).
func TestOutFailureReasonIsBounded(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"timeout seq 1", fmt.Errorf("%w, seq [%d]", ErrRequestTimeout, 1), ReasonTimeout},
		{"timeout seq 999999", fmt.Errorf("%w, seq [%d]", ErrRequestTimeout, 999999), ReasonTimeout},
		{"socket write error", fmt.Errorf("%w: %w", ErrWriteFailed, &net.OpError{Op: "write", Err: errors.New("connection refused")}), ReasonWriteError},
		{"other", errors.New("PFCP server is not initialized"), ReasonSendError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := OutFailureReason(tc.err); got != tc.want {
				t.Errorf("OutFailureReason(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}

	// The whole point: the sequence number must not reach the label.
	if OutFailureReason(cases[1].err) != OutFailureReason(cases[2].err) {
		t.Error("two request timeouts with different sequence numbers produced different reason labels; the sequence number is leaking into the metric")
	}
}

// TestRequestTimeoutClassifiesAsBoundedTimeout ties the classifier to the real error a timed-out
// request returns, so a future change to the error's wrapping cannot silently reintroduce the
// unbounded label.
func TestRequestTimeoutClassifiesAsBoundedTimeout(t *testing.T) {
	retries, reqTimeout, rspTimeout := GetRetryTimingForTest()
	t.Cleanup(func() { SetRetryTimingForTest(retries, reqTimeout, rspTimeout) })

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to open loopback UDP socket: %v", err)
	}
	defer conn.Close()

	SetRetryTimingForTest(1, time.Millisecond, time.Millisecond)

	tx := &Transaction{
		Conn:         conn,
		DestAddr:     conn.LocalAddr().(*net.UDPAddr),
		EventChannel: make(chan EventType, 1),
		SendMsg:      []byte{0x01},
		TxType:       SendingRequest,
	}

	startErr := tx.Start()
	if startErr == nil {
		t.Fatal("a request that received no response returned nil; expected a timeout")
	}
	if !errors.Is(startErr, ErrRequestTimeout) {
		t.Errorf("request timeout error %v is not wrapped with ErrRequestTimeout; errors.Is classification would break", startErr)
	}
	if got := OutFailureReason(startErr); got != ReasonTimeout {
		t.Errorf("real request timeout classified as %q, want %q", got, ReasonTimeout)
	}
}

// TestWriteFailureClassifiesAsBoundedWriteError ties the classifier to the real error a failed
// socket write returns, so a change to its wrapping cannot silently drop it into the catch-all (or,
// worse, leak the peer address into the label).
func TestWriteFailureClassifiesAsBoundedWriteError(t *testing.T) {
	retries, reqTimeout, rspTimeout := GetRetryTimingForTest()
	t.Cleanup(func() { SetRetryTimingForTest(retries, reqTimeout, rspTimeout) })

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to open loopback UDP socket: %v", err)
	}
	destAddr := conn.LocalAddr().(*net.UDPAddr)
	conn.Close() // close before Start so WriteToUDP fails

	SetRetryTimingForTest(1, time.Millisecond, time.Millisecond)

	tx := &Transaction{
		Conn:         conn,
		DestAddr:     destAddr,
		EventChannel: make(chan EventType, 1),
		SendMsg:      []byte{0x01},
		TxType:       SendingRequest,
	}

	startErr := tx.Start()
	if startErr == nil {
		t.Fatal("a request whose write failed returned nil; expected a write error")
	}
	if !errors.Is(startErr, ErrWriteFailed) {
		t.Errorf("write error %v is not wrapped with ErrWriteFailed; errors.Is classification would break", startErr)
	}
	if got := OutFailureReason(startErr); got != ReasonWriteError {
		t.Errorf("real write failure classified as %q, want %q", got, ReasonWriteError)
	}
}
