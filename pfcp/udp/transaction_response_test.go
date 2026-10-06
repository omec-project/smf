// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package udp

import (
	"net"
	"testing"
	"time"
)

// TestResponseTransactionRetentionExpiryIsNotAFailure covers a SendingResponse transaction whose
// retention window expires with no retransmitted request. The datagram was already written, so the
// expiry is the normal, successful end of the transaction: Start must return nil. Returning an error
// there would make startTxLifeCycle count every ordinary heartbeat/session/association response as an
// N4 "Out/Failure" once the window closes.
func TestResponseTransactionRetentionExpiryIsNotAFailure(t *testing.T) {
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
		TxType:       SendingResponse,
	}

	if err := tx.Start(); err != nil {
		t.Errorf("SendingResponse retention expiry returned %v; a successfully written response must not be counted as a send failure", err)
	}
}

// TestResponseTransactionWriteErrorIsStillAFailure covers the other half of the distinction: a
// genuine write failure (here, a closed socket) must still surface as an error so it is counted.
func TestResponseTransactionWriteErrorIsStillAFailure(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to open loopback UDP socket: %v", err)
	}
	destAddr := conn.LocalAddr().(*net.UDPAddr)
	// Close before Start so WriteToUDP fails.
	conn.Close()

	SetRetryTimingForTest(1, time.Millisecond, time.Millisecond)

	tx := &Transaction{
		Conn:         conn,
		DestAddr:     destAddr,
		EventChannel: make(chan EventType, 1),
		SendMsg:      []byte{0x01},
		TxType:       SendingResponse,
	}

	if err := tx.Start(); err == nil {
		t.Error("a response whose write failed returned nil; a real send failure must still be counted")
	}
}
