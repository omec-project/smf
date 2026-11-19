// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package handler_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/handler"
	"github.com/omec-project/smf/pfcp/lisequence"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func nilCtxTestConfig() {
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: new(false)},
				EnableUpfAdapter: false,
			},
		}
	}
}

func modRsp(seid uint64, seq uint32) *udp.Message {
	return &udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("4.4.4.4"), Port: 8805},
		PfcpMessage: message.NewSessionModificationResponse(0, 0, seid, seq, 0, ie.NewCause(ie.CauseRequestAccepted)),
	}
}

// The nil guard from omec-project/smf#643 sits after the interception block rather
// than immediately after the context lookup, so the two tests below pin both halves
// of that placement.

func TestLIModificationResponseNoSMContextIsDiscarded(t *testing.T) {
	nilCtxTestConfig()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handler panicked on a response for a released session: %v", r)
		}
	}()

	handler.HandlePfcpSessionModificationResponse(modRsp(0xDEADBEEF, 4242))
}

// The reason the guard cannot sit at the lookup. A modification this element sent
// for interception is answered on the sequence number alone, and it must still be
// answered when the session it referred to has since been released. Guarding at the
// lookup would discard the answer, and a refused activation would never be retried.
func TestLIAnswerSurvivesAReleasedSession(t *testing.T) {
	nilCtxTestConfig()

	const seq uint32 = 4243
	req := lisequence.Request{SEID: 0xDEADBEEF, NodeID: "5.5.5.5", Duplicating: true}
	lisequence.Mark(seq, req)

	var gotReq lisequence.Request
	var gotCause uint8
	var gotAnswered, called bool

	orig := handler.LIModificationAnswered
	handler.LIModificationAnswered = func(r lisequence.Request, cause uint8, answered bool) {
		gotReq, gotCause, gotAnswered, called = r, cause, answered, true
	}
	defer func() { handler.LIModificationAnswered = orig }()

	// No SM context is registered for this SEID, so the lookup yields nil.
	handler.HandlePfcpSessionModificationResponse(modRsp(0xDEADBEEF, seq))

	if !called {
		t.Fatal("the interception answer was not made for a released session; the nil guard is placed too early")
	}
	if gotReq.NodeID != req.NodeID || gotReq.Duplicating != req.Duplicating {
		t.Errorf("answered with the wrong request: got %+v, want %+v", gotReq, req)
	}
	if !gotAnswered || gotCause != ie.CauseRequestAccepted {
		t.Errorf("answered=%v cause=%d, want answered=true cause=%d", gotAnswered, gotCause, ie.CauseRequestAccepted)
	}
	if _, _, first := lisequence.Take(seq); first {
		t.Error("the sequence was not answered, so the interception block did not run")
	}
}
