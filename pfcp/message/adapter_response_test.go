// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
)

// In adapter mode the user plane's answer comes back in the body, so a status other than OK is not
// a slow answer -- it is the only answer there will be. Reporting it is what lets the caller stop
// waiting on SBIPFCPCommunicationChan; returning nil left it waiting for a response that could not
// arrive.
//
// The body is a message that parses, deliberately. With an empty one the status check can be
// removed and this still passes, because the parse fails instead and the function reports that --
// the test would then be asserting that something went wrong rather than that the refusal was
// noticed.
func TestAnAdapterThatRefusesTheModificationIsReported(t *testing.T) {
	answer := pfcp_message.NewSessionModificationResponse(0, 0, 1, 1, 0,
		ie.NewCause(ie.CauseRequestAccepted))

	body := make([]byte, answer.MarshalLen())
	if err := answer.MarshalTo(body); err != nil {
		t.Fatalf("marshalling the answer: %v", err)
	}

	recorder := httptest.NewRecorder()
	recorder.WriteHeader(http.StatusBadGateway)

	if _, err := recorder.Write(body); err != nil {
		t.Fatalf("writing the body: %v", err)
	}

	if err := handleAdapterModificationResponse(recorder.Result(), 1); err == nil {
		t.Error("a refusal from the adapter was reported as a delivered modification")
	}
}

// And an answer that did arrive is still dispatched rather than treated as a refusal.
func TestAnAdapterAnswerThatCannotBeParsedIsReported(t *testing.T) {
	recorder := httptest.NewRecorder()
	recorder.WriteHeader(http.StatusOK)

	if _, err := recorder.WriteString("not a pfcp message"); err != nil {
		t.Fatalf("writing the body: %v", err)
	}

	if err := handleAdapterModificationResponse(recorder.Result(), 1); err == nil {
		t.Error("a reply that is not a PFCP message was reported as a delivered modification")
	}
}

// And an answer that parses but that the handler cannot use -- here, a modification response with
// no Cause -- is reported too. The handler used to drop it in silence, dispatch returned nil, and
// the caller then waited on SBIPFCPCommunicationChan for a verdict nothing would write.
func TestAnAdapterAnswerTheHandlerCannotUseIsReported(t *testing.T) {
	answer := pfcp_message.NewSessionModificationResponse(0, 0, 1, 1, 0)

	body := make([]byte, answer.MarshalLen())
	if err := answer.MarshalTo(body); err != nil {
		t.Fatalf("marshalling the answer: %v", err)
	}

	recorder := httptest.NewRecorder()
	recorder.WriteHeader(http.StatusOK)

	if _, err := recorder.Write(body); err != nil {
		t.Fatalf("writing the body: %v", err)
	}

	if err := handleAdapterModificationResponse(recorder.Result(), 1); err == nil {
		t.Error("a modification response with no Cause was reported as delivered")
	}
}

// A heartbeat the adapter refused is a heartbeat that failed. It fell through to the success
// return, and the heartbeat loop counts only failures it is told about toward declaring a user
// plane lost -- so a refusing adapter kept its user plane associated for good.
//
// The body is a heartbeat response that parses, for the same reason as the test above: with an
// empty one the status check can go and this still passes, on the parse failure instead.
func TestAnAdapterThatRefusesAHeartbeatIsReported(t *testing.T) {
	answer := pfcp_message.NewHeartbeatResponse(1, ie.NewRecoveryTimeStamp(time.Now()))

	body := make([]byte, answer.MarshalLen())
	if err := answer.MarshalTo(body); err != nil {
		t.Fatalf("marshalling the answer: %v", err)
	}

	recorder := httptest.NewRecorder()
	recorder.WriteHeader(http.StatusBadGateway)

	if _, err := recorder.Write(body); err != nil {
		t.Fatalf("writing the body: %v", err)
	}

	if _, err := adapterReply(recorder.Result(), "heartbeat"); err == nil {
		t.Error("a heartbeat the adapter refused was read as answered")
	}
}

// And an answer that did come back is still read.
func TestAHeartbeatTheAdapterDeliveredIsRead(t *testing.T) {
	answer := pfcp_message.NewHeartbeatResponse(1, ie.NewRecoveryTimeStamp(time.Now()))

	body := make([]byte, answer.MarshalLen())
	if err := answer.MarshalTo(body); err != nil {
		t.Fatalf("marshalling the answer: %v", err)
	}

	recorder := httptest.NewRecorder()
	recorder.WriteHeader(http.StatusOK)

	if _, err := recorder.Write(body); err != nil {
		t.Fatalf("writing the body: %v", err)
	}

	msg, err := adapterReply(recorder.Result(), "heartbeat")
	if err != nil {
		t.Fatalf("a delivered heartbeat answer was refused: %v", err)
	}

	if msg.MessageType() != pfcp_message.MsgTypeHeartbeatResponse {
		t.Errorf("read a %s, want a heartbeat response", msg.MessageTypeName())
	}
}
