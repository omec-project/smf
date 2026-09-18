// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
