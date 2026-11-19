// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/wmnsk/go-pfcp/ie"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// A request to the adapter carries the whole PFCP message, so a modification that sets
// duplication carries the DUPL flag and the session's identifiers with it. Logging the
// encoded request, even at debug level, puts which sessions are intercepted in the general
// log; the native path logs only sequence numbers.
func TestAnAdapterRequestIsNotLoggedWithItsBody(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	orig := logger.PfcpLog
	logger.PfcpLog = zap.New(core).Sugar()
	t.Cleanup(func() { logger.PfcpLog = orig })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	msg := pfcp_message.NewSessionModificationRequest(0, 0, 0x1234567890, 4242, 0,
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(0x02, 0x08)))
	body := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(body); err != nil {
		t.Fatalf("marshalling the request: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(body)

	rsp, err := SendPfcpMsgToAdapter(*smf_context.NewNodeID("1.1.1.72"), msg,
		&net.UDPAddr{IP: net.ParseIP("1.1.1.72"), Port: 8805}, nil, server.URL)
	if err != nil {
		t.Fatalf("sending to the adapter: %v", err)
	}
	if err := rsp.Body.Close(); err != nil {
		t.Fatalf("closing the reply: %v", err)
	}

	if logs.Len() == 0 {
		t.Fatal("nothing was logged at debug level, so this test cannot see the line it guards")
	}
	for _, entry := range logs.All() {
		if strings.Contains(entry.Message, encoded) {
			t.Errorf("an adapter request was logged with its PFCP body: %q", entry.Message)
		}
	}
}
