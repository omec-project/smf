// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

func TestSendSMContextStatusNotificationUsesExactCallbackURI(t *testing.T) {
	requestPath := make(chan string, 1)
	requestBody := make(chan models.SmContextStatusNotification, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath <- r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read callback body: %v", err)
		}
		var notification models.SmContextStatusNotification
		if err := json.Unmarshal(body, &notification); err != nil {
			t.Fatalf("unmarshal callback body: %v", err)
		}
		requestBody <- notification
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	callbackPath := "/sm-context-status"
	problemDetails, err := SendSMContextStatusNotification(server.URL + callbackPath)
	if err != nil {
		t.Fatalf("SendSMContextStatusNotification returned error: %v", err)
	}
	if problemDetails != nil {
		t.Fatalf("expected no problem details, got %#v", problemDetails)
	}
	if got := <-requestPath; got != callbackPath {
		t.Fatalf("expected callback path %q, got %q", callbackPath, got)
	}
	notification := <-requestBody
	if got := (&notification).GetStatusInfo().ResourceStatus; got != models.RESOURCESTATUS_RELEASED {
		t.Fatalf("expected resource status %q, got %q", models.RESOURCESTATUS_RELEASED, got)
	}
}
