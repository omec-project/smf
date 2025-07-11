// SPDX-FileCopyrightText: 2025 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
/*
 * NF Polling Unit Tests
 *
 */

package polling

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/openapi/models"
)

func TestStartPollingService_Success(t *testing.T) {
	ctx := t.Context()
	originalFetchPlmnConfig := fetchPlmnConfig
	defer func() {
		fetchPlmnConfig = originalFetchPlmnConfig
	}()

	expectedConfig := []models.PlmnId{{Mcc: "001", Mnc: "01"}}
	fetchPlmnConfig = func(poller *nfConfigPoller, pollingEndpoint string) ([]models.PlmnId, error) {
		return expectedConfig, nil
	}
	pollingChan := make(chan []models.PlmnId, 1)

	go StartPollingService(ctx, "http://dummy", pollingChan)
	time.Sleep(initialPollingInterval)

	select {
	case result := <-pollingChan:
		if !reflect.DeepEqual(result, expectedConfig) {
			t.Errorf("Expected %+v, got %+v", expectedConfig, result)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Timeout waiting for PLMN config")
	}
}

func TestStartPollingService_RetryAfterFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	originalFetchPlmnConfig := fetchPlmnConfig
	defer func() {
		fetchPlmnConfig = originalFetchPlmnConfig
	}()

	callCount := 0
	fetchPlmnConfig = func(poller *nfConfigPoller, pollingEndpoint string) ([]models.PlmnId, error) {
		callCount++
		return nil, errors.New("mock failure")
	}
	plmnChan := make(chan []models.PlmnId, 1)
	go StartPollingService(ctx, "http://dummy", plmnChan)

	time.Sleep(4 * initialPollingInterval)
	cancel()
	<-ctx.Done()

	if callCount < 2 {
		t.Error("Expected to retry after failure")
	}
	t.Logf("Tried %v times", callCount)
}

func TestHandlePolledPlmnConfig_ConfigChanged_ConfigurationIsUpdatedAndSendToChannel(t *testing.T) {
	testCases := []struct {
		name          string
		newPlmnConfig []models.PlmnId
	}{
		{
			name:          "One element",
			newPlmnConfig: []models.PlmnId{{Mcc: "001", Mnc: "02"}},
		},
		{
			name:          "Two elements",
			newPlmnConfig: []models.PlmnId{{Mcc: "001", Mnc: "02"}, {Mcc: "022", Mnc: "02"}},
		},
		{
			name:          "Empty config",
			newPlmnConfig: []models.PlmnId{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan []models.PlmnId, 1)
			poller := nfConfigPoller{
				currentPlmnConfig: []models.PlmnId{{Mcc: "001", Mnc: "01"}},
				plmnConfigChan:    ch,
			}
			poller.handlePolledPlmnConfig(tc.newPlmnConfig)

			if !reflect.DeepEqual(poller.currentPlmnConfig, tc.newPlmnConfig) {
				t.Errorf("Expected PLMN config to be updated to %v, got %v", tc.newPlmnConfig, poller.currentPlmnConfig)
			}
			select {
			case receivedPlmnConfig := <-ch:
				if !reflect.DeepEqual(receivedPlmnConfig, tc.newPlmnConfig) {
					t.Errorf("Expected config %v, got %v", tc.newPlmnConfig, receivedPlmnConfig)
				}
			case <-time.After(100 * time.Millisecond):
				t.Errorf("Expected config to be sent to channel, but it was not")
			}
		})
	}
}

func TestHandlePolledPlmnConfig_ConfigDidNotChanged_ConfigIsNotSendToChannel(t *testing.T) {
	testCases := []struct {
		name          string
		newPlmnConfig []models.PlmnId
	}{
		{
			name:          "Same config",
			newPlmnConfig: []models.PlmnId{{Mcc: "001", Mnc: "02"}},
		},
		{
			name:          "Empty config",
			newPlmnConfig: []models.PlmnId{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan []models.PlmnId, 1)
			poller := nfConfigPoller{
				currentPlmnConfig: tc.newPlmnConfig,
				plmnConfigChan:    ch,
			}
			poller.handlePolledPlmnConfig(tc.newPlmnConfig)

			if !reflect.DeepEqual(poller.currentPlmnConfig, tc.newPlmnConfig) {
				t.Errorf("Expected PLMN list to remain unchanged, got %v", poller.currentPlmnConfig)
			}

			select {
			case receivedPlmnConfig := <-ch:
				t.Errorf("Config was not expected, got %v", receivedPlmnConfig)
			case <-time.After(100 * time.Millisecond):
				// Expected case
			}
		})
	}
}

func TestFetchPlmnConfig(t *testing.T) {
	validPlmnList := []models.PlmnId{
		{Mcc: "001", Mnc: "01"},
		{Mcc: "002", Mnc: "02"},
	}
	validJson, err := json.Marshal(validPlmnList)
	if err != nil {
		t.Fail()
	}

	tests := []struct {
		name           string
		statusCode     int
		contentType    string
		responseBody   string
		expectedError  string
		expectedResult []models.PlmnId
	}{
		{
			name:           "200 OK with valid JSON",
			statusCode:     http.StatusOK,
			contentType:    "application/json",
			responseBody:   string(validJson),
			expectedError:  "",
			expectedResult: validPlmnList,
		},
		{
			name:          "200 OK with invalid Content-Type",
			statusCode:    http.StatusOK,
			contentType:   "text/plain",
			responseBody:  string(validJson),
			expectedError: "unexpected Content-Type: got text/plain, want application/json",
		},
		{
			name:          "400 Bad Request",
			statusCode:    http.StatusBadRequest,
			contentType:   "application/json",
			responseBody:  "",
			expectedError: "server returned 400 error code",
		},
		{
			name:          "500 Internal Server Error",
			statusCode:    http.StatusInternalServerError,
			contentType:   "application/json",
			responseBody:  "",
			expectedError: "server returned 500 error code",
		},
		{
			name:          "Unexpected Status Code 418",
			statusCode:    http.StatusTeapot,
			contentType:   "application/json",
			responseBody:  "",
			expectedError: "unexpected status code: 418",
		},
		{
			name:          "200 OK with invalid JSON",
			statusCode:    http.StatusOK,
			contentType:   "application/json",
			responseBody:  "{invalid-json}",
			expectedError: "failed to parse JSON response:",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				accept := r.Header.Get("Accept")
				if accept != "application/json" {
					t.Errorf("expected Accept header 'application/json', got '%s'", accept)
				}

				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.statusCode)
				_, err = w.Write([]byte(tc.responseBody))
				if err != nil {
					t.Fail()
				}
			}
			server := httptest.NewServer(http.HandlerFunc(handler))
			ch := make(chan []models.PlmnId, 1)
			poller := nfConfigPoller{
				currentPlmnConfig: []models.PlmnId{{Mcc: "001", Mnc: "01"}},
				plmnConfigChan:    ch,
				client:            &http.Client{},
			}
			defer server.Close()

			fetchedConfig, err := fetchPlmnConfig(&poller, server.URL)

			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("expected no error, got `%v`", err)
				}
				if !reflect.DeepEqual(tc.expectedResult, fetchedConfig) {
					t.Errorf("error in fetched config: expected `%v`, got `%v`", tc.expectedResult, fetchedConfig)
				}
			} else {
				if err == nil {
					t.Errorf("expected error `%v`, got nil", tc.expectedError)
				}
				if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("expected error `%v`, got `%v`", tc.expectedError, err)
				}
			}
		})
	}
}
