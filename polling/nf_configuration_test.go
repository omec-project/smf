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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/openapi/nfConfigApi"
)

func makeSessionConfig(sliceName, mcc, mnc, sst string, sd string, dnnName, ueSubnet, hostname string, port int32) nfConfigApi.SessionManagement {
	sstUint64, err := strconv.ParseUint(sst, 10, 8)
	if err != nil {
		panic("invalid SST value: " + sst)
	}
	sstint := int32(sstUint64)
	return nfConfigApi.SessionManagement{
		SliceName: sliceName,
		PlmnId: nfConfigApi.PlmnId{
			Mcc: mcc,
			Mnc: mnc,
		},
		Snssai: nfConfigApi.Snssai{
			Sst: sstint,
			Sd:  &sd,
		},
		IpDomain: []nfConfigApi.IpDomain{
			{
				DnnName:  dnnName,
				DnsIpv4:  "8.8.8.8",
				UeSubnet: ueSubnet,
				Mtu:      1400,
			},
		},
		Upf: &nfConfigApi.Upf{
			Hostname: hostname,
			Port:     &port,
		},
		GnbNames: []string{"gnb1", "gnb2"},
	}
}

func TestStartPollingService_Success(t *testing.T) {
	ctx := t.Context()
	sessionConfigOne := makeSessionConfig("slice1", "222", "03", "2", "2", "internet", "192.168.1.0/24", "192.168.1.1", 38414)
	originalFetcher := fetchSessionManagementConfig
	defer func() { fetchSessionManagementConfig = originalFetcher }()

	expectedConfig := []nfConfigApi.SessionManagement{sessionConfigOne}
	fetchSessionManagementConfig = func(poller *nfConfigPoller, endpoint string) ([]nfConfigApi.SessionManagement, error) {
		return expectedConfig, nil
	}

	sessionMgmtChan := make(chan []nfConfigApi.SessionManagement, 1)
	go StartPollingService(ctx, "http://dummy", func(cfg []nfConfigApi.SessionManagement) {
		sessionMgmtChan <- cfg
	})

	time.Sleep(initialPollingInterval)

	select {
	case result := <-sessionMgmtChan:
		if !reflect.DeepEqual(result, expectedConfig) {
			t.Errorf("Expected %+v, got %+v", expectedConfig, result)
		}
	case <-time.After(200 * time.Millisecond):
		t.Errorf("Timeout waiting for session management config")
	}
}

func TestStartPollingService_RetryAfterFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	originalFetcher := fetchSessionManagementConfig
	defer func() { fetchSessionManagementConfig = originalFetcher }()
	callCount := 0
	fetchSessionManagementConfig = func(poller *nfConfigPoller, pollingEndpoint string) ([]nfConfigApi.SessionManagement, error) {
		callCount++
		return nil, errors.New("mock failure")
	}
	// fetch always fails
	go StartPollingService(ctx, "http://dummy", func([]nfConfigApi.SessionManagement) {})

	time.Sleep(4 * initialPollingInterval)
	cancel()
	<-ctx.Done()

	if callCount < 2 {
		t.Error("Expected to retry after failure")
	}
	t.Logf("Tried %v times", callCount)
}

func TestStartPollingService_NoUpdateOnIdenticalConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	originalFetcher := fetchSessionManagementConfig
	defer func() { fetchSessionManagementConfig = originalFetcher }()
	sessionConfigOne := makeSessionConfig("slice1", "222", "02", "1", "2", "internet", "192.168.1.0/24", "192.168.2.1", 38422)
	callCount := 0
	expectedConfig := []nfConfigApi.SessionManagement{sessionConfigOne}
	fetchSessionManagementConfig = func(poller *nfConfigPoller, endpoint string) ([]nfConfigApi.SessionManagement, error) {
		return expectedConfig, nil
	}

	ch := make(chan struct{}, 1)
	go StartPollingService(ctx, "http://dummy", func(_ []nfConfigApi.SessionManagement) {
		callCount++
		ch <- struct{}{}
	})

	time.Sleep(2 * initialPollingInterval)
	cancel()
	<-ctx.Done()

	if callCount != 1 {
		t.Errorf("Expected callback to be called once for new config, got %d", callCount)
	}
}

func TestStartPollingService_UpdateOnDifferentConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	originalFetcher := fetchSessionManagementConfig
	defer func() { fetchSessionManagementConfig = originalFetcher }()
	sessionConfigOne := makeSessionConfig("slice1", "111", "01", "1", "1", "internet", "192.168.1.0/24", "192.168.1.1", 38412)
	sessionConfigTwo := makeSessionConfig("slice2", "111", "01", "1", "1", "fast", "192.168.2.0/24", "192.168.2.1", 38412)
	callCount := 0

	fetchSessionManagementConfig = func(poller *nfConfigPoller, endpoint string) ([]nfConfigApi.SessionManagement, error) {
		if callCount == 0 {
			return []nfConfigApi.SessionManagement{sessionConfigOne}, nil
		}
		return []nfConfigApi.SessionManagement{sessionConfigTwo}, nil
	}

	ch := make(chan struct{}, 2)
	go StartPollingService(ctx, "http://dummy", func(_ []nfConfigApi.SessionManagement) {
		callCount++
		ch <- struct{}{}
	})

	timeout := time.After(5 * initialPollingInterval)
	for i := 0; i < 2; i++ {
		select {
		case <-ch:
			// expected update
		case <-timeout:
			t.Fatalf("Timed out waiting for config update #%d", i+1)
		}
	}

	cancel()
	<-ctx.Done()

	if callCount != 2 {
		t.Errorf("Expected callback to be called twice for different configs, got %d", callCount)
	}
}

func TestFetchSessionManagementConfig(t *testing.T) {
	var sessionConfigs []nfConfigApi.SessionManagement
	sessionConfigOne := makeSessionConfig("slice1", "111", "01", "1", "1", "internet", "192.168.1.0/24", "192.168.1.1", 38412)
	sessionConfigs = append(sessionConfigs, sessionConfigOne)
	validJson, err := json.Marshal(sessionConfigs)
	if err != nil {
		t.Fail()
	}

	tests := []struct {
		name           string
		statusCode     int
		contentType    string
		responseBody   string
		expectedError  string
		expectedResult []nfConfigApi.SessionManagement
	}{
		{
			name:           "200 OK with valid JSON",
			statusCode:     http.StatusOK,
			contentType:    "application/json",
			responseBody:   string(validJson),
			expectedError:  "",
			expectedResult: sessionConfigs,
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
			poller := nfConfigPoller{
				currentSessionManagementConfig: sessionConfigs,
				client:                         server.Client(),
			}
			defer server.Close()

			fetchedConfig, err := poller.fetchSessionManagementConfig(server.URL)

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
