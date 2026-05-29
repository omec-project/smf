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
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/nfConfigApi"
)

func startTestPollingService(ctx context.Context, registrationChan, contextUpdateChan chan<- []nfConfigApi.SessionManagement) (context.CancelFunc, <-chan struct{}) {
	testCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		StartPollingService(testCtx, "http://dummy", registrationChan, contextUpdateChan)
	}()
	return cancel, done
}

func waitForPollingServiceStop(t *testing.T, cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for polling service to stop")
	}
}

func waitForPollingCondition(t *testing.T, timeout time.Duration, condition func() bool, failureMessage string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !condition() {
		t.Fatal(failureMessage)
	}
}

func makeSessionConfig(sliceName, mcc, mnc, sst, sd, dnnName, ueSubnet, hostname string, port int32) (nfConfigApi.SessionManagement, error) {
	sstUint64, err := strconv.ParseUint(sst, 10, 8)
	if err != nil {
		return nfConfigApi.SessionManagement{}, fmt.Errorf("invalid SST value '%s': %w", sst, err)
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
	}, nil
}

func TestStartPollingService_Success(t *testing.T) {
	tick := make(chan time.Time, 1)
	sessionConfigOne, err := makeSessionConfig(
		"slice1",
		"222",
		"03",
		"2",
		"2",
		"internet",
		"192.168.1.0/24",
		"192.168.1.1",
		38414,
	)
	if err != nil {
		t.Fatalf("failed to create sessionConfigOne: %v", err)
	}
	originalFetcher := fetchSessionManagementConfig
	originalPollingIntervalAfter := pollingIntervalAfter
	registrationChan := make(chan []nfConfigApi.SessionManagement, 1)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 1)
	var cancel context.CancelFunc
	var done <-chan struct{}
	defer func() {
		waitForPollingServiceStop(t, cancel, done)
		fetchSessionManagementConfig = originalFetcher
		pollingIntervalAfter = originalPollingIntervalAfter
	}()
	pollingIntervalAfter = func(time.Duration) <-chan time.Time {
		return tick
	}
	expectedConfig := []nfConfigApi.SessionManagement{sessionConfigOne}
	fetchSessionManagementConfig = func(poller *nfConfigPoller, endpoint string) ([]nfConfigApi.SessionManagement, error) {
		return expectedConfig, nil
	}
	cancel, done = startTestPollingService(t.Context(), registrationChan, contextUpdateChan)
	tick <- time.Now()

	select {
	case result := <-registrationChan:
		if !reflect.DeepEqual(result, expectedConfig) {
			t.Errorf("registrationChan: expected %+v, got %+v", expectedConfig, result)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for registration update")
	}

	select {
	case result := <-contextUpdateChan:
		if !reflect.DeepEqual(result, expectedConfig) {
			t.Errorf("contextUpdateChan: expected %+v, got %+v", expectedConfig, result)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for context update")
	}
}

func TestStartPollingService_RetryAfterFailure(t *testing.T) {
	originalFetcher := fetchSessionManagementConfig
	originalPollingIntervalAfter := pollingIntervalAfter
	tick := make(chan time.Time, 2)
	registrationChan := make(chan []nfConfigApi.SessionManagement, 1)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 1)
	var cancel context.CancelFunc
	var done <-chan struct{}
	defer func() {
		waitForPollingServiceStop(t, cancel, done)
		fetchSessionManagementConfig = originalFetcher
		pollingIntervalAfter = originalPollingIntervalAfter
	}()
	pollingIntervalAfter = func(time.Duration) <-chan time.Time {
		return tick
	}
	var callCount atomic.Int32
	fetchSessionManagementConfig = func(poller *nfConfigPoller, pollingEndpoint string) ([]nfConfigApi.SessionManagement, error) {
		currentCount := callCount.Add(1)
		return nil, fmt.Errorf("mock failure %d", currentCount)
	}
	cancel, done = startTestPollingService(context.Background(), registrationChan, contextUpdateChan)
	tick <- time.Now()
	waitForPollingCondition(t, time.Second, func() bool {
		return callCount.Load() >= 1
	}, "polling service did not process first retry tick")
	tick <- time.Now()
	waitForPollingCondition(t, time.Second, func() bool {
		return callCount.Load() >= 2
	}, "polling service did not process second retry tick")
	if callCount.Load() < 2 {
		t.Errorf("Expected at least 2 retry attempts, got %d", callCount.Load())
	}
}

func TestStartPollingService_NoUpdateOnIdenticalConfig(t *testing.T) {
	tick := make(chan time.Time, 2)
	originalFetcher := fetchSessionManagementConfig
	originalPollingIntervalAfter := pollingIntervalAfter
	registrationChan := make(chan []nfConfigApi.SessionManagement, 1)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 1)
	var cancel context.CancelFunc
	var done <-chan struct{}
	defer func() {
		waitForPollingServiceStop(t, cancel, done)
		fetchSessionManagementConfig = originalFetcher
		pollingIntervalAfter = originalPollingIntervalAfter
	}()
	pollingIntervalAfter = func(time.Duration) <-chan time.Time {
		return tick
	}
	sessionConfigOne, err := makeSessionConfig(
		"slice1",
		"222",
		"02",
		"1",
		"2",
		"internet",
		"192.168.1.0/24",
		"192.168.2.1",
		38422,
	)
	if err != nil {
		t.Fatalf("failed to create sessionConfigOne: %v", err)
	}
	expectedConfig := []nfConfigApi.SessionManagement{sessionConfigOne}
	fetchSessionManagementConfig = func(poller *nfConfigPoller, endpoint string) ([]nfConfigApi.SessionManagement, error) {
		return expectedConfig, nil
	}
	cancel, done = startTestPollingService(t.Context(), registrationChan, contextUpdateChan)
	tick <- time.Now()

	select {
	case config := <-registrationChan:
		if !reflect.DeepEqual(config, expectedConfig) {
			t.Errorf("registrationChan: expected %+v, got %+v", expectedConfig, config)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for registration update")
	}

	select {
	case config := <-contextUpdateChan:
		if !reflect.DeepEqual(config, expectedConfig) {
			t.Errorf("contextUpdateChan: expected %+v, got %+v", expectedConfig, config)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for context update")
	}

	tick <- time.Now()
	select {
	case config := <-registrationChan:
		t.Fatalf("unexpected duplicate registration update: %+v", config)
	case config := <-contextUpdateChan:
		t.Fatalf("unexpected duplicate context update: %+v", config)
	case <-time.After(200 * time.Millisecond):
		// expected
	}
}

func TestStartPollingService_UpdateOnDifferentConfig(t *testing.T) {
	tick := make(chan time.Time, 2)
	originalFetcher := fetchSessionManagementConfig
	originalPollingIntervalAfter := pollingIntervalAfter
	registrationChan := make(chan []nfConfigApi.SessionManagement, 2)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 2)
	var cancel context.CancelFunc
	var done <-chan struct{}
	defer func() {
		waitForPollingServiceStop(t, cancel, done)
		fetchSessionManagementConfig = originalFetcher
		pollingIntervalAfter = originalPollingIntervalAfter
	}()
	pollingIntervalAfter = func(time.Duration) <-chan time.Time {
		return tick
	}
	sessionConfigOne, err := makeSessionConfig(
		"slice1",
		"111",
		"01",
		"1",
		"1",
		"internet",
		"192.168.1.0/24",
		"192.168.1.1",
		38412,
	)
	if err != nil {
		t.Fatalf("failed to create sessionConfigOne: %v", err)
	}
	sessionConfigTwo, err := makeSessionConfig(
		"slice2",
		"111",
		"01",
		"1",
		"1",
		"fast",
		"192.168.2.0/24",
		"192.168.2.1",
		38412,
	)
	if err != nil {
		t.Fatalf("failed to create sessionConfigTwo: %v", err)
	}
	fetchCount := 0
	fetchSessionManagementConfig = func(poller *nfConfigPoller, endpoint string) ([]nfConfigApi.SessionManagement, error) {
		if fetchCount == 0 {
			fetchCount++
			return []nfConfigApi.SessionManagement{sessionConfigOne}, nil
		}
		return []nfConfigApi.SessionManagement{sessionConfigTwo}, nil
	}
	cancel, done = startTestPollingService(t.Context(), registrationChan, contextUpdateChan)
	tick <- time.Now()
	tick <- time.Now()

	configOneCount := 0
	configTwoCount := 0
	registrationCount := 0
	contextCount := 0
	timeout := time.After(2 * time.Second)
	// 4 updates are expected in total
	for i := 0; i < 4; i++ {
		select {
		case config := <-registrationChan:
			if reflect.DeepEqual(config, []nfConfigApi.SessionManagement{sessionConfigOne}) {
				configOneCount++
			} else if reflect.DeepEqual(config, []nfConfigApi.SessionManagement{sessionConfigTwo}) {
				configTwoCount++
			} else {
				t.Errorf("Received unexpected registration configuration: %+v", config)
			}
			registrationCount++
		case config := <-contextUpdateChan:
			if reflect.DeepEqual(config, []nfConfigApi.SessionManagement{sessionConfigOne}) {
				configOneCount++
			} else if reflect.DeepEqual(config, []nfConfigApi.SessionManagement{sessionConfigTwo}) {
				configTwoCount++
			} else {
				t.Errorf("Received unexpected context configuration: %+v", config)
			}
			contextCount++
		case <-timeout:
			t.Fatalf("Timed out waiting for update %d", i+1)
		}
	}
	if configOneCount != 2 {
		t.Errorf("Expected 2 updates with first config, got %d", configOneCount)
	}
	if configTwoCount != 2 {
		t.Errorf("Expected 2 updates with second config, got %d", configTwoCount)
	}
	if registrationCount != 2 {
		t.Errorf("Expected 2 updates on registration channel, got %d", registrationCount)
	}
	if contextCount != 2 {
		t.Errorf("Expected 2 updates on context channel, got %d", contextCount)
	}

	select {
	case extra := <-registrationChan:
		t.Errorf("Received unexpected registration update: %+v", extra)
	case extra := <-contextUpdateChan:
		t.Errorf("Received unexpected context update: %+v", extra)
	case <-time.After(200 * time.Millisecond):
		// this is expected
	}
}

func TestFetchSessionManagementConfig(t *testing.T) {
	var sessionConfigs []nfConfigApi.SessionManagement
	sessionConfigOne, err := makeSessionConfig(
		"slice1",
		"111",
		"01",
		"1",
		"1",
		"internet",
		"192.168.1.0/24",
		"192.168.1.1",
		38412,
	)
	if err != nil {
		t.Fatalf("failed to create sessionConfigOne: %v", err)
	}
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
