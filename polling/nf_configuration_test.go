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
	"sync"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sessionConfigOne := makeSessionConfig(
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
	originalFetcher := fetchSessionManagementConfig
	defer func() { fetchSessionManagementConfig = originalFetcher }()
	expectedConfig := []nfConfigApi.SessionManagement{sessionConfigOne}
	fetchSessionManagementConfig = func(poller *nfConfigPoller, endpoint string) ([]nfConfigApi.SessionManagement, error) {
		return expectedConfig, nil
	}
	registrationChan := make(chan []nfConfigApi.SessionManagement, 1)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 1)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		if result := <-registrationChan; !reflect.DeepEqual(result, expectedConfig) {
			t.Errorf("registrationChan: expected %+v, got %+v", expectedConfig, result)
		}
		wg.Done()
	}()

	go func() {
		if result := <-contextUpdateChan; !reflect.DeepEqual(result, expectedConfig) {
			t.Errorf("contextUpdateChan: expected %+v, got %+v", expectedConfig, result)
		}
		wg.Done()
	}()

	go StartPollingService(ctx, "http://dummy", registrationChan, contextUpdateChan)
	wg.Wait()
}

func TestStartPollingService_RetryAfterFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	originalFetcher := fetchSessionManagementConfig
	defer func() { fetchSessionManagementConfig = originalFetcher }()
	callCount := 0
	fetchSessionManagementConfig = func(poller *nfConfigPoller, pollingEndpoint string) ([]nfConfigApi.SessionManagement, error) {
		callCount++
		currentCount := callCount
		return nil, fmt.Errorf("mock failure %d", currentCount)
	}
	registrationChan := make(chan []nfConfigApi.SessionManagement, 1)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		StartPollingService(ctx, "http://dummy", registrationChan, contextUpdateChan)
	}()
	time.Sleep(3 * initialPollingInterval)
	cancel()
	wg.Wait()
	if callCount < 2 {
		t.Errorf("Expected at least 2 retry attempts, got %d", callCount)
	}
}

func TestStartPollingService_NoUpdateOnIdenticalConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updateCount := 0
	originalFetcher := fetchSessionManagementConfig
	defer func() { fetchSessionManagementConfig = originalFetcher }()
	sessionConfigOne := makeSessionConfig(
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
	expectedConfig := []nfConfigApi.SessionManagement{sessionConfigOne}
	fetchSessionManagementConfig = func(poller *nfConfigPoller, endpoint string) ([]nfConfigApi.SessionManagement, error) {
		return expectedConfig, nil
	}
	registrationChan := make(chan []nfConfigApi.SessionManagement, 1)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		config := <-registrationChan
		if !reflect.DeepEqual(config, expectedConfig) {
			t.Errorf("registrationChan: expected %+v, got %+v", expectedConfig, config)
		}
		updateCount += 1
	}()

	go func() {
		defer wg.Done()
		config := <-contextUpdateChan
		if !reflect.DeepEqual(config, expectedConfig) {
			t.Errorf("contextUpdateChan: expected %+v, got %+v", expectedConfig, config)
		}
		updateCount += 1
	}()
	go StartPollingService(ctx, "http://dummy", registrationChan, contextUpdateChan)
	time.Sleep(4 * initialPollingInterval)

	cancel()
	wg.Wait()

	if updateCount != 2 {
		t.Errorf("Expected exactly 2 updates, got %d", updateCount)
	}
}

func TestStartPollingService_UpdateOnDifferentConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	originalFetcher := fetchSessionManagementConfig
	defer func() { fetchSessionManagementConfig = originalFetcher }()
	sessionConfigOne := makeSessionConfig(
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
	sessionConfigTwo := makeSessionConfig(
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
	fetchCount := 0
	fetchSessionManagementConfig = func(poller *nfConfigPoller, endpoint string) ([]nfConfigApi.SessionManagement, error) {
		if fetchCount == 0 {
			fetchCount++
			return []nfConfigApi.SessionManagement{sessionConfigOne}, nil
		}
		return []nfConfigApi.SessionManagement{sessionConfigTwo}, nil
	}
	registrationChan := make(chan []nfConfigApi.SessionManagement, 2)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 2)
	type update struct {
		config []nfConfigApi.SessionManagement
		source string
	}

	updates := make(chan update, 4)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for config := range registrationChan {
			updates <- update{config: config, source: "registration"}
		}
	}()

	go func() {
		defer wg.Done()
		for config := range contextUpdateChan {
			updates <- update{config: config, source: "context"}
		}
	}()

	go StartPollingService(ctx, "http://dummy", registrationChan, contextUpdateChan)

	configOneCount := 0
	configTwoCount := 0
	registrationCount := 0
	contextCount := 0
	timeout := time.After(5 * initialPollingInterval)
	// 4 updates are expected in total
	for i := 0; i < 4; i++ {
		select {
		case received := <-updates:
			if reflect.DeepEqual(received.config, []nfConfigApi.SessionManagement{sessionConfigOne}) {
				configOneCount++
			} else if reflect.DeepEqual(received.config, []nfConfigApi.SessionManagement{sessionConfigTwo}) {
				configTwoCount++
			} else {
				t.Errorf("Received unexpected configuration: %+v", received.config)
			}

			switch received.source {
			case "registration":
				registrationCount++
			case "context":
				contextCount++
			}
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
	case extra := <-updates:
		t.Errorf("Received unexpected update: %+v", extra)
	case <-time.After(initialPollingInterval):
		// this is expected
	}
	cancel()
	close(registrationChan)
	close(contextUpdateChan)
	wg.Wait()
}

func TestFetchSessionManagementConfig(t *testing.T) {
	var sessionConfigs []nfConfigApi.SessionManagement
	sessionConfigOne := makeSessionConfig(
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
