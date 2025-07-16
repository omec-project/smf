// SPDX-FileCopyrightText: 2025 Canonical Ltd

// SPDX-License-Identifier: Apache-2.0
//

package polling

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/mohae/deepcopy"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/smf/logger"
)

const (
	initialPollingInterval = 5 * time.Second
	pollingMaxBackoff      = 40 * time.Second
	pollingBackoffFactor   = 2
	pollingPath            = "/nfconfig/session-management"
)

type nfConfigPoller struct {
	currentSessionManagementConfig []nfConfigApi.SessionManagement
	client                         *http.Client
}

// StartPollingService initializes the polling service and starts it.
// The polling service continuously makes HTTP GET request to the webconsole and updates the network configuration
func StartPollingService(ctx context.Context, webuiUri string, onUpdate func([]nfConfigApi.SessionManagement)) {
	poller := nfConfigPoller{
		currentSessionManagementConfig: []nfConfigApi.SessionManagement{},
		client:                         &http.Client{Timeout: initialPollingInterval},
	}

	interval := initialPollingInterval
	pollingEndpoint := webuiUri + pollingPath
	logger.PollConfigLog.Infof("Started polling service on %s every %v", pollingEndpoint, initialPollingInterval)

	for {
		select {
		case <-ctx.Done():
			logger.PollConfigLog.Infoln("Polling service shutting down")
			return
		case <-time.After(interval):
			newSessionManagementConfig, err := fetchSessionManagementConfig(&poller, pollingEndpoint)
			if err != nil {
				interval = minDuration(interval*time.Duration(pollingBackoffFactor), pollingMaxBackoff)
				logger.PollConfigLog.Errorf("Polling error. Retrying in %v: %+v", interval, err)
				continue
			}
			interval = initialPollingInterval

			// only trigger callback if config changed
			if !reflect.DeepEqual(newSessionManagementConfig, poller.currentSessionManagementConfig) {
				logger.PollConfigLog.Infof("Session Management config changed. New Session Management Data: %+v", newSessionManagementConfig)
				poller.currentSessionManagementConfig = deepcopy.Copy(newSessionManagementConfig).([]nfConfigApi.SessionManagement)
				onUpdate(newSessionManagementConfig)
			} else {
				logger.PollConfigLog.Debugf("Session management config did not change %+v", newSessionManagementConfig)
			}
		}
	}
}

var fetchSessionManagementConfig = func(p *nfConfigPoller, endpoint string) ([]nfConfigApi.SessionManagement, error) {
	return p.fetchSessionManagementConfig(endpoint)
}

func (p *nfConfigPoller) fetchSessionManagementConfig(pollingEndpoint string) ([]nfConfigApi.SessionManagement, error) {
	ctx, cancel := context.WithTimeout(context.Background(), initialPollingInterval)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollingEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %v failed: %w", pollingEndpoint, err)
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil, fmt.Errorf("unexpected Content-Type: got %s, want application/json", contentType)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		var config []nfConfigApi.SessionManagement
		if err := json.Unmarshal(body, &config); err != nil {
			logger.PollConfigLog.Debugf("Session-management raw response: %s", body)
			return nil, fmt.Errorf("failed to parse JSON response: %w", err)
		}
		return config, nil

	case http.StatusBadRequest, http.StatusInternalServerError:
		return nil, fmt.Errorf("server returned %d error code", resp.StatusCode)
	default:
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
