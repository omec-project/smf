// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-License-Identifier: Apache-2.0

package polling

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/omec-project/openapi/v2/nfConfigApi"
	"github.com/omec-project/openapi/v2/nfconfigpoll"
	"github.com/omec-project/smf/logger"
)

const (
	initialPollingInterval = 5 * time.Second
	pollingPath            = "/nfconfig/session-management"
)

// StartPollingService initializes the polling service and starts it.
// The polling service continuously makes HTTP GET request to the webconsole and updates the network configuration
func StartPollingService(ctx context.Context, webuiUri string, registrationChan, contextUpdateChan chan<- []nfConfigApi.SessionManagement) {
	poller, err := newPoller(webuiUri, registrationChan, contextUpdateChan, initialPollingInterval)
	if err != nil {
		logger.PollConfigLog.Errorf("failed to start polling service: %v", err)
		return
	}
	poller.Run(ctx)
}

func newPoller(webuiUri string, registrationChan, contextUpdateChan chan<- []nfConfigApi.SessionManagement, interval time.Duration) (*nfconfigpoll.Poller[[]nfConfigApi.SessionManagement], error) {
	delivery := &configDelivery{registrationChan: registrationChan, contextUpdateChan: contextUpdateChan}
	return nfconfigpoll.New(nfconfigpoll.Config[[]nfConfigApi.SessionManagement]{
		Name:     "Session Management",
		Endpoint: webuiUri + pollingPath,
		Log:      logger.PollConfigLog,
		Interval: interval,
		Initial:  []nfConfigApi.SessionManagement{},
		// Round-trip through JSON so the comparison and stored state always reflect the custom
		// (Un)MarshalJSON behaviour of nfConfigApi types (e.g. AdditionalProperties defaulting to an
		// empty map instead of nil), regardless of how the config was built.
		Normalize: nfconfigpoll.JSONRoundTrip[[]nfConfigApi.SessionManagement],
		OnChange: func(_ context.Context, cfg []nfConfigApi.SessionManagement) error {
			return delivery.deliver(cfg)
		},
	})
}

// configDelivery sends a config to the registration and the context update channels without ever
// blocking. If a channel is full the config is not lost: deliver returns an error so that the poller
// offers the same config again on the next poll. A channel that already accepted the config is
// remembered, so a retry only goes to the channel(s) that are still missing it.
// deliver is only called from the polling goroutine, so no locking is needed.
type configDelivery struct {
	registrationChan  chan<- []nfConfigApi.SessionManagement
	contextUpdateChan chan<- []nfConfigApi.SessionManagement

	pending                  []nfConfigApi.SessionManagement
	registrationDelivered    bool
	contextUpdateDelivered   bool
	hasPartiallyDeliveredCfg bool
}

func (d *configDelivery) deliver(cfg []nfConfigApi.SessionManagement) error {
	// A different config than the one partially delivered supersedes it: both channels get the new one.
	if d.hasPartiallyDeliveredCfg && !reflect.DeepEqual(d.pending, cfg) {
		d.reset()
	}

	if !d.registrationDelivered {
		select {
		case d.registrationChan <- cfg:
			d.registrationDelivered = true
		default:
			logger.PollConfigLog.Warn("registrationChan full, config will be retried on the next poll")
		}
	}
	if !d.contextUpdateDelivered {
		select {
		case d.contextUpdateChan <- cfg:
			d.contextUpdateDelivered = true
		default:
			logger.PollConfigLog.Warn("contextUpdateChan full, config will be retried on the next poll")
		}
	}

	if d.registrationDelivered && d.contextUpdateDelivered {
		d.reset()
		return nil
	}
	d.pending = cfg
	d.hasPartiallyDeliveredCfg = true
	return errors.New("channel full, config not delivered to all consumers")
}

func (d *configDelivery) reset() {
	d.pending = nil
	d.registrationDelivered = false
	d.contextUpdateDelivered = false
	d.hasPartiallyDeliveredCfg = false
}
