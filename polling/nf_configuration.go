// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-License-Identifier: Apache-2.0

package polling

import (
	"context"
	"reflect"
	"sync"
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

// pollingService runs the poller together with the retry of the deliveries it could not complete.
type pollingService struct {
	poller   *nfconfigpoll.Poller[[]nfConfigApi.SessionManagement]
	delivery *configDelivery
	interval time.Duration
}

// Run polls until ctx is done. Beside it, a consumer whose channel was full is offered the config again every
// interval, until it has it, whether or not the endpoint changes meanwhile.
func (s *pollingService) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.delivery.flush()
			}
		}
	})
	s.poller.Run(ctx)
	cancel()
	wg.Wait()
}

func newPoller(webuiUri string, registrationChan, contextUpdateChan chan<- []nfConfigApi.SessionManagement, interval time.Duration) (*pollingService, error) {
	initial := []nfConfigApi.SessionManagement{}
	delivery := newConfigDelivery(registrationChan, contextUpdateChan, initial)
	poller, err := nfconfigpoll.New(nfconfigpoll.Config[[]nfConfigApi.SessionManagement]{
		Name:     "Session Management",
		Endpoint: webuiUri + pollingPath,
		Log:      logger.PollConfigLog,
		Interval: interval,
		Initial:  initial,
		// Round-trip through JSON so the comparison and stored state always reflect the custom
		// (Un)MarshalJSON behaviour of nfConfigApi types (e.g. AdditionalProperties defaulting to an
		// empty map instead of nil), regardless of how the config was built.
		Normalize: nfconfigpoll.JSONRoundTrip[[]nfConfigApi.SessionManagement],
		// The poller's current value is always the latest config polled, so that a later return to an earlier
		// one is a change like any other. Delivery to the two consumers is the delivery's own business.
		OnChange: func(_ context.Context, cfg []nfConfigApi.SessionManagement) error {
			delivery.accept(cfg)
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	return &pollingService{poller: poller, delivery: delivery, interval: interval}, nil
}

// configDelivery gets the latest config to the registration and the context update channels without ever
// blocking. It remembers, for each channel, the last config that channel accepted, and wants each to end at the
// latest config. A channel that is full is offered the config again by flush. Tracking each consumer, rather than
// "the config being delivered", is what makes a return to an earlier config come out right: A reaches both, B only
// the registration, and A again needs sending to the registration only, the context being at A already.
type configDelivery struct {
	mu        sync.Mutex
	desired   []nfConfigApi.SessionManagement
	consumers [2]*deliveryTarget
}

type deliveryTarget struct {
	name      string
	ch        chan<- []nfConfigApi.SessionManagement
	delivered []nfConfigApi.SessionManagement // the last config this channel accepted
}

// newConfigDelivery starts with both consumers at initial, which is what they have before any config is polled.
func newConfigDelivery(registrationChan, contextUpdateChan chan<- []nfConfigApi.SessionManagement, initial []nfConfigApi.SessionManagement) *configDelivery {
	return &configDelivery{
		desired: initial,
		consumers: [2]*deliveryTarget{
			{name: "registrationChan", ch: registrationChan, delivered: initial},
			{name: "contextUpdateChan", ch: contextUpdateChan, delivered: initial},
		},
	}
}

// accept makes cfg the config the consumers are to end at, and offers it to those that do not have it.
func (d *configDelivery) accept(cfg []nfConfigApi.SessionManagement) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.desired = cfg
	d.flushLocked()
}

// flush offers the config to the consumers that are still missing it, and reports whether any is.
func (d *configDelivery) flush() (pending bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flushLocked()
}

func (d *configDelivery) flushLocked() (pending bool) {
	for _, c := range d.consumers {
		if reflect.DeepEqual(c.delivered, d.desired) {
			continue
		}
		select {
		case c.ch <- d.desired:
			c.delivered = d.desired
		default:
			logger.PollConfigLog.Warnf("%s full, config will be retried", c.name)
			pending = true
		}
	}
	return pending
}
