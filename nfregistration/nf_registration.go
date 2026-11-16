// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-License-Identifier: Apache-2.0

package nfregistration

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	"github.com/omec-project/openapi/v2/nrfregistration"
	"github.com/omec-project/smf/consumer"
	"github.com/omec-project/smf/logger"
)

var service = newService()

func newService() *nrfregistration.Service[[]nfConfigApi.SessionManagement] {
	// The consumer functions are looked up on every call so tests can replace them.
	svc, err := nrfregistration.New(nrfregistration.Config[[]nfConfigApi.SessionManagement]{
		NfName:  "SMF",
		Log:     logger.NrfRegistrationLog,
		IsEmpty: func(cfg []nfConfigApi.SessionManagement) bool { return len(cfg) == 0 },
		Register: func(ctx context.Context, cfg []nfConfigApi.SessionManagement) (*models.NFProfile, error) {
			nfProfile, _, err := consumer.SendRegisterNFInstance(ctx, cfg)
			return nfProfile, err
		},
		Update: func(ctx context.Context, patch []models.PatchItem) (*models.NFProfile, *models.ProblemDetails, error) {
			return consumer.SendUpdateNFInstance(ctx, patch)
		},
		Deregister:           func(ctx context.Context) error { return consumer.SendDeregisterNFInstance(ctx) },
		RequiresRegistration: IsRegistrationRequired,
		Clone:                deepCopySessionManagement,
	})
	if err != nil {
		panic(err) // the config above is static, so this is a programming error
	}
	return svc
}

// StartNfRegistrationService starts the registration service.
// If the new config is empty, the NF deregisters from the NRF. Else, it registers to the NRF.
// It cancels the registration in progress to ensure that only one registration process runs at the time.
func StartNfRegistrationService(ctx context.Context, sessionManagementConfigChan <-chan []nfConfigApi.SessionManagement) {
	service.Start(ctx, sessionManagementConfigChan)
}

// deregisterTimeout bounds DeregisterNF: it waits for the registration work in progress, which it cancels, and
// then sends the DELETE, and an NRF that does not answer must not hold up the termination of the NF.
var deregisterTimeout = 10 * time.Second

// DeregisterNF stops the heartbeat and deregisters the NF from the NRF.
var DeregisterNF = func() {
	ctx, cancel := context.WithTimeout(context.Background(), deregisterTimeout)
	defer cancel()
	service.Deregister(ctx)
}

func deepCopySessionManagement(input []nfConfigApi.SessionManagement) ([]nfConfigApi.SessionManagement, error) {
	b, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session management config: %w", err)
	}

	cloned := []nfConfigApi.SessionManagement{}
	if err := json.Unmarshal(b, &cloned); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session management config: %w", err)
	}

	return cloned, nil
}

func IsRegistrationRequired(newConfigs, oldConfigs []nfConfigApi.SessionManagement) bool {
	if len(newConfigs) != len(oldConfigs) {
		return true
	}

	for i := range newConfigs {
		newCfg := newConfigs[i]
		oldCfg := oldConfigs[i]
		if newCfg.PlmnId.GetMcc() != oldCfg.PlmnId.GetMcc() || newCfg.PlmnId.GetMnc() != oldCfg.PlmnId.GetMnc() {
			return true
		}
		if newCfg.Snssai.GetSst() != oldCfg.Snssai.GetSst() || newCfg.Snssai.GetSd() != oldCfg.Snssai.GetSd() {
			return true
		}
		newDnnSet := make(map[string]struct{})
		for _, d := range newCfg.IpDomain {
			newDnnSet[d.GetDnnName()] = struct{}{}
		}
		for _, d := range oldCfg.IpDomain {
			if _, exists := newDnnSet[d.GetDnnName()]; !exists {
				return true
			}
		}
		if len(newDnnSet) != len(oldCfg.IpDomain) {
			return true
		}
	}
	return false
}
