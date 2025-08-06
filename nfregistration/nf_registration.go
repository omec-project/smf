// SPDX-FileCopyrightText: 2025 Canonical Ltd
//
// SPDX-License-Identifier: Apache-2.0
//

package nfregistration

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/smf/consumer"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
)

var (
	keepAliveTimer      *time.Timer
	keepAliveTimerMutex sync.Mutex
	registerCtxMutex    sync.Mutex
	afterFunc           = time.AfterFunc
)

const (
	defaultHeartbeatTimer int32 = 60
	retryTime                   = 10 * time.Second
)

// StartNfRegistrationService starts the registration service.
// If the new config is empty, the NF deregisters from the NRF. Else, it registers to the NRF.
// It cancels registerCancel to ensure that only one registration process runs at the time.
func StartNfRegistrationService(ctx context.Context, sessionManagementConfigChan <-chan []nfConfigApi.SessionManagement) {
	var registerCancel context.CancelFunc
	var registerCtx context.Context
	lastRegisteredConfig := []nfConfigApi.SessionManagement{}
	nfInstanceID := smf_context.SMF_Self().NfInstanceID
	logger.NrfRegistrationLog.Infof("SMF[%s]: register to NRF service started", nfInstanceID)
	for {
		select {
		case <-ctx.Done():
			if registerCancel != nil {
				registerCancel()
			}
			logger.NrfRegistrationLog.Infof("SMF[%s]: NF registration service shutting down", nfInstanceID)
			return

		case newConfig := <-sessionManagementConfigChan:
			if len(newConfig) == 0 {
				logger.NrfRegistrationLog.Debugf("SMF[%s]: session management config is empty. SMF will deregister", nfInstanceID)
				DeregisterNF()
				lastRegisteredConfig = nil
				continue
			}
			if IsRegistrationRequired(newConfig, lastRegisteredConfig) {
				logger.NrfRegistrationLog.Debugf("SMF[%s]: detected changes in NF profile relevant config. Registering...", nfInstanceID)
				if registerCancel != nil {
					registerCancel()
				}
				registerCtx, registerCancel = context.WithCancel(context.Background())
				go registerNF(registerCtx, newConfig)
				copyConfig, err := deepCopySessionManagement(newConfig)
				if err != nil {
					logger.NrfRegistrationLog.Errorf("deep copy failed: %v", err)
					continue
				}
				lastRegisteredConfig = copyConfig
			} else {
				logger.NrfRegistrationLog.Debugf("SMF[%s]: no changes in NF profile relevant config. Skipping re-registration.", nfInstanceID)
			}
		}
	}
}

func deepCopySessionManagement(input []nfConfigApi.SessionManagement) ([]nfConfigApi.SessionManagement, error) {
	b, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session management config: %w", err)
	}

	copy := []nfConfigApi.SessionManagement{}
	if err := json.Unmarshal(b, &copy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session management config: %w", err)
	}

	return copy, nil
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

// registerNF sends a RegisterNFInstance.
// If it fails, it keeps retrying until the context is cancelled by StartNfRegistrationService
var registerNF = func(registerCtx context.Context, newSessionManagementConfig []nfConfigApi.SessionManagement) {
	registerCtxMutex.Lock()
	defer registerCtxMutex.Unlock()
	interval := 0 * time.Millisecond
	nfInstanceID := smf_context.SMF_Self().NfInstanceID
	for {
		select {
		case <-registerCtx.Done():
			logger.NrfRegistrationLog.Infoln("no-op. Registration context was cancelled")
			return
		case <-time.After(interval):
			if registerCtx.Err() != nil {
				logger.NrfRegistrationLog.Infof("SMF[%s]: registration aborted just before sending RegisterNFInstance", nfInstanceID)
				return
			}
			nfProfile, _, err := consumer.SendRegisterNFInstance(newSessionManagementConfig)
			if err != nil {
				logger.NrfRegistrationLog.Errorln("register SMF instance to NRF failed. Will retry.", err.Error())
				interval = retryTime
				continue
			}
			logger.NrfRegistrationLog.Infoln("register SMF instance to NRF with updated profile succeeded")
			startKeepAliveTimer(nfProfile.HeartBeatTimer, newSessionManagementConfig)
			return
		}
	}
}

// heartbeatNF is the callback function, this is called when keepalivetimer elapsed.
// It sends an Update NF instance to the NRF. If it fails, it tries to register again.
// keepAliveTimer is restarted at the end.
func heartbeatNF(sessionConfig []nfConfigApi.SessionManagement) {
	keepAliveTimerMutex.Lock()
	if keepAliveTimer == nil {
		keepAliveTimerMutex.Unlock()
		logger.NrfRegistrationLog.Infoln("heartbeat timer has been stopped, heartbeat will not be sent to NRF")
		return
	}
	keepAliveTimerMutex.Unlock()

	patchItem := []models.PatchItem{
		{
			Op:    "replace",
			Path:  "/nfStatus",
			Value: "REGISTERED",
		},
	}
	nfProfile, problemDetails, err := consumer.SendUpdateNFInstance(patchItem)

	if shouldRegister(problemDetails, err) {
		logger.NrfRegistrationLog.Debugln("NF heartbeat failed. Trying to register again")
		nfProfile, _, err = consumer.SendRegisterNFInstance(sessionConfig)
		if err != nil {
			logger.NrfRegistrationLog.Errorln("register SMF instance error:", err.Error())
		} else {
			logger.NrfRegistrationLog.Infoln("register SMF instance to NRF with updated profile succeeded")
		}
	} else {
		logger.NrfRegistrationLog.Debugln("SMF update NF instance (heartbeat) succeeded")
	}
	startKeepAliveTimer(nfProfile.HeartBeatTimer, sessionConfig)
}

func shouldRegister(problemDetails *models.ProblemDetails, err error) bool {
	if problemDetails != nil {
		logger.NrfRegistrationLog.Warnln("SMF update NF instance (heartbeat) problem details:", problemDetails)
		return true
	}
	if err != nil {
		logger.NrfRegistrationLog.Warnln("SMF update NF instance (heartbeat) error:", err.Error())
		return true
	}
	return false
}

var DeregisterNF = func() {
	keepAliveTimerMutex.Lock()
	stopKeepAliveTimer()
	keepAliveTimerMutex.Unlock()
	err := consumer.SendDeregisterNFInstance()
	if err != nil {
		logger.NrfRegistrationLog.Warnln("deregister instance from NRF error:", err.Error())
		return
	}
	logger.NrfRegistrationLog.Infoln("deregister instance from NRF successful")
}

func startKeepAliveTimer(profileHeartbeatTimer int32, sessionConfig []nfConfigApi.SessionManagement) {
	keepAliveTimerMutex.Lock()
	stopKeepAliveTimer()
	defer keepAliveTimerMutex.Unlock()
	heartbeatTimer := defaultHeartbeatTimer
	if profileHeartbeatTimer > 0 {
		heartbeatTimer = profileHeartbeatTimer
	}
	heartbeatFunction := func() { heartbeatNF(sessionConfig) }
	// AfterFunc starts a timer and waits for keepAliveTimer to elapse and then calls heartbeatNF function
	keepAliveTimer = afterFunc(time.Duration(heartbeatTimer)*time.Second, heartbeatFunction)
	logger.NrfRegistrationLog.Debugf("started heartbeat timer: %v sec", heartbeatTimer)
}

func stopKeepAliveTimer() {
	if keepAliveTimer != nil {
		keepAliveTimer.Stop()
		keepAliveTimer = nil
		logger.NrfRegistrationLog.Debugln("stopped heartbeat timer")
	}
}
