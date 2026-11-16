// Copyright (C) 2024-Present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

/*
 * SMF Configuration Factory
 */

package factory

import (
	"fmt"
	"sync"

	"github.com/omec-project/smf/logger"
	"github.com/omec-project/util/nfconfig"
)

var (
	SmfConfig         Config
	UERoutingConfig   RoutingConfig
	SmfConfigSyncLock sync.Mutex
)

// InitConfigFactory gets the NrfConfig and subscribes the config pod.
// This observes the GRPC client availability and connection status in a loop.
// When the GRPC server pod is restarted, GRPC connection status stuck in idle.
// If GRPC client does not exist, creates it. If client exists but GRPC connectivity is not ready,
// then it closes the existing client start a new client.
func InitConfigFactory(f string) error {
	SmfConfig = Config{}

	if err := nfconfig.LoadYAML(f, &SmfConfig); err != nil {
		return err
	}

	if SmfConfig.Configuration.KafkaInfo.EnableKafka == nil {
		enableKafka := true
		SmfConfig.Configuration.KafkaInfo.EnableKafka = &enableKafka
	}

	setT3591Defaults()

	webuiUri, err := nfconfig.ResolveWebuiUri(SmfConfig.Configuration.WebuiUri, logger.CfgLog)
	if err != nil {
		return err
	}
	SmfConfig.Configuration.WebuiUri = webuiUri
	return nil
}

func InitRoutingConfigFactory(f string) error {
	UERoutingConfig = RoutingConfig{}

	return nfconfig.LoadYAML(f, &UERoutingConfig)
}

func CheckConfigVersion() error {
	currentVersion := SmfConfig.GetVersion()

	if currentVersion != SMF_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("SMF config version is [%s], but expected is [%s]",
			currentVersion, SMF_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("SMF config version [%s]", currentVersion)

	currentVersion = UERoutingConfig.GetVersion()

	if currentVersion != UE_ROUTING_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("UE-Routing config version is [%s], but expected is [%s]",
			currentVersion, UE_ROUTING_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("UE-Routing config version [%s]", currentVersion)

	return nil
}

// setT3591Defaults fills in the T3591 block so that an absent or partial configuration behaves
// as the specification requires rather than as a zero value. ExpireTime is deliberately left at
// zero when unset: that is what selects automatic resolution, and only an explicit value
// overrides it.
func setT3591Defaults() {
	if SmfConfig.Configuration == nil {
		return
	}
	if SmfConfig.Configuration.T3591 == nil {
		SmfConfig.Configuration.T3591 = &TimerValue{}
	}
	if SmfConfig.Configuration.T3591.Enable == nil {
		enable := true
		SmfConfig.Configuration.T3591.Enable = &enable
	}
	if SmfConfig.Configuration.T3591.MaxRetryTimes <= 0 {
		// TS 24.501 table 10.3.2 NOTE 1: the procedure is aborted on the fifth expiry, so the
		// command is retransmitted on the first four.
		SmfConfig.Configuration.T3591.MaxRetryTimes = 4
	}
}
