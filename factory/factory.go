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
	"os"
	"sync"
	"time"

	grpcClient "github.com/omec-project/config5g/proto/client"
	protos "github.com/omec-project/config5g/proto/sdcoreConfig"
	"github.com/omec-project/smf/logger"
	"gopkg.in/yaml.v2"
)

var (
	SmfConfig         Config
	UERoutingConfig   RoutingConfig
	UpdatedSmfConfig  UpdateSmfConfig
	SmfConfigSyncLock sync.Mutex
)

// InitConfigFactory gets the NrfConfig and subscribes the config pod.
// This observes the GRPC client availability and connection status in a loop.
// When the GRPC server pod is restarted, GRPC connection status stuck in idle.
// If GRPC client does not exist, creates it. If client exists but GRPC connectivity is not ready,
// then it closes the existing client start a new client.
func InitConfigFactory(f string) error {
	if content, err := os.ReadFile(f); err != nil {
		return err
	} else {
		SmfConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &SmfConfig); yamlErr != nil {
			return yamlErr
		}

		if SmfConfig.Configuration.WebuiUri == "" {
			SmfConfig.Configuration.WebuiUri = "webui:9876"
		}

		if SmfConfig.Configuration.KafkaInfo.EnableKafka == nil {
			enableKafka := true
			SmfConfig.Configuration.KafkaInfo.EnableKafka = &enableKafka
		}

		if os.Getenv("MANAGED_BY_CONFIG_POD") == "true" {
			logger.CfgLog.Infoln("MANAGED_BY_CONFIG_POD is true")
			client, err := grpcClient.ConnectToConfigServer(SmfConfig.Configuration.WebuiUri)
			if err != nil {
				go updateConfig(client)
			}
			return err
		}
	}
	return nil
}

// updateConfig connects the config pod GRPC server and subscribes the config changes
// then updates SMF configuration
func updateConfig(client grpcClient.ConfClient) {
	var stream protos.ConfigService_NetworkSliceSubscribeClient
	var err error
	var configChannel chan *protos.NetworkSliceResponse
	for {
		if client != nil {
			stream, err = client.CheckGrpcConnectivity()
			if err != nil {
				logger.CfgLog.Errorf("%v", err)
				if stream != nil {
					time.Sleep(time.Second * 30)
					continue
				} else {
					err = client.GetConfigClientConn().Close()
					if err != nil {
						logger.CfgLog.Debugf("failing ConfigClient is not closed properly: %+v", err)
					}
					client = nil
					continue
				}
			}
			if configChannel == nil {
				configChannel = client.PublishOnConfigChange(true, stream)
				go SmfConfig.updateConfig(configChannel)
			}
		} else {
			client, err = grpcClient.ConnectToConfigServer(SmfConfig.Configuration.WebuiUri)
			if err != nil {
				logger.CfgLog.Errorf("%+v", err)
			}
			continue
		}
	}
}

func InitRoutingConfigFactory(f string) error {
	if content, err := os.ReadFile(f); err != nil {
		return err
	} else {
		UERoutingConfig = RoutingConfig{}

		if yamlErr := yaml.Unmarshal(content, &UERoutingConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
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
