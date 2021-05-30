/*
 * AMF Configuration Factory
 */

package factory

import (
	"fmt"
	"reflect"
	"io/ioutil"

	"gopkg.in/yaml.v2"

	"github.com/free5gc/smf/logger"
)

var (
	SmfConfig       Config
	UERoutingConfig RoutingConfig
)

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		SmfConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &SmfConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}

func InitRoutingConfigFactory(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		UERoutingConfig = RoutingConfig{}

		if yamlErr := yaml.Unmarshal(content, &UERoutingConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}

func UpdateSmfConfig(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		var smfConfig Config

		if yamlErr := yaml.Unmarshal(content, &smfConfig); yamlErr != nil {
			return yamlErr
		}
		//Checking which config has been changed
		if reflect.DeepEqual(SmfConfig.Configuration.SmfName, smfConfig.Configuration.SmfName) == false {
			logger.CfgLog.Infoln("updated SMF Name ", smfConfig.Configuration.SmfName)
		} 
		if reflect.DeepEqual(SmfConfig.Configuration.Sbi, smfConfig.Configuration.Sbi) == false {
			logger.CfgLog.Infoln("updated SMF Name ", smfConfig.Configuration.Sbi)
		} 
		if reflect.DeepEqual(SmfConfig.Configuration.PFCP, smfConfig.Configuration.PFCP) == false {
			logger.CfgLog.Infoln("updated PFCP ", smfConfig.Configuration.PFCP)
		} 
		if reflect.DeepEqual(SmfConfig.Configuration.SmfName, smfConfig.Configuration.NrfUri) == false {
			logger.CfgLog.Infoln("updated NrfUri ", smfConfig.Configuration.NrfUri)
		} 
		if reflect.DeepEqual(SmfConfig.Configuration.UserPlaneInformation, smfConfig.Configuration.UserPlaneInformation) == false {
			logger.CfgLog.Infoln("updated UserPlaneInformation ", smfConfig.Configuration.UserPlaneInformation)
		} 
		if reflect.DeepEqual(SmfConfig.Configuration.ServiceNameList, smfConfig.Configuration.ServiceNameList) == false {
			logger.CfgLog.Infoln("updated ServiceNameList ", smfConfig.Configuration.ServiceNameList)
		} 
		if reflect.DeepEqual(SmfConfig.Configuration.SNssaiInfo, smfConfig.Configuration.SNssaiInfo) == false {
			logger.CfgLog.Infoln("updated SNssaiInfo ", smfConfig.Configuration.SNssaiInfo)
		} 
		if reflect.DeepEqual(SmfConfig.Configuration.ULCL, smfConfig.Configuration.ULCL) == false {
			logger.CfgLog.Infoln("updated ULCL ", smfConfig.Configuration.ULCL)
		} 
		SmfConfig = smfConfig
	}
	return nil
}

func CheckConfigVersion() error {
	currentVersion := SmfConfig.GetVersion()

	if currentVersion != SMF_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("SMF config version is [%s], but expected is [%s].",
			currentVersion, SMF_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("SMF config version [%s]", currentVersion)

	currentVersion = UERoutingConfig.GetVersion()

	if currentVersion != UE_ROUTING_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("UE-Routing config version is [%s], but expected is [%s].",
			currentVersion, UE_ROUTING_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("UE-Routing config version [%s]", currentVersion)

	return nil
}
