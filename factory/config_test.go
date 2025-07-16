// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	GNB = "gnb"
)

func TestKafkaEnabledByDefault(t *testing.T) {
	err := InitConfigFactory("../config/smfcfg.yaml")
	if err != nil {
		t.Errorf("Could not load default configuration file: %v", err)
	}
	if !*SmfConfig.Configuration.KafkaInfo.EnableKafka {
		t.Errorf("Expected Kafka to be enabled by default, was disabled")
	}
}

// Webui URL is not set then default Webui URL value is returned
func TestGetDefaultWebuiUrl(t *testing.T) {
	if err := InitConfigFactory("../config/smfcfg.yaml"); err != nil {
		t.Logf("error in InitConfigFactory: %v", err)
	}
	got := SmfConfig.Configuration.WebuiUri
	want := "http://webui:5001"
	assert.Equal(t, got, want, "The webui URL is not correct.")
}

// Webui URL is set to a custom value then custom Webui URL is returned
func TestGetCustomWebuiUrl(t *testing.T) {
	if err := InitConfigFactory("../config/smfcfg_with_custom_webui_url.yaml"); err != nil {
		t.Logf("error in InitConfigFactory: %v", err)
	}
	got := SmfConfig.Configuration.WebuiUri
	want := "https://myspecialwebui:5002"
	assert.Equal(t, got, want, "The webui URL is not correct.")
}
