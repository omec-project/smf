// SPDX-FileCopyrightText: 2023 Open Networking Foundation <info@opennetworking.org>
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/omec-project/smf/factory"
	"github.com/omec-project/util/metricinfo"
)

var my_false bool = false

func TestInitializeKafkaStreamWithKafkaDisabled(t *testing.T) {
	config := factory.Configuration{
		KafkaInfo: factory.KafkaInfo{
			EnableKafka: &my_false,
		},
	}

	result := InitialiseKafkaStream(&config)

	if result != nil {
		t.Errorf("expected return value to be nil, got %v", result)
	}
	if StatWriter.kafkaWriter != nil {
		t.Errorf("expected kafkaWrite to be nil, got %v", StatWriter.kafkaWriter)
	}
}

func TestSendMessageWithKafkaDisabled(t *testing.T) {
	configuration := factory.Configuration{
		KafkaInfo: factory.KafkaInfo{
			EnableKafka: &my_false,
		},
	}
	config := factory.Config{
		Configuration: &configuration,
	}
	factory.SmfConfig = config

	err := InitialiseKafkaStream(&configuration)
	if err != nil {
		t.Errorf("expected return value to be nil, got %v", err)
	}

	writer := GetWriter()

	// If the kafkaWriter is called, this will panic and fail the test
	result := writer.SendMessage([]byte{0xFF})

	if result != nil {
		t.Errorf("expected return value to be nil, got %v", result)
	}
}

func TestPublishPduSessEventWithKafkaDisabled(t *testing.T) {
	configuration := factory.Configuration{
		KafkaInfo: factory.KafkaInfo{
			EnableKafka: &my_false,
		},
	}
	config := factory.Config{
		Configuration: &configuration,
	}
	factory.SmfConfig = config

	err := InitialiseKafkaStream(&configuration)
	if err != nil {
		t.Errorf("expected return value to be nil, got %v", err)
	}

	writer := GetWriter()

	// If the kafkaWriter is called, this will panic and fail the test
	result := writer.PublishPduSessEvent(metricinfo.CoreSubscriber{}, 0)

	if result != nil {
		t.Errorf("expected return value to be nil, got %v", result)
	}
}

func TestPublishMsgEventWithKafkaDisabled(t *testing.T) {
	configuration := factory.Configuration{
		KafkaInfo: factory.KafkaInfo{
			EnableKafka: &my_false,
		},
	}
	config := factory.Config{
		Configuration: &configuration,
	}
	factory.SmfConfig = config

	err := InitialiseKafkaStream(&configuration)
	if err != nil {
		t.Errorf("expected return value to be nil, got %v", err)
	}

	// If the kafkaWriter is called, this will panic and fail the test
	result := PublishMsgEvent(0)

	if result != nil {
		t.Errorf("expected return value to be nil, got %v", result)
	}
}

func TestPublishNfStatusWithKafkaDisabled(t *testing.T) {
	configuration := factory.Configuration{
		KafkaInfo: factory.KafkaInfo{
			EnableKafka: &my_false,
		},
	}
	config := factory.Config{
		Configuration: &configuration,
	}
	factory.SmfConfig = config

	err := InitialiseKafkaStream(&configuration)
	if err != nil {
		t.Errorf("expected return value to be nil, got %v", err)
	}

	writer := GetWriter()

	// If the kafkaWriter is called, this will panic and fail the test
	result := writer.PublishNfStatusEvent(metricinfo.MetricEvent{})

	if result != nil {
		t.Errorf("expected return value to be nil, got %v", result)
	}
}
