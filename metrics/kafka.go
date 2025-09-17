// SPDX-FileCopyrightText: 2022-present Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	mi "github.com/omec-project/util/metricinfo"
	"github.com/segmentio/kafka-go"
)

type Writer struct {
	kafkaWriter *kafka.Writer
}

var StatWriter Writer

func InitialiseKafkaStream(config *factory.Configuration) error {
	if !*config.KafkaInfo.EnableKafka {
		logger.KafkaLog.Warnln("Kafka is disabled")
		return nil
	}

	brokerUrl := "kafka:9092"
	topicName := "sdcore-data-source-smf"

	if config.KafkaInfo.BrokerUri != "" && config.KafkaInfo.BrokerPort != 0 {
		brokerUrl = fmt.Sprintf("%s:%d", config.KafkaInfo.BrokerUri, config.KafkaInfo.BrokerPort)
	}

	logger.KafkaLog.Debugf("initialise kafka broker url: %s", brokerUrl)

	if config.KafkaInfo.Topic != "" {
		topicName = config.KafkaInfo.Topic
	}

	logger.KafkaLog.Debugf("initialise kafka Topic: %s", topicName)

	producer := kafka.Writer{
		Addr:                   kafka.TCP(brokerUrl),
		Topic:                  topicName,
		AllowAutoTopicCreation: true,
		Balancer:               &kafka.LeastBytes{},
		BatchTimeout:           10 * time.Millisecond,
	}

	StatWriter = Writer{
		kafkaWriter: &producer,
	}

	logger.KafkaLog.Debugf("initialising kafka stream with url[%s], topic[%s]", brokerUrl, topicName)
	return nil
}

func GetWriter() Writer {
	return StatWriter
}

func (writer Writer) SendMessage(message []byte) error {
	if !*factory.SmfConfig.Configuration.KafkaInfo.EnableKafka {
		return nil
	}
	msg := kafka.Message{Value: message}
	if err := writer.kafkaWriter.WriteMessages(context.Background(), msg); err != nil {
		logger.KafkaLog.Errorf("kafka send message write error: %s", err.Error())
		return err
	}
	return nil
}

func (writer Writer) PublishPduSessEvent(ctxt mi.CoreSubscriber, op mi.SubscriberOp) error {
	smKafkaEvt := mi.MetricEvent{
		EventType:      mi.CSubscriberEvt,
		SubscriberData: mi.CoreSubscriberData{Subscriber: ctxt, Operation: op},
	}
	if msg, err := json.Marshal(smKafkaEvt); err != nil {
		logger.KafkaLog.Errorf("publishing pdu sess event marshal error: %s", err.Error())
		return err
	} else {
		logger.KafkaLog.Debugf("publishing pdu sess event[%s]", string(msg))
		err := StatWriter.SendMessage(msg)
		if err != nil {
			logger.KafkaLog.Errorf("publishing pdu sess event error: %s", err.Error())
		}
	}
	return nil
}

var nfInstanceId string

// initialised by context package
func SetNfInstanceId(s string) {
	nfInstanceId = s
}

func PublishMsgEvent(msgType mi.SmfMsgType) error {
	if !*factory.SmfConfig.Configuration.KafkaInfo.EnableKafka {
		return nil
	}
	smKafkaMsgEvt := mi.MetricEvent{EventType: mi.CMsgTypeEvt, MsgType: mi.CoreMsgType{MsgType: msgType.String(), SourceNfId: nfInstanceId}}
	if msg, err := json.Marshal(smKafkaMsgEvt); err != nil {
		logger.KafkaLog.Errorf("publishing msg event marshal error: %s", err.Error())
		return err
	} else {
		logger.KafkaLog.Debugf("publishing msg event: %s", string(msg))
		err := StatWriter.SendMessage(msg)
		if err != nil {
			logger.KafkaLog.Errorf("publishing msg event error: %s", err.Error())
		}
	}
	return nil
}

func (writer Writer) PublishNfStatusEvent(msgEvent mi.MetricEvent) error {
	if msg, err := json.Marshal(msgEvent); err != nil {
		logger.KafkaLog.Errorf("publishing nf status marshal error: %s", err.Error())
		return err
	} else {
		logger.KafkaLog.Debugf("publishing nf status event: %s", string(msg))
		if err := StatWriter.SendMessage(msg); err != nil {
			logger.KafkaLog.Errorf("publishing nf status event error: %s", err.Error())
		}
	}
	return nil
}
