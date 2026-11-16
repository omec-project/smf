// Copyright (C) 2024-Present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	utilLogger "github.com/omec-project/util/logger"
	"go.uber.org/zap/zapcore"
)

var component = utilLogger.NewComponent("SMF")

var (
	AppLog             = component.Category("App")
	InitLog            = component.Category("Init")
	CfgLog             = component.Category("CFG")
	DataRepoLog        = component.Category("DRepo")
	PfcpLog            = component.Category("PFCP")
	PduSessLog         = component.Category("PduSess")
	GsmLog             = component.Category("GSM")
	CtxLog             = component.Category("CTX")
	ConsumerLog        = component.Category("Consumer")
	GinLog             = component.Category("GIN")
	ProducerLog        = component.Category("Producer")
	UPNodeLog          = component.Category("UPNode")
	FsmLog             = component.Category("Fsm")
	TxnFsmLog          = component.Category("TxnFsm")
	QosLog             = component.Category("QosFsm")
	KafkaLog           = component.Category("Kafka")
	PollConfigLog      = component.Category("PollConfig")
	NrfRegistrationLog = component.Category("NrfRegistration")
	EventExposureLog   = component.Category("EventExposure")
)

// SetLogLevel: set the log level (panic|fatal|error|warn|info|debug)
func SetLogLevel(level zapcore.Level) {
	InitLog.Infoln("set log level:", level)
	component.SetLevel(level)
}
