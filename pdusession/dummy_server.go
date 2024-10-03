// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package pdusession

import (
	"net/http"

	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/pfcp"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/omec-project/util/http2_util"
	utilLogger "github.com/omec-project/util/logger"
	"github.com/omec-project/util/path_util"
)

func DummyServer() {
	router := utilLogger.NewGinWithZap(logger.GinLog)

	AddService(router)

	go udp.Run(pfcp.Dispatch)

	smfKeyLogPath := path_util.Free5gcPath("free5gc/smfsslkey.log")
	smfPemPath := path_util.Free5gcPath("free5gc/support/TLS/smf.pem")
	smfkeyPath := path_util.Free5gcPath("free5gc/support/TLS/smf.key")

	var server *http.Server
	if srv, err := http2_util.NewServer(":29502", smfKeyLogPath, router); err != nil {
	} else {
		server = srv
	}

	if err := server.ListenAndServeTLS(smfPemPath, smfkeyPath); err != nil {
		logger.PduSessLog.Fatalln(err)
	}
}
