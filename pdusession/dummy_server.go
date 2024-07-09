// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package pdusession

import (
	"log"
	"net"
	"net/http"

	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/pfcp"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/omec-project/util/http2_util"
	logger_util "github.com/omec-project/util/logger"
	"github.com/omec-project/util/path_util"
)

func DummyServer() {
	router := logger_util.NewGinWithLogrus(logger.GinLog)

	AddService(router)

	sourceAddress := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8805,
	}

	go udp.Run(sourceAddress, pfcp.Dispatch)
	err := udp.WaitForServer()
	if err != nil {
		log.Fatal(err)
	}

	smfKeyLogPath := path_util.Free5gcPath("free5gc/smfsslkey.log")
	smfPemPath := path_util.Free5gcPath("free5gc/support/TLS/smf.pem")
	smfkeyPath := path_util.Free5gcPath("free5gc/support/TLS/smf.key")

	var server *http.Server
	if srv, err := http2_util.NewServer(":29502", smfKeyLogPath, router); err != nil {
	} else {
		server = srv
	}

	if err := server.ListenAndServeTLS(smfPemPath, smfkeyPath); err != nil {
		log.Fatal(err)
	}
}
