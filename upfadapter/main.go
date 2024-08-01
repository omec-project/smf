// SPDX-FileCopyrightText: 2022-present Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"encoding/json"
	"io"
	"net/http"

	"upf-adapter/config"
	"upf-adapter/logger"
	"upf-adapter/pfcp"
	"upf-adapter/pfcp/udp"

	"github.com/wmnsk/go-pfcp/message"
)

// Hnadler for SMF initiated msgs
func handler(w http.ResponseWriter, req *http.Request) {
	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		logger.AppLog.Errorf("server: could not read request body: %s\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	var udpPodMsg config.UdpPodPfcpMsg
	json.Unmarshal(reqBody, &udpPodMsg)

	pfcpMessage, err := message.Parse(udpPodMsg.Msg.Body)
	if err != nil {
		logger.AppLog.Errorf("error parsing pfcp msg")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logger.AppLog.Debugf("\n received msg type [%v], upf nodeId [%s], smfIp [%v], msg [%v]",
		pfcpMessage.MessageType(), udpPodMsg.UpNodeID.NodeIdValue, udpPodMsg.SmfIp, udpPodMsg.Msg)

	pfcpJsonRsp, err := pfcp.ForwardPfcpMsgToUpf(pfcpMessage, udpPodMsg.UpNodeID)
	if err != nil {
		logger.AppLog.Errorf("error forwarding pfcp msg to UPF: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(pfcpJsonRsp)
	logger.AppLog.Debugf("response sent for %v", pfcpMessage.MessageType())
}

// UDP handler for pfcp msg from UPF
func init() {
	go udp.Run(pfcp.Dispatch)
}

// Handler for msgs from SMF
func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
