// SPDX-FileCopyrightText: 2022-present Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package message

import (
	"net"
	"time"

	"upf-adapter/config"
	"upf-adapter/logger"
	"upf-adapter/pfcp/handler"
	"upf-adapter/pfcp/udp"
	"upf-adapter/types"

	"github.com/wmnsk/go-pfcp/message"
)

func SendPfcpAssociationSetupRequest(upNodeID types.NodeID, pMsg message.Message) error {
	logger.PfcpLog.Debugf("send pfcp association request to upfNodeId [%v], pfcpMsg [%v]", upNodeID, pMsg)
	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: udp.PFCP_PORT,
	}
	eventData := udp.PfcpEventData{LSEID: 0, ErrHandler: handler.HandlePfcpSendError}
	logger.PfcpLog.Debugf("send pfcp msg addr [%v], pfcpMsg [%v]", addr, pMsg)
	if err := udp.SendPfcp(pMsg, addr, eventData); err != nil {
		return err
	}
	return nil
}

func SendHeartbeatRequest(upNodeID types.NodeID, pMsg message.Message) error {
	addr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: udp.PFCP_PORT,
	}
	udp.SendPfcp(pMsg, addr, nil)
	return nil
}

func SendPfcpSessionEstablishmentRequest(upNodeID types.NodeID, pMsg message.Message) error {
	upaddr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: udp.PFCP_PORT,
	}
	eventData := udp.PfcpEventData{LSEID: 0, ErrHandler: handler.HandlePfcpSendError}
	if err := udp.SendPfcp(pMsg, upaddr, eventData); err != nil {
		return err
	}
	return nil
}

func SendPfcpSessionModificationRequest(upNodeID types.NodeID, pMsg message.Message) error {
	upaddr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: udp.PFCP_PORT,
	}
	eventData := udp.PfcpEventData{LSEID: 0, ErrHandler: handler.HandlePfcpSendError}
	if err := udp.SendPfcp(pMsg, upaddr, eventData); err != nil {
		return err
	}
	return nil
}

func SendPfcpSessionDeletionRequest(upNodeID types.NodeID, pMsg message.Message) error {
	upaddr := &net.UDPAddr{
		IP:   upNodeID.ResolveNodeIdToIp(),
		Port: udp.PFCP_PORT,
	}
	eventData := udp.PfcpEventData{LSEID: 0, ErrHandler: handler.HandlePfcpSendError}
	if err := udp.SendPfcp(pMsg, upaddr, eventData); err != nil {
		return err
	}
	return nil
}

// Go routine to send hearbeat towards UPFs
func ProbeUpfHearbeatReq() {
	for {
		time.Sleep(5 * time.Second)
		for nodeId, upf := range config.UpfCfg.UPFs {

			logger.PfcpLog.Debugf("sending heartbeat request to upf [%v]", nodeId)
			if config.IsUpfAssociated(upf.NodeID) {
				pfcpMsg, err := config.BuildPfcpHeartbeatRequest()
				if err != nil {
					logger.PfcpLog.Errorf("Failed to build heartbeat request for upf [%v]", nodeId)
					continue
				}
				SendHeartbeatRequest(upf.NodeID, pfcpMsg)
			}
		}
	}
}
