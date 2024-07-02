// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package upf

import (
	"net"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/pfcp/message"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
)

const (
	maxHeartbeatRetry        = 3  // sec
	maxHeartbeatInterval     = 10 // sec
	maxUpfProbeRetryInterval = 10 // sec
)

func InitPfcpHeartbeatRequest(userplane *context.UserPlaneInformation) {
	// Iterate through all UPFs and send heartbeat to active UPFs
	for {
		time.Sleep(maxHeartbeatInterval * time.Second)
		for _, upf := range userplane.UPFs {
			upf.UPF.UpfLock.Lock()
			if (upf.UPF.UPFStatus == context.AssociatedSetUpSuccess) && upf.UPF.NHeartBeat < maxHeartbeatRetry {
				remoteAddress := &net.UDPAddr{
					IP:   upf.NodeID.ResolveNodeIdToIp(),
					Port: int(upf.Port),
				}
				err := message.SendHeartbeatRequest(remoteAddress, upf.NodeID) // needs lock in sync rsp(adapter mode)
				if err != nil {
					logger.PfcpLog.Errorf("send pfcp heartbeat request failed: %v for UPF[%v, %v]: ", err, upf.NodeID, upf.NodeID.ResolveNodeIdToIp())
				} else {
					upf.UPF.NHeartBeat++
				}
			} else if upf.UPF.NHeartBeat == maxHeartbeatRetry {
				logger.PfcpLog.Errorf("pfcp heartbeat failure for UPF: [%v]", upf.NodeID)
				heartbeatRequest := pfcp_message.HeartbeatRequest{}
				metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, heartbeatRequest.MessageTypeName(), "Out", "Failure", "Timeout")
				upf.UPF.UPFStatus = context.NotAssociated
			}
			upf.UPF.UpfLock.Unlock()
		}
	}
}

func ProbeInactiveUpfs(upfs *context.UserPlaneInformation) {
	// Iterate through all UPFs and send PFCP request to inactive UPFs
	for {
		time.Sleep(maxUpfProbeRetryInterval * time.Second)
		for _, upf := range upfs.UPFs {
			upf.UPF.UpfLock.Lock()
			if upf.UPF.UPFStatus == context.NotAssociated {
				remoteAddress := &net.UDPAddr{
					IP:   upf.NodeID.ResolveNodeIdToIp(),
					Port: int(upf.Port),
				}
				message.SendPfcpAssociationSetupRequest(remoteAddress, upf.NodeID)
			}
			upf.UPF.UpfLock.Unlock()
		}
	}
}
