// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package upf

import (
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
	// associationSetupTimeout bounds how long a UPF may sit in AssociatedSettingUp: neither
	// this loop nor the heartbeat loop acts on that state, so a lost or delayed Association
	// Setup Response would otherwise strand the UPF there forever.
	associationSetupTimeout = 20 * time.Second
)

func InitPfcpHeartbeatRequest() {
	// Iterate through all UPFs and send heartbeat to active UPFs
	for {
		time.Sleep(maxHeartbeatInterval * time.Second)
		userplane := context.SMF_Self().UserPlaneInformation
		if userplane == nil {
			continue
		}
		for _, upf := range userplane.UPFs {
			upf.UPF.UpfLock.Lock()
			if (upf.UPF.UPFStatus == context.AssociatedSetUpSuccess) && upf.UPF.NHeartBeat < maxHeartbeatRetry {
				err := message.SendHeartbeatRequest(upf.NodeID, upf.Port) // needs lock in sync rsp(adapter mode)
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

func ProbeInactiveUpfs() {
	// Iterate through all UPFs and send PFCP request to inactive UPFs
	for {
		time.Sleep(maxUpfProbeRetryInterval * time.Second)
		upfs := context.SMF_Self().UserPlaneInformation
		if upfs == nil {
			continue
		}
		for _, upf := range upfs.UPFs {
			probeUpf(upf)
		}
	}
}

// probeUpf resets a UPF stuck in AssociatedSettingUp past associationSetupTimeout, then (re)sends
// the PFCP Association Setup Request for any UPF that is still not associated. On a successful
// send it marks the UPF AssociatedSettingUp with a fresh AssociationSetupSentAt, so a retry issued
// from here is covered by the same timeout as one issued from service.Start, instead of relying on
// the next probe interval to notice a send that never got a response.
func probeUpf(upNode *context.UPNode) {
	upNode.UPF.UpfLock.Lock()
	defer upNode.UPF.UpfLock.Unlock()

	if upNode.UPF.UPFStatus == context.AssociatedSettingUp &&
		time.Since(upNode.UPF.AssociationSetupSentAt) > associationSetupTimeout {
		logger.PfcpLog.Warnf("pfcp association setup response never arrived for UPF[%v]; retrying", upNode.NodeID)
		upNode.UPF.UPFStatus = context.NotAssociated
	}
	if upNode.UPF.UPFStatus == context.NotAssociated {
		if err := message.SendPfcpAssociationSetupRequest(upNode.NodeID, upNode.Port); err != nil {
			logger.PfcpLog.Errorf("send pfcp association setup request failed: %v ", err)
			return
		}
		upNode.UPF.UPFStatus = context.AssociatedSettingUp
		upNode.UPF.AssociationSetupSentAt = time.Now()
	}
}
