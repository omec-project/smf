// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/pfcp/message"
)

type PFCPState struct {
	nodeID  context.NodeID
	pdrList []*context.PDR
	farList []*context.FAR
	qerList []*context.QER
	port    uint16
}

// SendPFCPRules send all datapaths to UPFs
func SendPFCPRules(smContext *context.SMContext) {
	pfcpPool := make(map[string]*PFCPState)

	for _, dataPath := range smContext.Tunnel.DataPathPool {
		if dataPath.Activated {
			for curDataPathNode := dataPath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
				pdrList := make([]*context.PDR, 0, 2)
				farList := make([]*context.FAR, 0, 2)
				qerList := make([]*context.QER, 0, 2)

				if curDataPathNode.UpLinkTunnel != nil && curDataPathNode.UpLinkTunnel.PDR != nil {
					for _, pdr := range curDataPathNode.UpLinkTunnel.PDR {
						pdrList = append(pdrList, pdr)
						farList = append(farList, pdr.FAR)
						if pdr.QER != nil {
							qerList = append(qerList, pdr.QER...)
						}
					}
				}
				if curDataPathNode.DownLinkTunnel != nil && curDataPathNode.DownLinkTunnel.PDR != nil {
					for _, pdr := range curDataPathNode.DownLinkTunnel.PDR {
						pdrList = append(pdrList, pdr)
						farList = append(farList, pdr.FAR)

						if pdr.QER != nil {
							qerList = append(qerList, pdr.QER...)
						}
					}
				}

				pfcpState := pfcpPool[curDataPathNode.GetNodeIP()]
				if pfcpState == nil {
					pfcpPool[curDataPathNode.GetNodeIP()] = &PFCPState{
						nodeID:  curDataPathNode.UPF.NodeID,
						port:    curDataPathNode.UPF.Port,
						pdrList: pdrList,
						farList: farList,
						qerList: qerList,
					}
				} else {
					pfcpState.pdrList = append(pfcpState.pdrList, pdrList...)
					pfcpState.farList = append(pfcpState.farList, farList...)
					pfcpState.qerList = append(pfcpState.qerList, qerList...)
				}
			}
		}
	}
	// Every UPF an establishment request goes out to here is one the response handlers must hear
	// back from before the single create verdict is queued: see PendingUPF on SMContext. Built as a
	// complete set before any request is sent -- and before PendingUPF is touched -- rather than
	// grown one entry at a time alongside the sends below: a synchronous dispatch (e.g. the adapter)
	// can deliver the first UPF's response before a later UPF in this loop has been added, and an
	// incomplete map would let that response see itself as the last one pending and queue a verdict
	// early.
	pendingEstablish := make(context.PendingUPF)
	for ip := range pfcpPool {
		sessionContext, exist := smContext.PFCPContext[ip]
		if !exist || sessionContext.RemoteSEID == 0 {
			pendingEstablish[ip] = true
		}
	}
	// PendingUPF is also read by an awaited modification (SmStatePfcpModify); restoration can call
	// this function to reissue rules while one is in flight (see pfcp/message/send.go), a supported
	// overlap. Replacing the map here unconditionally would discard that modification's own
	// bookkeeping, so only the create-pending procedure that actually consumes establishment
	// verdicts owns it.
	if smContext.SMContextState == context.SmStatePfcpCreatePending {
		smContext.PendingUPF = pendingEstablish
	}
	for ip, pfcp := range pfcpPool {
		sessionContext, exist := smContext.PFCPContext[ip]
		if !exist || sessionContext.RemoteSEID == 0 {
			err := message.SendPfcpSessionEstablishmentRequest(
				pfcp.nodeID, smContext, pfcp.pdrList, pfcp.farList, nil, pfcp.qerList, pfcp.port)
			if err != nil {
				logger.PduSessLog.Errorf("send pfcp session establishment request failed: %v for UPF[%v, %v]: ", err, pfcp.nodeID, pfcp.nodeID.ResolveNodeIdToIp())
			}
		} else {
			err := message.SendPfcpSessionModificationRequest(
				pfcp.nodeID, smContext, pfcp.pdrList, pfcp.farList, nil, pfcp.qerList, nil, nil, nil, pfcp.port)
			if err != nil {
				logger.PduSessLog.Errorf("send pfcp session modification request failed: %v for UPF[%v, %v]: ", err, pfcp.nodeID, pfcp.nodeID.ResolveNodeIdToIp())
			}
		}
	}
}
