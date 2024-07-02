// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
)

type PFCPState struct {
	nodeID  smf_context.NodeID
	pdrList []*smf_context.PDR
	farList []*smf_context.FAR
	qerList []*smf_context.QER
	port    uint16
}

// SendPFCPRule send one datapath to UPF
func SendPFCPRule(smContext *smf_context.SMContext, dataPath *smf_context.DataPath) {
	logger.PduSessLog.Infoln("Send PFCP Rule")
	logger.PduSessLog.Infoln("DataPath: ", dataPath)
	for curDataPathNode := dataPath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
		pdrList := make([]*smf_context.PDR, 0, 2)
		farList := make([]*smf_context.FAR, 0, 2)
		qerList := make([]*smf_context.QER, 0, 2)

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

		sessionContext, exist := smContext.PFCPContext[curDataPathNode.GetNodeIP()]
		if !exist || sessionContext.RemoteSEID == 0 {
			remoteAddress := &net.UDPAddr{
				IP:   curDataPathNode.UPF.NodeID.ResolveNodeIdToIp(),
				Port: int(curDataPathNode.UPF.Port),
			}
			pfcp_message.SendPfcpSessionEstablishmentRequest(
				remoteAddress,
				curDataPathNode.UPF.NodeID,
				smContext,
				pdrList,
				farList,
				nil,
				qerList,
			)
		} else {
			remoteAddress := &net.UDPAddr{
				IP:   curDataPathNode.UPF.NodeID.ResolveNodeIdToIp(),
				Port: int(curDataPathNode.UPF.Port),
			}
			pfcp_message.SendPfcpSessionModificationRequest(
				remoteAddress,
				curDataPathNode.UPF.NodeID,
				smContext,
				pdrList,
				farList,
				nil,
				qerList,
			)
		}
	}
}

// SendPFCPRules send all datapaths to UPFs
func SendPFCPRules(smContext *smf_context.SMContext) {
	pfcpPool := make(map[string]*PFCPState)

	for _, dataPath := range smContext.Tunnel.DataPathPool {
		if dataPath.Activated {
			for curDataPathNode := dataPath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
				pdrList := make([]*smf_context.PDR, 0, 2)
				farList := make([]*smf_context.FAR, 0, 2)
				qerList := make([]*smf_context.QER, 0, 2)

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
	for ip, pfcp := range pfcpPool {
		sessionContext, exist := smContext.PFCPContext[ip]
		remoteAddress := &net.UDPAddr{
			IP:   pfcp.nodeID.ResolveNodeIdToIp(),
			Port: int(pfcp.port),
		}
		if !exist || sessionContext.RemoteSEID == 0 {
			pfcp_message.SendPfcpSessionEstablishmentRequest(
				remoteAddress,
				pfcp.nodeID,
				smContext,
				pfcp.pdrList,
				pfcp.farList,
				nil,
				pfcp.qerList,
			)
		} else {
			pfcp_message.SendPfcpSessionModificationRequest(
				remoteAddress,
				pfcp.nodeID,
				smContext,
				pfcp.pdrList,
				pfcp.farList,
				nil,
				pfcp.qerList,
			)
		}
	}
}

func removeDataPath(smContext *smf_context.SMContext, datapath *smf_context.DataPath) {
	for curDPNode := datapath.FirstDPNode; curDPNode != nil; curDPNode = curDPNode.Next() {
		if curDPNode.DownLinkTunnel != nil && curDPNode.DownLinkTunnel.PDR != nil {
			for _, pdr := range curDPNode.DownLinkTunnel.PDR {
				pdr.State = smf_context.RULE_REMOVE
				pdr.FAR.State = smf_context.RULE_REMOVE
			}
		}
		if curDPNode.UpLinkTunnel != nil && curDPNode.UpLinkTunnel.PDR != nil {
			for _, pdr := range curDPNode.UpLinkTunnel.PDR {
				pdr.State = smf_context.RULE_REMOVE
				pdr.FAR.State = smf_context.RULE_REMOVE
			}
		}
	}
}

// UpdateDataPathToUPF update the datapath of the UPF
func UpdateDataPathToUPF(smContext *smf_context.SMContext, oldDataPath, updateDataPath *smf_context.DataPath) {
	if oldDataPath == nil {
		SendPFCPRule(smContext, updateDataPath)
		return
	} else {
		removeDataPath(smContext, oldDataPath)
		SendPFCPRule(smContext, updateDataPath)
	}
}
