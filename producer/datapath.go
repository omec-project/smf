// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/lawfulintercept"
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
	// Lawful Interception CC Triggering Function: mark the session's forwarding
	// FARs for user-plane duplication when the target is tasked for CC, before
	// the FARs are encoded and sent to every serving UPF. Silent no-op unless LI
	// is configured.
	lawfulintercept.ApplyCCTrigger(smContext)

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
						port:    curDataPathNode.UPF.PFCPPort(),
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
	// verdicts owns it. Assigned through ResetPendingUPF, not the field directly: the PFCP response
	// handlers delete from this same map without SMLock, so a direct write races them (see
	// SMContext.PendingUPFLock's declaration).
	if smContext.SMContextState == context.SmStatePfcpCreatePending {
		smContext.ResetPendingUPF(pendingEstablish)
	}
	for ip, pfcp := range pfcpPool {
		sessionContext, exist := smContext.PFCPContext[ip]
		if !exist || sessionContext.RemoteSEID == 0 {
			// ip is the exact key this UPF was registered under in PendingUPF above, handed to the send
			// so a missing-context synchronous failure drains its own batch entry rather than waking
			// the create FSM while the rest of the batch is still in flight.
			err := message.SendPfcpSessionEstablishmentRequest(
				pfcp.nodeID, smContext, ip, pfcp.pdrList, pfcp.farList, nil, pfcp.qerList, pfcp.port)
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

// ModifySessionForLI sends a PFCP session modification carrying the forwarding
// FARs that the Lawful Interception CC trigger has just marked RULE_UPDATE
// (duplication switched on or off for an already-established session). It groups
// the changed FARs by serving UPF and sends one modification per live PFCP
// session, mirroring SendPFCPRules' per-UPF fan-out. Caller holds smContext.SMLock.
//
// It is injected into the LI subsystem via lawfulintercept.SetSessionModifier
// because smf/producer imports smf/lawfulintercept — the reverse call would be a
// cycle. It is silent by design: no LI-specific logging.
func ModifySessionForLI(smContext *context.SMContext) error {
	if smContext == nil || smContext.Tunnel == nil {
		return nil
	}
	type group struct {
		nodeID  context.NodeID
		port    uint16
		farList []*context.FAR
		seen    map[*context.FAR]bool
	}
	groups := map[string]*group{}
	for _, dataPath := range smContext.Tunnel.DataPathPool {
		if !dataPath.Activated {
			continue
		}
		for node := dataPath.FirstDPNode; node != nil; node = node.Next() {
			// No live PFCP session on this UPF yet, so nothing to modify. Checked before its FARs
			// are read, because the create path builds a UPF's establishment without SMLock and
			// writes those FARs' state while it does.
			ip := node.GetNodeIP()
			if sessionContext, exist := smContext.PFCPContext[ip]; !exist || sessionContext.RemoteSEID == 0 {
				continue
			}
			for _, tun := range []*context.GTPTunnel{node.UpLinkTunnel, node.DownLinkTunnel} {
				if tun == nil {
					continue
				}
				for _, pdr := range tun.PDR {
					if pdr == nil || pdr.FAR == nil || pdr.FAR.State != context.RULE_UPDATE {
						continue
					}
					g := groups[ip]
					if g == nil {
						g = &group{nodeID: node.UPF.NodeID, port: node.UPF.PFCPPort(), seen: map[*context.FAR]bool{}}
						groups[ip] = g
					}
					if !g.seen[pdr.FAR] {
						g.seen[pdr.FAR] = true
						g.farList = append(g.farList, pdr.FAR)
					}
				}
			}
		}
	}
	var firstErr error
	for _, g := range groups {
		// Only FARs are carried: LI flips the DUPL bit on existing forwarding FARs
		// (marked RULE_UPDATE), so there is nothing to create or remove.
		//
		// Sent through the LI-marked path so the response is recognisable. This
		// modification is not part of the session's own procedure and must not be
		// able to complete one: it is sent whenever a warrant changes, which can be
		// while the subscriber's own modification is outstanding to the same UPF.
		if err := message.SendPfcpSessionModificationRequestForLI(
			g.nodeID, smContext, g.farList, g.port); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
