// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package producer

import (
	"net"
	"reflect"

	"github.com/free5gc/flowdesc"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/pfcp/pfcpUdp"
	"github.com/free5gc/smf/context"
	"github.com/free5gc/smf/logger"
	"github.com/free5gc/smf/pfcp/message"
)

func AddPDUSessionAnchorAndULCL(smContext *context.SMContext, nodeID pfcpType.NodeID) {
	bpMGR := smContext.BPManager
	pendingUPF := bpMGR.PendingUPF

	switch bpMGR.AddingPSAState {
	case context.ActivatingDataPath:
		// select PSA2
		bpMGR.SelectPSA2(smContext)
		smContext.AllocateLocalSEIDForDataPath(bpMGR.ActivatingPath)
		// select an upf as ULCL
		err := bpMGR.FindULCL(smContext)
		if err != nil {
			logger.PduSessLog.Errorln(err)
			return
		}

		// Allocate Path PDR and TEID
		bpMGR.ActivatingPath.ActivateTunnelAndPDR(smContext, 255)
		// N1N2MessageTransfer Here

		// Establish PSA2
		EstablishPSA2(smContext)
	case context.EstablishingNewPSA:

		trggierUPFIP := nodeID.ResolveNodeIdToIp().String()
		_, exist := pendingUPF[trggierUPFIP]

		if exist {
			delete(pendingUPF, trggierUPFIP)
		} else {
			logger.CtxLog.Warnln("In AddPDUSessionAnchorAndULCL case EstablishingNewPSA")
			logger.CtxLog.Warnln("UPF IP ", trggierUPFIP, " doesn't exist in pending UPF!")
			return
		}

		if pendingUPF.IsEmpty() {
			EstablishRANTunnelInfo(smContext)
			// Establish ULCL
			EstablishULCL(smContext)
		}

	case context.EstablishingULCL:

		trggierUPFIP := nodeID.ResolveNodeIdToIp().String()
		_, exist := pendingUPF[trggierUPFIP]

		if exist {
			delete(pendingUPF, trggierUPFIP)
		} else {
			logger.CtxLog.Warnln("In AddPDUSessionAnchorAndULCL case EstablishingULCL")
			logger.CtxLog.Warnln("UPF IP ", trggierUPFIP, " doesn't exist in pending UPF!")
			return
		}

		if pendingUPF.IsEmpty() {
			UpdatePSA2DownLink(smContext)
		}

	case context.UpdatingPSA2DownLink:

		trggierUPFIP := nodeID.ResolveNodeIdToIp().String()
		_, exist := pendingUPF[trggierUPFIP]

		if exist {
			delete(pendingUPF, trggierUPFIP)
		} else {
			logger.CtxLog.Warnln("In AddPDUSessionAnchorAndULCL case EstablishingULCL")
			logger.CtxLog.Warnln("UPF IP ", trggierUPFIP, " doesn't exist in pending UPF!")
			return
		}

		if pendingUPF.IsEmpty() {
			UpdateRANAndIUPFUpLink(smContext)
		}
	case context.UpdatingRANAndIUPFUpLink:
		trggierUPFIP := nodeID.ResolveNodeIdToIp().String()
		_, exist := pendingUPF[trggierUPFIP]

		if exist {
			delete(pendingUPF, trggierUPFIP)
		} else {
			logger.CtxLog.Warnln("In AddPDUSessionAnchorAndULCL case UpdatingRANAndIUPFUpLink")
			logger.CtxLog.Warnln("UPF IP ", trggierUPFIP, " doesn't exist in pending UPF!")
			return
		}

		if pendingUPF.IsEmpty() {
			bpMGR.AddingPSAState = context.Finished
			bpMGR.BPStatus = context.AddPSASuccess
			logger.CtxLog.Infoln("[SMF] Add PSA success")
		}
	}
}

func EstablishPSA2(smContext *context.SMContext) {
	bpMGR := smContext.BPManager
	bpMGR.PendingUPF = make(context.PendingUPF)
	activatingPath := bpMGR.ActivatingPath
	ulcl := bpMGR.ULCL
	logger.PduSessLog.Infoln("In EstablishPSA2")
	nodeAfterULCL := false
	for curDataPathNode := activatingPath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
		if nodeAfterULCL {
			addr := net.UDPAddr{
				IP:   curDataPathNode.UPF.NodeID.NodeIdValue,
				Port: pfcpUdp.PFCP_PORT,
			}

			logger.PduSessLog.Traceln("Send to upf addr: ", addr.String())

			upLinkPDR := curDataPathNode.UpLinkTunnel.PDR

			pdrList := []*context.PDR{upLinkPDR}
			farList := []*context.FAR{upLinkPDR.FAR}
			barList := []*context.BAR{}
			qerList := upLinkPDR.QER

			lastNode := curDataPathNode.Prev()

			if lastNode != nil && !reflect.DeepEqual(lastNode.UPF.NodeID, ulcl.NodeID) {
				downLinkPDR := curDataPathNode.DownLinkTunnel.PDR
				pdrList = append(pdrList, downLinkPDR)
				farList = append(farList, downLinkPDR.FAR)
			}

			curDPNodeIP := curDataPathNode.UPF.NodeID.ResolveNodeIdToIp().String()
			bpMGR.PendingUPF[curDPNodeIP] = true
			message.SendPfcpSessionEstablishmentRequest(
				curDataPathNode.UPF.NodeID, smContext, pdrList, farList, barList, qerList)
		} else {
			if reflect.DeepEqual(curDataPathNode.UPF.NodeID, ulcl.NodeID) {
				nodeAfterULCL = true
			}
		}
	}

	bpMGR.AddingPSAState = context.EstablishingNewPSA
	logger.PduSessLog.Traceln("End of EstablishPSA2")
}

func ULCLModificationRequest(smContext *context.SMContext, appFlow string, precedence uint32, appID string, sdfFilter string) {

	logger.PduSessLog.Infoln("In ULCLModificationRequest")

	bpMGR := smContext.BPManager
	bpMGR.PendingUPF = make(context.PendingUPF)
	activatingPath := bpMGR.ActivatingPath
	ulcl := bpMGR.ULCL

	//find updatedUPF in activatingPath
	for curDPNode := activatingPath.FirstDPNode; curDPNode != nil; curDPNode = curDPNode.Next() {
		if reflect.DeepEqual(ulcl.NodeID, curDPNode.UPF.NodeID) {
			UPLinkPDR := curDPNode.UpLinkTunnel.PDR
			DownLinkPDR := curDPNode.DownLinkTunnel.PDR
			UPLinkPDR.State = context.RULE_INITIAL

			FlowDespcription := flowdesc.NewIPFilterRule()
			err := flowdesc.Decode(appFlow, FlowDespcription)
			if err != nil {
				logger.PduSessLog.Errorf("Invalid flow Description: %s\n", err)
			}

			FlowDespcriptionStr, err := flowdesc.Encode(FlowDespcription)
			if err != nil {
				logger.PduSessLog.Errorf("Error occurs when encoding flow despcription: %s\n", err)
			}

			if sdfFilter == "sdfFilter" {
			  UPLinkPDR.PDI.SDFFilter = &pfcpType.SDFFilter{
				Bid:                     false,
				Fl:                      false,
				Spi:                     false,
				Ttc:                     false,
				Fd:                      true,
				LengthOfFlowDescription: uint16(len(FlowDespcriptionStr)),
				FlowDescription:         []byte(FlowDespcriptionStr),
			  }
		        } else {
				UPLinkPDR.PDI.ApplicationID = appID
			}

			UPLinkPDR.Precedence = uint32(precedence)
			pdrList := []*context.PDR{UPLinkPDR, DownLinkPDR}
			farList := []*context.FAR{UPLinkPDR.FAR, DownLinkPDR.FAR}
			barList := []*context.BAR{}
			qerList := DownLinkPDR.QER

			curDPNodeIP := ulcl.NodeID.ResolveNodeIdToIp().String()
			bpMGR.PendingUPF[curDPNodeIP] = true
			message.SendPfcpSessionModificationRequest(ulcl.NodeID, smContext, pdrList, farList, barList, qerList)
			break
		}
	}

	bpMGR.AddingPSAState = context.EstablishingULCL
	logger.PfcpLog.Info("[SMF] ULCLModificationRequest msg has been send")

}

func EstablishULCL(smContext *context.SMContext) {
	logger.PduSessLog.Infoln("In EstablishULCL")

	bpMGR := smContext.BPManager
	bpMGR.PendingUPF = make(context.PendingUPF)
	activatingPath := bpMGR.ActivatingPath
	dest := activatingPath.Destination
	ulcl := bpMGR.ULCL

	// find updatedUPF in activatingPath
	for curDPNode := activatingPath.FirstDPNode; curDPNode != nil; curDPNode = curDPNode.Next() {
		if reflect.DeepEqual(ulcl.NodeID, curDPNode.UPF.NodeID) {
			UPLinkPDR := curDPNode.UpLinkTunnel.PDR
			DownLinkPDR := curDPNode.DownLinkTunnel.PDR
			UPLinkPDR.State = context.RULE_INITIAL

			FlowDespcription := flowdesc.NewIPFilterRule()
			err := FlowDespcription.SetAction(flowdesc.Permit) // permit
			if err != nil {
				logger.PduSessLog.Errorf("Error occurs when setting flow despcription: %s\n", err)
			}
			err = FlowDespcription.SetDirection(flowdesc.Out) // uplink
			if err != nil {
				logger.PduSessLog.Errorf("Error occurs when setting flow despcription: %s\n", err)
			}
			// based on the 3gpp TS 129 244 - V16.5.0, section 5.2.1A.2A Provisioning of SDF filters
			//Source Interface is CORE, this indicates that the filter is for downlink data flow, so the UP function
			// shall apply the Flow Description as is
			// Source Interface is ACCESS, this indicates that the filter is for uplink data flow, so the UP function
			// So, swapping the dest & src in uplink to match the spec
			// shall swap the source and destination address/port in the Flow Description
			err = FlowDespcription.SetSourceIP(dest.DestinationIP)
			if err != nil {
				logger.PduSessLog.Errorf("Error occurs when setting flow despcription: %s\n", err)
			}
			err = FlowDespcription.SetSourcePorts(dest.DestinationPort)
			if err != nil {
				logger.PduSessLog.Errorf("Error occurs when setting flow despcription: %s\n", err)
			}
			err = FlowDespcription.SetDestinationIP(smContext.PDUAddress.To4().String())
			if err != nil {
				logger.PduSessLog.Errorf("Error occurs when setting flow despcription: %s\n", err)
			}

			FlowDespcriptionStr, err := flowdesc.Encode(FlowDespcription)
			if err != nil {
				logger.PduSessLog.Errorf("Error occurs when encoding flow despcription: %s\n", err)
			}

			UPLinkPDR.PDI.SDFFilter = &pfcpType.SDFFilter{
				Bid:                     false,
				Fl:                      false,
				Spi:                     false,
				Ttc:                     false,
				Fd:                      true,
				LengthOfFlowDescription: uint16(len(FlowDespcriptionStr)),
				FlowDescription:         []byte(FlowDespcriptionStr),
			}

			UPLinkPDR.Precedence = 30

			pdrList := []*context.PDR{UPLinkPDR, DownLinkPDR}
			farList := []*context.FAR{UPLinkPDR.FAR, DownLinkPDR.FAR}
			barList := []*context.BAR{}
			qerList := UPLinkPDR.QER

			curDPNodeIP := ulcl.NodeID.ResolveNodeIdToIp().String()
			bpMGR.PendingUPF[curDPNodeIP] = true
			message.SendPfcpSessionModificationRequest(ulcl.NodeID, smContext, pdrList, farList, barList, qerList)
			break
		}
	}

	bpMGR.AddingPSAState = context.EstablishingULCL
	logger.PfcpLog.Info("[SMF] Establish ULCL msg has been send")
}

func UpdatePSA2DownLink(smContext *context.SMContext) {
	logger.PduSessLog.Traceln("In UpdatePSA2DownLink")

	bpMGR := smContext.BPManager
	bpMGR.PendingUPF = make(context.PendingUPF)
	ulcl := bpMGR.ULCL
	activatingPath := bpMGR.ActivatingPath

	farList := []*context.FAR{}
	pdrList := []*context.PDR{}
	barList := []*context.BAR{}
	qerList := []*context.QER{}

	for curDataPathNode := activatingPath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
		lastNode := curDataPathNode.Prev()

		if lastNode != nil {
			if reflect.DeepEqual(lastNode.UPF.NodeID, ulcl.NodeID) {
				downLinkPDR := curDataPathNode.DownLinkTunnel.PDR
				downLinkPDR.State = context.RULE_INITIAL
				downLinkPDR.FAR.State = context.RULE_INITIAL

				pdrList = append(pdrList, downLinkPDR)
				farList = append(farList, downLinkPDR.FAR)
				qerList = append(qerList, downLinkPDR.QER...)

				curDPNodeIP := curDataPathNode.UPF.NodeID.ResolveNodeIdToIp().String()
				bpMGR.PendingUPF[curDPNodeIP] = true
				message.SendPfcpSessionModificationRequest(
					curDataPathNode.UPF.NodeID, smContext, pdrList, farList, barList, qerList)
				logger.PfcpLog.Info("[SMF] Update PSA2 downlink msg has been send")
				break
			}
		}
	}

	bpMGR.AddingPSAState = context.UpdatingPSA2DownLink
}

func EstablishRANTunnelInfo(smContext *context.SMContext) {
	logger.PduSessLog.Traceln("In UpdatePSA2DownLink")

	bpMGR := smContext.BPManager
	activatingPath := bpMGR.ActivatingPath

	defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
	defaultANUPF := defaultPath.FirstDPNode

	activatingANUPF := activatingPath.FirstDPNode

	// Uplink ANUPF In TEID
	activatingANUPF.UpLinkTunnel.TEID = defaultANUPF.UpLinkTunnel.TEID
	activatingANUPF.UpLinkTunnel.PDR.PDI.LocalFTeid.Teid = defaultANUPF.UpLinkTunnel.PDR.PDI.LocalFTeid.Teid

	// Downlink ANUPF OutTEID

	defaultANUPFDLFAR := defaultANUPF.DownLinkTunnel.PDR.FAR
	activatingANUPFDLFAR := activatingANUPF.DownLinkTunnel.PDR.FAR
	activatingANUPFDLFAR.ApplyAction = pfcpType.ApplyAction{
		Buff: false,
		Drop: false,
		Dupl: false,
		Forw: true,
		Nocp: false,
	}
	activatingANUPFDLFAR.ForwardingParameters = &context.ForwardingParameters{
		DestinationInterface: pfcpType.DestinationInterface{
			InterfaceValue: pfcpType.DestinationInterfaceAccess,
		},
		NetworkInstance: []byte(smContext.Dnn),
	}

	activatingANUPFDLFAR.State = context.RULE_INITIAL
	activatingANUPFDLFAR.ForwardingParameters.OuterHeaderCreation = new(pfcpType.OuterHeaderCreation)
	anOuterHeaderCreation := activatingANUPFDLFAR.ForwardingParameters.OuterHeaderCreation
	anOuterHeaderCreation.OuterHeaderCreationDescription = pfcpType.OuterHeaderCreationGtpUUdpIpv4
	anOuterHeaderCreation.Teid = defaultANUPFDLFAR.ForwardingParameters.OuterHeaderCreation.Teid
	anOuterHeaderCreation.Ipv4Address = defaultANUPFDLFAR.ForwardingParameters.OuterHeaderCreation.Ipv4Address
}

func UpdateRANAndIUPFUpLink(smContext *context.SMContext) {
	bpMGR := smContext.BPManager
	bpMGR.PendingUPF = make(context.PendingUPF)
	activatingPath := bpMGR.ActivatingPath
	dest := activatingPath.Destination
	ulcl := bpMGR.ULCL

	for curDPNode := activatingPath.FirstDPNode; curDPNode != nil; curDPNode = curDPNode.Next() {
		if reflect.DeepEqual(ulcl.NodeID, curDPNode.UPF.NodeID) {
			break
		} else {
			UPLinkPDR := curDPNode.UpLinkTunnel.PDR
			DownLinkPDR := curDPNode.DownLinkTunnel.PDR
			UPLinkPDR.State = context.RULE_INITIAL
			DownLinkPDR.State = context.RULE_INITIAL

			if _, exist := bpMGR.UpdatedBranchingPoint[curDPNode.UPF]; exist {
				// add SDF Filter
				FlowDespcription := flowdesc.NewIPFilterRule()
				err := FlowDespcription.SetAction(flowdesc.Permit) // permit
				if err != nil {
					logger.PduSessLog.Errorf("Error occurs when setting flow despcription: %s\n", err)
				}
			        err = FlowDespcription.SetDirection(flowdesc.Out) // uplink
				if err != nil {
					logger.PduSessLog.Errorf("Error occurs when setting flow despcription: %s\n", err)
				}
			        // based on the 3gpp TS 129 244 - V16.5.0, section 5.2.1A.2A Provisioning of SDF filters
				//Source Interface is CORE, this indicates that the filter is for downlink data flow, so the UP function
				// shall apply the Flow Description as is
				// Source Interface is ACCESS, this indicates that the filter is for uplink data flow, so the UP function
				// So, swapping the dest & src in uplink to match the spec
				err = FlowDespcription.SetSourceIP(dest.DestinationIP)
				if err != nil {
					logger.PduSessLog.Errorf("Error occurs when setting flow despcription: %s\n", err)
				}
			        err = FlowDespcription.SetSourcePorts(dest.DestinationPort)
				if err != nil {
					logger.PduSessLog.Errorf("Error occurs when setting flow despcription: %s\n", err)
				}
				err = FlowDespcription.SetDestinationIP(smContext.PDUAddress.To4().String())
				if err != nil {
					logger.PduSessLog.Errorf("Error occurs when setting flow despcription: %s\n", err)
				}

				FlowDespcriptionStr, err := flowdesc.Encode(FlowDespcription)
				if err != nil {
					logger.PduSessLog.Errorf("Error occurs when encoding flow despcription: %s\n", err)
				}

				UPLinkPDR.PDI.SDFFilter = &pfcpType.SDFFilter{
					Bid:                     false,
					Fl:                      false,
					Spi:                     false,
					Ttc:                     false,
					Fd:                      true,
					LengthOfFlowDescription: uint16(len(FlowDespcriptionStr)),
					FlowDescription:         []byte(FlowDespcriptionStr),
				}
			}

			pdrList := []*context.PDR{UPLinkPDR, DownLinkPDR}
			farList := []*context.FAR{UPLinkPDR.FAR, DownLinkPDR.FAR}
			barList := []*context.BAR{}
			qerList := UPLinkPDR.QER

			curDPNodeIP := curDPNode.UPF.NodeID.ResolveNodeIdToIp().String()
			bpMGR.PendingUPF[curDPNodeIP] = true
			message.SendPfcpSessionModificationRequest(curDPNode.UPF.NodeID, smContext, pdrList, farList, barList, qerList)
		}
	}

	if bpMGR.PendingUPF.IsEmpty() {
		bpMGR.AddingPSAState = context.Finished
		bpMGR.BPStatus = context.AddPSASuccess
		logger.CtxLog.Infoln("[SMF] Add PSA success")
	} else {
		bpMGR.AddingPSAState = context.UpdatingRANAndIUPFUpLink
	}
}
