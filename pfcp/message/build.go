// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"errors"
	"net"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type Flag uint8

// BuildPfcpHeartbeatRequest shall trigger hearbeat request to all Attached UPFs
func BuildPfcpHeartbeatRequest() message.Message {
	return message.NewHeartbeatRequest(
		getSeqNumber(),
		ie.NewRecoveryTimeStamp(udp.ServerStartTime),
		nil,
	)
}

func BuildPfcpAssociationSetupRequest() message.Message {
	return message.NewAssociationSetupRequest(
		getSeqNumber(),
		ie.NewNodeIDHeuristic(context.SMF_Self().CPNodeID.ResolveNodeIdToIp().String()),
		ie.NewRecoveryTimeStamp(udp.ServerStartTime),
		ie.NewCPFunctionFeatures(0),
	)
}

func BuildPfcpAssociationSetupResponse(cause uint8) message.Message {
	return message.NewAssociationSetupResponse(
		1,
		ie.NewNodeIDHeuristic(context.SMF_Self().CPNodeID.ResolveNodeIdToIp().String()),
		ie.NewCause(cause),
		ie.NewRecoveryTimeStamp(udp.ServerStartTime),
		ie.NewCPFunctionFeatures(0),
	)
}

func BuildPfcpAssociationReleaseResponse(cause uint8) message.Message {
	return message.NewAssociationReleaseResponse(
		1,
		ie.NewNodeIDHeuristic(context.SMF_Self().CPNodeID.ResolveNodeIdToIp().String()),
		ie.NewCause(cause),
	)
}

// SetBit sets the bit at the given position to the specified value (true or false)
// Positions go from 1 to 8
func (f *Flag) SetBit(position uint8, value bool) {
	if position < 1 || position > 8 {
		return
	}
	if value {
		*f |= 1 << (position - 1)
	} else {
		*f &= ^(1 << (position - 1))
	}
}

func createPDIIE(pdi *context.PDI) *ie.IE {
	fteidFlags := new(Flag)
	fteidFlags.SetBit(1, pdi.LocalFTeid.V4)
	fteidFlags.SetBit(2, pdi.LocalFTeid.V6)
	fteidFlags.SetBit(3, pdi.LocalFTeid.Ch)
	fteidFlags.SetBit(4, pdi.LocalFTeid.Chid)

	ueIPAddressflags := new(Flag)
	ueIPAddressflags.SetBit(1, pdi.UEIPAddress.V6)
	ueIPAddressflags.SetBit(2, pdi.UEIPAddress.V4)
	ueIPAddressflags.SetBit(3, pdi.UEIPAddress.Sd)
	ueIPAddressflags.SetBit(4, pdi.UEIPAddress.Ipv6d)
	ueIPAddressflags.SetBit(5, pdi.UEIPAddress.CHV4)
	ueIPAddressflags.SetBit(6, pdi.UEIPAddress.CHV6)
	ueIPAddressflags.SetBit(7, pdi.UEIPAddress.IP6PL)

	createPDIIes := make([]*ie.IE, 0)
	createPDIIes = append(createPDIIes,
		ie.NewSourceInterface(pdi.SourceInterface.InterfaceValue),
	)
	createPDIIes = append(createPDIIes,
		ie.NewFTEID(
			uint8(*fteidFlags),
			pdi.LocalFTeid.Teid,
			pdi.LocalFTeid.Ipv4Address,
			pdi.LocalFTeid.Ipv6Address,
			pdi.LocalFTeid.ChooseId,
		),
	)
	createPDIIes = append(createPDIIes,
		ie.NewNetworkInstance(string(pdi.NetworkInstance)),
	)
	createPDIIes = append(createPDIIes,
		ie.NewUEIPAddress(
			uint8(*ueIPAddressflags),
			pdi.UEIPAddress.Ipv4Address.String(),
			pdi.UEIPAddress.Ipv6Address.String(),
			pdi.UEIPAddress.Ipv6PrefixDelegationBits,
			pdi.UEIPAddress.Ipv6PrefixLength,
		),
	)

	if pdi.ApplicationID != "" {
		createPDIIes = append(createPDIIes, ie.NewApplicationID(pdi.ApplicationID))
	}

	if pdi.SDFFilter != nil {
		createPDIIes = append(createPDIIes, ie.NewSDFFilter(
			string(pdi.SDFFilter.FlowDescription),
			string(pdi.SDFFilter.TosTrafficClass),
			string(pdi.SDFFilter.SecurityParameterIndex),
			string(pdi.SDFFilter.FlowLabel),
			pdi.SDFFilter.SdfFilterId,
		),
		)
	}

	return ie.NewPDI(createPDIIes...)
}

func pdrToCreatePDR(pdr *context.PDR) *ie.IE {
	ies := make([]*ie.IE, 0)
	ies = append(ies, ie.NewPDRID(pdr.PDRID))
	ies = append(ies, ie.NewPrecedence(pdr.Precedence))
	ies = append(ies, createPDIIE(&pdr.PDI))
	ies = append(ies, ie.NewOuterHeaderRemoval(pdr.OuterHeaderRemoval.OuterHeaderRemovalDescription, 0))
	ies = append(ies, ie.NewFARID(pdr.FAR.FARID))
	for _, qer := range pdr.QER {
		if qer != nil {
			ies = append(ies, ie.NewQERID(qer.QERID))
		}
	}
	return ie.NewCreatePDR(ies...)
}

func farToCreateFAR(far *context.FAR) *ie.IE {
	createFARies := make([]*ie.IE, 0)
	createFARies = append(createFARies, ie.NewFARID(far.FARID))
	applyActionflag := new(Flag)
	applyActionflag.SetBit(1, far.ApplyAction.Drop)
	applyActionflag.SetBit(2, far.ApplyAction.Forw)
	applyActionflag.SetBit(3, far.ApplyAction.Buff)
	applyActionflag.SetBit(4, far.ApplyAction.Nocp)
	applyActionflag.SetBit(5, far.ApplyAction.Dupl)
	createFARies = append(createFARies, ie.NewApplyAction(uint8(*applyActionflag)))
	if far.BAR != nil {
		createFARies = append(createFARies, ie.NewBARID(far.BAR.BARID))
	}
	if far.ForwardingParameters != nil {
		forwardingParametersIEs := make([]*ie.IE, 0)
		forwardingParametersIEs = append(forwardingParametersIEs, ie.NewDestinationInterface(far.ForwardingParameters.DestinationInterface.InterfaceValue))
		forwardingParametersIEs = append(forwardingParametersIEs, ie.NewNetworkInstance(string(far.ForwardingParameters.NetworkInstance)))
		forwardingParametersIEs = append(forwardingParametersIEs, ie.NewOuterHeaderCreation(
			far.ForwardingParameters.OuterHeaderCreation.OuterHeaderCreationDescription,
			far.ForwardingParameters.OuterHeaderCreation.Teid,
			far.ForwardingParameters.OuterHeaderCreation.Ipv4Address.String(),
			far.ForwardingParameters.OuterHeaderCreation.Ipv6Address.String(),
			far.ForwardingParameters.OuterHeaderCreation.PortNumber,
			0, // Here we set ctag and stag to 0, let's valiate this makes sense
			0,
		))

		if far.ForwardingParameters.ForwardingPolicyID != "" {
			forwardingParametersIEs = append(forwardingParametersIEs, ie.NewForwardingPolicy(far.ForwardingParameters.ForwardingPolicyID))
		}
		createFARies = append(createFARies, ie.NewForwardingParameters(forwardingParametersIEs...))
	}
	return ie.NewCreateFAR(createFARies...)
}

func barToCreateBAR(bar *context.BAR) *ie.IE {
	createBARies := make([]*ie.IE, 0)
	createBARies = append(createBARies, ie.NewBARID(bar.BARID))
	createBARies = append(createBARies, ie.NewDownlinkDataNotificationDelay(bar.DownlinkDataNotificationDelay.DelayValue))
	return ie.NewCreateBAR(createBARies...)
}

func qerToCreateQER(qer *context.QER) *ie.IE {
	createQERies := make([]*ie.IE, 0)
	createQERies = append(createQERies, ie.NewQERID(qer.QERID))
	createQERies = append(createQERies, ie.NewGateStatus(qer.GateStatus.ULGate, qer.GateStatus.DLGate))
	createQERies = append(createQERies, ie.NewQFI(qer.QFI.QFI))
	createQERies = append(createQERies, ie.NewMBR(qer.MBR.ULMBR, qer.MBR.DLMBR))
	createQERies = append(createQERies, ie.NewGBR(qer.GBR.ULGBR, qer.GBR.DLGBR))
	return ie.NewCreateQER(createQERies...)
}

func pdrToUpdatePDR(pdr *context.PDR) *ie.IE {
	updatePDRies := make([]*ie.IE, 0)
	updatePDRies = append(updatePDRies, ie.NewPDRID(pdr.PDRID))
	updatePDRies = append(updatePDRies, ie.NewPrecedence(pdr.Precedence))
	updatePDRies = append(updatePDRies, createPDIIE(&pdr.PDI))
	updatePDRies = append(updatePDRies, ie.NewOuterHeaderRemoval(pdr.OuterHeaderRemoval.OuterHeaderRemovalDescription, 0))
	updatePDRies = append(updatePDRies, ie.NewFARID(pdr.FAR.FARID))
	for _, qer := range pdr.QER {
		if qer != nil {
			updatePDRies = append(updatePDRies, ie.NewQERID(qer.QERID))
		}
	}
	return ie.NewUpdatePDR(updatePDRies...)
}

func farToUpdateFAR(far *context.FAR) *ie.IE {
	updateFARies := make([]*ie.IE, 0)
	updateFARies = append(updateFARies, ie.NewFARID(far.FARID))

	if far.BAR != nil {
		updateFARies = append(updateFARies, ie.NewBARID(far.BAR.BARID))
	}

	applyActionflag := new(Flag)
	applyActionflag.SetBit(1, far.ApplyAction.Drop)
	applyActionflag.SetBit(2, far.ApplyAction.Forw)
	applyActionflag.SetBit(3, far.ApplyAction.Buff)
	applyActionflag.SetBit(4, far.ApplyAction.Nocp)
	applyActionflag.SetBit(5, far.ApplyAction.Dupl)
	updateFARies = append(updateFARies, ie.NewApplyAction(uint8(*applyActionflag)))

	if far.ForwardingParameters != nil {
		forwardingParametersIEs := make([]*ie.IE, 0)
		forwardingParametersIEs = append(forwardingParametersIEs, ie.NewDestinationInterface(far.ForwardingParameters.DestinationInterface.InterfaceValue))
		forwardingParametersIEs = append(forwardingParametersIEs, ie.NewNetworkInstance(string(far.ForwardingParameters.NetworkInstance)))
		forwardingParametersIEs = append(forwardingParametersIEs, ie.NewOuterHeaderCreation(
			far.ForwardingParameters.OuterHeaderCreation.OuterHeaderCreationDescription,
			far.ForwardingParameters.OuterHeaderCreation.Teid,
			far.ForwardingParameters.OuterHeaderCreation.Ipv4Address.String(),
			far.ForwardingParameters.OuterHeaderCreation.Ipv6Address.String(),
			far.ForwardingParameters.OuterHeaderCreation.PortNumber,
			0, // Here we set ctag and stag to 0, let's valiate this makes sense
			0,
		))
		if far.ForwardingParameters.PFCPSMReqFlags != nil {
			pfcpSMReqFlag := new(Flag)
			pfcpSMReqFlag.SetBit(1, far.ForwardingParameters.PFCPSMReqFlags.Drobu)
			pfcpSMReqFlag.SetBit(2, far.ForwardingParameters.PFCPSMReqFlags.Sndem)
			pfcpSMReqFlag.SetBit(3, far.ForwardingParameters.PFCPSMReqFlags.Qaurr)
			forwardingParametersIEs = append(forwardingParametersIEs, ie.NewPFCPSMReqFlags(uint8(*pfcpSMReqFlag)))
			// reset original far sndem flag
			far.ForwardingParameters.PFCPSMReqFlags = nil
		}

		if far.ForwardingParameters.ForwardingPolicyID != "" {
			forwardingParametersIEs = append(forwardingParametersIEs, ie.NewForwardingPolicy(far.ForwardingParameters.ForwardingPolicyID))
		}
		updateFARies = append(updateFARies, ie.NewForwardingParameters(forwardingParametersIEs...))
	}
	return ie.NewUpdateFAR(updateFARies...)
}

func BuildPfcpSessionEstablishmentRequest(
	upNodeID context.NodeID,
	smContext *context.SMContext,
	pdrList []*context.PDR,
	farList []*context.FAR,
	barList []*context.BAR,
	qerList []*context.QER,
) (message.Message, error) {
	nodeIDstr := upNodeID.ResolveNodeIdToIp().String()
	pfcpContext, ok := smContext.PFCPContext[nodeIDstr]
	if !ok {
		return nil, errors.New("PFCP context not found for UP Node ID: " + nodeIDstr)
	}
	seid := pfcpContext.LocalSEID

	nodeIDtoIP := upNodeID.ResolveNodeIdToIp()
	var ipv4Address net.IP
	var ipv6Address net.IP
	if nodeIDtoIP.To4() != nil {
		ipv4Address = nodeIDtoIP
		ipv6Address = nil
	} else {
		ipv4Address = nil
		ipv6Address = nodeIDtoIP
	}
	ies := make([]*ie.IE, 0)
	ies = append(ies, ie.NewNodeIDHeuristic(context.SMF_Self().CPNodeID.ResolveNodeIdToIp().String()))
	ies = append(ies, ie.NewFSEID(seid, ipv4Address, ipv6Address))

	for _, pdr := range pdrList {
		if pdr.State == context.RULE_INITIAL {
			ies = append(ies, ie.NewCreatePDR(pdrToCreatePDR(pdr)))
		}
	}

	for _, far := range farList {
		if far.State == context.RULE_INITIAL {
			ies = append(ies, ie.NewCreateFAR(farToCreateFAR(far)))
		}
		far.State = context.RULE_CREATE
	}

	for _, bar := range barList {
		if bar.State == context.RULE_INITIAL {
			ies = append(ies, ie.NewCreateBAR(barToCreateBAR(bar)))
		}
		bar.State = context.RULE_CREATE
	}

	qerMap := make(map[uint32]*context.QER)
	for _, qer := range qerList {
		qerMap[qer.QERID] = qer
	}
	for _, filteredQER := range qerMap {
		if filteredQER.State == context.RULE_INITIAL {
			ies = append(ies, ie.NewCreateQER(qerToCreateQER(filteredQER)))
		}
		filteredQER.State = context.RULE_CREATE
	}

	ies = append(ies, ie.NewPDNType(ie.PDNTypeIPv4))

	return message.NewSessionEstablishmentRequest(
		0,
		0,
		0,
		getSeqNumber(),
		0,
		ies...,
	), nil
}

// TODO: Replace dummy value in PFCP message
func BuildPfcpSessionModificationRequest(
	upNodeID context.NodeID,
	smContext *context.SMContext,
	pdrList []*context.PDR,
	farList []*context.FAR,
	barList []*context.BAR,
	qerList []*context.QER,
) (message.Message, error) {
	ies := make([]*ie.IE, 0)
	nodeIDtoIP := upNodeID.ResolveNodeIdToIp().String()

	pfcpContext, ok := smContext.PFCPContext[nodeIDtoIP]
	if !ok {
		return nil, errors.New("PFCP context not found for UP Node ID: " + nodeIDtoIP)
	}

	localSEID := pfcpContext.LocalSEID
	remoteSEID := pfcpContext.RemoteSEID
	ies = append(ies, ie.NewFSEID(localSEID, context.SMF_Self().CPNodeID.ResolveNodeIdToIp(), nil))

	for _, pdr := range pdrList {
		switch pdr.State {
		case context.RULE_INITIAL:
			ies = append(ies, pdrToCreatePDR(pdr))
		case context.RULE_UPDATE:
			ies = append(ies, pdrToUpdatePDR(pdr))
		case context.RULE_REMOVE:
			ies = append(ies, ie.NewRemovePDR(ie.NewPDRID(pdr.PDRID)))
		}
		pdr.State = context.RULE_CREATE
	}

	for _, far := range farList {
		switch far.State {
		case context.RULE_INITIAL:
			ies = append(ies, farToCreateFAR(far))
		case context.RULE_UPDATE:
			ies = append(ies, farToUpdateFAR(far))
		case context.RULE_REMOVE:
			ies = append(ies, ie.NewRemoveFAR(ie.NewFARID(far.FARID)))
		}
		far.State = context.RULE_CREATE
	}

	for _, bar := range barList {
		switch bar.State {
		case context.RULE_INITIAL:
			ies = append(ies, barToCreateBAR(bar))
		}
	}

	for _, qer := range qerList {
		switch qer.State {
		case context.RULE_INITIAL:
			ies = append(ies, qerToCreateQER(qer))
		}
		qer.State = context.RULE_CREATE
	}

	return message.NewSessionModificationRequest(
		1,
		0,
		remoteSEID,
		getSeqNumber(),
		12,
		ies...,
	), nil
}

func BuildPfcpSessionDeletionRequest(
	upNodeID context.NodeID,
	smContext *context.SMContext,
) (message.Message, error) {
	nodeIDtoIP := upNodeID.ResolveNodeIdToIp().String()
	pfcpContext, ok := smContext.PFCPContext[nodeIDtoIP]
	if !ok {
		return nil, errors.New("PFCP context not found for UP Node ID: " + nodeIDtoIP)
	}
	localSEID := pfcpContext.LocalSEID
	remoteSEID := pfcpContext.RemoteSEID
	return message.NewSessionDeletionRequest(
		1,
		0,
		remoteSEID,
		getSeqNumber(),
		12,
		ie.NewFSEID(localSEID, context.SMF_Self().CPNodeID.ResolveNodeIdToIp(), nil),
	), nil
}

func BuildPfcpSessionReportResponse(cause uint8, drobu bool, seqFromUPF uint32, seid uint64) message.Message {
	flag := new(Flag)
	if drobu {
		flag.SetBit(1, true)
	}
	return message.NewSessionReportResponse(
		0,
		0,
		seid,
		seqFromUPF,
		0,
		ie.NewCause(cause),
		ie.NewPFCPSRRspFlags(uint8(*flag)),
	)
}
