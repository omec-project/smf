// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package qos

import (
	"encoding/binary"
	"fmt"

	"github.com/free5gc/openapi/models"
)

func (obj *IPFilterRule) String() string {

	return fmt.Sprintf("IPFilter content: ProtocolId:[%v], Source:[Ip:[%v], Mask:[%v], Port:[%v] Port-range [%v-%v]],Destination [Ip [%v], Mask [%v], Port [%v], Port-range [%v-%v]]",
		obj.protoId, obj.sAddrv4.addr, obj.sAddrv4.mask, obj.sPort, obj.sPortRange.lowLimit, obj.sPortRange.highLimit, obj.dAddrv4.addr, obj.sAddrv4.mask, obj.dPort, obj.dPortRange.lowLimit, obj.dPortRange.highLimit)
}

func (obj QosRule) String() string {
	return fmt.Sprintf("QosRule:[Id:[%v], Precedence:[%v], OpCode:[%v]], DQR:[%v], QFI:[%v], PacketFilters:[%v]",
		obj.Identifier, obj.Precedence, RuleOperation(obj.OperationCode), obj.DQR, obj.QFI, obj.PacketFilterList)
}

func (obj PacketFilter) String() string {
	return fmt.Sprintf("\nPacketFilter:[Id:[%v], direction:[%v], content:[\n%v]]", obj.Identifier, PfDirectionString(obj.Direction), obj.Content)
}

func (obj PacketFilterComponent) String() string {
	switch obj.ComponentType {
	case PFComponentTypeSingleLocalPort:
		fallthrough
	case PFComponentTypeSingleRemotePort:
		return fmt.Sprintf("PFComponent content: type:[%v] value:[%v]\n",
			PfcString(obj.ComponentType), binary.BigEndian.Uint16(obj.ComponentValue))
	case PFComponentTypeLocalPortRange:
		fallthrough
	case PFComponentTypeRemotePortRange:
		return fmt.Sprintf("PFComponent content: type:[%v] value:[%v-%v]\n",
			PfcString(obj.ComponentType), binary.BigEndian.Uint16(obj.ComponentValue[:2]), binary.BigEndian.Uint16(obj.ComponentValue[2:]))
	default:
		return fmt.Sprintf("PFComponent content: type:[%v] value:[%v]\n", PfcString(obj.ComponentType), obj.ComponentValue)
	}

}

func RuleOperation(op uint8) string {
	switch op {
	case OperationCodeCreateNewQoSRule:
		return "CreateNewQoSRule"
	case OperationCodeDeleteExistingQoSRule:
		return "DeleteExistingQoSRule"
	case OperationCodeModifyExistingQoSRuleAndAddPacketFilters:
		return "ModifyExistingQoSRuleAndAddPacketFilters"
	case OperationCodeModifyExistingQoSRuleAndReplaceAllPacketFilters:
		return "ModifyExistingQoSRuleAndReplaceAllPacketFilters"
	case OperationCodeModifyExistingQoSRuleAndDeletePacketFilters:
		return "ModifyExistingQoSRuleAndDeletePacketFilters"
	case OperationCodeModifyExistingQoSRuleWithoutModifyingPacketFilters:
		return "ModifyExistingQoSRuleWithoutModifyingPacketFilters"
	default:
		return "invalid"
	}
}

func PfDirectionString(dir uint8) string {
	switch dir {
	case PacketFilterDirectionDownlink:
		return "Downlink"
	case PacketFilterDirectionUplink:
		return "Uplink"
	case PacketFilterDirectionBidirectional:
		return "Bidirectional"
	default:
		return "Unspecified"
	}
}

func PfcString(pfcpType uint8) string {
	switch pfcpType {
	case PFComponentTypeMatchAll:
		return "MatchAll"
	case PFComponentTypeIPv4RemoteAddress:
		return "IPv4RemoteAddress"
	case PFComponentTypeIPv4LocalAddress:
		return "IPv4LocalAddress"
	case PFComponentTypeIPv6RemoteAddress:
		return "IPv6RemoteAddress"
	case PFComponentTypeIPv6LocalAddress:
		return "IPv6LocalAddress"
	case PFComponentTypeProtocolIdentifierOrNextHeader:
		return "ProtocolIdentifierOrNextHeader"
	case PFComponentTypeSingleLocalPort:
		return "SingleLocalPort"
	case PFComponentTypeLocalPortRange:
		return "LocalPortRange"
	case PFComponentTypeSingleRemotePort:
		return "SingleRemotePort"
	case PFComponentTypeRemotePortRange:
		return "RemotePortRange"
	case PFComponentTypeSecurityParameterIndex:
		return "SecurityParameterIndex"
	case PFComponentTypeTypeOfServiceOrTrafficClass:
		return "TypeOfServiceOrTrafficClass"
	case PFComponentTypeFlowLabel:
		return "FlowLabel"
	case PFComponentTypeDestinationMACAddress:
		return "DestinationMACAddress"
	case PFComponentTypeSourceMACAddress:
		return "SourceMACAddress"
	case PFComponentType8021Q_CTAG_VID:
		return "8021Q_CTAG_VID"
	case PFComponentType8021Q_STAG_VID:
		return "8021Q_STAG_VID"
	case PFComponentType8021Q_CTAG_PCPOrDEI:
		return "8021Q_CTAG_PCPOrDEI"
	case PFComponentType8021Q_STAG_PCPOrDEI:
		return "8021Q_STAG_PCPOrDEI"
	case PFComponentTypeEthertype:
		return "Ethertype"
	default:
		return "invalid"
	}
}

func PccRuleString(pcc *models.PccRule) string {

	return fmt.Sprintf("PccRule:[RuleId:[%v], Precdence:[%v], RefQosData:[%v], flow:[%v]]",
		pcc.PccRuleId, pcc.Precedence, pcc.RefQosData[0], PccFlowInfosString(pcc.FlowInfos))
}

func PccFlowInfosString(flows []models.FlowInformation) []string {

	var flowStrs []string
	for _, flow := range flows {
		str := fmt.Sprintf("FlowInfo:[flowDesc:[%v], PFId:[%v], direction:[%v]]",
			flow.FlowDescription, flow.PackFiltId, flow.FlowDirection)

		flowStrs = append(flowStrs, str)
	}
	return flowStrs
}
