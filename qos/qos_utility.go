// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package qos

import (
	"encoding/binary"
	"fmt"
)

func (obj *IPFilterRule) String() string {

	return fmt.Sprintf("IPFilter content: ProtocolId:[%v], Source:[Ip:[%v], Mask:[%v], Port:[%v] Port-range [%v-%v]],Destination [Ip [%v], Mask [%v], Port [%v], Port-range [%v-%v]]",
		obj.protoId, obj.sAddrv4.addr, obj.sAddrv4.mask, obj.sPort, obj.sPortRange.lowLimit, obj.sPortRange.highLimit, obj.dAddrv4.addr, obj.sAddrv4.mask, obj.dPort, obj.dPortRange.lowLimit, obj.dPortRange.highLimit)
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
