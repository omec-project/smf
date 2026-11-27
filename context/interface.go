// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package context

const (
	SourceInterfaceAccess uint8 = iota
	SourceInterfaceCore
)

const (
	DestinationInterfaceAccess uint8 = iota
	DestinationInterfaceCore
	DestinationInterfaceSgiLanN6Lan
	DestinationInterfaceCpFunction
	// DestinationInterfaceLIFunction is the destination for user-plane packets
	// duplicated for Lawful Interception (TS 29.244 Table 8.2.24-1).
	DestinationInterfaceLIFunction
)

type SourceInterface struct {
	InterfaceValue uint8 // 0x00001111
}

type DestinationInterface struct {
	InterfaceValue uint8 // 0x00001111
}
