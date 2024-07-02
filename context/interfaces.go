// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Canonical Ltd.

package context

const (
	SourceInterfaceAccess uint8 = iota
	SourceInterfaceCore
)

const (
	DestinationInterfaceAccess uint8 = iota
	DestinationInterfaceCore
	DestinationInterfaceSgiLanN6Lan
)
