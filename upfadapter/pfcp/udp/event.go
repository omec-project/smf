// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// The content of this file was taken from https://github.com/omec-project/pfcp

package udp

type EventType uint8

const (
	ReceiveResendRequest EventType = iota
	ReceiveValidResponse
)
