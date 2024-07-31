// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// The content of this file was taken from https://github.com/omec-project/pfcp

package udp

import (
	"net"

	"github.com/wmnsk/go-pfcp/message"
)

type Message struct {
	RemoteAddr  *net.UDPAddr
	PfcpMessage message.Message
	EventData   interface{}
}
