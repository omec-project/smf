// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// This code exists because of a bug in the go-pfcp ie.UserPlaneIPResourceInformation() function.
// The User Plane IP Resource Information has been deprecated in 3GPP Release 16.
// This file should be removed from the project as we get rid of the User Plane IP Resource Information
// IE in the PFCP Association Setup Response Message

package handler

import (
	"fmt"
	"net"

	"github.com/wmnsk/go-pfcp/ie"
)

const (
	Mask4 = 1<<4 - 1
	Mask3 = 1<<3 - 1
)

const (
	BitMask7 = 1 << 6
	BitMask6 = 1 << 5
	BitMask2 = 1 << 1
	BitMask1 = 1
)

func utob(u uint8) bool {
	return u != 0
}

func UnmarshalUEIPInformationBinary(data []byte) (*ie.UserPlaneIPResourceInformationFields, error) {
	u := &ie.UserPlaneIPResourceInformationFields{}
	length := uint16(len(data))

	var idx uint16 = 0
	// Octet 5
	if length < idx+1 {
		return nil, fmt.Errorf("inadequate TLV length: %d", length)
	}
	Assosi := utob(data[idx] & BitMask7)
	Assoni := utob(data[idx] & BitMask6)
	Teidri := data[idx] >> 2 & Mask3
	V6 := utob(data[idx] & BitMask2)
	V4 := utob(data[idx] & BitMask1)
	idx = idx + 1

	// Octet 6
	if Teidri != 0 {
		if length < idx+1 {
			return nil, fmt.Errorf("inadequate TLV length: %d", length)
		}
		u.TEIDRange = data[idx]
		idx = idx + 1
	}

	// Octet m to (m+3)
	if V4 {
		if length < idx+net.IPv4len {
			return nil, fmt.Errorf("inadequate TLV length: %d", length)
		}
		u.IPv4Address = net.IP(data[idx : idx+net.IPv4len])
		idx = idx + net.IPv4len
	}

	// Octet p to (p+15)
	if V6 {
		if length < idx+net.IPv6len {
			return nil, fmt.Errorf("inadequate TLV length: %d", length)
		}
		u.IPv6Address = net.IP(data[idx : idx+net.IPv6len])
		idx = idx + net.IPv6len
	}

	if !V4 && !V6 {
		return nil, fmt.Errorf("none of V4 and V6 flags is set")
	}

	// Octet r
	if Assosi {
		if length < idx+1 {
			return nil, fmt.Errorf("inadequate TLV length: %d", length)
		}
		u.SourceInterface = data[length-1] & Mask4
		data = data[:length-1]
	}

	// Octet k to l
	if Assoni {
		if length < idx+1 {
			return nil, fmt.Errorf("inadequate TLV length: %d", length)
		}
		u.NetworkInstance = string(data[idx:])
	}
	return u, nil
}
