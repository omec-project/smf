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
	"io"
	"net"

	"github.com/wmnsk/go-pfcp/ie"
)

func has7thBit(f uint8) bool {
	return (f&0x40)>>6 == 1
}

func has6thBit(f uint8) bool {
	return (f&0x20)>>5 == 1
}

func has2ndBit(f uint8) bool {
	return (f&0x02)>>1 == 1
}

func has1stBit(f uint8) bool {
	return (f & 0x01) == 1
}

func UnmarshalUEIPInformationBinary(b []byte) (*ie.UserPlaneIPResourceInformationFields, error) {
	l := len(b)
	if l < 2 {
		return nil, io.ErrUnexpectedEOF
	}

	f := &ie.UserPlaneIPResourceInformationFields{}

	f.Flags = b[0]
	offset := 1

	if (f.Flags>>2)&0x07 != 0 {
		if l < offset+1 {
			return nil, io.ErrUnexpectedEOF
		}
		f.TEIDRange = b[offset]
		offset++
	}

	if has1stBit(f.Flags) {
		if l < offset+4 {
			return nil, io.ErrUnexpectedEOF
		}
		f.IPv4Address = net.IP(b[offset : offset+4]).To4()
		offset += 4
	}

	if has2ndBit(f.Flags) {
		if l < offset+16 {
			return nil, io.ErrUnexpectedEOF
		}
		f.IPv6Address = net.IP(b[offset : offset+16]).To16()
		offset += 16
	}

	if has6thBit(f.Flags) {
		n := l
		if has7thBit(f.Flags) {
			n--
			f.SourceInterface = b[n] & 0x0f
		}
		f.NetworkInstance = string(b[offset:n])
		return f, nil
	}

	if has7thBit(f.Flags) {
		f.SourceInterface = b[offset] & 0x0f
		fmt.Println("Source Interface: ", f.SourceInterface)
	}

	return f, nil
}
