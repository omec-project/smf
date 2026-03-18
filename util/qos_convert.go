// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"strconv"
	"strings"
)

func BitRateTokbps(bitrate string) uint64 {
	s := strings.Split(bitrate, " ")
	var kbps uint64

	var digit int

	if n, err := strconv.Atoi(s[0]); err != nil {
		return 0
	} else {
		digit = n
	}

	switch s[1] {
	case "bps":
		kbps = uint64(digit / 1000)
	case "Kbps":
		kbps = uint64(digit * 1)
	case "Mbps":
		kbps = uint64(digit * 1000)
	case "Gbps":
		kbps = uint64(digit * 1000000)
	case "Tbps":
		kbps = uint64(digit * 1000000000)
	}
	return kbps
}

func NormalizeBitRate(br string) string {
	// Example: "128.000000 Kbps" → "128 Kbps"
	parts := strings.Split(br, ".")
	if len(parts) > 1 {
		br = parts[0] + " Kbps"
	}
	return strings.TrimSpace(br)
}
