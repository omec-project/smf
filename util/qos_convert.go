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
	fields := strings.Fields(br)
	if len(fields) == 0 {
		return strings.TrimSpace(br)
	}
	numeric := fields[0]
	unit := ""
	if len(fields) > 1 {
		unit = strings.Join(fields[1:], " ")
	}
	if strings.Contains(numeric, ".") {
		numeric = strings.TrimRight(strings.TrimRight(numeric, "0"), ".")
		if numeric == "" {
			numeric = "0"
		}
	}
	if unit != "" {
		br = numeric + " " + unit
	} else {
		br = numeric
	}
	return strings.TrimSpace(br)
}
