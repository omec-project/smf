// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"strconv"
	"strings"
)

const bpsUnit = "bps"

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
	case bpsUnit:
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
	br = strings.TrimSpace(br)
	if br == "" {
		return br
	}

	fields := strings.Fields(br)
	numeric, unit := "", ""
	if len(fields) >= 2 {
		numeric = fields[0]
		unit = strings.Join(fields[1:], " ")
	} else {
		// Handle concatenated forms like "100Mbps" / "100mbps"
		s := fields[0]
		lower := strings.ToLower(s)
		for _, u := range []string{"tbps", "gbps", "mbps", "kbps", "bps"} {
			if strings.HasSuffix(lower, u) {
				numeric = s[:len(s)-len(u)]
				unit = u
				break
			}
		}
		if numeric == "" {
			numeric = s
		}
	}
	if strings.Contains(numeric, ".") {
		numeric = strings.TrimRight(strings.TrimRight(numeric, "0"), ".")
		if numeric == "" {
			numeric = "0"
		}
	}

	// Canonicalize unit casing to match BitRateTokbps
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "bps":
		unit = bpsUnit
	case "kbps":
		unit = "Kbps"
	case "mbps":
		unit = "Mbps"
	case "gbps":
		unit = "Gbps"
	case "tbps":
		unit = "Tbps"
	default:
		unit = strings.TrimSpace(unit)
	}

	if unit != "" {
		return strings.TrimSpace(numeric + " " + unit)
	}
	return strings.TrimSpace(numeric)
}
