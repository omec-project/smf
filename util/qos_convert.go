// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"strconv"
	"strings"
)

const bpsUnit = "bps"

// BitRateToBps is the single place a bitrate string is parsed into a number: every unit-aware
// consumer of these strings -- the user plane's kbps rates below and the gNB's raw bps AMBR in
// context.sessionAmbrToBps -- is built on this, so there is exactly one reading of what "10 Mbps"
// means rather than two parsers that can drift apart on how they split or round.
//
// Split on a single space and read the first two tokens, deliberately: that is how the radio's
// side of the same rate is parsed (ngapConvert.UEAmbrToInt64). Without a unit there is nothing to
// scale by, and the unit is read from s[1] a few lines down -- so a value like "10", which a
// policy can carry and NormalizeBitRate passes through unchanged when it recognises no unit,
// indexed past the end and took the process with it.
func BitRateToBps(bitrate string) uint64 {
	s := strings.Split(bitrate, " ")
	if len(s) < 2 {
		return 0
	}

	digit, err := strconv.Atoi(s[0])
	if err != nil {
		return 0
	}

	// Matched case-insensitively: a policy's "10 mbps" is as valid as "10 Mbps", and the caller
	// reaching this directly (sessionAmbrToBps, the raw-string MBR reads in CreatePccRuleQer and
	// CreateSessRuleQer) has no other chance to canonicalize the casing before it is read.
	switch strings.ToLower(s[1]) {
	case bpsUnit:
		return uint64(digit)
	case "kbps":
		return uint64(digit) * 1000
	case "mbps":
		return uint64(digit) * 1000000
	case "gbps":
		return uint64(digit) * 1000000000
	case "tbps":
		return uint64(digit) * 1000000000000
	}
	return 0
}

// BitRateTokbps rounds a bitrate down to whole kbps, for the user plane's MBR/GBR rate fields.
// The rounding is for the user plane's benefit alone: it is why NGAP's AMBR reads BitRateToBps
// directly instead of going through this.
func BitRateTokbps(bitrate string) uint64 {
	return BitRateToBps(bitrate) / 1000
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
