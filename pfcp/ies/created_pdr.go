// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package ies

import (
	"fmt"
	"strings"

	"github.com/wmnsk/go-pfcp/ie"
)

// CheckOneFTEID reports an error when the Created PDR IEs of one response carry more than one
// F-TEID.
//
// The SMF asks for one F-TEID per uplink tunnel, by giving the tunnel's PDRs a common CHOOSE ID
// (TS 29.244 clause 5.5.3), and the RAN is told that one TEID. A UPF that does not support CHOOSE
// ID assigns each PDR its own, and every PDR on a TEID other than the one the RAN was told matches
// no packet. Nothing fails at the time, so it is said here.
func CheckOneFTEID(createdPDRs []*ie.IE) error {
	var first *ie.FTEIDFields
	var assigned []string
	differ := false
	for _, createdPDR := range createdPDRs {
		fteid, err := createdPDR.FTEID()
		if err != nil {
			continue
		}
		if first == nil {
			first = fteid
		} else if fteid.TEID != first.TEID || !fteid.IPv4Address.Equal(first.IPv4Address) {
			differ = true
		}
		pdr := "PDR ?"
		if pdrID, err := createdPDR.PDRID(); err == nil {
			pdr = fmt.Sprintf("PDR %d", pdrID)
		}
		assigned = append(assigned, fmt.Sprintf("%s: TEID %#x at %v", pdr, fteid.TEID, fteid.IPv4Address))
	}
	if !differ {
		return nil
	}
	return fmt.Errorf("the UPF assigned %d uplink PDRs different F-TEIDs where one was asked for (%s): "+
		"it does not support CHOOSE ID, and the PDRs on a TEID the RAN was not told match no uplink packet",
		len(assigned), strings.Join(assigned, ", "))
}
