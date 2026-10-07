// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package ies_test

import (
	"net"
	"strings"
	"testing"

	"github.com/omec-project/smf/pfcp/ies"
	"github.com/wmnsk/go-pfcp/ie"
)

const n3 = "10.0.0.1"

func createdPDR(pdrID uint16, teid uint32, addr string) *ie.IE {
	return ie.NewCreatedPDR(
		ie.NewPDRID(pdrID),
		ie.NewFTEID(0x01, teid, net.ParseIP(addr), nil, 0),
	)
}

func TestOneFTEIDAcrossTheCreatedPDRsIsAccepted(t *testing.T) {
	if err := ies.CheckOneFTEID([]*ie.IE{
		createdPDR(1, 0x31d, n3),
		createdPDR(2, 0x31d, n3),
		createdPDR(3, 0x31d, n3),
	}); err != nil {
		t.Errorf("three PDRs on one F-TEID reported as differing: %v", err)
	}
}

// What the measured fault looked like: two uplink PDRs, each given its own TEID by a UPF that
// ignores CHOOSE ID. The error names every PDR and TEID, so the log says which rule the RAN cannot
// reach rather than only that one exists.
func TestADifferentTEIDIsReportedWithEveryPDR(t *testing.T) {
	err := ies.CheckOneFTEID([]*ie.IE{
		createdPDR(5, 0x31d, n3),
		createdPDR(6, 0x31e, n3),
	})
	if err == nil {
		t.Fatal("two PDRs on TEIDs 0x31d and 0x31e were not reported")
	}
	for _, want := range []string{"PDR 5: TEID 0x31d", "PDR 6: TEID 0x31e", "CHOOSE ID"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// An F-TEID is a TEID and an address, so the same TEID at another address is another tunnel.
func TestTheSameTEIDAtAnotherAddressIsReported(t *testing.T) {
	if err := ies.CheckOneFTEID([]*ie.IE{
		createdPDR(1, 0x31d, n3),
		createdPDR(2, 0x31d, "10.0.0.2"),
	}); err == nil {
		t.Error("one TEID at two addresses was not reported")
	}
}

// Downlink PDRs, and uplink PDRs the UPF was not asked to allocate for, come back without an
// F-TEID. They are not a second tunnel.
func TestACreatedPDRWithoutAnFTEIDIsNotCounted(t *testing.T) {
	if err := ies.CheckOneFTEID([]*ie.IE{
		createdPDR(1, 0x31d, n3),
		ie.NewCreatedPDR(ie.NewPDRID(2)),
		ie.NewCreatedPDR(ie.NewPDRID(3), ie.NewUEIPAddress(0x02, "10.250.0.7", "", 0, 0)),
		createdPDR(4, 0x31d, n3),
	}); err != nil {
		t.Errorf("Created PDRs without an F-TEID reported as differing: %v", err)
	}
	if err := ies.CheckOneFTEID(nil); err != nil {
		t.Errorf("a response with no Created PDR reported as differing: %v", err)
	}
}
