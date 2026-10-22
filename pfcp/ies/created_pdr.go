// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package ies

import (
	"fmt"
	"strings"

	"github.com/omec-project/smf/context"
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

// CreatedFTEID is the F-TEID of one Created PDR, with the ID of the PDR that carries it.
type CreatedFTEID struct {
	PDRID     uint16
	HavePDRID bool
	FTEID     *ie.FTEIDFields
}

// CreatedFTEIDs returns the F-TEID of every Created PDR that carries one, in response order. A
// response to a batch spanning several data paths holds one per path's uplink tunnel.
func CreatedFTEIDs(createdPDRs []*ie.IE) []CreatedFTEID {
	var out []CreatedFTEID
	for _, createdPDR := range createdPDRs {
		fteid, err := createdPDR.FTEID()
		if err != nil {
			continue
		}
		pdrID, err := createdPDR.PDRID()
		out = append(out, CreatedFTEID{PDRID: pdrID, HavePDRID: err == nil, FTEID: fteid})
	}
	return out
}

// ApplyCreatedFTEIDs stores the F-TEIDs of one establishment response on the uplink tunnels of the
// UPF identified by nodeID, and returns the F-TEID whose address is to be advertised for that UPF.
//
// A tunnel takes the F-TEID of its own PDR. Every uplink PDR the SMF sends a UPF shares one CHOOSE ID
// (uplinkTunnelChooseId), so the UPF may return the group's F-TEID on a single member PDR (TS 29.244
// clause 5.5.3); a tunnel with none of its PDRs in the response takes it from the response too, or it
// would keep a TEID the UPF never allocated. The address returned is the one paired with the default
// path's access tunnel, whose TEID NGAP carries; when that tunnel is not on this UPF it is the first
// in the response. It is nil when the response carries no F-TEID.
//
// An error is returned when the F-TEID cannot be placed on any of the session's data paths.
func ApplyCreatedFTEIDs(pool context.DataPathPool, nodeID context.NodeID, created []CreatedFTEID) (*ie.FTEIDFields, error) {
	if len(created) == 0 {
		return nil, nil
	}
	applied := make(map[*context.DataPathNode]*ie.FTEIDFields)
	for i, c := range created {
		node := pool.FindNode(nodeID, c.PDRID, c.HavePDRID)
		// The first is the one FindNode may place by fallback; the rest only update a tunnel
		// that claims their PDR.
		if i > 0 && (!c.HavePDRID || !node.OwnsUplinkPDR(c.PDRID)) {
			continue
		}
		if node == nil || node.UpLinkTunnel == nil {
			return nil, fmt.Errorf("UPF[%s] answered establishment but is not on any of this session's data paths",
				nodeID.ResolveNodeIdToIp().String())
		}
		node.UpLinkTunnel.TEID = c.FTEID.TEID
		applied[node] = c.FTEID
	}

	for _, path := range pool {
		if path == nil {
			continue
		}
		for node := path.FirstDPNode; node != nil; node = node.Next() {
			if _, done := applied[node]; done || node.UPF == nil || !node.UPF.NodeID.Equal(nodeID) ||
				node.UpLinkTunnel == nil || len(node.UpLinkTunnel.PDR) == 0 {
				continue
			}
			node.UpLinkTunnel.TEID = created[0].FTEID.TEID
			applied[node] = created[0].FTEID
		}
	}

	if defaultPath := pool.GetDefaultPath(); defaultPath != nil {
		if fteid, ok := applied[defaultPath.FirstDPNode]; ok {
			return fteid, nil
		}
	}
	return created[0].FTEID, nil
}
