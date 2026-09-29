// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"time"
)

type PFCPSessionResponseStatus int

const (
	SessionUpdateSuccess PFCPSessionResponseStatus = iota
	SessionUpdateFailed
	SessionReleaseSuccess
	SessionReleaseFailed
	SessionUpdateTimeout
	SessionReleaseTimeout
	SessionEstablishSuccess
	SessionEstablishFailed
	SessionEstablishTimeout
)

type PFCPSessionContext struct {
	PDRs      map[uint16]*PDR
	NodeID    NodeID
	LocalSEID uint64
	// RemoteSEID is zero until the node acknowledges the session, and is set back to zero by
	// restoration to make the next send an establishment rather than a modification. Those two
	// cases look identical here, so ClearedByRestoration tells them apart.
	RemoteSEID uint64
	// ClearedByRestoration records that the zero above was written deliberately, by a restoration
	// of a session this node once held -- not that the node has never acknowledged the session.
	ClearedByRestoration bool
	// AcknowledgedAtRecovery is the node's recovery timestamp as this element held it when the
	// node acknowledged the session, which identifies the incarnation that holds it. A node
	// refuses an establishment until it is associated, and association is where the held
	// timestamp is replaced, so a session a restarted node accepted carries the new one. Zero when
	// unknown -- a session restored from the database -- which restoration treats as lost.
	AcknowledgedAtRecovery time.Time
}

func (pfcpSessionContext *PFCPSessionContext) String() string {
	str := ""
	for pdrID, pdr := range pfcpSessionContext.PDRs {
		str += fmt.Sprintln("PDR ID:", pdrID)
		str += fmt.Sprintf("%+v\n", pdr)
	}

	str += fmt.Sprintln("Node ID:", pfcpSessionContext.NodeID.ResolveNodeIdToIp().String())
	str += fmt.Sprintln("LocalSEID:", pfcpSessionContext.LocalSEID)
	str += fmt.Sprintln("RemoteSEID:", pfcpSessionContext.RemoteSEID)

	return str
}

func (pfcpSessionResponseStatus PFCPSessionResponseStatus) String() string {
	switch pfcpSessionResponseStatus {
	case SessionUpdateSuccess:
		return "SessionUpdateSuccess"
	case SessionUpdateFailed:
		return "SessionUpdateFailed"
	case SessionReleaseSuccess:
		return "SessionReleaseSuccess"
	case SessionReleaseFailed:
		return "SessionReleaseFailed"
	case SessionUpdateTimeout:
		return "SessionUpdateTimeout"
	case SessionReleaseTimeout:
		return "SessionReleaseTimeout"
	default:
		return "Unknown PFCP Session Response Status"
	}
}
