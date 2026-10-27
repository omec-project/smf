// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import "net"

// Exported to the external tests in this directory only.

var StartSmContextWriteWorkers = startSmContextWriteWorkers

// ForgetInMemory drops a context from every in-memory index, leaving only what is stored: the state
// a restart leaves it in.
func ForgetInMemory(smContext *SMContext) {
	smContextPool.Delete(smContext.Ref)
	canonicalRef.CompareAndDelete(canonicalName(smContext.Identifier, smContext.PDUSessionID), smContext.Ref)
	for _, pfcpContext := range smContext.PFCPContext {
		seidSMContextMap.Delete(pfcpContext.LocalSEID)
	}
}

// RegisterCurrent makes ref the subscriber's current session for the PDU session ID.
func RegisterCurrent(identifier string, pduSessionID int32, ref string) {
	canonicalRef.Store(canonicalName(identifier, pduSessionID), ref)
}

// AllocatorHolds reports whether the allocator has ip marked in use.
func AllocatorHolds(a *IPAllocator, ip net.IP) bool {
	a.g.lock.Lock()
	defer a.g.lock.Unlock()
	return a.g.isUsed[int64(IPAddrOffset(ip.To4(), a.ipNetwork.IP))]
}
