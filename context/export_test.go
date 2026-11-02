// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"

	mi "github.com/omec-project/util/metricinfo"
)

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

// SetupSmfCount is the part of SetupSmfCollection that reads this start's smfCount. It returns a
// function that puts back the smfCount read before.
func SetupSmfCount() (restore func()) {
	prev := smfCountAtStart.Load()
	setupSmfCount()
	return func() { smfCountAtStart.Store(prev) }
}

// RegisterCurrent makes ref the subscriber's current session for the PDU session ID.
func RegisterCurrent(identifier string, pduSessionID int32, ref string) {
	canonicalRef.Store(canonicalName(identifier, pduSessionID), ref)
}

// CapturePublished replaces the subscriber event stream, returning a function that restores it.
func CapturePublished(publish func(mi.CoreSubscriber, mi.SubscriberOp) error) (restore func()) {
	prev := publishPduSessEvent
	publishPduSessEvent = publish
	return func() { publishPduSessEvent = prev }
}

// SEIDHeldBy is the context the in-memory SEID index holds for a local SEID, without the datastore
// fallback GetSMContextBySEID adds.
func SEIDHeldBy(seid uint64) *SMContext {
	if value, ok := seidSMContextMap.Load(seid); ok {
		return value.(*SMContext)
	}
	return nil
}

// HoldSEID enters a context in the in-memory SEID index, as establishing its PFCP session does.
func HoldSEID(seid uint64, smContext *SMContext) {
	seidSMContextMap.Store(seid, smContext)
}

// AllocatorHolds reports whether the allocator has ip marked in use.
func AllocatorHolds(a *IPAllocator, ip net.IP) bool {
	a.g.lock.Lock()
	defer a.g.lock.Unlock()
	return a.g.isUsed[int64(IPAddrOffset(ip.To4(), a.ipNetwork.IP))]
}

// HoldsQER reports whether the QER with this identifier is still allocated from the UPF's pool.
func (upf *UPF) HoldsQER(qerID uint32) bool {
	_, ok := upf.qerPool.Load(qerID)
	return ok
}

// HoldsBAR reports whether the BAR with this identifier is still allocated from the UPF's pool.
func (upf *UPF) HoldsBAR(barID uint8) bool {
	_, ok := upf.barPool.Load(barID)
	return ok
}
