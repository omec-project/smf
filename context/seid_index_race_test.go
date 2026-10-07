// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"sync"
	"testing"
)

// The SEID-keyed lookups run from PFCP handlers that do not hold SMLock -- the establishment
// send-error handler on the transaction goroutine, and the modification/deletion response handlers --
// while AllocateLocalSEIDForDataPath inserts PFCPContext entries (e.g. a PSA/ULCL branch activation
// reached from a response handler). When those lookups iterated PFCPContext, a concurrent insert made
// the iteration a process-crashing fatal error ("concurrent map iteration and map write"). They now
// read the seidToPFCPCtx index under its own lock instead. Run under -race: against the old iterating
// lookups the detector reports the insert here against the read; with the index it is clean.
func TestSeidKeyedLookupsAreRaceFreeAgainstPFCPContextInserts(t *testing.T) {
	smContext := &SMContext{PFCPContext: make(map[string]*PFCPSessionContext)}

	const inserts = 200 // keep every "10.0.0.N" a valid IPv4 so NewNodeID does not treat it as an FQDN
	var wg sync.WaitGroup

	// One writer mimics AllocateLocalSEIDForDataPath: it grows PFCPContext and records the index
	// entry for each new local SEID, exactly as that function does for a new branch.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= inserts; i++ {
			seid := uint64(i)
			key := fmt.Sprintf("10.0.0.%d", i)
			smContext.PFCPContext[key] = &PFCPSessionContext{LocalSEID: seid, NodeID: *NewNodeID(key)}
			smContext.recordPFCPCtxRef(seid, key, *NewNodeID(key))
		}
	}()

	// Readers hammer both SEID-keyed lookups without SMLock, as the unlocked handlers do.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 1; i <= inserts; i++ {
				seid := uint64(i)
				if key, ok := smContext.GetPFCPContextKeyByLocalSEID(seid); ok && key == "" {
					t.Errorf("seid %d indexed with an empty key", seid)
				}
				_ = smContext.GetNodeIDByLocalSEID(seid)
			}
		}()
	}

	wg.Wait()

	// After all inserts, every SEID resolves to its key and NodeID through the index.
	for i := 1; i <= inserts; i++ {
		seid := uint64(i)
		want := fmt.Sprintf("10.0.0.%d", i)
		if key, ok := smContext.GetPFCPContextKeyByLocalSEID(seid); !ok || key != want {
			t.Fatalf("GetPFCPContextKeyByLocalSEID(%d) = %q,%v; want %q,true", seid, key, ok, want)
		}
		nid := smContext.GetNodeIDByLocalSEID(seid)
		if got := nid.ResolveNodeIdToIp().String(); got != want {
			t.Fatalf("GetNodeIDByLocalSEID(%d) resolved to %q; want %q", seid, got, want)
		}
	}
}
