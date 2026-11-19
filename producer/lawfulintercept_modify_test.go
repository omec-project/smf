// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	smf_context "github.com/omec-project/smf/context"
)

// TestModifySessionForLIReadsTheUPFPortUnderItsLock runs ModifySessionForLI against a
// configuration reconciliation writing the UPF's port, which it does under UpfLock. Under -race
// an unguarded read of the port is reported.
func TestModifySessionForLIReadsTheUPFPortUnderItsLock(t *testing.T) {
	nodeID := smf_context.NewNodeID("1.1.1.91")
	upf := &smf_context.UPF{NodeID: *nodeID, Port: 8805}
	far := &smf_context.FAR{FARID: 1, State: smf_context.RULE_UPDATE}
	sc := &smf_context.SMContext{
		Tunnel: &smf_context.UPTunnel{DataPathPool: smf_context.DataPathPool{1: {
			Activated: true,
			FirstDPNode: &smf_context.DataPathNode{
				UPF:          upf,
				UpLinkTunnel: &smf_context.GTPTunnel{PDR: map[string]*smf_context.PDR{"ul": {FAR: far}}},
			},
		}}},
		// No live PFCP session on the UPF, so nothing is sent: the port is read and grouped only.
		PFCPContext: map[string]*smf_context.PFCPSessionContext{},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			upf.UpfLock.Lock()
			upf.Port = 8805
			upf.UpfLock.Unlock()
		}
	}()
	for range 200 {
		sc.SMLock.Lock()
		if err := ModifySessionForLI(sc); err != nil {
			t.Errorf("ModifySessionForLI: %v", err)
		}
		sc.SMLock.Unlock()
	}
	<-done
}
