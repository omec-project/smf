// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	smf_context "github.com/omec-project/smf/context"
)

// With the UPF adapter the association response is handled synchronously inside the send, and the
// adapter's handler takes no lock of its own: it relies on the caller holding UpfLock, as probeUpf
// does. Sent without it, the UPF is marked associated before the new recovery timestamp is held,
// an establishment acknowledged in between records the previous incarnation's, and restoration
// re-establishes that session over itself.
func TestTheAssociationSendIsMadeUnderTheUPFLock(t *testing.T) {
	const ip = "10.30.0.60"
	nodeID := smf_context.NewNodeID(ip)
	upf := smf_context.NewUPF(nodeID, nil)
	t.Cleanup(func() { smf_context.RemoveUPFNodeByNodeID(*nodeID) })

	held := false
	previous := sendAssociationSetupRequest
	sendAssociationSetupRequest = func(smf_context.NodeID, uint16) error {
		if upf.UpfLock.TryLock() {
			upf.UpfLock.Unlock()
		} else {
			held = true
		}
		// What the adapter's synchronous handler does inside the send.
		upf.UPFStatus = smf_context.AssociatedSetUpSuccess
		return nil
	}
	t.Cleanup(func() { sendAssociationSetupRequest = previous })

	dataPath := &smf_context.DataPath{FirstDPNode: &smf_context.DataPathNode{UPF: upf}}
	if err := ensureDataPathUpfAssociated(dataPath); err != nil {
		t.Fatalf("ensureDataPathUpfAssociated: %v", err)
	}
	if !held {
		t.Error("the association request was sent without UpfLock held; with the UPF adapter its " +
			"response is then written with no lock, and the association status and the new " +
			"recovery timestamp are not seen together")
	}
}
