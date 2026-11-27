// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept_test

import (
	"net/http"
	"testing"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/lawfulintercept"
	"github.com/omec-project/smf/producer"
	"github.com/omec-project/util/li/types"
)

// TestAPartialSendLeavesOtherFARsToTheScan: a handler that sends part of a session's rules
// under SMLock while a warrant is stored and its scan is waiting for the lock. The handler
// re-derives duplication on the FARs it sends; the uplink FAR it does not send must reach the
// UPF through the scan. Re-deriving every FAR in the handler marks the uplink one duplicating
// and RULE_UPDATE without sending it, and the scan then finds nothing to change.
func TestAPartialSendLeavesOtherFARsToTheScan(t *testing.T) {
	const (
		supi = "imsi-262019876543297"
		node = "10.0.9.3"
	)

	origConfig := factory.SmfConfig.Configuration
	off := false
	factory.SmfConfig.Configuration = &factory.Configuration{
		KafkaInfo:        factory.KafkaInfo{EnableKafka: &off},
		EnableUpfAdapter: true,
	}
	t.Cleanup(func() { factory.SmfConfig.Configuration = origConfig })

	upfs := &adapterUPFs{sent: map[string][]uint32{}}
	origTransport := http.DefaultTransport
	http.DefaultTransport = upfs
	t.Cleanup(func() { http.DefaultTransport = origTransport })

	lawfulintercept.SetSessionModifier(producer.ModifySessionForLI)
	t.Cleanup(func() { lawfulintercept.SetSessionModifier(nil) })

	sc := smfctx.NewSMContext(supi, 5)
	t.Cleanup(func() { smfctx.RemoveSMContext(sc.Ref) })

	ul := &smfctx.FAR{FARID: 1, State: smfctx.RULE_CREATE, ApplyAction: smfctx.ApplyAction{Forw: true}}
	dl := &smfctx.FAR{FARID: 2, State: smfctx.RULE_CREATE, ApplyAction: smfctx.ApplyAction{Forw: true}}
	n := smfctx.NewDataPathNode()
	n.UPF = &smfctx.UPF{NodeID: *smfctx.NewNodeID(node), Port: 8805}
	n.UpLinkTunnel.PDR["ul"] = &smfctx.PDR{PDRID: 1, FAR: ul}
	n.DownLinkTunnel.PDR["dl"] = &smfctx.PDR{PDRID: 2, FAR: dl}

	sc.SMLock.Lock()
	sc.Supi = supi
	sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
		1: &smfctx.DataPath{FirstDPNode: n, IsDefaultPath: true, Activated: true},
	}}
	sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{
		node: {NodeID: n.UPF.NodeID, LocalSEID: 0x9301, RemoteSEID: 0x9401},
	}
	sc.SMLock.Unlock()

	activate := lawfulintercept.ActivateForTest(t, types.InterceptTask{
		XID:      "task-cc-partial-send",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543297"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	})

	// The handler, as HandleUpdateN2Msg does on a setup response: the downlink FAR is
	// rewritten and sent, and the uplink one is not part of the request.
	sc.SMLock.Lock()
	dl.ApplyAction = smfctx.ApplyAction{Forw: true}
	dl.State = smfctx.RULE_UPDATE
	lawfulintercept.ApplyCCTriggerTo(sc, []*smfctx.FAR{dl})
	if !dl.ApplyAction.Dupl {
		sc.SMLock.Unlock()
		t.Fatal("the FAR the handler sends was not given the tasking's duplication")
	}
	dl.State = smfctx.RULE_CREATE // the send, which marks what it encodes
	sc.SMLock.Unlock()

	activate()

	if got := upfs.to(node); len(got) != 1 || got[0] != ul.FARID {
		t.Errorf("the scan sent FARs %v, want the uplink FAR [%d]: the handler did not send it, "+
			"so without the scan it is never duplicated at the UPF", got, ul.FARID)
	}
}
