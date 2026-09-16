// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
//
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/Npcf_SMPolicyControl"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The upf-adapter dispatcher carries its own copy of the release-and-adopt block, so it needs its
// own proof that the report goes out. The two handlers are mutually exclusive and have drifted
// before -- one function with two call sites only prevents that if both call sites are pinned.
func TestAdapterEstablishmentResponseReportsTheUpfAllocatedAddress(t *testing.T) {
	const (
		smfIpv4 = "192.168.139.18"
		upfIpv4 = "192.168.100.2"
	)

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(models.SmPolicyDecision{}); err != nil {
			t.Errorf("encode decision: %v", err)
		}
	}))
	defer server.Close()

	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: new(bool)},
				EnableUpfAdapter: true,
			},
		}
	}

	nodeID := smf_context.NewNodeID("3.3.3.3")
	smContext := smf_context.NewSMContext("imsi-001010123456798", 10)
	smContext.Tunnel = &smf_context.UPTunnel{
		DataPathPool: smf_context.DataPathPool{
			10: &smf_context.DataPath{
				IsDefaultPath: true,
				FirstDPNode: &smf_context.DataPathNode{
					UPF:          &smf_context.UPF{},
					UpLinkTunnel: &smf_context.GTPTunnel{},
				},
			},
		},
	}
	smContext.AllocateLocalSEIDForDataPath(&smf_context.DataPath{
		FirstDPNode: &smf_context.DataPathNode{UPF: &smf_context.UPF{NodeID: *nodeID}},
	})
	seid := smContext.PFCPContext[nodeID.ResolveNodeIdToIp().String()].LocalSEID

	cfg := Npcf_SMPolicyControl.NewConfiguration()
	serverConfig := &cfg.Servers[0]
	apiRootVar := serverConfig.Variables["apiRoot"]
	apiRootVar.DefaultValue = server.URL
	serverConfig.Variables["apiRoot"] = apiRootVar
	smContext.SMPolicyClient = Npcf_SMPolicyControl.NewAPIClient(cfg)
	smContext.PolicyReportedIpv4 = smfIpv4

	allocator, err := smf_context.NewIPAllocator("192.168.139.0/24")
	if err != nil {
		t.Fatalf("build the UE IP allocator: %v", err)
	}
	smContext.DNNInfo = &smf_context.SnssaiSmfDnnInfo{UeIPAllocator: allocator}
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP(smfIpv4)}

	adapter.InsertPfcpTxn(1, nodeID)
	rsp := message.NewSessionEstablishmentResponse(
		0, 0, seid, 1, 0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("3.3.3.3", "", ""),
		ie.NewRecoveryTimeStamp(time.Now()),
		ie.NewCreatedPDR(
			ie.NewFTEID(0, 4321, net.ParseIP("192.168.1.1"), nil, 0),
			ie.NewUEIPAddress(0x02, upfIpv4, "", 0, 0),
		),
	)

	adapter.HandlePfcpSessionEstablishmentResponse(&udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("3.3.3.3"), Port: 8805},
		PfcpMessage: rsp,
	})

	if smContext.PDUAddress == nil || smContext.PDUAddress.Ip.String() != upfIpv4 {
		t.Fatalf("the adapter handler did not adopt the UPF address; PDUAddress = %+v", smContext.PDUAddress)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("PCF was called %d times by the adapter establishment response, want 1", got)
	}
	if smContext.PolicyReportedIpv4 != upfIpv4 {
		t.Errorf("PolicyReportedIpv4 = %q, want %q", smContext.PolicyReportedIpv4, upfIpv4)
	}
}
