// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
//
// SPDX-License-Identifier: Apache-2.0

// This file is the external test package. The reason it was originally written that way is gone:
// it allocates a local SEID from a counter global to the test binary, and
// TestHandlePfcpSessionEstablishmentResponse used to expect to hold SEID 1, so allocating from
// inside the package would have taken it. That test now allocates dynamically and asserts nothing
// about which SEID it gets, so nothing here depends on file ordering any more. Kept external
// because there is no longer a reason either way, not because the old one still holds.

package handler_test

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
	"github.com/omec-project/smf/pfcp/handler"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

const (
	wiringSmfAllocatedIpv4 = "192.168.139.17"
	wiringUpfAllocatedIpv4 = "192.168.100.1"
)

// The wiring, not the helper. Everything above tests reportUeIpChangeToPCF directly, which cannot
// tell whether the establishment response ever calls it -- a report nothing invokes looks exactly
// like a report with nothing to say. This drives the real handler with a Created PDR carrying a UE
// IP address and asserts the PCF heard about it.
func TestEstablishmentResponseReportsTheUpfAllocatedAddress(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(models.SmPolicyDecision{}); err != nil {
			t.Errorf("encode decision: %v", err)
		}
	}))
	defer server.Close()

	// AllocateLocalSEID reads factory.SmfConfig.Configuration.EnableDbStore, so the config has to
	// exist for the allocation path not to panic when this test runs in isolation.
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: new(bool)},
				EnableUpfAdapter: false,
			},
		}
	}

	nodeID := smf_context.NewNodeID("1.1.1.1")
	smContext := smf_context.NewSMContext("imsi-001010123456799", 10)
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
	datapath := &smf_context.DataPath{
		FirstDPNode: &smf_context.DataPathNode{UPF: &smf_context.UPF{NodeID: *nodeID}},
	}
	smContext.AllocateLocalSEIDForDataPath(datapath)
	seid := smContext.PFCPContext[nodeID.ResolveNodeIdToIp().String()].LocalSEID

	// Set after NewSMContext, which builds the rest of the context.
	cfg := Npcf_SMPolicyControl.NewConfiguration()
	serverConfig := &cfg.Servers[0]
	apiRootVar := serverConfig.Variables["apiRoot"]
	apiRootVar.DefaultValue = server.URL
	serverConfig.Variables["apiRoot"] = apiRootVar
	smContext.SMPolicyClient = Npcf_SMPolicyControl.NewAPIClient(cfg)
	smContext.PolicyReportedIpv4 = wiringSmfAllocatedIpv4
	// What the create path leaves behind: the address the SMF allocated and told the PCF about,
	// and the pool it came from, since adopting the UPF's address releases this one first.
	allocator, err := smf_context.NewIPAllocator("192.168.139.0/24")
	if err != nil {
		t.Fatalf("build the UE IP allocator: %v", err)
	}
	smContext.DNNInfo = &smf_context.SnssaiSmfDnnInfo{UeIPAllocator: allocator}
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP(wiringSmfAllocatedIpv4)}

	pfcp_message.InsertPfcpTxn(1, nodeID)
	rsp := message.NewSessionEstablishmentResponse(
		0, 0, seid, 1, 0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("1.1.1.1", "", ""),
		ie.NewRecoveryTimeStamp(time.Now()),
		ie.NewCreatedPDR(
			ie.NewFTEID(0, 4321, net.ParseIP("192.168.1.1"), nil, 0),
			ie.NewUEIPAddress(0x02, wiringUpfAllocatedIpv4, "", 0, 0),
		),
	)

	handler.HandlePfcpSessionEstablishmentResponse(&udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 8805},
		PfcpMessage: rsp,
	})

	if smContext.PDUAddress == nil || smContext.PDUAddress.Ip.String() != wiringUpfAllocatedIpv4 {
		t.Fatalf("the handler did not adopt the UPF address; PDUAddress = %+v", smContext.PDUAddress)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("PCF was called %d times by the establishment response, want 1", got)
	}
	if smContext.PolicyReportedIpv4 != wiringUpfAllocatedIpv4 {
		t.Errorf("PolicyReportedIpv4 = %q, want %q", smContext.PolicyReportedIpv4, wiringUpfAllocatedIpv4)
	}
}

// The report has to leave before the old address goes back in the pool.
//
// Releasing first makes the pool free to hand that address to another session while this report is
// still in flight -- up to five seconds -- so the PCF can be holding it as this session's binding
// key at the moment it becomes another subscriber's. That is the collision the report exists to
// prevent, so the ordering is the feature, not an implementation detail.
//
// Observed through PDUAddress.Ip, which ReleaseUeIpAddr zeroes in the same breath as returning the
// address to the pool, so the two are indistinguishable in time. The obvious alternative -- have
// the PCF stub allocate and see whether it is handed the old address -- cannot work here and looks
// like it does: _IDPool.allocate walks a rolling index rather than reusing the most recently freed
// id, so a released address is not the next one out.
func TestEstablishmentResponseReportsBeforeReleasingTheOldAddress(t *testing.T) {
	var addressAtReportTime atomic.Value

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if encErr := json.NewEncoder(w).Encode(models.SmPolicyDecision{}); encErr != nil {
			t.Errorf("encode decision: %v", encErr)
		}
	}))
	defer server.Close()

	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: new(bool)},
				EnableUpfAdapter: false,
			},
		}
	}

	nodeID := smf_context.NewNodeID("1.1.1.2")
	smContext := smf_context.NewSMContext("imsi-001010123456800", 10)
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
	datapath := &smf_context.DataPath{
		FirstDPNode: &smf_context.DataPathNode{UPF: &smf_context.UPF{NodeID: *nodeID}},
	}
	smContext.AllocateLocalSEIDForDataPath(datapath)
	seid := smContext.PFCPContext[nodeID.ResolveNodeIdToIp().String()].LocalSEID

	cfg := Npcf_SMPolicyControl.NewConfiguration()
	serverConfig := &cfg.Servers[0]
	apiRootVar := serverConfig.Variables["apiRoot"]
	apiRootVar.DefaultValue = server.URL
	serverConfig.Variables["apiRoot"] = apiRootVar
	smContext.SMPolicyClient = Npcf_SMPolicyControl.NewAPIClient(cfg)
	smContext.PolicyReportedIpv4 = wiringSmfAllocatedIpv4

	allocator, err := smf_context.NewIPAllocator("192.168.139.0/24")
	if err != nil {
		t.Fatalf("build the UE IP allocator: %v", err)
	}
	smContext.DNNInfo = &smf_context.SnssaiSmfDnnInfo{UeIPAllocator: allocator}
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP(wiringSmfAllocatedIpv4)}

	// Sampled from the PCF's side of the call, which is the only point inside the window.
	transport := &recordingTransport{
		before: func() { addressAtReportTime.Store(smContext.PDUAddress.Ip.String()) },
	}
	smContext.SMPolicyClient.GetConfig().HTTPClient = &http.Client{Transport: transport}

	pfcp_message.InsertPfcpTxn(1, nodeID)
	rsp := message.NewSessionEstablishmentResponse(
		0, 0, seid, 1, 0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("1.1.1.2", "", ""),
		ie.NewRecoveryTimeStamp(time.Now()),
		ie.NewCreatedPDR(
			ie.NewFTEID(0, 4322, net.ParseIP("192.168.1.1"), nil, 0),
			ie.NewUEIPAddress(0x02, wiringUpfAllocatedIpv4, "", 0, 0),
		),
	)

	handler.HandlePfcpSessionEstablishmentResponse(&udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 8805},
		PfcpMessage: rsp,
	})

	sampled, _ := addressAtReportTime.Load().(string)
	if sampled == "" {
		t.Fatal("the PCF was never called, so the ordering was not observed at all")
	}
	if sampled != wiringSmfAllocatedIpv4 {
		t.Errorf("when the report went out PDUAddress.Ip was %q, not %q: the old address had already "+
			"been released, so the pool can hand it to another session while the PCF still holds it "+
			"as this one's binding key", sampled, wiringSmfAllocatedIpv4)
	}
}

// recordingTransport runs before hands control back at the moment the request leaves.
type recordingTransport struct {
	before func()
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.before()
	return http.DefaultTransport.RoundTrip(req)
}
