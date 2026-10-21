// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler_test

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/handler"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type Flag uint8

// setBit sets the bit at the given position to the specified value (true or false)
// Positions go from 1 to 8
func (f *Flag) setBit(position uint8) {
	if position < 1 || position > 8 {
		return
	}
	*f |= 1 << (position - 1)
}

func TestFindUEIPAddressNoAddressInCreatedPDR(t *testing.T) {
	sessionEstablishmentResponse := message.NewSessionEstablishmentResponse(
		0,
		0,
		0,
		0,
		0,
		ie.NewCreatedPDR(
			ie.NewPDRID(12345),
		),
	)

	createdPDRIEs := sessionEstablishmentResponse.CreatedPDR

	ipAddress := handler.FindUEIPAddress(createdPDRIEs)

	if ipAddress != nil {
		t.Errorf("Expected nil, got %v", ipAddress)
	}
}

func TestFindUEIPAddressNoUEIPAddressInCreatedPDR(t *testing.T) {
	ueIPAddressFlags := new(Flag)
	ueIPAddressFlags.setBit(2)
	sessionEstablishmentResponse := message.NewSessionEstablishmentResponse(
		0,
		0,
		0,
		0,
		0,
		ie.NewCreatedPDR(
			ie.NewPDRID(12345),
			ie.NewUEIPAddress(uint8(*ueIPAddressFlags), "1.2.3.4", "", 0, 0),
		),
	)

	createdPDRIEs := sessionEstablishmentResponse.CreatedPDR

	ipAddress := handler.FindUEIPAddress(createdPDRIEs)

	if !ipAddress.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("Expected %v, got %v", "1.2.3.4", ipAddress)
	}
}

func TestHandlePfcpAssociationSetupResponse(t *testing.T) {
	kafkaInfo := factory.KafkaInfo{
		EnableKafka: new(false),
	}
	configuration := &factory.Configuration{
		KafkaInfo:        kafkaInfo,
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NewNodeID("1.1.1.1")
	upf := context.NewUPF(upNodeID, nil)
	// Left in the package-level UPF pool, a repeated -count run would accumulate a second entry
	// under the same NodeID, and which one RetrieveUPFNodeByNodeID's map-ordered Range returns is
	// then nondeterministic between iterations.
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(*upNodeID) })
	SnssaiInfos := make([]context.SnssaiUPFInfo, 0)
	snssaiInfo := context.SnssaiUPFInfo{
		DnnList: []context.DnnUPFInfoItem{
			{
				Dnn: "internet",
			},
		},
	}
	SnssaiInfos = append(SnssaiInfos, snssaiInfo)
	upf.SNssaiInfos = SnssaiInfos
	pfcp_message.InsertPfcpTxn(1, upNodeID)
	recoveryTimestamp := time.Now()
	msg := message.NewAssociationSetupResponse(
		1,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("1.1.1.1", "", ""),
		ie.NewRecoveryTimeStamp(recoveryTimestamp),
	)

	remoteAddress := &net.UDPAddr{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 8810,
	}
	udpMessage := udp.Message{
		RemoteAddr:  remoteAddress,
		PfcpMessage: msg,
	}

	handler.HandlePfcpAssociationSetupResponse(&udpMessage)

	if upf.UPFStatus != context.AssociatedSetUpSuccess {
		t.Errorf("Expected UPFStatus %v, got %v", context.AssociatedSetUpSuccess, upf.UPFStatus)
	}
	if upf.RecoveryTimeStamp.RecoveryTimeStamp.Truncate(1*time.Second) != recoveryTimestamp.Truncate(1*time.Second) {
		t.Errorf("Expected RecoveryTimeStamp %v, got %v", recoveryTimestamp.Truncate(1*time.Second), upf.RecoveryTimeStamp.RecoveryTimeStamp.Truncate(1*time.Second))
	}
}

func TestHandlePfcpSessionEstablishmentResponse(t *testing.T) {
	recoveryTimestamp := time.Now()
	nodeID := context.NewNodeID("1.1.1.1")
	smContext := context.NewSMContext("imsi-123456789012345", 10)

	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			10: &context.DataPath{
				IsDefaultPath: true,
				FirstDPNode: &context.DataPathNode{
					UPF: &context.UPF{NodeID: *nodeID},
					UpLinkTunnel: &context.GTPTunnel{
						TEID: 0,
					},
				},
			},
		},
		ANInformation: struct {
			IPAddress net.IP
			TEID      uint32
		}{
			IPAddress: net.ParseIP("192.168.1.1"),
			TEID:      0,
		},
	}

	smContext.PFCPContext = map[string]*context.PFCPSessionContext{
		nodeID.ResolveNodeIdToIp().String(): {
			RemoteSEID: 12345,
		},
	}

	datapath := &context.DataPath{
		FirstDPNode: &context.DataPathNode{
			UPF: &context.UPF{},
		},
	}
	smContext.AllocateLocalSEIDForDataPath(datapath)

	// AllocateLocalSEID draws from a package-level counter shared by every test in the binary, so
	// the value it hands out here is not reliably 1 once other tests have run before it (as under
	// go test -count=N, which reruns the whole binary's tests in the same process). Read back
	// whatever it actually allocated instead of assuming it.
	var localSEID uint64
	for _, pfcpCtx := range smContext.PFCPContext {
		if pfcpCtx.LocalSEID != 0 {
			localSEID = pfcpCtx.LocalSEID
		}
	}
	if localSEID == 0 {
		t.Fatal("failed to allocate a local SEID for the test SMContext")
	}
	seq := uint32(localSEID)
	pfcp_message.InsertPfcpTxn(seq, nodeID)

	rsp := message.NewSessionEstablishmentResponse(
		0,
		0,
		localSEID,
		seq,
		0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("1.1.1.1", "", ""),
		ie.NewRecoveryTimeStamp(recoveryTimestamp),
		ie.NewFSEID(0xABCD, net.ParseIP("1.1.1.1"), nil),
		ie.NewCreatedPDR(
			ie.NewFTEID(0, 4321, net.ParseIP("192.168.1.1"), nil, 0),
		),
	)

	udpMessage := udp.Message{
		RemoteAddr: &net.UDPAddr{
			IP:   net.ParseIP("1.1.1.1"),
			Port: 8809,
		},
		PfcpMessage: rsp,
	}

	handler.HandlePfcpSessionEstablishmentResponse(&udpMessage)

	if smContext.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode.UpLinkTunnel.TEID != 4321 {
		t.Errorf("Expected TEID 4321, got %d", smContext.Tunnel.ANInformation.TEID)
	}

	expectedIP := net.ParseIP("192.168.1.1")
	if !smContext.Tunnel.ANInformation.IPAddress.Equal(expectedIP) {
		t.Errorf("Expected ANInformation IP %v, got %v", expectedIP, smContext.Tunnel.ANInformation.IPAddress)
	}
}

// TestHandlePfcpSessionEstablishmentResponseNilTunnel covers the defensive
// guard for a stale Session Establishment Response arriving after the Tunnel
// has been nilled (e.g. by releaseTunnel). The handler must not panic on the
// nil Tunnel and must consume the pending PFCP txn on the ignore path so it is
// not leaked.
func TestHandlePfcpSessionEstablishmentResponseNilTunnel(t *testing.T) {
	// AllocateLocalSEID reads factory.SmfConfig.Configuration.EnableDbStore, so
	// the config must be initialized for the SEID allocation path not to panic
	// when this test runs in isolation.
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: new(false)},
				EnableUpfAdapter: false,
			},
		}
	}

	nodeID := context.NewNodeID("2.2.2.2")
	smContext := context.NewSMContext("imsi-123456789012399", 20)

	// Register the context in the SEID lookup map by allocating a local SEID
	// for a data path, mirroring what HandlePDUSessionSMContextCreate does
	// before sending the PFCP Establishment Request.
	datapath := &context.DataPath{
		FirstDPNode: &context.DataPathNode{
			UPF: &context.UPF{NodeID: *nodeID},
		},
	}
	smContext.AllocateLocalSEIDForDataPath(datapath)

	// Read the allocated SEID back so the lookup in the handler succeeds
	// regardless of the global allocation counter (test ordering).
	var localSEID uint64
	for _, pfcpCtx := range smContext.PFCPContext {
		if pfcpCtx.LocalSEID != 0 {
			localSEID = pfcpCtx.LocalSEID
		}
	}
	if localSEID == 0 {
		t.Fatal("failed to allocate a local SEID for the test SMContext")
	}

	// Simulate the realistic failure case: Tunnel nilled while a stale
	// Establishment Response is still in flight.
	smContext.Tunnel = nil

	const seq uint32 = 0x424242
	pfcp_message.InsertPfcpTxn(seq, nodeID)

	rsp := message.NewSessionEstablishmentResponse(
		0,
		0,
		localSEID,
		seq,
		0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("2.2.2.2", "", ""),
		ie.NewRecoveryTimeStamp(time.Now()),
	)

	udpMessage := udp.Message{
		RemoteAddr: &net.UDPAddr{
			IP:   net.ParseIP("2.2.2.2"),
			Port: 8809,
		},
		PfcpMessage: rsp,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handler panicked on nil Tunnel (guard regression?): %v", r)
		}
	}()

	handler.HandlePfcpSessionEstablishmentResponse(&udpMessage)

	if leaked := pfcp_message.FetchPfcpTxn(seq); leaked != nil {
		t.Errorf("expected pending PFCP txn for seq %d to be consumed on the nil-Tunnel ignore path, but it was still present", seq)
	}
}

// TestHandlePfcpSessionEstablishmentResponseChannelGatedByState covers the SMContextState gate on
// SBIPFCPCommunicationChan: the normal establishment path waits in SmStatePfcpCreatePending and
// must receive the signal, while restoration's reissue leaves the context in some other state and
// must not receive it (an unconditional send would leave a stale value for the next unrelated
// modification or release that waits on the channel).
func TestHandlePfcpSessionEstablishmentResponseChannelGatedByState(t *testing.T) {
	for _, tc := range []struct {
		name       string
		imsi       string
		state      context.SMContextState
		wantSignal bool
	}{
		{
			name:       "awaited establishment sends the signal",
			imsi:       "imsi-100000000000001",
			state:      context.SmStatePfcpCreatePending,
			wantSignal: true,
		},
		{
			name:       "unawaited response (e.g. restoration) withholds the signal",
			imsi:       "imsi-100000000000002",
			state:      context.SmStateActive,
			wantSignal: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// AllocateLocalSEID reads factory.SmfConfig.Configuration.EnableDbStore, so the config
			// must be initialized for the SEID allocation path not to panic when this test runs in
			// isolation.
			if factory.SmfConfig.Configuration == nil {
				factory.SmfConfig = factory.Config{
					Configuration: &factory.Configuration{
						KafkaInfo:        factory.KafkaInfo{EnableKafka: new(false)},
						EnableUpfAdapter: false,
					},
				}
			}

			nodeID := context.NewNodeID("1.1.1.1")
			smContext := context.NewSMContext(tc.imsi, 10)
			smContext.SMContextState = tc.state

			smContext.Tunnel = &context.UPTunnel{
				DataPathPool: context.DataPathPool{
					10: &context.DataPath{
						IsDefaultPath: true,
						FirstDPNode: &context.DataPathNode{
							UPF: &context.UPF{NodeID: *nodeID},
						},
					},
				},
			}

			datapath := &context.DataPath{
				FirstDPNode: &context.DataPathNode{
					UPF: &context.UPF{NodeID: *nodeID},
				},
			}
			smContext.AllocateLocalSEIDForDataPath(datapath)

			var localSEID uint64
			for _, pfcpCtx := range smContext.PFCPContext {
				if pfcpCtx.LocalSEID != 0 {
					localSEID = pfcpCtx.LocalSEID
				}
			}
			if localSEID == 0 {
				t.Fatal("failed to allocate a local SEID for the test SMContext")
			}

			smContext.PendingUPF = context.PendingUPF{nodeID.ResolveNodeIdToIp().String(): true}

			seq := uint32(localSEID)
			pfcp_message.InsertPfcpTxn(seq, nodeID)

			rsp := message.NewSessionEstablishmentResponse(
				0,
				0,
				localSEID,
				seq,
				0,
				ie.NewCause(ie.CauseRequestAccepted),
				ie.NewNodeID("1.1.1.1", "", ""),
				ie.NewRecoveryTimeStamp(time.Now()),
				ie.NewFSEID(0xABCD, net.ParseIP("1.1.1.1"), nil),
			)

			udpMessage := udp.Message{
				RemoteAddr: &net.UDPAddr{
					IP:   net.ParseIP("1.1.1.1"),
					Port: 8809,
				},
				PfcpMessage: rsp,
			}

			handler.HandlePfcpSessionEstablishmentResponse(&udpMessage)

			select {
			case status := <-smContext.SBIPFCPCommunicationChan:
				if !tc.wantSignal {
					t.Errorf("expected no send to SBIPFCPCommunicationChan when SMContextState is %v, got signal %v", tc.state, status)
				} else if status != context.SessionEstablishSuccess {
					t.Errorf("expected SessionEstablishSuccess, got %v", status)
				}
			default:
				if tc.wantSignal {
					t.Error("expected a send to SBIPFCPCommunicationChan when SMContextState is SmStatePfcpCreatePending, got none")
				}
			}
		})
	}
}

// A data path through several user planes establishes a session on each, and every answer lands
// on the session's channel, which holds one verdict and is read once. Written with a blocking send,
// the second answer parked its dispatch goroutine until the first was read and then left itself
// behind as a stale verdict for the next exchange. It has to come back, and leave one verdict.
func TestASecondEstablishmentAnswerIsNotQueuedBehindTheFirst(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: new(false)},
				EnableUpfAdapter: false,
			},
		}
	}

	nodeID := context.NewNodeID("1.1.1.2")
	smContext := context.NewSMContext("imsi-100000000000003", 10)
	smContext.SMContextState = context.SmStatePfcpCreatePending

	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			10: &context.DataPath{
				IsDefaultPath: true,
				FirstDPNode:   &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
			},
		},
	}

	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{
		FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
	})

	var localSEID uint64
	for _, pfcpCtx := range smContext.PFCPContext {
		if pfcpCtx.LocalSEID != 0 {
			localSEID = pfcpCtx.LocalSEID
		}
	}
	if localSEID == 0 {
		t.Fatal("failed to allocate a local SEID for the test SMContext")
	}

	// The first user plane's verdict, already waiting to be read.
	smContext.SBIPFCPCommunicationChan <- context.SessionEstablishSuccess

	seq := uint32(localSEID)
	pfcp_message.InsertPfcpTxn(seq, nodeID)

	rsp := message.NewSessionEstablishmentResponse(0, 0, localSEID, seq, 0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("1.1.1.2", "", ""),
		ie.NewRecoveryTimeStamp(time.Now()),
		ie.NewFSEID(0xABCD, net.ParseIP("1.1.1.2"), nil),
	)

	done := make(chan struct{})

	go func() {
		defer close(done)

		handler.HandlePfcpSessionEstablishmentResponse(&udp.Message{
			RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.2"), Port: 8809},
			PfcpMessage: rsp,
		})
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the second establishment answer is still blocked on the session's channel")
	}

	if len(smContext.SBIPFCPCommunicationChan) != 1 {
		t.Errorf("channel holds %d verdicts, want the one the create procedure will read", len(smContext.SBIPFCPCommunicationChan))
	}
}

// TestHandlePfcpSessionEstablishmentResponseIgnoresNonPendingResponse covers a response from a
// UPF this handler is not actually waiting on as part of the create batch -- e.g. a PSA/ULCL branch
// addition, which tracks its own responses in BPManager.PendingUPF rather than smContext.PendingUPF,
// but can still be in flight while the context is create-pending. Counting such a response toward
// smContext.EstablishmentFailed or treating an unrelated, already-empty smContext.PendingUPF as "no
// more to wait for" would let it poison or preempt the verdict for a batch it was never part of.
func TestHandlePfcpSessionEstablishmentResponseIgnoresNonPendingResponse(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: new(false)},
				EnableUpfAdapter: false,
			},
		}
	}

	nodeID := context.NewNodeID("1.1.1.11")
	smContext := context.NewSMContext("imsi-100000000000009", 10)
	smContext.SMContextState = context.SmStatePfcpCreatePending

	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			10: &context.DataPath{
				IsDefaultPath: true,
				FirstDPNode:   &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
			},
		},
	}
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{
		FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
	})

	var localSEID uint64
	for _, pfcpCtx := range smContext.PFCPContext {
		if pfcpCtx.LocalSEID != 0 {
			localSEID = pfcpCtx.LocalSEID
		}
	}
	if localSEID == 0 {
		t.Fatal("failed to allocate a local SEID for the test SMContext")
	}

	smContext.PendingUPF = context.PendingUPF{}

	seq := uint32(localSEID)
	pfcp_message.InsertPfcpTxn(seq, nodeID)

	rsp := message.NewSessionEstablishmentResponse(
		0, 0, localSEID, seq, 0,
		ie.NewCause(ie.CauseRequestRejected),
		ie.NewNodeID("1.1.1.11", "", ""),
		ie.NewRecoveryTimeStamp(time.Now()),
	)

	handler.HandlePfcpSessionEstablishmentResponse(&udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.11"), Port: 8809},
		PfcpMessage: rsp,
	})

	select {
	case status := <-smContext.SBIPFCPCommunicationChan:
		t.Errorf("expected no verdict for a response outside the tracked batch, got %v", status)
	default:
	}

	if smContext.EstablishmentFailed {
		t.Error("EstablishmentFailed latched by a response that was never part of the tracked batch")
	}
}

const (
	accessUpf     = "1.1.2.1"
	secondaryUpf  = "1.1.2.2"
	verdictAccept = "accept"
	verdictReject = "reject"
)

// twoTrackedCreateBatch builds a create-pending session whose data path runs through the access-side
// and secondary UPFs, both registered in the create batch's PendingUPF, mirroring what SendPFCPRules
// populates before any establishment request goes out. It returns the context and the two UPFs' local
// SEIDs, which the responses below are addressed to.
func twoTrackedCreateBatch(t *testing.T, imsi string) (sm *context.SMContext, accessSEID, secondarySEID uint64) {
	t.Helper()
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: new(false)},
				EnableUpfAdapter: false,
			},
		}
	}

	smContext := context.NewSMContext(imsi, 10)
	smContext.SMContextState = context.SmStatePfcpCreatePending
	smContext.Tunnel = context.NewUPTunnel()

	for _, upfIP := range []string{accessUpf, secondaryUpf} {
		node := context.NewDataPathNode()
		node.UPF = context.NewUPF(context.NewNodeID(upfIP), nil)
		path := context.NewDataPath()
		path.FirstDPNode = node
		path.IsDefaultPath = upfIP == accessUpf
		smContext.Tunnel.AddDataPath(path)
		smContext.AllocateLocalSEIDForDataPath(path)
	}

	smContext.PendingUPF = context.PendingUPF{accessUpf: true, secondaryUpf: true}

	return smContext, smContext.PFCPContext[accessUpf].LocalSEID, smContext.PFCPContext[secondaryUpf].LocalSEID
}

// TestHandlePfcpSessionEstablishmentResponseAggregatesConflictingTrackedUPFs drives the native handler
// through a create batch whose two tracked UPFs disagree: the access-side UPF accepts and the secondary
// UPF rejects. The aggregate verdict must be a single failure regardless of which response arrives
// first -- an acceptance from the access side must not override a rejection from the secondary, and the
// handler must not restore an access-side-only gate that would miss the secondary's rejection. The
// single-UPF acceptance, untracked-rejection, and failure-helper tests cannot catch that regression
// because none of them has two tracked UPFs disagreeing.
func TestHandlePfcpSessionEstablishmentResponseAggregatesConflictingTrackedUPFs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		imsi  string
		first string // which UPF answers first: "accept" (access) or "reject" (secondary)
	}{
		{"access accepts before the secondary rejects", "imsi-100000000000010", verdictAccept},
		{"secondary rejects before the access accepts", "imsi-100000000000011", verdictReject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smContext, accessSEID, secondarySEID := twoTrackedCreateBatch(t, tc.imsi)

			deliver := map[string]func(){
				verdictAccept: func() {
					pfcp_message.InsertPfcpTxn(uint32(accessSEID), context.NewNodeID(accessUpf))
					handler.HandlePfcpSessionEstablishmentResponse(&udp.Message{
						RemoteAddr: &net.UDPAddr{IP: net.ParseIP(accessUpf), Port: 8809},
						PfcpMessage: message.NewSessionEstablishmentResponse(0, 0, accessSEID, uint32(accessSEID), 0,
							ie.NewCause(ie.CauseRequestAccepted),
							ie.NewNodeID(accessUpf, "", ""),
							ie.NewRecoveryTimeStamp(time.Now()),
							ie.NewFSEID(0xABCD, net.ParseIP(accessUpf), nil),
						),
					})
				},
				verdictReject: func() {
					pfcp_message.InsertPfcpTxn(uint32(secondarySEID), context.NewNodeID(secondaryUpf))
					handler.HandlePfcpSessionEstablishmentResponse(&udp.Message{
						RemoteAddr: &net.UDPAddr{IP: net.ParseIP(secondaryUpf), Port: 8809},
						PfcpMessage: message.NewSessionEstablishmentResponse(0, 0, secondarySEID, uint32(secondarySEID), 0,
							ie.NewCause(ie.CauseRequestRejected),
							ie.NewNodeID(secondaryUpf, "", ""),
							ie.NewRecoveryTimeStamp(time.Now()),
						),
					})
				},
			}

			second := verdictReject
			if tc.first == verdictReject {
				second = verdictAccept
			}

			deliver[tc.first]()
			if n := len(smContext.SBIPFCPCommunicationChan); n != 0 {
				t.Fatalf("a verdict was queued after only the first of two tracked UPFs answered: %d queued", n)
			}

			deliver[second]()
			select {
			case v := <-smContext.SBIPFCPCommunicationChan:
				if v != context.SessionEstablishFailed {
					t.Fatalf("aggregate verdict = %v, want SessionEstablishFailed", v)
				}
			default:
				t.Fatal("no verdict queued after both tracked UPFs answered; the create FSM would block forever")
			}
			if n := len(smContext.SBIPFCPCommunicationChan); n != 0 {
				t.Errorf("more than one verdict queued: %d still waiting", n)
			}
		})
	}
}

// TestHandlePfcpSessionModificationResponseNoSMContext covers a Session
// Modification Response that arrives after its session has been released, so
// GetSMContextBySEID returns nil. Both the accepted and the rejected branch
// dereference smContext unconditionally, and Dispatch runs each message on its
// own goroutine with no recover, so an unguarded dereference here ends the
// process rather than the request. The establishment and deletion handlers
// already check; this one must too.
func TestHandlePfcpSessionModificationResponseNoSMContext(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: new(false)},
				EnableUpfAdapter: false,
			},
		}
	}

	// A SEID no session was ever registered under, so the lookup returns nil.
	const unknownSEID uint64 = 0xDEADBEEF

	cases := []struct {
		name  string
		cause uint8
	}{
		{"accepted", ie.CauseRequestAccepted},
		{"rejected", ie.CauseRequestRejected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rsp := message.NewSessionModificationResponse(
				0, 0, unknownSEID, 1, 0,
				ie.NewCause(tc.cause),
			)

			udpMessage := udp.Message{
				RemoteAddr: &net.UDPAddr{
					IP:   net.ParseIP("3.3.3.3"),
					Port: 8805,
				},
				PfcpMessage: rsp,
			}

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handler panicked on a response for a released session: %v", r)
				}
			}()

			handler.HandlePfcpSessionModificationResponse(&udpMessage)
		})
	}
}
