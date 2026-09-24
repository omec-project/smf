// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The two user planes the fixture's session is anchored on; the first carries the default path.
const (
	firstUpf  = "10.0.0.31"
	secondUpf = "10.0.0.32"
)

// sessionOnTwoUserPlanes is a session in state with one PFCP session on each of two user planes,
// both still pending. It returns the local SEID the first one's replies are addressed to.
func sessionOnTwoUserPlanes(t *testing.T, state context.SMContextState) (*context.SMContext, uint64) {
	t.Helper()

	prev := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prev })

	disabled := false
	factory.SmfConfig = factory.Config{Configuration: &factory.Configuration{
		KafkaInfo:        factory.KafkaInfo{EnableKafka: &disabled},
		EnableUpfAdapter: true,
	}}

	smContext := context.NewSMContext("imsi-208930000000048", 8)
	smContext.Tunnel = context.NewUPTunnel()

	for _, upfIP := range []string{firstUpf, secondUpf} {
		node := context.NewDataPathNode()
		node.UPF = context.NewUPF(context.NewNodeID(upfIP), nil)

		path := context.NewDataPath()
		path.FirstDPNode = node
		path.IsDefaultPath = upfIP == firstUpf
		smContext.Tunnel.AddDataPath(path)
		smContext.AllocateLocalSEIDForDataPath(path)
	}

	smContext.PendingUPF = context.PendingUPF{firstUpf: true, secondUpf: true}
	smContext.SMContextState = state

	return smContext, smContext.PFCPContext[firstUpf].LocalSEID
}

// A reply the handlers cannot use is reported, not dropped. In adapter mode the reply is the only
// answer the request gets -- there is no transaction left to time out -- so a reply dropped in
// silence left the caller waiting on the session's channel for good.
func TestAReplyTheHandlersCannotUseIsReported(t *testing.T) {
	smContext, seid := sessionOnTwoUserPlanes(t, context.SmStatePfcpModify)

	cases := map[string]message.Message{
		"a modification response with no cause":    message.NewSessionModificationResponse(0, 0, seid, 1, 0),
		"a modification response for no session":   message.NewSessionModificationResponse(0, 0, seid+1000, 1, 0, ie.NewCause(ie.CauseRequestAccepted)),
		"a deletion response with no cause":        message.NewSessionDeletionResponse(0, 0, seid, 1, 0),
		"a message that is not a session response": message.NewHeartbeatRequest(1, ie.NewRecoveryTimeStamp(time.Now()), nil),
	}

	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			if err := HandleAdapterPfcpRsp(reply, &udp.PfcpEventData{LSEID: seid}); err == nil {
				t.Error("an unusable reply was reported as handled; the caller would wait for a verdict nothing will send")
			}

			if n := len(smContext.SBIPFCPCommunicationChan); n != 0 {
				t.Errorf("%d verdicts queued for a reply that was not used", n)
			}
		})
	}
}

// And a reply that is one of several stays silent, as it should: the session is still collecting
// the others, and the verdict comes with the last. Reporting it as a failure would answer the
// release early, and the last reply's blocking send would then find the channel full -- on the
// goroutine that reads it, which in adapter mode is the one dispatching.
func TestAReplyOneOfSeveralIsNotAFailure(t *testing.T) {
	smContext, seid := sessionOnTwoUserPlanes(t, context.SmStatePfcpRelease)

	reply := message.NewSessionDeletionResponse(0, 0, seid, 1, 0, ie.NewCause(ie.CauseRequestAccepted))
	if err := HandleAdapterPfcpRsp(reply, &udp.PfcpEventData{LSEID: seid}); err != nil {
		t.Fatalf("the first of two deletion replies was reported as unusable: %v", err)
	}

	if n := len(smContext.SBIPFCPCommunicationChan); n != 0 {
		t.Errorf("%d verdicts queued while a user plane is still pending", n)
	}

	if smContext.PendingUPF[firstUpf] {
		t.Error("the reply was not counted: its user plane is still pending")
	}
}

// Nor is a reply to a request no one waits for. Restoration reissues establishments for sessions
// that are already active, and their answers are dropped by design.
func TestAnAnswerToAnUnawaitedEstablishmentIsNotAFailure(t *testing.T) {
	smContext, seid := sessionOnTwoUserPlanes(t, context.SmStateActive)

	const seq = 4343
	InsertPfcpTxn(seq, context.NewNodeID(firstUpf))

	reply := message.NewSessionEstablishmentResponse(0, 0, seid, seq, 0,
		ie.NewNodeID(firstUpf, "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(99, net.ParseIP(firstUpf), nil))

	if err := HandleAdapterPfcpRsp(reply, &udp.PfcpEventData{LSEID: seid}); err != nil {
		t.Fatalf("an answer to restoration's establishment was reported as unusable: %v", err)
	}

	if n := len(smContext.SBIPFCPCommunicationChan); n != 0 {
		t.Errorf("%d verdicts queued for an establishment nobody waits on", n)
	}
}
