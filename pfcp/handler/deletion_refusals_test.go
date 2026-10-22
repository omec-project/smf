// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// Two nodes refusing their deletions must resume the release waiter once, when the batch is empty. A
// verdict per refusal queued a second behind the first with the one-slot channel taken, and the send
// blocked -- inline in the goroutine that reads the channel in adapter mode, with SMLock held.
func TestDeletionRefusalsResumeTheWaiterOnceTheBatchIsEmpty(t *testing.T) {
	smContext := context.NewSMContext("imsi-100000000000071", 12)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })
	smContext.SMContextState = context.SmStatePfcpRelease

	seids := make([]uint64, 0, 2)
	pending := make(context.PendingUPF)
	for _, ip := range []string{"10.82.0.1", "10.82.0.2"} {
		smContext.AllocateLocalSEIDForDataPath(&context.DataPath{
			FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *context.NewNodeID(ip)}},
		})
		seids = append(seids, smContext.PFCPContext[ip].LocalSEID)
		pending[ip] = true
	}
	smContext.ResetPendingUPF(pending)

	refuse := func(seid uint64) {
		rsp := message.NewSessionDeletionResponse(0, 0, seid, 1, 0, ie.NewCause(ie.CauseRequestRejected))
		HandlePfcpSessionDeletionResponse(&udp.Message{
			RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("10.82.0.1"), Port: 8805},
			PfcpMessage: rsp,
		})
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		refuse(seids[0])
		if got := len(smContext.SBIPFCPCommunicationChan); got != 0 {
			t.Errorf("the first refusal resumed the waiter with a node still pending")
		}
		refuse(seids[1])
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a refusal blocked on the verdict channel")
	}

	select {
	case got := <-smContext.SBIPFCPCommunicationChan:
		if got != context.SessionReleaseSuccess {
			t.Errorf("the waiter was resumed with %v, want SessionReleaseSuccess", got)
		}
	default:
		t.Fatal("the waiter was never resumed once every node had answered")
	}
}

// A verdict already waiting -- a send failure answers the waiter at once -- must not make a later
// refusal block.
func TestDeletionRefusalDoesNotBlockBehindAQueuedVerdict(t *testing.T) {
	smContext := context.NewSMContext("imsi-100000000000072", 13)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })
	smContext.SMContextState = context.SmStatePfcpRelease
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{
		FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *context.NewNodeID("10.82.0.3")}},
	})
	seid := smContext.PFCPContext["10.82.0.3"].LocalSEID
	smContext.ResetPendingUPF(context.PendingUPF{"10.82.0.3": true})
	smContext.SBIPFCPCommunicationChan <- context.SessionReleaseFailed

	done := make(chan struct{})
	go func() {
		defer close(done)
		HandlePfcpSessionDeletionResponse(&udp.Message{
			RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("10.82.0.3"), Port: 8805},
			PfcpMessage: message.NewSessionDeletionResponse(0, 0, seid, 1, 0, ie.NewCause(ie.CauseRequestRejected)),
		})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a refusal blocked behind a verdict already queued")
	}
}

// A deletion response with no Cause, or one that cannot be read, is a refusal and not nothing: the
// transport has already completed the request's transaction on receiving it, so no retry timeout is
// left to wake the release, and a response dropped here would leave it waiting for good.
func TestDeletionResponseWithAnUnusableCauseResumesTheWaiter(t *testing.T) {
	for name, build := range map[string]func(seid uint64) message.Message{
		"no cause": func(seid uint64) message.Message { return message.NewSessionDeletionResponse(0, 0, seid, 1, 0) },
		"unreadable cause": func(seid uint64) message.Message {
			return message.NewSessionDeletionResponse(0, 0, seid, 1, 0, ie.New(ie.Cause, []byte{}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			smContext := context.NewSMContext("imsi-100000000000073", 14)
			t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })
			smContext.SMContextState = context.SmStatePfcpRelease
			smContext.AllocateLocalSEIDForDataPath(&context.DataPath{
				FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *context.NewNodeID("10.82.0.4")}},
			})
			seid := smContext.PFCPContext["10.82.0.4"].LocalSEID
			smContext.ResetPendingUPF(context.PendingUPF{"10.82.0.4": true})

			HandlePfcpSessionDeletionResponse(&udp.Message{
				RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("10.82.0.4"), Port: 8805},
				PfcpMessage: build(seid),
			})

			select {
			case got := <-smContext.SBIPFCPCommunicationChan:
				if got != context.SessionReleaseSuccess {
					t.Errorf("the waiter was resumed with %v, want SessionReleaseSuccess", got)
				}
			default:
				t.Fatal("an unusable deletion response left the release waiting")
			}
		})
	}
}
