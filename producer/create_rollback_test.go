// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"testing"
	"time"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/message"
)

// rollbackFixture is a create-pending session whose only UPF accepted its leg, with the SMF's PFCP
// socket and the UPF's both on loopback so the deletion the rollback sends can be read off the wire.
type rollbackFixture struct {
	smContext  *smf_context.SMContext
	upf        *net.UDPConn
	remoteSEID uint64
}

// rollbackUpfIP is where the SMF and the UPF both listen, and where the session is keyed.
const rollbackUpfIP = "127.0.0.1"

func newRollbackFixture(t *testing.T) *rollbackFixture {
	t.Helper()
	ip := rollbackUpfIP

	prevConfig := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prevConfig })
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled}},
	}

	// The retry timing is shortened so that an unanswered deletion times out in milliseconds, not
	// seconds, and cannot outlive the test.
	retries, reqTimeout, rspTimeout := udp.GetRetryTimingForTest()
	udp.SetRetryTimingForTest(1, 50*time.Millisecond, 50*time.Millisecond)
	t.Cleanup(func() { udp.SetRetryTimingForTest(retries, reqTimeout, rspTimeout) })

	smfConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip), Port: 0})
	if err != nil {
		t.Fatalf("listening for the SMF: %v", err)
	}
	t.Cleanup(func() { _ = smfConn.Close() })
	prevServer := udp.GetServer()
	udp.SetServer(&udp.PfcpServer{Conn: smfConn})
	t.Cleanup(func() { udp.SetServer(prevServer) })

	upfConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip), Port: 0})
	if err != nil {
		t.Fatalf("listening for the UPF: %v", err)
	}
	t.Cleanup(func() { _ = upfConn.Close() })

	nodeID := smf_context.NewNodeID(ip)
	upf := smf_context.NewUPF(nodeID, nil)
	t.Cleanup(func() { smf_context.RemoveUPFNodeByNodeID(*nodeID) })
	upf.Port = uint16(upfConn.LocalAddr().(*net.UDPAddr).Port)

	// No rules on the tunnel: deactivation then has nothing to send, so the only message on the wire
	// is the deletion. singleUpfTunnel in the fsm tests is built the same way.
	node := smf_context.NewDataPathNode()
	node.UPF = upf
	dataPath := &smf_context.DataPath{IsDefaultPath: true, FirstDPNode: node}

	smContext := smf_context.NewSMContext("imsi-208930000000201", 21)
	t.Cleanup(func() { smf_context.RemoveSMContext(smContext.Ref) })
	smContext.Tunnel = &smf_context.UPTunnel{DataPathPool: smf_context.DataPathPool{1: dataPath}}
	smContext.AllocateLocalSEIDForDataPath(dataPath)
	const remoteSEID = uint64(0xabcd0001)
	smContext.PFCPContext[ip].RemoteSEID = remoteSEID
	smContext.SMContextState = smf_context.SmStatePfcpCreatePending
	// Queued ahead of the blocking read in SendPfcpSessionReleaseReq, so the rollback completes
	// without a PFCP peer answering.
	smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess

	// Registered last, so it runs first. Nothing answers the deletion, so reading its datagram does not
	// mean the transaction behind it -- its retry goroutine and timeout handler -- has finished, and
	// that handler reads the server, retry timing and configuration the cleanups above restore. Wait
	// for it before they do, as startSmfPfcpSocket does.
	t.Cleanup(udp.WaitForAllTransactions)

	return &rollbackFixture{smContext: smContext, upf: upfConn, remoteSEID: remoteSEID}
}

// A create that fails as a whole -- another UPF rejected its leg, or this one was lost to a restart
// -- must not leave an accepted UPF holding its session. Removing the context drops the SEID mapping,
// so nothing could delete it afterwards, and the rule allocations are never given back.
func TestRollbackFailedCreateDeletesTheAcceptedLegAndReleasesTheTunnel(t *testing.T) {
	f := newRollbackFixture(t)

	RollbackFailedCreate(f.smContext)

	if f.smContext.Tunnel != nil {
		t.Errorf("the tunnel was not released; the data path's rule allocations stay with a context about to be removed")
	}

	if err := f.upf.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("setting the read deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := f.upf.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the accepted UPF was sent nothing; its session would be left behind: %v", err)
	}
	msg, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parsing what the UPF was sent: %v", err)
	}
	deletion, ok := msg.(*message.SessionDeletionRequest)
	if !ok {
		t.Fatalf("the UPF was sent a %T, want a Session Deletion Request", msg)
	}
	if deletion.SEID() != f.remoteSEID {
		t.Errorf("the deletion is addressed to SEID %#x, want the UPF's own %#x", deletion.SEID(), f.remoteSEID)
	}
}

// Nothing is held by a context with no tunnel, and it must not wait for an answer that cannot come.
func TestRollbackFailedCreateWithNoTunnelReturnsWithoutSending(t *testing.T) {
	f := newRollbackFixture(t)
	f.smContext.Tunnel = nil

	done := make(chan struct{})
	go func() {
		RollbackFailedCreate(f.smContext)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the rollback of a context with no tunnel did not return")
	}

	if err := f.upf.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("setting the read deadline: %v", err)
	}
	if n, _, err := f.upf.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Errorf("a %d-byte message was sent for a context that holds nothing", n)
	}
}

// A purged context's teardown belongs to its replacement, and the handlers do not answer its
// deletions, so waiting on one would never return.
func TestRollbackFailedCreateLeavesAPurgedContextToItsReplacement(t *testing.T) {
	f := newRollbackFixture(t)
	f.smContext.LocalPurged.Store(true)

	done := make(chan struct{})
	go func() {
		RollbackFailedCreate(f.smContext)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the rollback of a purged context did not return")
	}

	if f.smContext.Tunnel == nil {
		t.Errorf("the tunnel of a purged context was released by the rollback; the replacement owns that")
	}
}

// A leg that never acknowledged the session -- the one that rejected its own -- holds nothing and has
// no SEID of its own to address a deletion to. None is sent, and the release must not wait for an
// answer to a request that was never made.
func TestRollbackFailedCreateSkipsALegThatNeverAcknowledged(t *testing.T) {
	f := newRollbackFixture(t)
	f.smContext.PFCPContext["127.0.0.1"].RemoteSEID = 0
	// The fixture queues a verdict ahead of the wait; take it back, so that only what the release
	// itself queues can resume it.
	<-f.smContext.SBIPFCPCommunicationChan

	done := make(chan struct{})
	go func() {
		RollbackFailedCreate(f.smContext)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the rollback waited for a deletion that was never sent")
	}

	if f.smContext.Tunnel != nil {
		t.Errorf("the tunnel was not released")
	}
	if err := f.upf.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("setting the read deadline: %v", err)
	}
	if n, _, err := f.upf.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Errorf("a %d-byte message was sent to a node that holds no session", n)
	}
}

// An FQDN UPF's address can move after the rules are allocated. The rollback must still find the
// session where it was stored: deactivating the data path used to dereference the entry a fresh
// resolution named, and the teardown stopped before sending the deletion.
func TestRollbackFailedCreateDeletesTheSessionOfAnFqdnUpfWhoseAddressMoved(t *testing.T) {
	f := newRollbackFixture(t)

	const fqdn = "upf.rollback-moved.test"
	node := f.smContext.Tunnel.DataPathPool[1].FirstDPNode
	port := f.upf.LocalAddr().(*net.UDPAddr).Port
	// The session was allocated while the name resolved to 127.0.0.1, which is where it is keyed.
	node.UPF.NodeID = *smf_context.NewNodeID(fqdn)
	f.smContext.PFCPContext["127.0.0.1"].NodeID = node.UPF.NodeID
	smf_context.InsertDnsHostIp(fqdn, net.ParseIP("127.0.0.2"))
	moved, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: port})
	if err != nil {
		t.Skipf("no second loopback address to move the UPF to: %v", err)
	}
	t.Cleanup(func() { _ = moved.Close() })

	RollbackFailedCreate(f.smContext)

	if f.smContext.Tunnel != nil {
		t.Errorf("the tunnel was not released")
	}
	if err = moved.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("setting the read deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := moved.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the UPF at its new address was sent nothing; its session would be left behind: %v", err)
	}
	msg, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parsing what the UPF was sent: %v", err)
	}
	deletion, ok := msg.(*message.SessionDeletionRequest)
	if !ok {
		t.Fatalf("the UPF was sent a %T, want a Session Deletion Request", msg)
	}
	if deletion.SEID() != f.remoteSEID {
		t.Errorf("the deletion is addressed to SEID %#x, want the UPF's own %#x", deletion.SEID(), f.remoteSEID)
	}
}

// The wait for the deletions' verdict ends on its own bound. A response the handler finds unusable
// can leave nothing to wake it, and the rollback holds SMLock throughout: waiting for good would
// leave the failed create's context, and the lock, held for good.
func TestRollbackFailedCreateStopsWaitingForAVerdictThatNeverComes(t *testing.T) {
	f := newRollbackFixture(t)
	// The fixture queues a verdict ahead of the wait; take it back, so that nothing answers.
	<-f.smContext.SBIPFCPCommunicationChan
	prev := rollbackVerdictTimeout
	rollbackVerdictTimeout = 100 * time.Millisecond
	t.Cleanup(func() { rollbackVerdictTimeout = prev })
	// Longer than the bound, so that it is the bound that ends the wait and not the transport's.
	retries, reqTimeout, rspTimeout := udp.GetRetryTimingForTest()
	udp.SetRetryTimingForTest(1, 600*time.Millisecond, 600*time.Millisecond)
	t.Cleanup(func() { udp.SetRetryTimingForTest(retries, reqTimeout, rspTimeout) })

	done := make(chan struct{})
	go func() {
		RollbackFailedCreate(f.smContext)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the rollback waited on a verdict that was never coming")
	}

	if !f.smContext.SMLock.TryLock() {
		t.Fatal("the rollback returned with SMLock still held")
	}
	f.smContext.SMLock.Unlock()
}

// A verdict left on the channel by the failed establishment is not an answer to the deletions the
// rollback sends. Read as one -- the wait takes any verdict outside the release ones for a success --
// it ended the wait at once, with the deletions still in flight.
func TestRollbackFailedCreateDoesNotTakeAStaleEstablishmentVerdictForTheAnswer(t *testing.T) {
	f := newRollbackFixture(t)
	<-f.smContext.SBIPFCPCommunicationChan
	f.smContext.SBIPFCPCommunicationChan <- smf_context.SessionEstablishFailed

	const bound = 300 * time.Millisecond
	prev := rollbackVerdictTimeout
	rollbackVerdictTimeout = bound
	t.Cleanup(func() { rollbackVerdictTimeout = prev })
	// Longer than the bound, so that nothing but the bound can end the wait.
	retries, reqTimeout, rspTimeout := udp.GetRetryTimingForTest()
	udp.SetRetryTimingForTest(1, 800*time.Millisecond, 800*time.Millisecond)
	t.Cleanup(func() { udp.SetRetryTimingForTest(retries, reqTimeout, rspTimeout) })

	start := time.Now()
	RollbackFailedCreate(f.smContext)

	if elapsed := time.Since(start); elapsed < bound/2 {
		t.Errorf("the rollback returned after %v, taking the stale verdict for the deletions' answer", elapsed)
	}
}
