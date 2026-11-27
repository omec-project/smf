// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"sync"
	"testing"
	"time"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/message"
)

// TestModifySessionForLIReadsTheUPFPortUnderItsLock runs ModifySessionForLI against a
// configuration reconciliation writing the UPF's port, which it does under UpfLock. Under -race
// an unguarded read of the port is reported.
//
// The session has a live PFCP session on the UPF, so each call groups its FAR, reads the port and
// sends; the SMF and the UPF both listen on loopback, and every modification is read off the wire.
// Without a live session ModifySessionForLI skips the UPF before it reads the port.
func TestModifySessionForLIReadsTheUPFPortUnderItsLock(t *testing.T) {
	const ip = "127.0.0.1"
	const iterations = 50

	prevConfig := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prevConfig })
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled}},
	}

	// Nothing answers the modifications, so their transactions time out; shortened so they end in
	// milliseconds and cannot outlive the test.
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
	upfPort := uint16(upfConn.LocalAddr().(*net.UDPAddr).Port)

	nodeID := smf_context.NewNodeID(ip)
	upf := smf_context.NewUPF(nodeID, nil)
	t.Cleanup(func() { smf_context.RemoveUPFNodeByNodeID(*nodeID) })
	upf.Port = upfPort

	far := &smf_context.FAR{FARID: 1, State: smf_context.RULE_UPDATE}
	node := smf_context.NewDataPathNode()
	node.UPF = upf
	node.UpLinkTunnel = &smf_context.GTPTunnel{PDR: map[string]*smf_context.PDR{"ul": {FAR: far}}}
	dataPath := &smf_context.DataPath{Activated: true, IsDefaultPath: true, FirstDPNode: node}

	sc := smf_context.NewSMContext("imsi-208930000000291", 21)
	t.Cleanup(func() { smf_context.RemoveSMContext(sc.Ref) })
	sc.Tunnel = &smf_context.UPTunnel{DataPathPool: smf_context.DataPathPool{1: dataPath}}
	sc.AllocateLocalSEIDForDataPath(dataPath)
	const remoteSEID = uint64(0xabcd0091)
	sc.PFCPContext[ip].RemoteSEID = remoteSEID

	// Registered last, so it runs first: the timeout handlers read the server, retry timing and
	// configuration the cleanups above restore.
	t.Cleanup(udp.WaitForAllTransactions)

	// Read concurrently, so no datagram is lost to a full socket buffer. A retransmission repeats its
	// sequence number, so modifications are counted by sequence number.
	var mu sync.Mutex
	seqs := map[uint32]bool{}
	var wrongSEID []uint64
	read := make(chan struct{})
	go func() {
		defer close(read)
		buf := make([]byte, 2048)
		for {
			if err := upfConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				return
			}
			n, _, err := upfConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg, err := message.Parse(buf[:n])
			if err != nil {
				continue
			}
			if req, ok := msg.(*message.SessionModificationRequest); ok {
				mu.Lock()
				seqs[req.Sequence()] = true
				if req.SEID() != remoteSEID {
					wrongSEID = append(wrongSEID, req.SEID())
				}
				done := len(seqs) == iterations
				mu.Unlock()
				if done {
					return
				}
			}
		}
	}()

	written := make(chan struct{})
	go func() {
		defer close(written)
		for range 200 {
			upf.UpfLock.Lock()
			upf.Port = upfPort
			upf.UpfLock.Unlock()
		}
	}()
	for range iterations {
		sc.SMLock.Lock()
		// The send marks the FAR applied, so it is marked changed again for the next call to
		// group it and read the port.
		far.State = smf_context.RULE_UPDATE
		if err := ModifySessionForLI(sc); err != nil {
			t.Errorf("ModifySessionForLI: %v", err)
		}
		sc.SMLock.Unlock()
	}
	<-written
	<-read

	mu.Lock()
	defer mu.Unlock()
	if len(seqs) != iterations {
		t.Errorf("the UPF received %d modifications, want %d", len(seqs), iterations)
	}
	if len(wrongSEID) != 0 {
		t.Errorf("modifications addressed to SEIDs %v, want %#x", wrongSEID, remoteSEID)
	}
}
