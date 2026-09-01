// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The whole mechanism rests on one thing: a restored session must be sent as a session
// ESTABLISHMENT, not a modification. A restarted UPF holds no session, so a modification addressed
// to a session identifier it never issued is either rejected or, worse, applied to unrelated state.
//
// Nothing else in the suite looks at what actually goes on the wire, so this stands up a PFCP
// socket for the SMF and a listener standing in for the UPF, and reads the message type off it.
func TestARestoredSessionIsSentAsAnEstablishmentNotAModification(t *testing.T) {
	nativeDatapath(t)
	upfConn, upfPort := listenLoopback(t)
	startSmfPfcpSocket(t)

	upf := context.NewUPF(context.NewNodeID("127.0.0.1"), nil)
	upf.UPFStatus = context.AssociatedSetUpSuccess
	upf.Port = upfPort
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: time.Now()}
	// The N3 interface the RAN was told to send to. Without it the tunnel cannot be pinned.
	upf.N3Interfaces = []context.UPFInterfaceInfo{{
		NetworkInstance:       "internet",
		IPv4EndPointAddresses: []net.IP{net.ParseIP("192.168.252.3")},
	}}

	smContext, wantPDRID, wantTEID := sessionWithDataPath(t, "imsi-208930000000901", 1, upf)

	// A session that is currently established: the UPF has issued an identifier for it. Left as it
	// is, the activation path would send a modification.
	pfcpCtx := smContext.PFCPContext["127.0.0.1"]
	pfcpCtx.RemoteSEID = 0xBEEF

	if !reissue(smContext, "127.0.0.1") {
		t.Fatalf("the session was not re-issued")
	}

	msg := readPfcp(t, upfConn)
	if got, want := msg.MessageType(), message.MsgTypeSessionEstablishmentRequest; got != want {
		t.Fatalf("the restarted UPF received message type %d, want %d (session establishment). "+
			"A modification names a session the restarted UPF never created.", got, want)
	}

	// The rules go back with the identifiers the SMF already holds. They mean something to a UPF
	// only while it holds the rules they name, and a restarted one holds none, so carrying them
	// over is both safe and what keeps every existing reference to a rule valid.
	establishment, ok := msg.(*message.SessionEstablishmentRequest)
	if !ok {
		t.Fatalf("unexpected message shape %T", msg)
	}
	if len(establishment.CreatePDR) == 0 {
		t.Fatalf("the establishment carried no Create PDR, so nothing was re-installed")
	}
	pdrID, err := establishment.CreatePDR[0].PDRID()
	if err != nil {
		t.Fatalf("reading the PDR ID back: %v", err)
	}
	if pdrID != wantPDRID {
		t.Errorf("the re-installed PDR is %d, want %d; restoration renumbered a rule it should have "+
			"carried over, leaving every reference the SMF holds pointing at the old value", pdrID, wantPDRID)
	}

	// The uplink tunnel must be named, not re-chosen. If the CHOOSE flag is still set the UPF
	// allocates a second TEID, the RAN is never told, and every uplink packet keeps arriving on the
	// old one and misses the rule table -- which is what the cluster showed.
	pdi, err := establishment.CreatePDR[0].PDI()
	if err != nil {
		t.Fatalf("reading the PDI back: %v", err)
	}
	var fteid *ie.IE
	for _, child := range pdi {
		if child.Type == ie.FTEID {
			fteid = child
		}
	}
	if fteid == nil {
		t.Fatalf("the re-installed PDR carries no F-TEID, so the UPF has nothing to match uplink on")
	}
	f, err := fteid.FTEID()
	if err != nil {
		t.Fatalf("parsing the F-TEID: %v", err)
	}
	if f.HasCh() {
		t.Errorf("the F-TEID still has the CHOOSE flag set, so the restarted UPF will allocate a new " +
			"tunnel the RAN knows nothing about")
	}
	if f.TEID != wantTEID {
		t.Errorf("the re-installed tunnel is TEID %#x, want %#x — the one the RAN is sending on", f.TEID, wantTEID)
	}
}

// nativeDatapath selects the PFCP datapath rather than the adapter, which would post the message to
// an HTTP endpoint instead of putting it on the wire.
func nativeDatapath(t *testing.T) {
	t.Helper()
	enabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{
			KafkaInfo:        factory.KafkaInfo{EnableKafka: &enabled},
			EnableUpfAdapter: false,
		},
	}
}

func listenLoopback(t *testing.T) (*net.UDPConn, uint16) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("standing in for the UPF: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// startSmfPfcpSocket gives the SMF a real socket to send from, which the send path takes from the
// package-level server rather than opening per message.
func startSmfPfcpSocket(t *testing.T) {
	t.Helper()
	self := context.SMF_Self()
	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserving a port for the SMF: %v", err)
	}
	port := free.LocalAddr().(*net.UDPAddr).Port
	free.Close()

	self.CPNodeID = *context.NewNodeID("127.0.0.1")
	self.PFCPPort = port
	udp.Run(func(*udp.Message) {})
	time.Sleep(50 * time.Millisecond) // let the listener bind before anything is sent
}

func readPfcp(t *testing.T, conn *net.UDPConn) message.Message {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("setting a read deadline: %v", err)
	}
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the restarted UPF received nothing: %v", err)
	}
	msg, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parsing what the UPF received: %v", err)
	}
	return msg
}

// sessionWithDataPath builds a session with one activated data path anchored on the given UPF, so
// the activation path has rules to send.
func sessionWithDataPath(t *testing.T, supi string, psi int32, upf *context.UPF) (*context.SMContext, uint16, uint32) {
	t.Helper()
	pdr, err := upf.AddPDR()
	if err != nil {
		t.Fatalf("allocating a PDR: %v", err)
	}
	// What ActivateUpLinkTunnel builds: the CHOOSE flag set, asking the UPF to allocate the tunnel.
	// Restoration has to turn this into a named tunnel, and a bare PDR would not exercise that.
	pdr.PDI.SourceInterface = context.SourceInterface{InterfaceValue: context.SourceInterfaceAccess}
	pdr.PDI.LocalFTeid = &context.FTEID{Ch: true}

	smContext := context.NewSMContext(supi, psi)
	// The N3 address is resolved per session type, the same way the N2 setup resolves it.
	smContext.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			1: &context.DataPath{
				Activated:     true,
				IsDefaultPath: true,
				FirstDPNode: &context.DataPathNode{
					UPF:          upf,
					UpLinkTunnel: &context.GTPTunnel{TEID: 0x1234, PDR: map[string]*context.PDR{"default": pdr}},
				},
			},
		},
	}
	smContext.SMLock.Lock()
	smContext.PFCPContext[upf.NodeID.ResolveNodeIdToIp().String()] = &context.PFCPSessionContext{
		NodeID:    upf.NodeID,
		LocalSEID: 4321,
	}
	smContext.SMLock.Unlock()
	return smContext, pdr.PDRID, 0x1234
}
