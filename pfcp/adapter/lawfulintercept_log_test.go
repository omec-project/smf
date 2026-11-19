// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"net"
	"strings"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestTheAdapterResponseLogsDoNotNameAnInterceptedSubscriber drives both adapter response
// handlers for a session whose FAR is duplicating, and reads every PFCP log line they write. A
// line carrying the session's FARs would carry `Dup:true` next to the subscriber's SUPI, and
// grepping the log for it would list every intercepted subscriber.
func TestTheAdapterResponseLogsDoNotNameAnInterceptedSubscriber(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	core, logs := observer.New(zapcore.DebugLevel)
	orig := logger.PfcpLog
	logger.PfcpLog = zap.New(core).Sugar()
	t.Cleanup(func() { logger.PfcpLog = orig })

	const (
		supi = "imsi-123456789012371"
		ip   = "1.1.1.71"
	)
	nodeID := context.NewNodeID(ip)
	smContext := context.NewSMContext(supi, 14)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })
	smContext.AllocateLocalSEIDForDataPath(&context.DataPath{
		FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
	})
	pfcpContext := smContext.PFCPContext[ip]
	if pfcpContext.PDRs == nil {
		pfcpContext.PDRs = map[uint16]*context.PDR{}
	}
	pfcpContext.PDRs[1] = &context.PDR{
		PDRID: 1,
		FAR:   &context.FAR{FARID: 1, ApplyAction: context.ApplyAction{Forw: true, Dupl: true}},
	}
	seid := pfcpContext.LocalSEID
	if !strings.Contains(smContext.String(), "Dup:true") {
		t.Fatal("the session's own text does not carry the duplicating FAR, so this test cannot " +
			"see the disclosure it guards against")
	}

	rsp := &udp.Message{RemoteAddr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 8805}}

	rsp.PfcpMessage = message.NewSessionEstablishmentResponse(0, 0, seid, 9191, 0,
		ie.NewCause(ie.CauseRequestAccepted), ie.NewNodeID(ip, "", ""))
	// No transaction is pending for the sequence, so the handler refuses the response; the
	// session has been logged by then.
	if err := adapter.HandlePfcpSessionEstablishmentResponse(rsp); err == nil {
		t.Fatal("the establishment response was accepted with no transaction pending, so this " +
			"test is not driving the path it describes")
	}

	rsp.PfcpMessage = message.NewSessionModificationResponse(0, 0, seid, 9192, 0,
		ie.NewCause(ie.CauseRequestAccepted))
	if err := adapter.HandlePfcpSessionModificationResponse(rsp); err != nil {
		t.Fatalf("the modification response was refused: %v", err)
	}

	sawSession := false
	for _, entry := range logs.All() {
		if strings.Contains(entry.Message, "Dup:true") || strings.Contains(entry.Message, supi) {
			t.Errorf("a PFCP log line names the intercepted subscriber: %q", entry.Message)
		}
		if strings.Contains(entry.Message, smContext.Ref) {
			sawSession = true
		}
	}
	if !sawSession {
		t.Error("no PFCP log line identifies the session by its reference")
	}
}
