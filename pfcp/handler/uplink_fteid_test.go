// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package handler_test

import (
	"net"
	"strings"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/handler"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// A UPF that ignores CHOOSE ID gives each uplink PDR its own TEID, and the RAN is told one of
// them. Nothing fails at that point, so the establishment response is the only place the SMF can
// say so. The adapter dispatcher has the same test; only one of the two runs in a deployment.
func TestAnEstablishmentWithMoreThanOneUplinkFTEIDIsReported(t *testing.T) {
	for _, tc := range []struct {
		name       string
		imsi       string
		teids      []uint32
		wantReport bool
	}{
		{"one TEID across the PDRs", "imsi-100000000000031", []uint32{0x31d, 0x31d}, false},
		{"a TEID per PDR", "imsi-100000000000032", []uint32{0x31d, 0x31e}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if factory.SmfConfig.Configuration == nil {
				factory.SmfConfig = factory.Config{
					Configuration: &factory.Configuration{
						KafkaInfo:        factory.KafkaInfo{EnableKafka: boolPointer(false)},
						EnableUpfAdapter: false,
					},
				}
			}

			const ip = "1.1.1.31"
			nodeID := context.NewNodeID(ip)
			smContext := context.NewSMContext(tc.imsi, 10)
			t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })
			core, logs := observer.New(zap.ErrorLevel)
			smContext.SubPfcpLog = zap.New(core).Sugar()
			smContext.SMContextState = context.SmStatePfcpCreatePending
			smContext.Tunnel = &context.UPTunnel{
				DataPathPool: context.DataPathPool{
					10: &context.DataPath{
						IsDefaultPath: true,
						FirstDPNode: &context.DataPathNode{
							UPF:          &context.UPF{NodeID: *nodeID},
							UpLinkTunnel: &context.GTPTunnel{},
						},
					},
				},
			}
			smContext.AllocateLocalSEIDForDataPath(&context.DataPath{
				FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}},
			})
			localSEID := smContext.PFCPContext[ip].LocalSEID

			ies := []*ie.IE{
				ie.NewCause(ie.CauseRequestAccepted),
				ie.NewNodeID(ip, "", ""),
			}
			for i, teid := range tc.teids {
				ies = append(ies, ie.NewCreatedPDR(
					ie.NewPDRID(uint16(i+1)),
					ie.NewFTEID(0x01, teid, net.ParseIP("10.0.0.1"), nil, 0),
				))
			}
			seq := uint32(localSEID)
			pfcp_message.InsertPfcpTxn(seq, nodeID)
			handler.HandlePfcpSessionEstablishmentResponse(&udp.Message{
				RemoteAddr:  &net.UDPAddr{IP: net.ParseIP(ip), Port: 8805},
				PfcpMessage: message.NewSessionEstablishmentResponse(0, 0, localSEID, seq, 0, ies...),
			})

			reported := logs.FilterMessageSnippet("CHOOSE ID").All()
			if !tc.wantReport {
				if len(reported) != 0 {
					t.Errorf("one F-TEID reported as several: %q", reported[0].Message)
				}
				return
			}
			if len(reported) != 1 {
				t.Fatalf("%d reports of TEIDs %#x, want 1", len(reported), tc.teids)
			}
			if msg := reported[0].Message; !strings.Contains(msg, "the RAN is told TEID 0x31d") {
				t.Errorf("report %q does not say which TEID the RAN is told", msg)
			}
		})
	}
}
