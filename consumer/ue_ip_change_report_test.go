// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
//
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/omec-project/openapi/v2/Npcf_SMPolicyControl"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	reportSmfIpv4 = "192.168.139.17"
	reportUpfIpv4 = "192.168.100.1"
)

// countingPCFStub answers every SM policy update with 200 and counts the requests.
func countingPCFStub(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(models.SmPolicyDecision{}); err != nil {
			t.Errorf("encode decision: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func smContextForReport(t *testing.T, server *httptest.Server) *smf_context.SMContext {
	t.Helper()
	cfg := Npcf_SMPolicyControl.NewConfiguration()
	serverConfig := &cfg.Servers[0]
	apiRootVar := serverConfig.Variables["apiRoot"]
	apiRootVar.DefaultValue = server.URL
	serverConfig.Variables["apiRoot"] = apiRootVar

	return &smf_context.SMContext{
		Supi:               "imsi-001010123456789",
		PDUSessionID:       10,
		SMPolicyClient:     Npcf_SMPolicyControl.NewAPIClient(cfg),
		PolicyReportedIpv4: reportSmfIpv4,
		SubPfcpLog:         logger.PfcpLog.With("test", t.Name()),
	}
}

// The case this exists for: the UPF allocated a different address from the one the PCF was told.
func TestReportUeIpChangeReportsAnAddressThatMoved(t *testing.T) {
	server, calls := countingPCFStub(t)
	smContext := smContextForReport(t, server)

	ReportUeIpChange(smContext, net.ParseIP(reportUpfIpv4))

	if got := calls.Load(); got != 1 {
		t.Errorf("PCF was called %d times, want 1", got)
	}
	if smContext.PolicyReportedIpv4 != reportUpfIpv4 {
		t.Errorf("PolicyReportedIpv4 = %q, want %q", smContext.PolicyReportedIpv4, reportUpfIpv4)
	}
}

// The establishment response arrives once per UPF on the path, so an address that did not move must
// not produce a report -- and a second response carrying the same address must not produce another.
func TestReportUeIpChangeIsSilentWhenTheAddressDidNotMove(t *testing.T) {
	server, calls := countingPCFStub(t)
	smContext := smContextForReport(t, server)

	ReportUeIpChange(smContext, net.ParseIP(reportSmfIpv4))
	if got := calls.Load(); got != 0 {
		t.Fatalf("PCF was called %d times for an unchanged address, want 0", got)
	}

	ReportUeIpChange(smContext, net.ParseIP(reportUpfIpv4))
	ReportUeIpChange(smContext, net.ParseIP(reportUpfIpv4))
	if got := calls.Load(); got != 1 {
		t.Errorf("PCF was called %d times for one change reported twice, want 1", got)
	}
}

// A PCF that refuses the report must not leave the SMF believing it was delivered, and must not
// fail the session either -- the user plane is correct and only the binding is affected.
func TestReportUeIpChangeSurvivesARefusal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	smContext := smContextForReport(t, server)

	ReportUeIpChange(smContext, net.ParseIP(reportUpfIpv4))

	if smContext.PolicyReportedIpv4 != reportSmfIpv4 {
		t.Errorf("PolicyReportedIpv4 = %q, want it unchanged at %q after a refusal",
			smContext.PolicyReportedIpv4, reportSmfIpv4)
	}
}

// The success line has to name both addresses, which means reading the old one before the call.
// A successful report overwrites PolicyReportedIpv4 with the new address, so logging the field
// afterwards prints the new one twice -- and the whole value of the line is saying which address
// the PCF should stop binding to.
func TestReportUeIpChangeLogsTheAddressItMovedFrom(t *testing.T) {
	server, _ := countingPCFStub(t)
	smContext := smContextForReport(t, server)

	logged := &capturingCore{}
	smContext.SubPfcpLog = zap.New(logged).Sugar()

	ReportUeIpChange(smContext, net.ParseIP(reportUpfIpv4))

	line := logged.message()
	if line == "" {
		t.Fatal("nothing was logged, so the report said nothing about the move")
	}
	if !strings.Contains(line, reportSmfIpv4) {
		t.Errorf("log line %q does not name the address the PCF should stop binding to (%s)",
			line, reportSmfIpv4)
	}
	if !strings.Contains(line, reportUpfIpv4) {
		t.Errorf("log line %q does not name the new address (%s)", line, reportUpfIpv4)
	}
}

// capturingCore keeps the last message written through it.
type capturingCore struct {
	mu   sync.Mutex
	last string
}

func (c *capturingCore) message() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

func (c *capturingCore) Enabled(zapcore.Level) bool        { return true }
func (c *capturingCore) With([]zapcore.Field) zapcore.Core { return c }
func (c *capturingCore) Sync() error                       { return nil }
func (c *capturingCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	return checked.AddCore(entry, c)
}

func (c *capturingCore) Write(entry zapcore.Entry, _ []zapcore.Field) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = entry.Message
	return nil
}
