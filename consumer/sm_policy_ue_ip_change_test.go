// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
//
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/Npcf_SMPolicyControl"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
)

const (
	testSmfAllocatedIpv4 = "192.168.139.17"
	testUpfAllocatedIpv4 = "192.168.100.1"
)

// pcfStub answers UpdateSMPolicy with the given status and hands back what it received.
func pcfStub(t *testing.T, status int) (*httptest.Server, <-chan string, <-chan models.SmPolicyUpdateContextData) {
	t.Helper()
	paths := make(chan string, 4)
	bodies := make(chan models.SmPolicyUpdateContextData, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		var body models.SmPolicyUpdateContextData
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode update body: %v", err)
		}
		bodies <- body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status < 300 {
			if err := json.NewEncoder(w).Encode(models.SmPolicyDecision{}); err != nil {
				t.Errorf("encode decision: %v", err)
			}
		}
	}))
	t.Cleanup(server.Close)
	return server, paths, bodies
}

func smContextWithPCF(t *testing.T, server *httptest.Server) *smf_context.SMContext {
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
		PolicyReportedIpv4: testSmfAllocatedIpv4,
	}
}

// The report carries the trigger, the address the UE now has, and the one the SMF gave back -- the
// last of these is what lets the PCF stop honouring a binding key that is in the pool again.
func TestUeIpChangeReportCarriesBothAddressesAndTheTrigger(t *testing.T) {
	server, paths, bodies := pcfStub(t, http.StatusOK)
	smContext := smContextWithPCF(t, server)

	status, err := SendSMPolicyAssociationUpdateUeIpChange(smContext, testUpfAllocatedIpv4)
	if err != nil {
		t.Fatalf("report failed: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}

	if got, want := <-paths, "/npcf-smpolicycontrol/v1/sm-policies/imsi-001010123456789-10/update"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	body := <-bodies
	if len(body.RepPolicyCtrlReqTriggers) != 1 || body.RepPolicyCtrlReqTriggers[0] != models.POLICYCONTROLREQUESTTRIGGER_UE_IP_CH {
		t.Errorf("reported triggers = %v, want [UE_IP_CH]", body.RepPolicyCtrlReqTriggers)
	}
	if body.GetIpv4Address() != testUpfAllocatedIpv4 {
		t.Errorf("ipv4Address = %q, want %q", body.GetIpv4Address(), testUpfAllocatedIpv4)
	}
	if body.GetRelIpv4Address() != testSmfAllocatedIpv4 {
		t.Errorf("relIpv4Address = %q, want %q", body.GetRelIpv4Address(), testSmfAllocatedIpv4)
	}
	if smContext.PolicyReportedIpv4 != testUpfAllocatedIpv4 {
		t.Errorf("PolicyReportedIpv4 = %q, want %q", smContext.PolicyReportedIpv4, testUpfAllocatedIpv4)
	}
}

// A session whose policy association was created without an address has nothing to release, and
// saying so would have the PCF clear a binding it never held.
func TestUeIpChangeReportOmitsTheReleaseWhenThereIsNothingToRelease(t *testing.T) {
	server, _, bodies := pcfStub(t, http.StatusOK)
	smContext := smContextWithPCF(t, server)
	smContext.PolicyReportedIpv4 = ""

	if _, err := SendSMPolicyAssociationUpdateUeIpChange(smContext, testUpfAllocatedIpv4); err != nil {
		t.Fatalf("report failed: %v", err)
	}
	if body := <-bodies; body.RelIpv4Address != nil {
		t.Errorf("relIpv4Address = %q, want it absent", body.GetRelIpv4Address())
	}
}

// A refused report must not be recorded as delivered: the address the PCF holds has not changed, so
// the next establishment response has to try again rather than conclude there is nothing to say.
func TestUeIpChangeReportRefusedLeavesTheRecordedAddressAlone(t *testing.T) {
	server, _, _ := pcfStub(t, http.StatusInternalServerError)
	smContext := smContextWithPCF(t, server)

	if _, err := SendSMPolicyAssociationUpdateUeIpChange(smContext, testUpfAllocatedIpv4); err == nil {
		t.Fatal("expected the refused report to return an error")
	}
	if smContext.PolicyReportedIpv4 != testSmfAllocatedIpv4 {
		t.Errorf("PolicyReportedIpv4 = %q, want it unchanged at %q", smContext.PolicyReportedIpv4, testSmfAllocatedIpv4)
	}
}

// unboundedReportBound is how long this test waits before calling the report
// unbounded. It is deliberately a fixed number rather than a multiple of
// ueIpChangeReportTimeout: a bound derived from the value under test moves
// whenever that value does, so raising the timeout to something useless would
// raise this with it and the test would still pass.
const unboundedReportBound = 30 * time.Second

// A PCF that accepts the connection and never answers must not hold the caller.
// This report runs on the establishment path while the PFCP handler holds
// SMLock, so an unbounded call would keep the lock for as long as the PCF
// stayed silent and take the session's release path with it. The generated
// client carries no timeout of its own, so the bound has to come from the
// context this passes.
func TestUeIpChangeReportDoesNotWaitOnASilentPCF(t *testing.T) {
	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Registered before the close of release so that it runs after it: Close
	// waits for connections whose handler is still in flight, and a handler
	// parked on release would hold it there.
	defer server.Close()
	defer close(release)

	smContext := smContextWithPCF(t, server)

	// Off the test goroutine, so an unbounded call reports itself here rather
	// than hanging until the whole package times out.
	done := make(chan error, 1)
	go func() {
		_, reportErr := SendSMPolicyAssociationUpdateUeIpChange(smContext, testUpfAllocatedIpv4)
		done <- reportErr
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the report to fail against a PCF that never answers")
		}
	case <-time.After(unboundedReportBound):
		t.Fatalf("report had not returned after %s; on the establishment path it would still be "+
			"holding SMLock", unboundedReportBound)
	}

	// Pinned separately, because the check above only proves the call ends, not
	// that it ends soon enough to be held under SMLock.
	if ueIpChangeReportTimeout > 10*time.Second {
		t.Errorf("ueIpChangeReportTimeout is %s; this runs under SMLock on every establishment, "+
			"so it has to stay short", ueIpChangeReportTimeout)
	}

	// The address must not be recorded as reported when it was not.
	if smContext.PolicyReportedIpv4 != testSmfAllocatedIpv4 {
		t.Errorf("PolicyReportedIpv4 = %q after a failed report, want the address unchanged at %q",
			smContext.PolicyReportedIpv4, testSmfAllocatedIpv4)
	}
}

// The create records the address it told the PCF about, and this drives the
// create to prove it rather than pre-setting the field.
//
// Every other test here starts from a context whose PolicyReportedIpv4 is
// already populated, so all of them would still pass if the create never set
// it -- and then a real session would report no relIpv4Address on its first
// change, leaving the PCF binding an address that had moved on. Drive the
// writer, not the reader.
func TestCreateRecordsTheAddressItToldThePCFAbout(t *testing.T) {
	// Read off the wire rather than through models.SmPolicyContextData:
	// unmarshalling into the generated model succeeds while leaving Ipv4Address
	// nil, so the assertion below would have passed against an empty body.
	var sent map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Errorf("decode create body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(models.SmPolicyDecision{}); err != nil {
			t.Errorf("encode decision: %v", err)
		}
	}))
	defer server.Close()

	smContext := smContextWithPCF(t, server)
	// Not pre-populated: the create is what has to set it.
	smContext.PolicyReportedIpv4 = ""
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP(testSmfAllocatedIpv4)}
	smContext.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
	smContext.Snssai = &models.Snssai{Sst: 1, Sd: openapi.PtrString("010203")}
	smContext.DnnConfiguration = models.DnnConfiguration{}

	if _, _, err := SendSMPolicyAssociationCreate(smContext); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	if sent["ipv4Address"] != testSmfAllocatedIpv4 {
		t.Fatalf("the create sent ipv4Address %v, want %q", sent["ipv4Address"], testSmfAllocatedIpv4)
	}
	if smContext.PolicyReportedIpv4 != testSmfAllocatedIpv4 {
		t.Errorf("PolicyReportedIpv4 = %q after a create that sent %q; a later change would then omit "+
			"relIpv4Address and leave the PCF binding an address that has moved on",
			smContext.PolicyReportedIpv4, testSmfAllocatedIpv4)
	}
}

// A session established before PolicyReportedIpv4 existed decodes it as empty
// when it is restored, and its first address change would then report no
// released address at all -- leaving the PCF binding the old one for the rest of
// the session, which is what this report exists to prevent.
//
// The address the PCF was told at create is still the one the context holds at
// this point, because the report runs before the UPF's address is adopted.
func TestUeIpChangeReportFallsBackForAContextFromBeforeTheFieldExisted(t *testing.T) {
	server, _, bodies := pcfStub(t, http.StatusOK)
	smContext := smContextWithPCF(t, server)

	// As a restored pre-upgrade context looks.
	smContext.PolicyReportedIpv4 = ""
	smContext.PDUAddress = &smf_context.UeIpAddr{Ip: net.ParseIP(testSmfAllocatedIpv4)}

	if _, err := SendSMPolicyAssociationUpdateUeIpChange(smContext, testUpfAllocatedIpv4); err != nil {
		t.Fatalf("report failed: %v", err)
	}

	body := <-bodies
	if body.GetRelIpv4Address() != testSmfAllocatedIpv4 {
		t.Errorf("relIpv4Address = %q, want %q: without it the PCF keeps binding the address the "+
			"session no longer has", body.GetRelIpv4Address(), testSmfAllocatedIpv4)
	}
}
