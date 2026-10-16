// SPDX-FileCopyrightText: 2026 Forsway Solutions AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"strings"
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

func amfProfileWithNamfComm(apiPrefix string) models.NFProfileDiscovery {
	var commService models.NFService
	commService.SetServiceInstanceId("namf-comm")
	commService.SetServiceName(models.SERVICENAME_NAMF_COMM)
	commService.SetApiPrefix(apiPrefix)
	var prof models.NFProfileDiscovery
	prof.SetNfInstanceId("amf-instance-1")
	prof.SetNfType(models.NFTYPE_AMF)
	prof.SetNfStatus(models.NFSTATUS_REGISTERED)
	prof.SetNfServiceList(map[string]models.NFService{commService.GetServiceInstanceId(): commService})
	return prof
}

func TestRebuildCommunicationClient_WithNamfComm_BuildsClientAndSetsApiRoot(t *testing.T) {
	const apiPrefix = "http://10.42.0.42:29518"

	smCtx := &SMContext{}
	smCtx.AMFProfile = amfProfileWithNamfComm(apiPrefix)

	smCtx.RebuildCommunicationClient()

	if smCtx.CommunicationClient == nil {
		t.Fatalf("expected CommunicationClient to be non-nil after RebuildCommunicationClient")
	}
	// Ensure the apiRoot variable was wired through to the configuration.
	cfg := smCtx.CommunicationClient.GetConfig()
	if cfg == nil || len(cfg.Servers) == 0 {
		t.Fatalf("expected client configuration with at least one server")
	}
	apiRootVar, ok := cfg.Servers[0].Variables["apiRoot"]
	if !ok {
		t.Fatalf("expected apiRoot variable to be present on server[0]")
	}
	if apiRootVar.DefaultValue != apiPrefix {
		t.Errorf("apiRoot DefaultValue = %q, want %q", apiRootVar.DefaultValue, apiPrefix)
	}
}

func TestRebuildCommunicationClient_NoServices_LeavesClientNil(t *testing.T) {
	smCtx := &SMContext{}
	// AMFProfile.NfServiceList is nil here.

	smCtx.RebuildCommunicationClient()

	if smCtx.CommunicationClient != nil {
		t.Errorf("expected CommunicationClient to remain nil when NfServiceList is nil")
	}
}

func TestRebuildCommunicationClient_NoNamfComm_LeavesClientNil(t *testing.T) {
	smCtx := &SMContext{}
	var nfService models.NFService
	nfService.SetServiceInstanceId("namf-evts")
	nfService.SetServiceName(models.SERVICENAME_NAMF_EVTS)
	nfService.SetApiPrefix("http://10.42.0.42:29518")
	var prof models.NFProfileDiscovery
	prof.SetNfInstanceId("amf-instance-2")
	prof.SetNfType(models.NFTYPE_AMF)
	prof.SetNfStatus(models.NFSTATUS_REGISTERED)
	prof.SetNfServiceList(map[string]models.NFService{"namf-evts": nfService})
	smCtx.AMFProfile = prof

	smCtx.RebuildCommunicationClient()

	if smCtx.CommunicationClient != nil {
		t.Errorf("expected CommunicationClient to remain nil when no namf-comm service is present")
	}
}

// Belt-and-braces: a fresh build replaces any previously held client.
func TestRebuildCommunicationClient_RebuildReplacesExistingClient(t *testing.T) {
	const firstApiPrefix = "http://10.42.0.10:29518"
	const secondApiPrefix = "http://10.42.0.20:29518"

	smCtx := &SMContext{}
	smCtx.AMFProfile = amfProfileWithNamfComm(firstApiPrefix)
	smCtx.RebuildCommunicationClient()
	if smCtx.CommunicationClient == nil {
		t.Fatalf("setup: expected non-nil CommunicationClient after first build")
	}
	first := smCtx.CommunicationClient

	smCtx.AMFProfile = amfProfileWithNamfComm(secondApiPrefix)
	smCtx.RebuildCommunicationClient()

	if smCtx.CommunicationClient == nil {
		t.Fatalf("expected non-nil CommunicationClient after second build")
	}
	if smCtx.CommunicationClient == first {
		t.Errorf("expected a fresh CommunicationClient instance after rebuild, got the same pointer")
	}
	apiRootVar := smCtx.CommunicationClient.GetConfig().Servers[0].Variables["apiRoot"]
	if !strings.Contains(apiRootVar.DefaultValue, "10.42.0.20") {
		t.Errorf("apiRoot DefaultValue = %q, expected it to reflect the second AMF endpoint", apiRootVar.DefaultValue)
	}
}
