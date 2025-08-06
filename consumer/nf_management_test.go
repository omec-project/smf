// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Open Networking Foundation <info@opennetworking.org>

package consumer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
)

func makeSessionCfg() nfConfigApi.SessionManagement {
	sd := "010203"
	port := int32(8805)
	return nfConfigApi.SessionManagement{
		SliceName: "slice-internet",
		PlmnId:    nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
		Snssai:    nfConfigApi.Snssai{Sst: 1, Sd: &sd},
		IpDomain: []nfConfigApi.IpDomain{{
			DnnName:  "internet",
			DnsIpv4:  "8.8.8.8",
			UeSubnet: "10.10.0.0/16",
			Mtu:      1400,
		}},
		Upf:      &nfConfigApi.Upf{Hostname: "upf-1", Port: &port},
		GnbNames: []string{"gnb1", "gnb2"},
	}
}

func makeSMFContext() *smfContext.SMFContext {
	return &smfContext.SMFContext{
		NfInstanceID: "test-nf-id",
		URIScheme:    "http",
		RegisterIPv4: "127.0.0.1",
		SBIPort:      8080,
	}
}

func validateBasicProfile(profile models.NfProfile, t *testing.T) {
	if profile.NfInstanceId != "test-nf-id" {
		t.Errorf("expected NfInstanceId to be 'test-nf-id', got %s", profile.NfInstanceId)
	}
	if profile.NfServices == nil || len(*profile.NfServices) == 0 {
		t.Error("expected non-nil and non-empty NfServices")
	}
	if profile.SmfInfo == nil || profile.SmfInfo.SNssaiSmfInfoList == nil {
		t.Error("expected non-nil SmfInfo and SNssaiSmfInfoList")
	}
}

func TestGetNfProfile(t *testing.T) {
	validCfg := makeSessionCfg()
	validCtx := makeSMFContext()
	originalCfg := factory.SmfConfig.Configuration
	defer func() {
		factory.SmfConfig.Configuration = originalCfg
	}()
	factory.SmfConfig.Configuration = &factory.Configuration{
		ServiceNameList: []string{"pdusession"},
	}

	tests := []struct {
		name      string
		smfCtx    *smfContext.SMFContext
		cfgs      []nfConfigApi.SessionManagement
		expectErr bool
		errorMsg  string
		validate  func(models.NfProfile, *testing.T)
	}{
		{
			name:      "Valid config and context",
			smfCtx:    validCtx,
			cfgs:      []nfConfigApi.SessionManagement{validCfg},
			expectErr: false,
			validate:  validateBasicProfile,
		},
		{
			name:      "Nil SMF context",
			smfCtx:    nil,
			cfgs:      []nfConfigApi.SessionManagement{validCfg},
			expectErr: true,
			errorMsg:  "SMF context is nil",
		},
		{
			name:      "Empty config",
			smfCtx:    validCtx,
			cfgs:      nil,
			expectErr: true,
			errorMsg:  "session management config is empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := getNfProfile(tc.smfCtx, tc.cfgs)
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("expected error to contain %q, got %v", tc.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("did not expect error, got: %v", err)
				}
				if tc.validate != nil {
					tc.validate(profile, t)
				}
			}
		})
	}
}

func TestNfIDUpdated_NrfURLNotOverwritten(t *testing.T) {
	svr := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/nnrf-nfm/v1/nf-instances/") {
			w.Header().Set("Location", fmt.Sprintf("%s/nnrf-nfm/v1/nf-instances/mocked-id", r.Host))
			w.WriteHeader(http.StatusCreated)
		} else {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}))
	svr.EnableHTTP2 = true
	svr.StartTLS()
	defer svr.Close()
	if err := factory.InitConfigFactory("../config/smfcfg.yaml"); err != nil {
		t.Fatalf("Could not read example configuration file")
	}
	self := smfContext.SMF_Self()
	self.NrfUri = svr.URL
	self.RegisterIPv4 = "127.0.0.2"

	_, _, err := SendRegisterNFInstance([]nfConfigApi.SessionManagement{makeSessionCfg()})
	if err != nil {
		t.Errorf("Got and error %+v", err)
	}
	if self.NfInstanceID != "mocked-id" {
		t.Errorf("Expected NfId to be 'mocked-id', got %v", self.NfInstanceID)
	}
	if self.NrfUri != svr.URL {
		t.Errorf("Expected NRF URL to stay %s, but was %s", svr.URL, self.NrfUri)
	}
}
