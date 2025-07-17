// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Open Networking Foundation <info@opennetworking.org>
package consumer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/omec-project/openapi/nfConfigApi"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
)

func makeSessionConfig(sliceName, mcc, mnc, sst string, sd string, dnnName, ueSubnet, hostname string, port int32) nfConfigApi.SessionManagement {
	sstUint64, err := strconv.ParseUint(sst, 10, 8)
	if err != nil {
		panic("invalid SST value: " + sst)
	}
	sstint := int32(sstUint64)
	return nfConfigApi.SessionManagement{
		SliceName: sliceName,
		PlmnId: nfConfigApi.PlmnId{
			Mcc: mcc,
			Mnc: mnc,
		},
		Snssai: nfConfigApi.Snssai{
			Sst: sstint,
			Sd:  &sd,
		},
		IpDomain: []nfConfigApi.IpDomain{
			{
				DnnName:  dnnName,
				DnsIpv4:  "8.8.8.8",
				UeSubnet: ueSubnet,
				Mtu:      1400,
			},
		},
		Upf: &nfConfigApi.Upf{
			Hostname: hostname,
			Port:     &port,
		},
		GnbNames: []string{"gnb1", "gnb2"},
	}
}

func Test_nf_id_updated_and_nrf_url_is_not_overwritten_when_registering(t *testing.T) {
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

	sessionConfigOne := makeSessionConfig("slice1", "111", "01", "1", "1", "internet", "192.168.1.0/24", "192.168.1.1", 38412)
	_, _, err := SendRegisterNFInstance([]nfConfigApi.SessionManagement{sessionConfigOne})
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
