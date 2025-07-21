// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-License-Identifier: Apache-2.0
//

package context

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/omec-project/openapi/nfConfigApi"
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

func TestUpdateSmfContext(t *testing.T) {
	tests := []struct {
		name     string
		config   []nfConfigApi.SessionManagement
		validate func(*SMFContext, error) (bool, string)
	}{
		{
			name:   "Empty config should clear context",
			config: nil,
			validate: func(smCtx *SMFContext, err error) (bool, string) {
				if err != nil {
					return false, err.Error()
				}
				if len(smCtx.SnssaiInfos) != 0 {
					return false, "expected SnssaiInfos to be cleared"
				}
				if len(smCtx.UserPlaneInformation.UPNodes) != 0 {
					return false, "expected UPNodes to be cleared"
				}
				return true, ""
			},
		},
		{
			name: "Valid single slice config",
			config: []nfConfigApi.SessionManagement{
				makeSessionConfig("slice1", "111", "01", "1", "1", "internet", "192.168.1.0/24", "upf-1", 38412),
			},
			validate: func(smCtx *SMFContext, err error) (bool, string) {
				if err != nil {
					return false, err.Error()
				}
				if len(smCtx.SnssaiInfos) != 1 {
					return false, fmt.Sprintf("expected 1 SnssaiInfo, got %d", len(smCtx.SnssaiInfos))
				}
				if _, ok := smCtx.UserPlaneInformation.UPNodes["upf-1"]; !ok {
					return false, "expected UPNode for upf-1 to exist"
				}
				return true, ""
			},
		},
		{
			name: "Multiple slice config",
			config: []nfConfigApi.SessionManagement{
				makeSessionConfig("slice1", "111", "01", "1", "1", "internet", "192.168.1.0/24", "upf-1", 38412),
				makeSessionConfig("slice2", "111", "01", "1", "1", "fast", "192.168.2.0/24", "upf-2", 38412),
			},
			validate: func(smCtx *SMFContext, err error) (bool, string) {
				if err != nil {
					return false, err.Error()
				}
				if len(smCtx.SnssaiInfos) != 2 {
					return false, fmt.Sprintf("expected 2 SnssaiInfos, got %d", len(smCtx.SnssaiInfos))
				}
				if _, ok := smCtx.UserPlaneInformation.UPNodes["upf-1"]; !ok {
					return false, "expected UPNode for upf-1"
				}
				if _, ok := smCtx.UserPlaneInformation.UPNodes["upf-2"]; !ok {
					return false, "expected UPNode for upf-2"
				}
				return true, ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			smCtx := &SMFContext{}
			err := UpdateSmfContext(smCtx, tt.config)
			if ok, msg := tt.validate(smCtx, err); !ok {
				t.Errorf("validation failed: %s", msg)
			}
		})
	}
}

func TestUpdateUPFConfiguration(t *testing.T) {
	port := int32(38412)
	upf := nfConfigApi.Upf{
		Hostname: "upf-test",
		Port:     &port,
	}

	tests := []struct {
		name      string
		smfCtx    *SMFContext
		upf       nfConfigApi.Upf
		gnbNames  []string
		existing  map[string]*UPNode
		expectErr bool
		validate  func(t *testing.T, ctx *SMFContext)
	}{
		{
			name:      "missing hostname should return error",
			smfCtx:    &SMFContext{UserPlaneInformation: &UserPlaneInformation{UPNodes: map[string]*UPNode{}}},
			upf:       nfConfigApi.Upf{},
			gnbNames:  nil,
			existing:  map[string]*UPNode{},
			expectErr: true,
			validate: func(t *testing.T, ctx *SMFContext) {
				if len(ctx.UserPlaneInformation.UPNodes) != 0 {
					t.Errorf("expected no UPNodes to be added when hostname is missing, got %d", len(ctx.UserPlaneInformation.UPNodes))
				}
			},
		},
		{
			name:      "valid UPF with gNB links",
			smfCtx:    &SMFContext{UserPlaneInformation: &UserPlaneInformation{UPNodes: map[string]*UPNode{}}},
			upf:       upf,
			gnbNames:  []string{"gnbA", "gnbB"},
			existing:  map[string]*UPNode{},
			expectErr: false,
			validate: func(t *testing.T, ctx *SMFContext) {
				if _, ok := ctx.UserPlaneInformation.UPNodes["upf-test"]; !ok {
					t.Errorf("expected UPNode upf-test to exist")
				}
				if _, ok := ctx.UserPlaneInformation.UPNodes["gnbA"]; !ok {
					t.Errorf("expected AN node gnbA to exist")
				}
				if _, ok := ctx.UserPlaneInformation.UPNodes["gnbB"]; !ok {
					t.Errorf("expected AN node gnbB to exist")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := updateUPFConfiguration(tt.smfCtx, tt.upf, tt.gnbNames, tt.existing)
			if (err != nil) != tt.expectErr {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.validate(t, tt.smfCtx)
		})
	}
}
