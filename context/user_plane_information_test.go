package context

import (
	"strconv"
	"testing"

	"github.com/omec-project/openapi/nfConfigApi"
)

func makeTestSessionConfig(sliceName, mcc, mnc, sst, sd, dnn, ueSubnet, upfName string, gnbNames []string) nfConfigApi.SessionManagement {
	sstParsed, err := strconv.ParseInt(sst, 10, 32)
	if err != nil {
		sstParsed = 1
	}
	sstUint := int32(sstParsed)
	return nfConfigApi.SessionManagement{
		SliceName: sliceName,
		PlmnId:    nfConfigApi.PlmnId{Mcc: mcc, Mnc: mnc},
		Snssai:    nfConfigApi.Snssai{Sst: sstUint, Sd: &sd},
		IpDomain: []nfConfigApi.IpDomain{
			{
				DnnName:  dnn,
				DnsIpv4:  "8.8.8.8",
				UeSubnet: ueSubnet,
				Mtu:      1400,
			},
		},
		Upf: &nfConfigApi.Upf{
			Hostname: upfName,
			Port:     func() *int32 { p := int32(8805); return &p }(),
		},
		GnbNames: gnbNames,
	}
}

func TestBuildUserPlaneInformation_DefaultPathScenarios(t *testing.T) {
	tests := []struct {
		name       string
		existing   *UserPlaneInformation
		config     []nfConfigApi.SessionManagement
		assertions func(t *testing.T, upi *UserPlaneInformation)
	}{
		{
			name:     "Single slice basic default path",
			existing: nil,
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "001", "02", "1", "010101", "internet", "10.0.0.0/24", "10.1.1.1", []string{"gnb1"}),
			},
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				if len(upi.DefaultUserPlanePath) == 0 {
					t.Error("expected default user plane path to be set")
				}
			},
		},
		{
			name:     "No AN nodes in config",
			existing: nil,
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "002", "01", "2", "010101", "internet", "10.0.0.0/24", "10.1.1.1", []string{}),
			},
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				if len(upi.AccessNetwork) != 0 {
					t.Error("expected no AN nodes")
				}
			},
		},
		{
			name:     "Multiple slices with overlapping gNBs",
			existing: nil,
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "001", "01", "1", "010101", "internet", "10.0.0.0/24", "10.1.1.1", []string{"gnb1", "gnb2"}),
				makeTestSessionConfig("slice2", "001", "01", "1", "010102", "iot", "10.0.1.0/24", "10.1.1.2", []string{"gnb1"}),
			},
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				if _, ok := upi.AccessNetwork["gnb1"]; !ok {
					t.Error("expected gnb1 to be in AccessNetwork")
				}
				if len(upi.UPFs) != 2 {
					t.Errorf("expected 2 UPFs, got %d", len(upi.UPFs))
				}
			},
		},
		{
			name:     "DNNs are merged into the same SNSSAI entry",
			existing: nil,
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "001", "01", "1", "010101", "internet", "10.0.0.0/24", "10.1.1.1", []string{"gnb1"}),
				makeTestSessionConfig("slice1", "001", "01", "1", "010101", "iot", "10.0.2.0/24", "10.1.1.1", []string{"gnb2"}),
			},
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				if len(upi.UPFs) != 1 {
					t.Errorf("expected 1 UPF, got %d", len(upi.UPFs))
				}
				if len(upi.UPFs["10.1.1.1"].UPF.SNssaiInfos[0].DnnList) != 2 {
					t.Errorf("expected 2 DNN entries for merged SNSSAI")
				}
			},
		},
		{
			name:     "Invalid UPF hostname",
			existing: nil,
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "001", "01", "1", "010101", "internet", "10.0.0.0/24", "invalid_host*name", []string{"gnb1"}),
			},
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				upf := upi.UPFs["invalid_host*name"]
				if upf == nil || upf.NodeID.NodeIdType != NodeIdTypeFqdn {
					t.Error("expected UPF NodeIdType to be FQDN for invalid hostname")
				}
			},
		},
		{
			name: "Reusing existing UserPlaneInformation",
			existing: BuildUserPlaneInformationFromSessionManagement(nil, []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice1", "001", "01", "1", "010101", "internet", "10.0.0.0/24", "10.1.1.1", []string{"gnb1"}),
			}),
			config: []nfConfigApi.SessionManagement{
				makeTestSessionConfig("slice2", "001", "01", "1", "010102", "iot", "10.0.1.0/24", "10.1.1.2", []string{"gnb2"}),
			},
			assertions: func(t *testing.T, upi *UserPlaneInformation) {
				if len(upi.UPFs) != 2 {
					t.Errorf("expected 2 UPFs, got %d", len(upi.UPFs))
				}
				if _, ok := upi.UPFs["10.1.1.1"]; !ok {
					t.Error("original UPF should still exist")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upi := BuildUserPlaneInformationFromSessionManagement(tt.existing, tt.config)
			tt.assertions(t, upi)
		})
	}
}
