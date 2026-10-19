// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-License-Identifier: Apache-2.0
//

package context

import (
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
)

const (
	testGnb1 = "gnb1"
	testGnb2 = "gnb2"
)

func makeSessionConfig(
	sliceName, mcc, mnc, sst string,
	sd string, dnnName, ueSubnet, hostname string, port int32,
) nfConfigApi.SessionManagement {
	sstUint64, err := strconv.ParseUint(sst, 10, 8)
	if err != nil {
		sstUint64 = 0
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
		GnbNames: []string{testGnb1, testGnb2},
	}
}

func TestUpdateSmfContext(t *testing.T) {
	validSingleSliceConfig := makeSessionConfig("slice1", "222", "02", "2", "1", "internet", "192.168.1.0/24", "upf-1", 38415)

	multiSliceConfig := []nfConfigApi.SessionManagement{
		makeSessionConfig("slice1", "111", "01", "1", "1", "internet", "192.168.1.0/24", "upf-1", 38412),
		makeSessionConfig("slice2", "111", "01", "1", "1", "fast", "192.168.2.0/24", "upf-2", 38412),
	}

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
				if smCtx.UserPlaneInformation != nil && len(smCtx.UserPlaneInformation.UPNodes) != 0 {
					return false, "expected UPNodes to be cleared"
				}
				return true, ""
			},
		},
		{
			name:   "Valid single slice config",
			config: []nfConfigApi.SessionManagement{validSingleSliceConfig},
			validate: func(smCtx *SMFContext, err error) (bool, string) {
				if err != nil {
					return false, err.Error()
				}
				if len(smCtx.SnssaiInfos) != 1 {
					return false, fmt.Sprintf("expected 1 SnssaiInfo, got %d", len(smCtx.SnssaiInfos))
				}
				if smCtx.UserPlaneInformation == nil || smCtx.UserPlaneInformation.DefaultUserPlanePath == nil {
					return false, "UserPlaneInformation or DefaultUserPlanePath is nil"
				}
				if _, ok := smCtx.UserPlaneInformation.UPNodes["upf-1"]; !ok {
					return false, "expected UPNode for upf-1 to exist"
				}
				if _, ok := smCtx.UserPlaneInformation.AccessNetwork[testGnb1]; !ok {
					return false, "expected gnb1 in AccessNetwork"
				}
				if _, ok := smCtx.UserPlaneInformation.AccessNetwork[testGnb2]; !ok {
					return false, "expected gnb2 in AccessNetwork"
				}
				if len(smCtx.UserPlaneInformation.UPFIPToName) == 0 {
					return false, "expected UPFIPToName to be populated"
				}
				return true, ""
			},
		},
		{
			name:   "Multiple slice config",
			config: multiSliceConfig,
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
		{
			name: "Duplicate UPF should merge DNNs",
			config: []nfConfigApi.SessionManagement{
				makeSessionConfig("slice1", "111", "01", "1", "010101", "internet", "192.168.1.0/24", "upf-1", 38412),
				makeSessionConfig("slice1", "112", "01", "1", "010101", "iot", "192.168.2.0/24", "upf-1", 38412),
			},
			validate: func(smCtx *SMFContext, err error) (bool, string) {
				if len(smCtx.UserPlaneInformation.UPFs) != 1 {
					return false, "expected 1 UPF for duplicate hostname"
				}
				if len(smCtx.SnssaiInfos) != 2 {
					return false, "expected 1 SnssaiInfo for same slice"
				}
				return true, ""
			},
		},
		{
			name: "Invalid UPF IP should fallback to FQDN",
			config: []nfConfigApi.SessionManagement{
				makeSessionConfig("slice1", "112", "01", "1", "010101", "internet", "192.168.1.0/24", "bad:ip", 38412),
			},
			validate: func(smCtx *SMFContext, err error) (bool, string) {
				upf := smCtx.UserPlaneInformation.UPFs["bad:ip"]
				if upf == nil {
					return false, "expected UPF to be created with bad IP hostname"
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

func TestRetrieveDnnInformationFallsBackToSstOnlyWhenSdMissing(t *testing.T) {
	originalInfos := smfContext.SnssaiInfos
	t.Cleanup(func() {
		smfContext.SnssaiInfos = originalInfos
	})

	info := &SnssaiSmfDnnInfo{MTU: 1400}
	smfContext.SnssaiInfos = []SnssaiSmfInfo{{
		Snssai:   SNssai{Sst: 1, Sd: "010101"},
		DnnInfos: map[string]*SnssaiSmfDnnInfo{"internet": info},
	}}

	if got := RetrieveDnnInformation(models.Snssai{Sst: 1}, "internet"); got != info {
		t.Fatalf("expected Sst-only fallback to return configured DNN info, got %#v", got)
	}

	var requested models.Snssai
	requested.SetSst(1)
	requested.SetSd("FFFFFF")
	if got := RetrieveDnnInformation(requested, "internet"); got != nil {
		t.Fatalf("expected no fallback when request includes Sd, got %#v", got)
	}
}

// applyToSelfWithin applies cfg to the SMF's own context and fails the test if
// that does not return within the bound. It must be the SMF's own context, not
// a fresh SMFContext: the empty-configuration deadlock is a re-entry of the
// package-level context's lock, which a throwaway context never reaches.
func applyToSelfWithin(t *testing.T, cfg []nfConfigApi.SessionManagement) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- UpdateSmfContext(SMF_Self(), cfg) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("UpdateSmfContext returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("UpdateSmfContext(%d slices) did not return within 3s: the context lock is held by its own caller", len(cfg))
	}
}

// restoreSelfAfter puts back the SMF context fields the configuration tests
// replace, and drops the UPF records they register, so the package-level state
// is left as other tests expect it.
func restoreSelfAfter(t *testing.T) {
	t.Helper()
	snssaiInfos := smfContext.SnssaiInfos
	userPlane := smfContext.UserPlaneInformation
	before := map[any]bool{}
	upfPool.Range(func(key, _ any) bool {
		before[key] = true
		return true
	})
	t.Cleanup(func() {
		smfContext.SnssaiInfos = snssaiInfos
		smfContext.UserPlaneInformation = userPlane
		upfPool.Range(func(key, _ any) bool {
			if !before[key] {
				upfPool.Delete(key)
			}
			return true
		})
	})
}

// upfRecordsFor counts the UPF records registered under nodeID.
func upfRecordsFor(nodeID NodeID) int {
	n := 0
	upfPool.Range(func(_, value any) bool {
		if value.(*UPF).NodeID.Equal(nodeID) {
			n++
		}
		return true
	})
	return n
}

func TestUpdateSmfContextEmptyConfigOnSelfReturns(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config []nfConfigApi.SessionManagement
	}{
		{"nil", nil},
		{"empty", []nfConfigApi.SessionManagement{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restoreSelfAfter(t)
			applyToSelfWithin(t, []nfConfigApi.SessionManagement{
				makeSessionConfig("slice1", "208", "93", "1", "010203", "internet", "192.168.1.0/24", "192.0.2.1", 8805),
			})
			applyToSelfWithin(t, tc.config)

			if len(smfContext.SnssaiInfos) != 0 {
				t.Errorf("expected no S-NSSAI info after an empty config, got %d", len(smfContext.SnssaiInfos))
			}
			if upi := smfContext.UserPlaneInformation; upi != nil && len(upi.UPNodes) != 0 {
				t.Errorf("expected no user plane nodes after an empty config, got %d", len(upi.UPNodes))
			}
		})
	}
}

func TestUpdateSmfContextAppliesConfigAfterEmpty(t *testing.T) {
	restoreSelfAfter(t)

	applyToSelfWithin(t, []nfConfigApi.SessionManagement{
		makeSessionConfig("slice1", "208", "93", "1", "010203", "internet", "192.168.1.0/24", "192.0.2.1", 8805),
	})
	applyToSelfWithin(t, nil)
	applyToSelfWithin(t, []nfConfigApi.SessionManagement{
		makeSessionConfig("slice2", "208", "93", "1", "000005", "internet2", "172.250.0.0/24", "192.0.2.2", 8805),
	})

	if len(smfContext.SnssaiInfos) != 1 || smfContext.SnssaiInfos[0].Snssai.Sd != "000005" {
		t.Fatalf("expected only slice2's S-NSSAI after re-provisioning, got %+v", smfContext.SnssaiInfos)
	}
	upNodes := smfContext.UserPlaneInformation.UPNodes
	if _, ok := upNodes["192.0.2.2"]; !ok {
		t.Errorf("expected the re-provisioned UPF to be configured, got nodes %v", keys(upNodes))
	}
	if _, ok := upNodes["192.0.2.1"]; ok {
		t.Errorf("expected the UPF from before the empty config to be gone, got nodes %v", keys(upNodes))
	}
	snssai := models.Snssai{Sst: 1}
	snssai.SetSd("000005")
	if RetrieveDnnInformation(snssai, "internet2") == nil {
		t.Error("expected DNN internet2 to be configured after re-provisioning")
	}
}

func TestRetrieveDnnInformationAfterEmptyConfigReturnsNil(t *testing.T) {
	restoreSelfAfter(t)

	applyToSelfWithin(t, []nfConfigApi.SessionManagement{
		makeSessionConfig("slice1", "208", "93", "1", "010203", "internet", "192.168.1.0/24", "192.0.2.1", 8805),
	})
	applyToSelfWithin(t, nil)

	snssai := models.Snssai{Sst: 1}
	snssai.SetSd("010203")
	got := make(chan *SnssaiSmfDnnInfo, 1)
	go func() {
		got <- RetrieveDnnInformation(snssai, "internet")
	}()
	select {
	case info := <-got:
		if info != nil {
			t.Fatalf("expected no DNN information with no configuration, got %#v", info)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RetrieveDnnInformation did not return within 3s after an empty config")
	}
}

func TestClearOnSelfReturnsAndClears(t *testing.T) {
	restoreSelfAfter(t)
	applyToSelfWithin(t, []nfConfigApi.SessionManagement{
		makeSessionConfig("slice1", "208", "93", "1", "010203", "internet", "192.168.1.0/24", "192.0.2.15", 8805),
	})

	clearWithin(t, SMF_Self())

	if len(smfContext.SnssaiInfos) != 0 || len(smfContext.UserPlaneInformation.UPNodes) != 0 {
		t.Errorf("expected Clear to discard the configuration, got %d S-NSSAI infos and %d nodes",
			len(smfContext.SnssaiInfos), len(smfContext.UserPlaneInformation.UPNodes))
	}
}

// Clear locks the context it is called on. Holding the SMF's own lock must
// therefore not stop another context from being cleared.
func TestClearLocksItsReceiver(t *testing.T) {
	other := &SMFContext{SnssaiInfos: []SnssaiSmfInfo{{}}}

	SMF_Self().Lock()
	defer SMF_Self().Unlock()
	clearWithin(t, other)

	if len(other.SnssaiInfos) != 0 {
		t.Errorf("expected Clear to discard the receiver's S-NSSAI info, got %d", len(other.SnssaiInfos))
	}
}

func clearWithin(t *testing.T, c *SMFContext) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		c.Clear()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Clear did not return within 3s")
	}
}

// A UPF that leaves the configuration and comes back must be the record the
// rest of the SMF already resolves it to. PFCP responses, heartbeats and session
// reports find a UPF by NodeID in the pool, so a second record for the same
// node lets them update one while the slice uses the other.
func TestReprovisionedUPFIsTheSameRecord(t *testing.T) {
	x := makeSessionConfig("slice1", "208", "93", "1", "010203", "internet", "192.168.1.0/24", "192.0.2.11", 8805)
	y := makeSessionConfig("slice2", "208", "93", "1", "000005", "internet2", "172.250.0.0/24", "192.0.2.12", 8805)

	for _, tc := range []struct {
		name   string
		middle []nfConfigApi.SessionManagement
	}{
		{"after an empty config", nil},
		{"after a config without it", []nfConfigApi.SessionManagement{y}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restoreSelfAfter(t)

			applyToSelfWithin(t, []nfConfigApi.SessionManagement{x, y})
			original := smfContext.UserPlaneInformation.UPNodes["192.0.2.11"].UPF
			original.UPFStatus = AssociatedSetUpSuccess
			// Taken from the record rather than built here: it is whatever the
			// configuration path derives from the hostname.
			xNodeID := original.NodeID

			applyToSelfWithin(t, tc.middle)
			applyToSelfWithin(t, []nfConfigApi.SessionManagement{x, y})

			node, ok := smfContext.UserPlaneInformation.UPNodes["192.0.2.11"]
			if !ok {
				t.Fatal("expected the UPF to be configured again")
			}
			if node.UPF != original {
				t.Error("expected the returning UPF to keep its record, got a new one")
			}
			if n := upfRecordsFor(xNodeID); n != 1 {
				t.Errorf("expected one UPF record for the node, got %d", n)
			}
			if got := RetrieveUPFNodeByNodeID(xNodeID); got != node.UPF {
				t.Error("expected a lookup by NodeID to return the record the slice uses")
			}
			if node.UPF.UPFStatus != AssociatedSetUpSuccess {
				t.Errorf("expected the association to survive, got status %v", node.UPF.UPFStatus)
			}
		})
	}
}

func TestReprovisionedUPFTakesTheNewConfiguration(t *testing.T) {
	restoreSelfAfter(t)

	applyToSelfWithin(t, []nfConfigApi.SessionManagement{
		makeSessionConfig("slice1", "208", "93", "1", "010203", "internet", "192.168.1.0/24", "192.0.2.13", 8805),
	})
	original := smfContext.UserPlaneInformation.UPNodes["192.0.2.13"].UPF
	original.UPFStatus = AssociatedSetUpSuccess

	applyToSelfWithin(t, nil)
	applyToSelfWithin(t, []nfConfigApi.SessionManagement{
		makeSessionConfig("slice3", "208", "93", "1", "000007", "internet3", "10.250.0.0/24", "192.0.2.13", 8806),
	})

	upf := smfContext.UserPlaneInformation.UPNodes["192.0.2.13"].UPF
	if upf != original {
		t.Fatal("expected the returning UPF to keep its record")
	}
	if upf.Port != 8806 {
		t.Errorf("expected the new port 8806, got %d", upf.Port)
	}
	if len(upf.SNssaiInfos) != 1 || upf.SNssaiInfos[0].SNssai.Sd != "000007" {
		t.Errorf("expected only the new slice's S-NSSAI, got %+v", upf.SNssaiInfos)
	}
	if len(upf.N9Interfaces) == 0 || upf.N9Interfaces[0].NetworkInstance != "internet3" {
		t.Errorf("expected the N9 interface for the new DNN, got %+v", upf.N9Interfaces)
	}
}

// The N3 address the UPF reported in its last session establishment is the one
// the RAN was given. A returning UPF keeps it rather than reverting to the
// configured address until the next establishment.
func TestReprovisionedUPFKeepsItsReportedN3Address(t *testing.T) {
	restoreSelfAfter(t)

	applyToSelfWithin(t, []nfConfigApi.SessionManagement{
		makeSessionConfig("slice1", "208", "93", "1", "010203", "internet", "192.168.1.0/24", "192.0.2.14", 8805),
	})
	original := smfContext.UserPlaneInformation.UPNodes["192.0.2.14"].UPF
	original.UPFStatus = AssociatedSetUpSuccess
	reported := net.ParseIP("198.51.100.7").To4()
	original.N3Interfaces = []UPFInterfaceInfo{{IPv4EndPointAddresses: []net.IP{reported}}}

	applyToSelfWithin(t, nil)
	applyToSelfWithin(t, []nfConfigApi.SessionManagement{
		makeSessionConfig("slice1", "208", "93", "1", "010203", "internet", "192.168.1.0/24", "192.0.2.14", 8805),
	})

	upf := smfContext.UserPlaneInformation.UPNodes["192.0.2.14"].UPF
	if upf != original {
		t.Fatal("expected the returning UPF to keep its record")
	}
	if len(upf.N3Interfaces) != 1 || len(upf.N3Interfaces[0].IPv4EndPointAddresses) != 1 ||
		!upf.N3Interfaces[0].IPv4EndPointAddresses[0].Equal(reported) {
		t.Errorf("expected the reported N3 address %s to survive, got %+v", reported, upf.N3Interfaces)
	}
}

// A returning UPF's N3 is the PFCP handlers' to replace, so a configuration update leaves it as it
// is even when it is empty: the adapter empties it before appending the reported address, and a
// configured address installed in between would be the one the RAN is given.
func TestReprovisionedUPFLeavesItsN3ToThePFCPHandlers(t *testing.T) {
	restoreSelfAfter(t)

	applyToSelfWithin(t, []nfConfigApi.SessionManagement{
		makeSessionConfig("slice1", "208", "93", "1", "010203", "internet", "192.168.1.0/24", "192.0.2.15", 8805),
	})
	original := smfContext.UserPlaneInformation.UPNodes["192.0.2.15"].UPF
	original.N3Interfaces = make([]UPFInterfaceInfo, 0)

	applyToSelfWithin(t, nil)
	applyToSelfWithin(t, []nfConfigApi.SessionManagement{
		makeSessionConfig("slice1", "208", "93", "1", "010203", "internet", "192.168.1.0/24", "192.0.2.15", 8805),
	})

	upf := smfContext.UserPlaneInformation.UPNodes["192.0.2.15"].UPF
	if upf != original {
		t.Fatal("expected the returning UPF to keep its record")
	}
	if len(upf.N3Interfaces) != 0 {
		t.Errorf("expected the configuration to leave the N3 alone, got %+v", upf.N3Interfaces)
	}
}

// A returning UPF is in use by its sessions while the configuration rewrites its port and N9, so
// the two must not race. This fails only under -race, which the unit tests run with.
func TestReprovisionedUPFIsRewrittenUnderItsLock(t *testing.T) {
	restoreSelfAfter(t)

	cfg := []nfConfigApi.SessionManagement{
		makeSessionConfig("slice1", "208", "93", "1", "010203", "internet", "192.168.1.0/24", "192.0.2.16", 8805),
	}
	applyToSelfWithin(t, cfg)
	upf := smfContext.UserPlaneInformation.UPNodes["192.0.2.16"].UPF
	applyToSelfWithin(t, nil)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				upf.GetInterface(models.UPINTERFACETYPE_N9, "internet")
				upf.PFCPPort()
			}
		}
	}()
	applyToSelfWithin(t, cfg)
	close(stop)
	<-done

	if got := upf.GetInterface(models.UPINTERFACETYPE_N9, "internet"); got == nil {
		t.Error("expected the returning UPF's N9 interface for its DNN")
	}
}

// NewUPF stores a record in the pool only once it is initialised: the heartbeat loop ranges the
// pool and reads what it finds under UpfLock, which does not order it after writes NewUPF made
// without the lock. This fails only under -race.
func TestAUPFIsInThePoolOnlyOnceInitialised(t *testing.T) {
	restoreSelfAfter(t)
	nodeID := NewNodeID("192.0.2.17")

	found := make(chan struct{})
	go func() {
		defer close(found)
		for {
			for _, upf := range RegisteredUPFs() {
				upf.UpfLock.Lock()
				ours := upf.NodeID.Equal(*nodeID) && upf.UPFStatus == NotAssociated
				upf.UpfLock.Unlock()
				if ours {
					return
				}
			}
		}
	}()
	NewUPF(nodeID, nil)
	select {
	case <-found:
	case <-time.After(3 * time.Second):
		t.Fatal("the new UPF never appeared in the pool")
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
