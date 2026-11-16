// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0

package nfregistration

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	"github.com/omec-project/smf/consumer"
)

// The registration logic is tested in openapi/nrfregistration. These tests check that the SMF wiring
// reaches the right consumer functions and the SMF-specific change detection.

const (
	dnnInternet = "internet"
	dnnIms      = "ims"
)

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

func makeSessionConfig(mcc, mnc string, sst int32, sd string, dnns []string, port int32) nfConfigApi.SessionManagement {
	ipDomain := []nfConfigApi.IpDomain{}
	for _, dnn := range dnns {
		ipDomain = append(ipDomain, nfConfigApi.IpDomain{DnnName: dnn, DnsIpv4: "8.8.8.8", UeSubnet: "10.0.0.0/24", Mtu: 1400})
	}
	return nfConfigApi.SessionManagement{
		SliceName: "slice",
		PlmnId:    nfConfigApi.PlmnId{Mcc: mcc, Mnc: mnc},
		Snssai:    nfConfigApi.Snssai{Sst: sst, Sd: &sd},
		IpDomain:  ipDomain,
		Upf:       &nfConfigApi.Upf{Hostname: "upf", Port: &port},
		GnbNames:  []string{"gnb1"},
	}
}

func startService(t *testing.T) chan<- []nfConfigApi.SessionManagement {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ch := make(chan []nfConfigApi.SessionManagement)
	go func() { defer close(done); StartNfRegistrationService(ctx, ch) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ch
}

func TestStartNfRegistrationService_NonEmptyConfigRegistersThenEmptyConfigDeregisters(t *testing.T) {
	origRegister, origDeregister := consumer.SendRegisterNFInstance, consumer.SendDeregisterNFInstance
	t.Cleanup(func() {
		consumer.SendRegisterNFInstance, consumer.SendDeregisterNFInstance = origRegister, origDeregister
	})
	var registeredWith atomic.Value
	var deregistered atomic.Int32
	consumer.SendRegisterNFInstance = func(_ context.Context, cfg []nfConfigApi.SessionManagement) (*models.NFProfile, string, error) {
		registeredWith.Store(cfg)
		return models.NewNFProfileWithDefaults(), "", nil
	}
	consumer.SendDeregisterNFInstance = func(context.Context) error {
		deregistered.Add(1)
		return nil
	}
	ch := startService(t)

	ch <- []nfConfigApi.SessionManagement{makeSessionConfig("001", "01", 1, "010203", []string{dnnInternet}, 8805)}
	waitFor(t, func() bool { return registeredWith.Load() != nil }, "SendRegisterNFInstance was not called")
	if got := registeredWith.Load().([]nfConfigApi.SessionManagement); len(got) != 1 || got[0].PlmnId.Mcc != "001" {
		t.Errorf("registered with %+v", got)
	}

	ch <- nil
	waitFor(t, func() bool { return deregistered.Load() == 1 }, "SendDeregisterNFInstance was not called for an empty config")
}

func TestDeregisterNF_CallsConsumer(t *testing.T) {
	orig := consumer.SendDeregisterNFInstance
	t.Cleanup(func() { consumer.SendDeregisterNFInstance = orig })
	var called atomic.Int32
	consumer.SendDeregisterNFInstance = func(context.Context) error { called.Add(1); return nil }

	DeregisterNF()
	if called.Load() != 1 {
		t.Errorf("SendDeregisterNFInstance calls = %d, want 1", called.Load())
	}
}

func TestHeartbeatUsesSendUpdateNFInstance(t *testing.T) {
	origRegister, origUpdate := consumer.SendRegisterNFInstance, consumer.SendUpdateNFInstance
	t.Cleanup(func() { consumer.SendRegisterNFInstance, consumer.SendUpdateNFInstance = origRegister, origUpdate })
	var updated atomic.Int32
	profile := models.NewNFProfileWithDefaults()
	profile.SetHeartBeatTimer(1)
	consumer.SendRegisterNFInstance = func(context.Context, []nfConfigApi.SessionManagement) (*models.NFProfile, string, error) {
		return profile, "", nil
	}
	consumer.SendUpdateNFInstance = func(context.Context, []models.PatchItem) (*models.NFProfile, *models.ProblemDetails, error) {
		updated.Add(1)
		return profile, nil, nil
	}
	ch := startService(t)

	ch <- []nfConfigApi.SessionManagement{makeSessionConfig("001", "01", 1, "010203", []string{dnnInternet}, 8805)}
	waitFor(t, func() bool { return updated.Load() >= 1 }, "heartbeat did not call SendUpdateNFInstance")
}

// A config that changes only what is not part of the NF profile (here the UPF port) must not
// trigger a new registration, while a PLMN change must.
func TestStartNfRegistrationService_ReRegistersOnlyWhenProfileRelevantConfigChanges(t *testing.T) {
	origRegister := consumer.SendRegisterNFInstance
	t.Cleanup(func() { consumer.SendRegisterNFInstance = origRegister })
	var registrations atomic.Int32
	consumer.SendRegisterNFInstance = func(context.Context, []nfConfigApi.SessionManagement) (*models.NFProfile, string, error) {
		registrations.Add(1)
		return models.NewNFProfileWithDefaults(), "", nil
	}
	ch := startService(t)

	ch <- []nfConfigApi.SessionManagement{makeSessionConfig("001", "01", 1, "000001", []string{dnnInternet}, 8805)}
	waitFor(t, func() bool { return registrations.Load() == 1 }, "expected the first registration")

	ch <- []nfConfigApi.SessionManagement{makeSessionConfig("001", "09", 1, "000001", []string{dnnInternet}, 8805)}
	waitFor(t, func() bool { return registrations.Load() == 2 }, "expected a registration after the PLMN changed")

	ch <- []nfConfigApi.SessionManagement{makeSessionConfig("001", "09", 1, "000001", []string{dnnInternet}, 9905)}
	time.Sleep(100 * time.Millisecond)
	if got := registrations.Load(); got != 2 {
		t.Errorf("registrations = %d, want 2: a UPF port change does not affect the NF profile", got)
	}
}

func TestIsRegistrationRequired(t *testing.T) {
	base := makeSessionConfig("001", "01", 1, "000001", []string{dnnInternet, dnnIms}, 8805)
	tests := []struct {
		name     string
		newCfg   []nfConfigApi.SessionManagement
		oldCfg   []nfConfigApi.SessionManagement
		expected bool
	}{
		{"identical", []nfConfigApi.SessionManagement{base}, []nfConfigApi.SessionManagement{base}, false},
		{"length differs", []nfConfigApi.SessionManagement{base, base}, []nfConfigApi.SessionManagement{base}, true},
		{"mcc differs", []nfConfigApi.SessionManagement{makeSessionConfig("002", "01", 1, "000001", []string{dnnInternet, dnnIms}, 8805)}, []nfConfigApi.SessionManagement{base}, true},
		{"mnc differs", []nfConfigApi.SessionManagement{makeSessionConfig("001", "02", 1, "000001", []string{dnnInternet, dnnIms}, 8805)}, []nfConfigApi.SessionManagement{base}, true},
		{"sst differs", []nfConfigApi.SessionManagement{makeSessionConfig("001", "01", 2, "000001", []string{dnnInternet, dnnIms}, 8805)}, []nfConfigApi.SessionManagement{base}, true},
		{"sd differs", []nfConfigApi.SessionManagement{makeSessionConfig("001", "01", 1, "000002", []string{dnnInternet, dnnIms}, 8805)}, []nfConfigApi.SessionManagement{base}, true},
		{"dnn removed", []nfConfigApi.SessionManagement{makeSessionConfig("001", "01", 1, "000001", []string{dnnInternet}, 8805)}, []nfConfigApi.SessionManagement{base}, true},
		{"dnn added", []nfConfigApi.SessionManagement{base}, []nfConfigApi.SessionManagement{makeSessionConfig("001", "01", 1, "000001", []string{dnnInternet}, 8805)}, true},
		{"dnn replaced", []nfConfigApi.SessionManagement{makeSessionConfig("001", "01", 1, "000001", []string{dnnInternet, "mms"}, 8805)}, []nfConfigApi.SessionManagement{base}, true},
		{"dnn order differs", []nfConfigApi.SessionManagement{makeSessionConfig("001", "01", 1, "000001", []string{dnnIms, dnnInternet}, 8805)}, []nfConfigApi.SessionManagement{base}, false},
		{"upf port differs", []nfConfigApi.SessionManagement{makeSessionConfig("001", "01", 1, "000001", []string{dnnInternet, dnnIms}, 9905)}, []nfConfigApi.SessionManagement{base}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRegistrationRequired(tc.newCfg, tc.oldCfg); got != tc.expected {
				t.Errorf("IsRegistrationRequired = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestDeepCopySessionManagement_IsIndependentCopy(t *testing.T) {
	orig := []nfConfigApi.SessionManagement{makeSessionConfig("001", "01", 1, "000001", []string{dnnInternet}, 8805)}
	cloned, err := deepCopySessionManagement(orig)
	if err != nil {
		t.Fatal(err)
	}
	// the clone is JSON-normalised (e.g. nil AdditionalProperties become empty maps), so compare fields
	if len(cloned) != 1 || cloned[0].PlmnId.Mcc != "001" || cloned[0].Snssai.GetSd() != "000001" ||
		cloned[0].IpDomain[0].DnnName != dnnInternet || cloned[0].Upf.GetPort() != 8805 {
		t.Fatalf("clone %+v differs from %+v", cloned, orig)
	}
	orig[0].PlmnId.Mcc = "999"
	orig[0].IpDomain[0].DnnName = "changed"
	if cloned[0].PlmnId.Mcc != "001" || cloned[0].IpDomain[0].DnnName != dnnInternet {
		t.Errorf("clone was affected by mutation of the original: %+v", cloned)
	}
}
