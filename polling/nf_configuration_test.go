// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0

package polling

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	gojson "github.com/goccy/go-json"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	"github.com/omec-project/openapi/v2/nfconfigpoll"
)

// The polling logic is tested in openapi/nfconfigpoll. These tests check the SMF wiring: endpoint,
// config type, normalisation and the delivery to the two channels.

func makeSessionConfig(sliceName, dnnName string) nfConfigApi.SessionManagement {
	sd := "010203"
	port := int32(8805)
	return nfConfigApi.SessionManagement{
		SliceName: sliceName,
		PlmnId:    nfConfigApi.PlmnId{Mcc: "208", Mnc: "93"},
		Snssai:    nfConfigApi.Snssai{Sst: 1, Sd: &sd},
		IpDomain:  []nfConfigApi.IpDomain{{DnnName: dnnName, DnsIpv4: "8.8.8.8", UeSubnet: "10.0.0.0/24", Mtu: 1400}},
		Upf:       &nfConfigApi.Upf{Hostname: "upf", Port: &port},
		GnbNames:  []string{"gnb1"},
	}
}

// serveConfig serves the config returned by current() as JSON and counts the polls.
func serveConfig(t *testing.T, polls *atomic.Int32, current func() []nfConfigApi.SessionManagement) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pollingPath {
			t.Errorf("polled %s, want %s", r.URL.Path, pollingPath)
		}
		polls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(current()); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runPoller(t *testing.T, url string, registrationChan, contextUpdateChan chan<- []nfConfigApi.SessionManagement) {
	t.Helper()
	poller, err := newPoller(url, registrationChan, contextUpdateChan, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); poller.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func receive(t *testing.T, ch <-chan []nfConfigApi.SessionManagement, what string) []nfConfigApi.SessionManagement {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(2 * time.Second):
		t.Fatalf("no config delivered on %s", what)
		return nil
	}
}

func TestPolling_DeliversPolledConfigToBothChannelsOnce(t *testing.T) {
	var polls atomic.Int32
	want := []nfConfigApi.SessionManagement{makeSessionConfig("slice1", "internet")}
	srv := serveConfig(t, &polls, func() []nfConfigApi.SessionManagement { return want })
	registrationChan := make(chan []nfConfigApi.SessionManagement, 4)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 4)
	runPoller(t, srv.URL, registrationChan, contextUpdateChan)

	for name, ch := range map[string]chan []nfConfigApi.SessionManagement{"registrationChan": registrationChan, "contextUpdateChan": contextUpdateChan} {
		got := receive(t, ch, name)
		if len(got) != 1 || got[0].SliceName != "slice1" || got[0].IpDomain[0].DnnName != "internet" {
			t.Errorf("%s: got %+v", name, got)
		}
	}
	// the config built in Go (nil AdditionalProperties) and the one polled are the same config after
	// normalisation, and an unchanged config is not delivered again
	waitUntil(t, func() bool { return polls.Load() >= 4 }, "the poller did not make 4 requests")
	select {
	case got := <-registrationChan:
		t.Errorf("unchanged config delivered again on registrationChan: %+v", got)
	case got := <-contextUpdateChan:
		t.Errorf("unchanged config delivered again on contextUpdateChan: %+v", got)
	default:
	}
}

func TestPolling_EmptyInitialConfigIsNotDelivered(t *testing.T) {
	var polls atomic.Int32
	srv := serveConfig(t, &polls, func() []nfConfigApi.SessionManagement { return []nfConfigApi.SessionManagement{} })
	registrationChan := make(chan []nfConfigApi.SessionManagement, 4)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 4)
	runPoller(t, srv.URL, registrationChan, contextUpdateChan)

	deadline := time.Now().Add(2 * time.Second)
	for polls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := polls.Load(); got < 3 {
		t.Fatalf("the poller made %d requests, want at least 3: the empty first config was never put to the test", got)
	}
	select {
	case got := <-registrationChan:
		t.Errorf("empty config delivered on registrationChan: %+v", got)
	case got := <-contextUpdateChan:
		t.Errorf("empty config delivered on contextUpdateChan: %+v", got)
	default:
	}
}

func TestPolling_DeliversChangedConfig(t *testing.T) {
	var polls atomic.Int32
	var current atomic.Value
	current.Store([]nfConfigApi.SessionManagement{makeSessionConfig("slice1", "internet")})
	srv := serveConfig(t, &polls, func() []nfConfigApi.SessionManagement { return current.Load().([]nfConfigApi.SessionManagement) })
	registrationChan := make(chan []nfConfigApi.SessionManagement, 4)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 4)
	runPoller(t, srv.URL, registrationChan, contextUpdateChan)

	receive(t, registrationChan, "registrationChan")
	receive(t, contextUpdateChan, "contextUpdateChan")

	current.Store([]nfConfigApi.SessionManagement{makeSessionConfig("slice2", "fast")})
	for name, ch := range map[string]chan []nfConfigApi.SessionManagement{"registrationChan": registrationChan, "contextUpdateChan": contextUpdateChan} {
		got := receive(t, ch, name)
		if len(got) != 1 || got[0].SliceName != "slice2" {
			t.Errorf("%s: got %+v", name, got)
		}
	}
}

// A full channel must not make the poller lose the config: it is offered again on the next poll,
// and the channel that already accepted it does not get it a second time.
func TestPolling_FullChannelIsRetriedWithoutResendingToTheOtherChannel(t *testing.T) {
	var polls atomic.Int32
	srv := serveConfig(t, &polls, func() []nfConfigApi.SessionManagement {
		return []nfConfigApi.SessionManagement{makeSessionConfig("slice1", "internet")}
	})
	registrationChan := make(chan []nfConfigApi.SessionManagement, 4)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 1)
	contextUpdateChan <- nil // full: the first deliveries to contextUpdateChan must fail
	runPoller(t, srv.URL, registrationChan, contextUpdateChan)

	receive(t, registrationChan, "registrationChan")
	// several polls pass while contextUpdateChan is full
	waitUntil(t, func() bool { return polls.Load() >= 5 }, "the poller did not make 5 requests")
	if got := receive(t, contextUpdateChan, "stale item"); got != nil {
		t.Fatalf("unexpected item %+v", got)
	}
	got := receive(t, contextUpdateChan, "contextUpdateChan after it was drained")
	if len(got) != 1 || got[0].SliceName != "slice1" {
		t.Errorf("contextUpdateChan: got %+v", got)
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case extra := <-registrationChan:
		t.Errorf("registrationChan received the config again on retry: %+v", extra)
	case extra := <-contextUpdateChan:
		t.Errorf("contextUpdateChan received the config twice: %+v", extra)
	default:
	}
}

// A newer config supersedes a partially delivered one: both channels get the newer config.
func TestConfigDelivery_NewerConfigSupersedesPartiallyDeliveredOne(t *testing.T) {
	registrationChan := make(chan []nfConfigApi.SessionManagement, 4)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 1)
	contextUpdateChan <- nil
	d := &configDelivery{registrationChan: registrationChan, contextUpdateChan: contextUpdateChan}
	first := []nfConfigApi.SessionManagement{makeSessionConfig("slice1", "internet")}
	second := []nfConfigApi.SessionManagement{makeSessionConfig("slice2", "fast")}

	if err := d.deliver(first); err == nil {
		t.Fatal("expected an error while contextUpdateChan is full")
	}
	<-contextUpdateChan
	if err := d.deliver(second); err != nil {
		t.Fatalf("deliver(second) = %v", err)
	}
	if got := <-registrationChan; !reflect.DeepEqual(got, first) {
		t.Errorf("registrationChan first item = %+v, want the first config", got)
	}
	if got := <-registrationChan; !reflect.DeepEqual(got, second) {
		t.Errorf("registrationChan second item = %+v, want the second config", got)
	}
	if got := <-contextUpdateChan; !reflect.DeepEqual(got, second) {
		t.Errorf("contextUpdateChan item = %+v, want the second config", got)
	}
}

// The normalisation by nfconfigpoll.JSONRoundTrip must be equivalent to the goccy round trip it
// replaced, including the AdditionalProperties defaulting and optional fields.
func TestNormalize_JSONRoundTripMatchesPreviousGoccyRoundTrip(t *testing.T) {
	pcscf := "10.0.0.9"
	cfg := makeSessionConfig("slice1", "internet")
	cfg.IpDomain[0].PcscfIpv4 = &pcscf
	cfg.AdditionalProperties = map[string]interface{}{"extra": "value"}
	noUpf := makeSessionConfig("slice2", "ims")
	noUpf.Upf = nil
	noUpf.Snssai.Sd = nil
	input := []nfConfigApi.SessionManagement{cfg, noUpf}

	got, err := nfconfigpoll.JSONRoundTrip(input)
	if err != nil {
		t.Fatal(err)
	}
	data, err := gojson.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var want []nfConfigApi.SessionManagement
	if err = gojson.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("JSONRoundTrip = %+v, goccy round trip = %+v", got, want)
	}
	again, err := nfconfigpoll.JSONRoundTrip(got)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, got) {
		t.Errorf("JSONRoundTrip is not idempotent: %+v vs %+v", again, got)
	}
}

// waitUntil fails the test if cond does not become true within a few seconds, instead of waiting for the
// test binary's timeout.
func waitUntil(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}
