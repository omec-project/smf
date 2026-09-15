// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/factory"
	"github.com/prometheus/client_golang/prometheus"
)

// seriesExists reports whether the given Prometheus gauge/counter family currently has a series
// carrying exactly the given labels. Used below to check a series was published, and later that it
// was actually removed rather than left behind under a relabelled identity.
func seriesExists(t *testing.T, family string, labels prometheus.Labels) bool {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != family {
			continue
		}
		for _, m := range mf.GetMetric() {
			got := make(prometheus.Labels, len(m.GetLabel()))
			for _, l := range m.GetLabel() {
				got[l.GetName()] = l.GetValue()
			}
			if len(got) != len(labels) {
				continue
			}
			match := true
			for k, v := range labels {
				if got[k] != v {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// TestChangeStateDeletesTheExactMetricSeriesRecordedOnActivation is a regression test: leaving
// SmStateActive used to re-derive the smf_pdu_session_profile ip/upf/enterprise labels from the
// session's current fields, rather than the ones the series was published under on entry. For a
// locally allocated address those disagree by the time the session leaves Active --
// ReleaseUeIpAddr zeroes PDUAddress.Ip before HandlePDUSessionSMContextRelease calls ChangeState --
// so the delete missed the real series and left it in the registry forever.
func TestChangeStateDeletesTheExactMetricSeriesRecordedOnActivation(t *testing.T) {
	prevConfig := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prevConfig })
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled},
		},
	}

	smContext := NewSMContext("imsi-208930000099999", 5)
	smContext.PDUAddress = &UeIpAddr{Ip: net.ParseIP("10.60.0.7")}
	smContext.Snssai = &models.Snssai{Sst: 1}
	smContext.Tunnel = &UPTunnel{
		DataPathPool: DataPathPool{
			1: &DataPath{
				FirstDPNode: &DataPathNode{
					UPF: &UPF{NodeID: *NewNodeID("10.90.0.1")},
				},
			},
		},
	}

	smContext.ChangeState(SmStateActive)

	activeLabels := prometheus.Labels{
		"id": smContext.Identifier, "ip": "10.60.0.7", "state": SmStateActive.String(),
		"upf": "10.90.0.1", "enterprise": "na",
	}
	if !seriesExists(t, "smf_pdu_session_profile", activeLabels) {
		t.Fatal("ChangeState(SmStateActive) did not publish the session profile series")
	}

	// What HandlePDUSessionSMContextRelease does in production: the UE's address is released --
	// zeroing PDUAddress.Ip -- before the state leaves Active.
	smContext.PDUAddress.Ip = net.IPv4(0, 0, 0, 0)

	smContext.ChangeState(SmStatePfcpRelease)

	if seriesExists(t, "smf_pdu_session_profile", activeLabels) {
		t.Error("leaving Active left the series recorded on entry behind: it is stale forever")
	}
}
