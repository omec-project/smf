// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func labelsOf(t *testing.T, c prometheus.Collector) map[string]bool {
	t.Helper()
	ch := make(chan prometheus.Metric, 16)
	c.Collect(ch)
	close(ch)
	seen := map[string]bool{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("writing metric: %v", err)
		}
		for _, l := range pb.GetLabel() {
			seen[l.GetName()] = true
		}
	}
	return seen
}

// A metrics endpoint is readable by anything that can reach the pod. A per-session label would put
// a subscriber identity there, which is the one thing these counters must not carry.
func TestRestorationMetricsCarryNoSubscriberIdentity(t *testing.T) {
	smfStats = initSmfStats()
	AddUpfRestorationStats("smf-1", "10.0.0.1", "restored", 3)
	SetUpfUnrestoredSessions("smf-1", "10.0.0.1", 2)

	forbidden := []string{"supi", "imsi", "pei", "gpsi", "msisdn", "ue", "session_id", "seid", "ip"}
	for _, c := range []prometheus.Collector{smfStats.upfRestoration, smfStats.upfUnrestored} {
		for label := range labelsOf(t, c) {
			for _, bad := range forbidden {
				if strings.Contains(strings.ToLower(label), bad) {
					t.Errorf("label %q looks like a subscriber identifier", label)
				}
			}
		}
	}
}

// A restoration that restored some sessions and released the rest must not be readable as one that
// simply completed. That conflation is the failure this change exists to remove.
func TestAPartialRestorationIsDistinguishableFromAFullOne(t *testing.T) {
	smfStats = initSmfStats()

	AddUpfRestorationStats("smf-1", "10.0.0.7", "restored", 5)
	SetUpfUnrestoredSessions("smf-1", "10.0.0.7", 0)
	full := gaugeValue(t, smfStats.upfUnrestored, "smf-1", "10.0.0.7")

	AddUpfRestorationStats("smf-1", "10.0.0.8", "restored", 3)
	AddUpfRestorationStats("smf-1", "10.0.0.8", "released", 2)
	SetUpfUnrestoredSessions("smf-1", "10.0.0.8", 2)
	partial := gaugeValue(t, smfStats.upfUnrestored, "smf-1", "10.0.0.8")

	if full != 0 {
		t.Errorf("a UPF whose sessions all came back reports %v outstanding, want 0", full)
	}
	if partial == full {
		t.Errorf("a UPF with sessions left behind is indistinguishable from a fully recovered one "+
			"(%v vs %v); an operator would read a partially dead UPF as healthy", partial, full)
	}
}

func gaugeValue(t *testing.T, g *prometheus.GaugeVec, labels ...string) float64 {
	t.Helper()
	var pb dto.Metric
	if err := g.WithLabelValues(labels...).Write(&pb); err != nil {
		t.Fatalf("reading gauge: %v", err)
	}
	return pb.GetGauge().GetValue()
}
