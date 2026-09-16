// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/factory"
	mi "github.com/omec-project/util/metricinfo"
	"github.com/prometheus/client_golang/prometheus"
)

// capturePublishedEvents redirects the publishPduSessEvent seam to record every Kafka event
// published during the test instead of sending it to a real broker, and enables Kafka (the
// early-return in PublishSmCtxtInfo would otherwise make it a no-op). It also restores both
// on cleanup.
func capturePublishedEvents(t *testing.T) *[]mi.CoreSubscriberData {
	t.Helper()
	prevConfig := factory.SmfConfig
	prevPublish := publishPduSessEvent
	t.Cleanup(func() {
		factory.SmfConfig = prevConfig
		publishPduSessEvent = prevPublish
	})

	enabled := true
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &enabled},
		},
	}

	events := make([]mi.CoreSubscriberData, 0)
	publishPduSessEvent = func(ctxt mi.CoreSubscriber, op mi.SubscriberOp) error {
		events = append(events, mi.CoreSubscriberData{Subscriber: ctxt, Operation: op})
		return nil
	}
	return &events
}

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
				IsDefaultPath: true,
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

// TestGetSmCtxtUpfNoDefaultPath is a regression test: a tunnel can exist with no default data
// path yet (e.g. PDUSessionSMContextCreate creates the tunnel before a path is ever added, then
// bails out to SmStateInit when no UPF path is found), and this used to panic on the assumption
// that DataPathPool key 1 was always populated with a data path.
func TestGetSmCtxtUpfNoDefaultPath(t *testing.T) {
	smContext := NewSMContext("imsi-208930000099998", 5)
	smContext.Tunnel = NewUPTunnel()

	name, ip := smContext.getSmCtxtUpf()
	if name != "" || ip != "" {
		t.Errorf("expected empty UPF name/ip with no default path, got name=%q ip=%q", name, ip)
	}
}

// TestGetSmCtxtUpfSurvivesLeavingActive is a regression test for the Kafka disconnect-event
// path: getSmCtxtUpf must still report the UPF the session was using after ChangeState has
// already moved SMContextState off SmStateActive (e.g. on release), since it now reads the
// tunnel/data-path directly instead of gating on SMContextState == SmStateActive.
func TestGetSmCtxtUpfSurvivesLeavingActive(t *testing.T) {
	prevConfig := factory.SmfConfig
	t.Cleanup(func() { factory.SmfConfig = prevConfig })
	disabled := false
	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled},
		},
	}

	smContext := NewSMContext("imsi-208930000099997", 5)
	smContext.Tunnel = &UPTunnel{
		DataPathPool: DataPathPool{
			1: &DataPath{
				IsDefaultPath: true,
				FirstDPNode: &DataPathNode{
					UPF: &UPF{NodeID: *NewNodeID("10.90.0.2")},
				},
			},
		},
	}

	smContext.SMContextState = SmStateActive
	smContext.ChangeState(SmStatePfcpRelease)

	name, ip := smContext.getSmCtxtUpf()
	if name != "10.90.0.2" || ip != "10.90.0.2" {
		t.Errorf("expected UPF 10.90.0.2 to still be reported after leaving Active, got name=%q ip=%q", name, ip)
	}
}

// TestGetSmCtxtUpfSurvivesTunnelClearedByRelease is a regression test: releaseTunnel sets
// smContext.Tunnel = nil before RemoveSMContext enters SmStateRelease and publishes the terminal
// disconnect event, so getSmCtxtUpf must fall back to the last UPF it resolved rather than
// reporting an empty one for that final event.
func TestGetSmCtxtUpfSurvivesTunnelClearedByRelease(t *testing.T) {
	const upfIP = "10.90.0.3"
	smContext := NewSMContext("imsi-208930000099992", 5)
	smContext.Tunnel = &UPTunnel{
		DataPathPool: DataPathPool{
			1: &DataPath{
				IsDefaultPath: true,
				FirstDPNode: &DataPathNode{
					UPF: &UPF{NodeID: *NewNodeID(upfIP)},
				},
			},
		},
	}

	// Resolve once while the tunnel is still present, as ChangeState(SmStatePfcpRelease) does.
	if name, ip := smContext.getSmCtxtUpf(); name != upfIP || ip != upfIP {
		t.Fatalf("expected UPF %s while the tunnel is present, got name=%q ip=%q", upfIP, name, ip)
	}

	smContext.Tunnel = nil // what releaseTunnel does before RemoveSMContext runs

	name, ip := smContext.getSmCtxtUpf()
	if name != upfIP || ip != upfIP {
		t.Errorf("expected UPF %s to survive the tunnel being cleared, got name=%q ip=%q", upfIP, name, ip)
	}
}

// TestGetSmCtxtUpfKeepsSnapshotOnTransientCacheMiss is a regression test: a transient FQDN DNS
// cache miss - even with the tunnel still present, as happens when RemoveSMContext runs before
// releaseTunnel - must fall back to the last-known-good UPF snapshot rather than reporting no UPF
// for that event, and must not blank the snapshot out for whatever call comes after it.
func TestGetSmCtxtUpfKeepsSnapshotOnTransientCacheMiss(t *testing.T) {
	const (
		cachedHostName = "upf-a"
		cachedHost     = cachedHostName + ".example.com"
		cachedIP       = "10.90.0.4"
		uncachedHost   = "upf-b.example.com"
	)
	InsertDnsHostIp(cachedHost, net.ParseIP(cachedIP))

	smContext := NewSMContext("imsi-208930000099991", 5)
	dataPath := &DataPath{
		IsDefaultPath: true,
		FirstDPNode: &DataPathNode{
			UPF: &UPF{NodeID: *NewNodeID(cachedHost)},
		},
	}
	smContext.Tunnel = &UPTunnel{DataPathPool: DataPathPool{1: dataPath}}

	if name, ip := smContext.getSmCtxtUpf(); name != cachedHostName || ip != cachedIP {
		t.Fatalf("expected the cached UPF, got name=%q ip=%q", name, ip)
	}

	// Same tunnel, now pointing at an FQDN that was never resolved into the cache: the miss must
	// fall back to the snapshot immediately, not just once the tunnel is later cleared.
	dataPath.FirstDPNode.UPF = &UPF{NodeID: *NewNodeID(uncachedHost)}
	if name, ip := smContext.getSmCtxtUpf(); name != cachedHostName || ip != cachedIP {
		t.Fatalf("expected the miss to fall back to the cached UPF, got name=%q ip=%q", name, ip)
	}

	smContext.Tunnel = nil // what releaseTunnel does before RemoveSMContext runs

	name, ip := smContext.getSmCtxtUpf()
	if name != cachedHostName || ip != cachedIP {
		t.Errorf("expected the snapshot to still be the last cached UPF (%s/%s), got name=%q ip=%q", cachedHostName, cachedIP, name, ip)
	}
}

// TestChangeStatePublishesReleaseAsDisconnectedDel is a regression test for the Kafka payload
// itself: it captures the event ChangeState publishes and asserts a release transition reports
// nextState (SmStateRelease -> Disconnected/Del), not the state being left. A regression that
// left PublishSmCtxtInfo before the state assignment would still pass the Prometheus-only tests
// above but would fail this one.
func TestChangeStatePublishesReleaseAsDisconnectedDel(t *testing.T) {
	events := capturePublishedEvents(t)

	smContext := NewSMContext("imsi-208930000099996", 5)
	smContext.Snssai = &models.Snssai{Sst: 1}
	smContext.SMContextState = SmStateActive

	smContext.ChangeState(SmStateRelease)

	if len(*events) != 1 {
		t.Fatalf("expected exactly 1 published event, got %d", len(*events))
	}
	got := (*events)[0]
	if got.Subscriber.SmfSubState != DISCONNECTED {
		t.Errorf("expected SmfSubState %q, got %q", DISCONNECTED, got.Subscriber.SmfSubState)
	}
	if got.Operation != mi.SubsOpDel {
		t.Errorf("expected op %v, got %v", mi.SubsOpDel, got.Operation)
	}
}

// TestChangeStateSkipsDuplicateNoOpTransition is a regression test: calling ChangeState again
// with the state the session is already in (as the release handlers do, e.g. calling
// ChangeState(SmStatePfcpRelease) more than once around the PFCP round trip) must not publish a
// second identical Kafka event.
func TestChangeStateSkipsDuplicateNoOpTransition(t *testing.T) {
	events := capturePublishedEvents(t)

	smContext := NewSMContext("imsi-208930000099995", 5)
	smContext.Snssai = &models.Snssai{Sst: 1}
	smContext.SMContextState = SmStateActive

	smContext.ChangeState(SmStatePfcpRelease)
	smContext.ChangeState(SmStatePfcpRelease) // no-op: already in this state

	if len(*events) != 1 {
		t.Fatalf("expected exactly 1 published event for a repeated no-op transition, got %d", len(*events))
	}
}

// TestMapPduSessStateToMetricStateAndOpInitialCreateIsAdd is a regression test: SmStatePfcpCreatePending
// is only ever entered from SmStateInit (the initial PDU session establishment), so it must report
// SubsOpAdd. Reporting SubsOpMod here would tell a downstream consumer that a session it never saw
// created is being updated.
func TestMapPduSessStateToMetricStateAndOpInitialCreateIsAdd(t *testing.T) {
	state, op := mapPduSessStateToMetricStateAndOp(SmStatePfcpCreatePending)
	if state != IDLE || op != mi.SubsOpAdd {
		t.Errorf("expected (%q, %v), got (%q, %v)", IDLE, mi.SubsOpAdd, state, op)
	}
}

// TestMapPduSessStateToMetricStateAndOpRollbackToInitIsMod is a regression test: SmStateInit is
// never the terminal transition (RemoveSMContext/SmStateRelease is), and every path that reaches
// it - a rolled-back create, the UE-driven release complete, the duplicate-PDU-ID replacement -
// calls RemoveSMContext right after. Reporting SubsOpDel here as well as on the SmStateRelease
// transition that follows would double the delete for one teardown.
func TestMapPduSessStateToMetricStateAndOpRollbackToInitIsMod(t *testing.T) {
	state, op := mapPduSessStateToMetricStateAndOp(SmStateInit)
	if state != IDLE || op != mi.SubsOpMod {
		t.Errorf("expected (%q, %v), got (%q, %v)", IDLE, mi.SubsOpMod, state, op)
	}
}

// TestChangeStateReleaseSequencePublishesExactlyOneDel is a regression test for the normal
// release flow: HandlePDUSessionSMContextRelease transitions Active -> SmStatePfcpRelease, then
// RemoveSMContext transitions SmStatePfcpRelease -> SmStateRelease. Both used to map to
// Disconnected/Del, so downstream consumers received two deletes for one release. Only the final,
// actually-terminal transition (SmStateRelease, which coincides with the pool removal) may publish
// the Del; entering SmStatePfcpRelease is just the start of teardown and can still roll back.
func TestChangeStateReleaseSequencePublishesExactlyOneDel(t *testing.T) {
	events := capturePublishedEvents(t)

	smContext := NewSMContext("imsi-208930000099993", 5)
	smContext.Snssai = &models.Snssai{Sst: 1}
	smContext.SMContextState = SmStateActive

	smContext.ChangeState(SmStatePfcpRelease) // HandlePDUSessionSMContextRelease
	smContext.ChangeState(SmStateRelease)     // RemoveSMContext

	if len(*events) != 2 {
		t.Fatalf("expected 2 published events (one per real transition), got %d", len(*events))
	}
	deletes := 0
	for _, evt := range *events {
		if evt.Operation == mi.SubsOpDel {
			deletes++
		}
	}
	if deletes != 1 {
		t.Errorf("expected exactly 1 Del across the release sequence, got %d", deletes)
	}
	last := (*events)[len(*events)-1]
	if last.Subscriber.SmfSubState != DISCONNECTED || last.Operation != mi.SubsOpDel {
		t.Errorf("expected the final transition to be %q/%v, got %q/%v",
			DISCONNECTED, mi.SubsOpDel, last.Subscriber.SmfSubState, last.Operation)
	}
}

// TestChangeStateIsTerminalAfterRelease is a regression test: RemoveSMContext deletes the session
// from the pool when it transitions to SmStateRelease, but the FSM handler that triggered it still
// returns its own "next" state (e.g. SmStateInit for a normal release, SmStateActive for the
// duplicate-PDU-ID replacement path) and HandleEvent applies it with an unconditional ChangeState
// call on the same, now-removed, SMContext. Without a terminal guard that second call would mutate
// the state and re-publish a Kafka event for a session downstream already saw deleted.
func TestChangeStateIsTerminalAfterRelease(t *testing.T) {
	events := capturePublishedEvents(t)

	smContext := NewSMContext("imsi-208930000099994", 5)
	smContext.Snssai = &models.Snssai{Sst: 1}
	smContext.SMContextState = SmStateActive

	smContext.ChangeState(SmStateRelease)
	smContext.ChangeState(SmStateInit) // simulates HandleEvent applying the FSM's returned next state

	if smContext.SMContextState != SmStateRelease {
		t.Errorf("expected state to stay SmStateRelease after release, got %v", smContext.SMContextState)
	}
	if len(*events) != 1 {
		t.Fatalf("expected exactly 1 published event (the release itself), got %d", len(*events))
	}
	if (*events)[0].Subscriber.SmfSubState != DISCONNECTED {
		t.Errorf("expected the one published event to be %q, got %q", DISCONNECTED, (*events)[0].Subscriber.SmfSubState)
	}
}
