// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

/*
* Handles statistics for SMF
*
 */

package metrics

import (
	"net/http"

	"github.com/omec-project/smf/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// SmfStats captures SMF level stats
type SmfStats struct {
	n11Msg      *prometheus.CounterVec
	n4Msg       *prometheus.CounterVec
	svcNrfMsg   *prometheus.CounterVec
	svcPcfMsg   *prometheus.CounterVec
	svcUdmMsg   *prometheus.CounterVec
	sessions    *prometheus.GaugeVec
	sessProfile *prometheus.GaugeVec

	// upfRestoration counts what happened to each session after a UPF restarted, and
	// upfUnrestored is how many of that UPF's sessions are currently not carrying traffic.
	//
	// These exist because the failure they describe is silent by construction. Before this,
	// every signal an operator could read reported health after a UPF restart: the association
	// reached its established state, heartbeats continued, and no error was logged, while every
	// session on that UPF forwarded nothing. A restoration that partially succeeds reproduces
	// exactly that ambiguity unless its outcome is counted.
	//
	// Labelled by UPF, never by subscriber. A per-session label here would put a SUPI in a
	// metrics endpoint.
	upfRestoration *prometheus.CounterVec
	upfUnrestored  *prometheus.GaugeVec
}

var smfStats *SmfStats

// msgCounterLabels is the shared label set for the per-interface message counters below.
var msgCounterLabels = []string{"smf_id", "msg_type", "direction", "result", "reason"}

func initSmfStats() *SmfStats {
	return &SmfStats{
		n11Msg: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "n11_messages_total",
			Help: "N11 interface counters",
		}, msgCounterLabels),

		n4Msg: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "n4_messages_total",
			Help: "N4 interface counters",
		}, msgCounterLabels),

		svcNrfMsg: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nrf_messages_total",
			Help: "NRF service counters",
		}, msgCounterLabels),

		svcPcfMsg: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pcf_messages_total",
			Help: "PCF service counters",
		}, msgCounterLabels),

		svcUdmMsg: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "udm_messages_total",
			Help: "UDM service counters",
		}, msgCounterLabels),

		sessions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "smf_pdu_sessions",
			Help: "Number of SMF PDU sessions currently in the SMF",
		}, []string{"node_id"}),

		sessProfile: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "smf_pdu_session_profile",
			Help: "SMF PDU session Profile",
		}, []string{"id", "ip", "state", "upf", "enterprise"}),

		upfRestoration: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "smf_upf_restoration_sessions_total",
			Help: "Sessions handled after a UPF restart, by outcome",
		}, []string{"id", "upf", "outcome"}),

		upfUnrestored: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "smf_upf_unrestored_sessions",
			Help: "Sessions on a UPF that are not carrying traffic after a restart",
		}, []string{"id", "upf"}),
	}
}

func (ps *SmfStats) register() error {
	if err := prometheus.Register(ps.n11Msg); err != nil {
		return err
	}
	if err := prometheus.Register(ps.n4Msg); err != nil {
		return err
	}
	if err := prometheus.Register(ps.svcNrfMsg); err != nil {
		return err
	}
	if err := prometheus.Register(ps.svcPcfMsg); err != nil {
		return err
	}
	if err := prometheus.Register(ps.svcUdmMsg); err != nil {
		return err
	}
	if err := prometheus.Register(ps.sessions); err != nil {
		return err
	}
	if err := prometheus.Register(ps.sessProfile); err != nil {
		return err
	}
	if err := prometheus.Register(ps.upfRestoration); err != nil {
		return err
	}
	if err := prometheus.Register(ps.upfUnrestored); err != nil {
		return err
	}
	return nil
}

func init() {
	smfStats = initSmfStats()

	if err := smfStats.register(); err != nil {
		logger.KafkaLog.Panicln("SMF Stats register failed")
	}
}

// InitMetrics initialises SMF stats
func InitMetrics() {
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(":9089", nil)
	if err != nil {
		logger.KafkaLog.Fatalf("failed to start metrics server: %v", err)
	}
}

// IncrementN11MsgStats increments message level stats
func IncrementN11MsgStats(smfID, msgType, direction, result, reason string) {
	smfStats.n11Msg.WithLabelValues(smfID, msgType, direction, result, reason).Inc()
}

// IncrementN4MsgStats increments message level stats
func IncrementN4MsgStats(smfID, msgType, direction, result, reason string) {
	smfStats.n4Msg.WithLabelValues(smfID, msgType, direction, result, reason).Inc()
}

// IncrementSvcNrfMsgStats increments message level stats
func IncrementSvcNrfMsgStats(smfID, msgType, direction, result, reason string) {
	smfStats.svcNrfMsg.WithLabelValues(smfID, msgType, direction, result, reason).Inc()
}

// IncrementSvcPcfMsgStats increments message level stats
func IncrementSvcPcfMsgStats(smfID, msgType, direction, result, reason string) {
	smfStats.svcPcfMsg.WithLabelValues(smfID, msgType, direction, result, reason).Inc()
}

// IncrementSvcUdmMsgStats increments message level stats
func IncrementSvcUdmMsgStats(smfID, msgType, direction, result, reason string) {
	smfStats.svcUdmMsg.WithLabelValues(smfID, msgType, direction, result, reason).Inc()
}

// SetSessStats maintains Session level stats
func SetSessStats(nodeId string, count uint64) {
	smfStats.sessions.WithLabelValues(nodeId).Set(float64(count))
}

// SetSessProfileStats maintains Session profile info
func SetSessProfileStats(id, ip, state, upf, enterprise string, count uint64) {
	smfStats.sessProfile.WithLabelValues(id, ip, state, upf, enterprise).Set(float64(count))
}

// AddUpfRestorationStats records the outcome for sessions handled after a UPF restart. The counts
// are kept apart on purpose: a restoration that restored some sessions and released the rest must
// not be reportable as simply having completed.
//
// The outcome is one of five, and a dashboard should expect all of them:
//
//	restored     - re-installed on the node and carrying traffic again
//	released     - torn down because the node would not accept it back
//	skipped      - not attempted: busy, purged, or no longer live
//	unexaminable - nothing could be learned about it, so it is not known to be healthy
//	gone         - no longer anchored on this node when the wave reached it
func AddUpfRestorationStats(smfID, upf, outcome string, count int) {
	if count <= 0 {
		return
	}
	smfStats.upfRestoration.WithLabelValues(smfID, upf, outcome).Add(float64(count))
}

// SetUpfUnrestoredSessions records how many of a UPF's sessions are not carrying traffic. It is set
// to zero on a restoration that leaves none behind, so a UPF that has recovered stops reporting a
// backlog it no longer has.
func SetUpfUnrestoredSessions(smfID, upf string, count int) {
	smfStats.upfUnrestored.WithLabelValues(smfID, upf).Set(float64(count))
}
