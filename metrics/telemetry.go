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
}

var smfStats *SmfStats

func initSmfStats() *SmfStats {
	return &SmfStats{
		n11Msg: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "n11_messages_total",
			Help: "N11 interface counters",
		}, []string{"smf_id", "msg_type", "direction", "result", "reason"}),

		n4Msg: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "n4_messages_total",
			Help: "N4 interface counters",
		}, []string{"smf_id", "msg_type", "direction", "result", "reason"}),

		svcNrfMsg: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nrf_messages_total",
			Help: "NRF service counters",
		}, []string{"smf_id", "msg_type", "direction", "result", "reason"}),

		svcPcfMsg: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pcf_messages_total",
			Help: "PCF service counters",
		}, []string{"smf_id", "msg_type", "direction", "result", "reason"}),

		svcUdmMsg: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "udm_messages_total",
			Help: "UDM service counters",
		}, []string{"smf_id", "msg_type", "direction", "result", "reason"}),

		sessions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "smf_pdu_sessions",
			Help: "Number of SMF PDU sessions currently in the SMF",
		}, []string{"node_id"}),

		sessProfile: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "smf_pdu_session_profile",
			Help: "SMF PDU session Profile",
		}, []string{"id", "ip", "state", "upf", "enterprise"}),
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
