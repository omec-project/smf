// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"time"

	"github.com/omec-project/smf/factory"
)

// T3591 values from 3GPP TS 24.501 table 10.3.2, the network-side 5GSM timer table.
const (
	// T3591Default applies to terrestrial access.
	T3591Default = 16 * time.Second

	// T3591Satellite applies to access via a satellite NG-RAN cell. NOTE 5 of that table
	// restricts it to satellite NG-RAN RAT type NR(MEO) or NR(GEO); NR(LEO) is not named
	// and therefore takes T3591Default, as does NR(OTHER_SAT).
	T3591Satellite = 22 * time.Second
)

// NasTimerSource records which layer decided a NAS timer value. The value alone is not enough
// to diagnose with: a session running the terrestrial value over a geostationary link aborts
// procedures early, and the symptom is indistinguishable from a UE that did not answer. Knowing
// whether the value came from configuration, from the network, or from a fallback is what
// separates the two.
type NasTimerSource string

const (
	// NasTimerSourceConfig means an operator set the value explicitly.
	NasTimerSourceConfig NasTimerSource = "config"

	// NasTimerSourceIndication means the AMF told us the extended NAS-SM timer applies.
	NasTimerSourceIndication NasTimerSource = "indication"

	// NasTimerSourceDefault means neither was available and the terrestrial value applies.
	NasTimerSourceDefault NasTimerSource = "default"
)

// ResolveT3591 returns the T3591 value for a session and the layer that decided it.
//
// TS 24.501 subclause 4.23.4 makes the AMF's extended NAS-SM timer indication the selector for
// the satellite value; the SMF is told rather than inferring it from the RAT type. Nothing
// guarantees the indication arrives, however — it depends on the RAN advertising the Rel-18
// RATInformation IE — so an explicit configured value takes precedence over it. A deployment
// that has had to configure the value has usually done so because the automatic path did not
// work, and a site is one orbit.
func ResolveT3591(cfg *factory.TimerValue, extendedNasSmTimer bool) (time.Duration, NasTimerSource) {
	if cfg != nil && cfg.ExpireTime > 0 {
		return cfg.ExpireTime, NasTimerSourceConfig
	}
	if extendedNasSmTimer {
		return T3591Satellite, NasTimerSourceIndication
	}
	return T3591Default, NasTimerSourceDefault
}
