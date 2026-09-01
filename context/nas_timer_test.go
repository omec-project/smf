// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"
	"time"

	"github.com/omec-project/smf/factory"
)

func TestResolveT3591(t *testing.T) {
	tests := []struct {
		name               string
		cfg                *factory.TimerValue
		extendedNasSmTimer bool
		wantValue          time.Duration
		wantSource         NasTimerSource
	}{
		{
			name:               "configured value overrides a present indication",
			cfg:                &factory.TimerValue{ExpireTime: 30 * time.Second},
			extendedNasSmTimer: true,
			wantValue:          30 * time.Second,
			wantSource:         NasTimerSourceConfig,
		},
		{
			name:               "configured value applies with no indication",
			cfg:                &factory.TimerValue{ExpireTime: 30 * time.Second},
			extendedNasSmTimer: false,
			wantValue:          30 * time.Second,
			wantSource:         NasTimerSourceConfig,
		},
		{
			name:               "indication decides when unconfigured",
			cfg:                &factory.TimerValue{},
			extendedNasSmTimer: true,
			wantValue:          T3591Satellite,
			wantSource:         NasTimerSourceIndication,
		},
		{
			name:               "terrestrial default when neither is available",
			cfg:                &factory.TimerValue{},
			extendedNasSmTimer: false,
			wantValue:          T3591Default,
			wantSource:         NasTimerSourceDefault,
		},
		{
			name:               "absent configuration behaves as unconfigured",
			cfg:                nil,
			extendedNasSmTimer: true,
			wantValue:          T3591Satellite,
			wantSource:         NasTimerSourceIndication,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotValue, gotSource := ResolveT3591(tc.cfg, tc.extendedNasSmTimer)
			if gotValue != tc.wantValue {
				t.Errorf("value = %s, want %s", gotValue, tc.wantValue)
			}
			if gotSource != tc.wantSource {
				t.Errorf("source = %s, want %s", gotSource, tc.wantSource)
			}
		})
	}
}

// A LEO session takes the terrestrial value. TS 24.501 table 10.3.2 NOTE 5 restricts the
// satellite value to RAT type NR(MEO) or NR(GEO), so the AMF does not set the indication for
// NR(LEO) and the SMF must not reach for 22s on its own.
func TestResolveT3591LeoTakesTerrestrialValue(t *testing.T) {
	value, source := ResolveT3591(&factory.TimerValue{}, false)
	if value != T3591Default {
		t.Fatalf("a LEO session must take %s, got %s", T3591Default, value)
	}
	if source != NasTimerSourceDefault {
		t.Fatalf("source = %s, want %s", source, NasTimerSourceDefault)
	}
	if T3591Default == T3591Satellite {
		t.Fatal("the terrestrial and satellite values must differ for this test to mean anything")
	}
}

func TestEffectiveT3591(t *testing.T) {
	enable, disable := true, false

	tests := []struct {
		name        string
		cfg         *factory.TimerValue
		wantEnabled bool
		wantRetries int
	}{
		{"absent block runs with defaults", nil, true, T3591MaxRetriesDefault},
		{"empty block runs with defaults", &factory.TimerValue{}, true, T3591MaxRetriesDefault},
		{"only a value set still runs", &factory.TimerValue{ExpireTime: time.Second}, true, T3591MaxRetriesDefault},
		{"explicit enable", &factory.TimerValue{Enable: &enable}, true, T3591MaxRetriesDefault},
		{"explicit disable is honoured", &factory.TimerValue{Enable: &disable}, false, T3591MaxRetriesDefault},
		{"retry count is respected", &factory.TimerValue{MaxRetryTimes: 2}, true, 2},
		{"a nonsense retry count falls back", &factory.TimerValue{MaxRetryTimes: -1}, true, T3591MaxRetriesDefault},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enabled, retries := EffectiveT3591(tc.cfg)
			if enabled != tc.wantEnabled {
				t.Errorf("enabled = %v, want %v", enabled, tc.wantEnabled)
			}
			if retries != tc.wantRetries {
				t.Errorf("maxRetries = %d, want %d", retries, tc.wantRetries)
			}
		})
	}
}
