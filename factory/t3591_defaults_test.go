// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package factory

import "testing"

func TestSetT3591DefaultsFillsAnAbsentBlock(t *testing.T) {
	SmfConfig = Config{Configuration: &Configuration{}}
	setT3591Defaults()

	cfg := SmfConfig.Configuration.T3591
	if cfg == nil {
		t.Fatal("T3591 configuration must not be left nil")
	}
	if !cfg.Enable {
		t.Error("T3591 must be enabled when no configuration is supplied")
	}
	if cfg.MaxRetryTimes != 4 {
		t.Errorf("MaxRetryTimes = %d, want 4 (TS 24.501 table 10.3.2 NOTE 1)", cfg.MaxRetryTimes)
	}
	if cfg.ExpireTime != 0 {
		t.Errorf("ExpireTime = %s, want 0 so that the value resolves automatically", cfg.ExpireTime)
	}
}

// A configuration file with no configuration section at all must not panic the defaulting.
func TestSetT3591DefaultsToleratesAbsentConfiguration(t *testing.T) {
	SmfConfig = Config{}
	setT3591Defaults()
	if SmfConfig.Configuration != nil {
		t.Fatal("defaulting must not invent a Configuration block")
	}
}

func TestSetT3591DefaultsKeepsAnExplicitValue(t *testing.T) {
	SmfConfig = Config{Configuration: &Configuration{}}
	SmfConfig.Configuration.T3591 = &TimerValue{Enable: true, ExpireTime: 22_000_000_000, MaxRetryTimes: 2}
	setT3591Defaults()

	cfg := SmfConfig.Configuration.T3591
	if cfg.ExpireTime != 22_000_000_000 {
		t.Errorf("ExpireTime = %s, want the configured value to survive defaulting", cfg.ExpireTime)
	}
	if cfg.MaxRetryTimes != 2 {
		t.Errorf("MaxRetryTimes = %d, want the configured value to survive defaulting", cfg.MaxRetryTimes)
	}
}
