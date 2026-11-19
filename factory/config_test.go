// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

const (
	GNB = "gnb"
)

func TestKafkaEnabledByDefault(t *testing.T) {
	err := InitConfigFactory("../config/smfcfg.yaml")
	if err != nil {
		t.Errorf("Could not load default configuration file: %v", err)
	}
	if !*SmfConfig.Configuration.KafkaInfo.EnableKafka {
		t.Errorf("Expected Kafka to be enabled by default, was disabled")
	}
}

func TestWebuiUrl(t *testing.T) {
	tests := []struct {
		name       string
		configFile string
		want       string
	}{
		{
			name:       "default webui URL",
			configFile: "../config/smfcfg.yaml",
			want:       "http://webui:5001",
		},
		{
			name:       "custom webui URL",
			configFile: "../config/smfcfg_with_custom_webui_url.yaml",
			want:       "https://myspecialwebui:5002",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore original config
			origSmfConfig := SmfConfig
			t.Cleanup(func() { SmfConfig = origSmfConfig })

			if err := InitConfigFactory(tt.configFile); err != nil {
				t.Logf("error in InitConfigFactory: %v", err)
			}

			got := SmfConfig.Configuration.WebuiUri
			if got != tt.want {
				t.Errorf("The webui URL is not correct. got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestLiBulkSwitchesAreTriState covers the two keys that carry an agreement the standard
// leaves to the deployment, at the layer where an operator's `false` is at risk of becoming
// nothing at all.
//
// The third case is the one worth having: a value that is not a boolean must be refused,
// not read as unset. Unset is the permissive answer for bulk deactivation, so silently
// defaulting a typo would leave the element performing exactly the operation the operator
// wrote the key to withhold. It is the rule the UPF's config already applies to its
// keepalive window.
func TestLiBulkSwitchesAreTriState(t *testing.T) {
	li := func(extra string) string {
		return `configuration:
  li:
    x1Listen: ":8443"
    neId: smf-1` + extra + "\n"
	}

	t.Run("both switches carry through", func(t *testing.T) {
		block, err := strictLiBlock([]byte(li(`
    deactivateAllTasks: false
    removeAllDestinations: true`)))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got := block.DeactivateAllTasks; got == nil || *got {
			t.Errorf("deactivateAllTasks = %v, want a stated false — a dropped restriction leaves "+
				"the element performing the operation the operator withheld", got)
		}
		if got := block.RemoveAllDestinations; got == nil || !*got {
			t.Errorf("removeAllDestinations = %v, want a stated true", got)
		}
	})

	t.Run("saying nothing is not saying false", func(t *testing.T) {
		block, err := strictLiBlock([]byte(li("")))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if block.DeactivateAllTasks != nil || block.RemoveAllDestinations != nil {
			t.Error("an li block that states no agreement must leave both unset, so the " +
				"standard's own defaults apply")
		}
	})

	t.Run("a value that is not a boolean is refused", func(t *testing.T) {
		block, err := strictLiBlock([]byte(li("\n    deactivateAllTasks: perhaps")))
		if err == nil {
			t.Errorf("an unparseable value was accepted as %v; it must be refused rather than "+
				"read as unset, which is the permissive answer",
				block.DeactivateAllTasks)
		}
	})
}

// TestAQuotedTriStateBooleanIsRefusedByTheConfigLoader pins why the charts validate
// these keys, so the chart test and this one cannot drift apart about what they guard.
//
// The three LI booleans are tri-state — unset means "the specification's default", which
// is why they are *bool — and the chart's own default for them is the empty string. That
// is exactly what invites an operator to replace it with a quoted value: `helm template
// … --set-string config.smf.li.x2x3KeepaliveEnabled=false` renders
// `x2x3KeepaliveEnabled: "false"`, which is a YAML string and not a YAML bool.
//
// What follows is the whole SMF configuration failing to load, not the LI block being
// ignored: the element crashloops over a lawful-interception key, which is the one cost
// an LI configuration mistake may never have. The chart refuses the render instead; this
// test is the reason that refusal is not decoration.
func TestAQuotedTriStateBooleanIsRefusedByTheConfigLoader(t *testing.T) {
	for _, key := range []string{"x2x3KeepaliveEnabled", "deactivateAllTasks", "removeAllDestinations"} {
		t.Run(key, func(t *testing.T) {
			var li Li

			err := yaml.Unmarshal([]byte(key+`: "false"`), &li)
			if err == nil {
				t.Fatalf("a quoted %s was accepted; the chart guard would be guarding nothing", key)
			}
			// The stable part of the message across YAML libraries is the type clash
			// itself. This module is on go.yaml.in/yaml/v4, which words it "cannot
			// construct !!str `false` into bool"; gopkg.in/yaml.v2 and v3 say "cannot
			// unmarshal". Asserting on the tag rather than the verb keeps this pinned to
			// the fact — a YAML string reaching a *bool — rather than to a library's
			// phrasing.
			if !strings.Contains(err.Error(), "!!str") {
				t.Errorf("refused for an unexpected reason, which may mean the type changed: %v", err)
			}
		})
	}

	// The unquoted forms are what the chart must emit, and both must load.
	for _, doc := range []string{"x2x3KeepaliveEnabled: false", "x2x3KeepaliveEnabled: true"} {
		var li Li
		if err := yaml.Unmarshal([]byte(doc), &li); err != nil {
			t.Errorf("a real YAML boolean was refused (%q): %v", doc, err)
		}
	}
}

// TestLiBlockRefusesUnknownKeys covers the whole startup path, not strictLiBlock alone: the
// property is that a mistyped LI key stops the network function from starting, and that is only
// true if InitConfigFactory calls the check.
//
// Both keys below are chosen because their defaults are not what the operator asked for. A
// dropped `keepaliveTimeout` leaves the X1 keepalive procedure on the clause default rather than
// the operator's TIME_P2; a dropped `admfUrl` leaves the fault channel a no-op, so nothing it is required to
// report — including a misconfiguration — reaches the ADMF. Neither is visible from outside: the
// element runs, answers X1, and looks provisioned.
func TestLiBlockRefusesUnknownKeys(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "smfcfg.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		return path
	}

	const good = `info:
  version: 1.0.0
configuration:
  li:
    x1Listen: ":8443"
    neId: smf-1
    admfUrl: https://admf:9443
    keepaliveTimeout: 30s
`

	t.Run("a conformant li block starts", func(t *testing.T) {
		orig := SmfConfig
		t.Cleanup(func() { SmfConfig = orig })

		if err := InitConfigFactory(write(t, good)); err != nil {
			t.Fatalf("a conformant li block was refused: %v", err)
		}
		if SmfConfig.Configuration.Li.KeepaliveTimeout != "30s" {
			t.Errorf("keepaliveTimeout = %q, want 30s — the strict pass must not disturb the decode",
				SmfConfig.Configuration.Li.KeepaliveTimeout)
		}
		// A reload that fixes the block must clear the recorded refusal, or one bad load
		// disables interception for the life of the process.
		if err := LiBlockError(); err != nil {
			t.Errorf("a conformant li block left a refusal recorded: %v", err)
		}
	})

	for _, tt := range []struct {
		name string
		typo string
	}{
		{"a misspelled fail-safe window", "keepaliveTimeut"},
		{"a misspelled ADMF endpoint", "admf_url"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			orig := SmfConfig
			t.Cleanup(func() { SmfConfig = orig })

			body := strings.Replace(good, "admfUrl", tt.typo, 1)
			if tt.typo == "keepaliveTimeut" {
				body = strings.Replace(good, "keepaliveTimeout", tt.typo, 1)
			}
			// **Both halves, and the second is the one easily lost.** The key must
			// be refused, *and* the network function must still come up: a configuration load
			// that fails takes PFCP, the SBI, registration and every subscriber's sessions with
			// it, over a typo in an optional subsystem — and a network function that will not
			// start announces to every operator and peer that it is LI-provisioned, which is
			// the disclosure undetectability exists to prevent. Asserting only the refusal
			// would pass a load that refuses the key by failing.
			if err := InitConfigFactory(write(t, body)); err != nil {
				t.Fatalf("a misspelled LI key stopped the whole configuration load, which stops "+
					"the network function: %v", err)
			}

			err := LiBlockError()
			if err == nil {
				t.Fatalf("%s was accepted, so the setting the operator wrote never reached the "+
					"element and its unsafe default stands with nothing saying so", tt.typo)
			}
			if !strings.Contains(err.Error(), tt.typo) {
				t.Errorf("the refusal does not name the key that was wrong: %v", err)
			}
		})
	}

	t.Run("a key outside the li block is still tolerated", func(t *testing.T) {
		orig := SmfConfig
		t.Cleanup(func() { SmfConfig = orig })

		// The scope of the check, asserted rather than assumed. A configuration can carry keys
		// this version does not model — one written for a later release; if strictness leaked
		// past the li block, every deployment carrying such a key would stop starting.
		body := strings.Replace(good, "configuration:\n", "configuration:\n  aKeyThisElementDoesNotModel: 1\n", 1)
		if err := InitConfigFactory(write(t, body)); err != nil {
			t.Fatalf("an unmodelled key outside the li block was refused, which would stop this "+
				"SMF starting on a key from a later release: %v", err)
		}
	})

	t.Run("no li block at all", func(t *testing.T) {
		orig := SmfConfig
		t.Cleanup(func() { SmfConfig = orig })

		if err := InitConfigFactory(write(t, "info:\n  version: 1.0.0\nconfiguration:\n  amfName: AMF\n")); err != nil {
			t.Fatalf("a configuration without interception was refused: %v", err)
		}
		if SmfConfig.Configuration.Li != nil {
			t.Errorf("an absent li block decoded as %+v; interception is opt-in", SmfConfig.Configuration.Li)
		}
	})

	t.Run("a null li block is no li block", func(t *testing.T) {
		orig := SmfConfig
		t.Cleanup(func() { SmfConfig = orig })

		if err := InitConfigFactory(write(t, "info:\n  version: 1.0.0\nconfiguration:\n  li:\n")); err != nil {
			t.Fatalf("a null li block was refused: %v", err)
		}
		if SmfConfig.Configuration.Li != nil || LiBlockError() != nil {
			t.Errorf("a null li block decoded as %+v, refusal %v", SmfConfig.Configuration.Li, LiBlockError())
		}
	})
}

// TestAnLiTypeErrorDoesNotStopTheConfigurationLoad covers the value half of the containment
// TestLiBlockRefusesUnknownKeys covers for keys. A value of the wrong type inside the li block is
// refused by the LI subsystem like an unknown key, and the configuration still loads.
//
// The block must still be non-nil: the LI subsystem starts on a present block, and it is the
// subsystem that declines to intercept and tells the ADMF. A nil block would turn interception
// off with nothing reported.
func TestAnLiTypeErrorDoesNotStopTheConfigurationLoad(t *testing.T) {
	const good = `info:
  version: 1.0.0
configuration:
  webuiUri: http://webui:5001
  li:
    x1Listen: ":8443"
    neId: smf-1
`

	for _, tt := range []struct {
		name string
		line string
	}{
		{"a sequence for a boolean", "    keepaliveDisabled: [true]\n"},
		{"a quoted boolean", "    keepaliveRetainTasking: \"true\"\n"},
		{"a mapping for a list", "    upfTriggers: {a: b}\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			orig := SmfConfig
			t.Cleanup(func() { SmfConfig = orig })

			path := filepath.Join(t.TempDir(), "smfcfg.yaml")
			if err := os.WriteFile(path, []byte(good+tt.line), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			if err := InitConfigFactory(path); err != nil {
				t.Fatalf("an LI type error stopped the whole configuration load, which stops the "+
					"network function: %v", err)
			}
			if LiBlockError() == nil {
				t.Error("an LI value of the wrong type was accepted")
			}
			if SmfConfig.Configuration.Li == nil {
				t.Error("a refused li block decoded as nil, so the LI subsystem never starts to " +
					"report the refusal")
			}
		})
	}

	t.Run("a type error outside the li block still fails the load", func(t *testing.T) {
		orig := SmfConfig
		t.Cleanup(func() { SmfConfig = orig })

		path := filepath.Join(t.TempDir(), "smfcfg.yaml")
		body := strings.Replace(good, "webuiUri: http://webui:5001", "webuiUri: [x]", 1)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		if err := InitConfigFactory(path); err == nil {
			t.Error("a type error outside the li block was accepted; the containment is for the " +
				"li block only")
		}
	})
}
