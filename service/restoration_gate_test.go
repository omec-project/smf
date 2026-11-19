// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"reflect"
	"testing"
	"time"

	smfContext "github.com/omec-project/smf/context"
)

// TestTheRestartHookIsGatedByTheInterceptionWiring: the gate is applied in one place, and a
// restart path reaches the restoration only through the hook it wraps. Dropping that line would
// fail nothing else: every restart path would still restore, with the interception record no
// longer settled first.
func TestTheRestartHookIsGatedByTheInterceptionWiring(t *testing.T) {
	previous, previousUngated := smfContext.OnRestart, ungatedRestart
	t.Cleanup(func() { smfContext.OnRestart, ungatedRestart = previous, previousUngated })
	ungatedRestart = nil

	restored := 0
	upstream := func(smfContext.NodeID, time.Time) { restored++ }
	smfContext.OnRestart = upstream

	gateRestorationOnLI()

	if smfContext.OnRestart == nil {
		t.Fatal("the wiring removed the restart hook")
	}
	if reflect.ValueOf(smfContext.OnRestart).Pointer() == reflect.ValueOf(upstream).Pointer() {
		t.Fatal("the restart hook was left unwrapped: restart paths reach the restoration directly")
	}
	// With interception not running, the gate passes straight through to the restoration it wraps.
	smfContext.OnRestart(*smfContext.NewNodeID("10.50.0.1"), time.Now())
	if restored != 1 {
		t.Errorf("the gated hook reached the restoration %d time(s), want 1", restored)
	}

	// Applied again, it wraps the producer's hook rather than itself. A gate around a gate takes
	// one node's restart lock twice, under UpfLock — which this test cannot observe directly,
	// with interception not running, so it checks what is wrapped.
	gateRestorationOnLI()
	if reflect.ValueOf(ungatedRestart).Pointer() != reflect.ValueOf(upstream).Pointer() {
		t.Error("applying the wiring a second time wrapped the gate instead of the producer's hook")
	}
	restored = 0
	smfContext.OnRestart(*smfContext.NewNodeID("10.50.0.1"), time.Now())
	if restored != 1 {
		t.Errorf("after the wiring ran twice the hook reached the restoration %d time(s), want 1", restored)
	}
}
