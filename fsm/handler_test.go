// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package fsm

import (
	"testing"

	smf_context "github.com/omec-project/smf/context"
)

// The state the delivery-failure indication leaves the session in, for each thing the producer can
// report it did. HandleEvent applies it on top of whatever the producer left, so a modification
// whose revert failed has to keep the release mark the producer set: returning Init for it, as the
// handler did, relabelled a session that needed releasing as one never set up.
//
// Tested on the mapping and not end to end: a revert now has something to undo only when the
// abandoned update changed rules the user plane carries, and the fixture for that lives with the
// producer, whose own tests drive a revert that fails.
func TestTheStateAfterADeliveryFailure(t *testing.T) {
	cases := []struct {
		name                   string
		modification, reverted bool
		want                   smf_context.SMContextState
	}{
		{"a modification put back", true, true, smf_context.SmStateActive},
		{"a modification whose revert failed", true, false, smf_context.SmStatePfcpRelease},
		{"not a modification", false, false, smf_context.SmStateInit},
	}

	for _, tc := range cases {
		if got := stateAfterTransferFailure(tc.modification, tc.reverted); got != tc.want {
			t.Errorf("%s: state = %s, want %s", tc.name, got, tc.want)
		}
	}
}
