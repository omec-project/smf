// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package qos

import "testing"

// The identifier goes on the wire in an NGAP modify request, where "flow 1" and "not a flow
// identifier" are different answers. GetQosFlowIdFromQosId narrows before anyone can tell them
// apart: 257 arrives as 1, which passes any range check made afterwards and names a flow the
// policy never mentioned.
func TestParseQosFlowIdRefusesWhatNarrowingWouldHide(t *testing.T) {
	cases := []struct {
		qosId   string
		want    uint8
		refused bool
	}{
		{qosId: "1", want: 1},
		{qosId: "5", want: 5},
		{qosId: "63", want: 63},
		{qosId: "0", refused: true},
		{qosId: "64", refused: true},
		{qosId: "257", refused: true},
		{qosId: "-1", refused: true},
		{qosId: "5x", refused: true},
		{qosId: "", refused: true},
	}

	for _, tc := range cases {
		got, err := ParseQosFlowId(tc.qosId)

		switch {
		case tc.refused && err == nil:
			t.Errorf("ParseQosFlowId(%q) = %d, want an error: it is not an assignable identifier", tc.qosId, got)
		case !tc.refused && err != nil:
			t.Errorf("ParseQosFlowId(%q) errored (%v), want %d", tc.qosId, err, tc.want)
		case !tc.refused && got != tc.want:
			t.Errorf("ParseQosFlowId(%q) = %d, want %d", tc.qosId, got, tc.want)
		}
	}
}

// The narrowing that makes this necessary, pinned so the reason survives the fix.
func TestGetQosFlowIdFromQosIdNarrows(t *testing.T) {
	if got := GetQosFlowIdFromQosId("257"); got != 1 {
		t.Errorf("GetQosFlowIdFromQosId(\"257\") = %d, want 1: this is the narrowing ParseQosFlowId exists to avoid", got)
	}
}
