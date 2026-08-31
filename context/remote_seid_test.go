// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import "testing"

// A PFCP message carries the SEID assigned by whoever receives it, so a report arriving
// under this element's SEID has to be answered under the user plane's.
func TestRemoteSEIDByLocalSEID(t *testing.T) {
	smContext := &SMContext{
		PFCPContext: map[string]*PFCPSessionContext{
			"192.168.252.3": {LocalSEID: 11, RemoteSEID: 0xAA},
			"192.168.252.4": {LocalSEID: 12, RemoteSEID: 0xBB},
		},
	}

	if got, found := smContext.RemoteSEIDByLocalSEID(12); !found || got != 0xBB {
		t.Errorf("RemoteSEIDByLocalSEID(12) = (%#x, %t), want (0xbb, true)", got, found)
	}

	// Not found must be distinguishable, so the caller can fall back to echoing rather
	// than answering under a zero SEID.
	if got, found := smContext.RemoteSEIDByLocalSEID(99); found || got != 0 {
		t.Errorf("RemoteSEIDByLocalSEID(99) = (%#x, %t), want (0, false)", got, found)
	}
}
