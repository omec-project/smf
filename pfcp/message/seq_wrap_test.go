// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	smf_context "github.com/omec-project/smf/context"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
)

// A request is recorded under the number getSeqNumber gives it, and its response is matched
// by the number the response header carries, which holds 24 bits. Past 2^24 requests, with or
// without the SMF_COUNT offset, the two must still be the same number.
func TestAResponseMatchesItsRequestAcrossTheSequenceWrap(t *testing.T) {
	upNodeID := smf_context.NodeID{
		NodeIdType:  smf_context.NodeIdTypeIpv4Address,
		NodeIdValue: net.ParseIP("127.0.0.1").To4(),
	}

	for _, tc := range []struct {
		name     string
		smfCount string
		offset   uint32
	}{
		{"one SMF", "1", 0},
		{"the third SMF", "3", 2 * 5000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SMF_COUNT", tc.smfCount)

			saved := atomic.LoadUint32(&seq)
			t.Cleanup(func() { atomic.StoreUint32(&seq, saved) })

			// The next numbers are the last two below the wrap and the first two past it.
			atomic.StoreUint32(&seq, maxSeqNumber-2-tc.offset)

			for range 4 {
				req := BuildPfcpHeartbeatRequest(getSeqNumber(), time.Now())
				InsertPfcpTxn(req.Sequence(), &upNodeID)

				b, err := req.Marshal()
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}

				// The UPF answers with the number it read from the request.
				rsp, err := pfcp_message.Parse(b)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}

				if got := FetchPfcpTxn(rsp.Sequence()); got == nil {
					t.Fatalf("request recorded under %#x: no transaction for the %#x its "+
						"response carries", req.Sequence(), rsp.Sequence())
				}
			}
		})
	}
}
