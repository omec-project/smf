// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/message"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
)

// Once the establishment has created a PDR, the PDR exists on the user plane, and a later
// modification carrying it has to update it rather than create it again under the same identifier
// -- which a conforming UPF refuses. The establishment moved FARs and QERs to RULE_CREATE and left
// PDRs at RULE_INITIAL, so the first modification to carry an established PDR without marking it
// sent it as a Create PDR.
func TestAnEstablishedPdrIsNotCreatedAgain(t *testing.T) {
	far := &context.FAR{FARID: 1}
	qer := &context.QER{QERID: 1}
	pdr := &context.PDR{PDRID: 1, Precedence: 255, FAR: far, QER: []*context.QER{qer}}

	if _, err := message.BuildPfcpSessionEstablishmentRequest(1, cpNodeID, net.ParseIP(cpNodeID), 1,
		[]*context.PDR{pdr}, []*context.FAR{far}, []*context.QER{qer}); err != nil {
		t.Fatalf("building the establishment: %v", err)
	}
	if pdr.State != context.RULE_CREATE {
		t.Errorf("after the establishment the PDR is in state %v, want RULE_CREATE, as its FAR and QER are", pdr.State)
	}

	msg, err := message.BuildPfcpSessionModificationRequest(2, 1, 2, net.ParseIP(cpNodeID),
		[]*context.PDR{pdr}, []*context.FAR{far}, []*context.QER{qer}, nil, nil, nil)
	if err != nil {
		t.Fatalf("building the modification: %v", err)
	}
	buf := make([]byte, msg.MarshalLen())
	if err = msg.MarshalTo(buf); err != nil {
		t.Fatal(err)
	}
	req, err := pfcp_message.ParseSessionModificationRequest(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(req.CreatePDR) != 0 {
		t.Errorf("the modification creates %d PDR(s) the establishment already created", len(req.CreatePDR))
	}
}
