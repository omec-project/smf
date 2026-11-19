// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x2x3"
)

// attrsOf indexes a PDU's conditional attributes by type, keeping every occurrence —
// the two target identifier attributes are the ones that may appear more than once.
func attrsOf(pdu *x2x3.PDU) map[uint16][]string {
	out := make(map[uint16][]string, len(pdu.Attributes))
	for _, a := range pdu.Attributes {
		out[a.Type] = append(out[a.Type], string(a.Value))
	}

	return out
}

// activateSessionIRI installs one IRI warrant for the target's SUPI, delivering to snd.
func activateSessionIRI(t *testing.T, snd sender) {
	t.Helper()
	st := store.New()
	st.Activate(types.InterceptTask{
		XID:      testTaskIRI,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	})
	active.Store(&subsystem{
		store: st, senderFor: func(string) sender { return snd },
		mdf2: configuredMDF2,
		ids:  x2x3.NewIdentity(testNEID, smfInterceptionPoint), neID: testNEID,
	})
	t.Cleanup(func() { active.Store(nil) })
}

// TestSessionXIRICarriesTheSixRequiredAttributes is TS 33.128 table 5.3.2-2 for the
// SMF's IRI-POI: the same six an AMF record owes, with this element's own identities.
func TestSessionXIRICarriesTheSixRequiredAttributes(t *testing.T) {
	snd := &captureSender{}
	activateSessionIRI(t, snd)

	ReportEstablishment(targetSM())
	if len(snd.pdus) != 1 {
		t.Fatalf("delivered %d records, want 1", len(snd.pdus))
	}
	attrs := attrsOf(snd.pdus[0])

	if got := attrs[x2x3.AttrNFID]; len(got) != 1 || got[0] != testNEID {
		t.Errorf("NFID = %q, want the configured network element identifier", got)
	}
	if got := attrs[x2x3.AttrIPID]; len(got) != 1 || got[0] != smfInterceptionPoint {
		t.Errorf("IPID = %q, want %q", got, smfInterceptionPoint)
	}
	if got := attrs[x2x3.AttrTimestamp]; len(got) != 1 || len(got[0]) != 8 {
		t.Errorf("timestamp = %q, want one 8-octet timespec", got)
	}
	if got := attrs[x2x3.AttrMatchedTargetIdentifier]; len(got) != 1 || got[0] != "<supiimsi>262019876543210</supiimsi>" {
		t.Errorf("matched target identifier = %q, want the SUPI the task named", got)
	}
	// The PEI twice: the IMEISV the UE presented, and the IMEI it carries, which is the
	// device's identity an IMEI warrant names.
	if got := len(attrs[x2x3.AttrOtherTargetIdentifier]); got != 3 {
		t.Errorf("other target identifiers = %d (%q), want the session's PEI (as its IMEISV and the "+
			"IMEI it carries) and GPSI", got, attrs[x2x3.AttrOtherTargetIdentifier])
	}
	if got := attrs[x2x3.AttrSequenceNumber]; len(got) != 1 {
		t.Fatalf("sequence number occurrences = %d, want 1", len(got))
	}
	if n := binary.BigEndian.Uint32([]byte(attrs[x2x3.AttrSequenceNumber][0])); n != 0 {
		t.Errorf("first record in this context numbered %d, want 0", n)
	}
}

// TestSessionNumberingFollowsTheCorrelationContext: for this POI the correlation
// identifier is part of clause 5.3.9's context, so two sessions of one warrant are
// numbered independently. This is the case a per-connection counter gets wrong, and
// both sessions' records travel the same connection to the same MDF2.
func TestSessionNumberingFollowsTheCorrelationContext(t *testing.T) {
	snd := &captureSender{}
	activateSessionIRI(t, snd)

	// Two sessions of one subject. correlationOf reads the PFCP context, which is
	// unset here, so both carry the zero correlation — one context, one sequence.
	ReportEstablishment(targetSM())
	ReportEstablishment(targetSM())

	if len(snd.pdus) != 2 {
		t.Fatalf("delivered %d records, want 2", len(snd.pdus))
	}
	for i, pdu := range snd.pdus {
		if n := binary.BigEndian.Uint32(attrValue(t, pdu, x2x3.AttrSequenceNumber)); n != uint32(i) {
			t.Errorf("record %d numbered %d, want %d — one context is one ascending sequence", i, n, i)
		}
	}
}

func attrValue(t *testing.T, pdu *x2x3.PDU, typ uint16) []byte {
	t.Helper()
	for _, a := range pdu.Attributes {
		if a.Type == typ {
			return a.Value
		}
	}
	t.Fatalf("PDU carries no attribute %d", typ)

	return nil
}

// TestInitRefusesWithoutAnElementIdentifier: an element that cannot say which network
// function produced a record does not deliver one. The refusal is a returned error, so
// interception does not start and the SMF keeps serving sessions.
func TestInitRefusesWithoutAnElementIdentifier(t *testing.T) {
	if err := Init(Config{X1Listen: testListenEphemeral}); !errors.Is(err, errNoElementIdentifier) {
		t.Errorf("Init without a network element identifier returned %v, want errNoElementIdentifier", err)
	}
	if active.Load() != nil {
		t.Error("interception is running after a refused initialisation")
	}
}

// TestEveryIdentityThisPOIProducesRenders is the AMF test's counterpart: targetsOf is
// the only source of the identities an SMF record's header reports, and one that
// cannot be rendered would drop a required attribute with nothing failing.
func TestEveryIdentityThisPOIProducesRenders(t *testing.T) {
	ids := targetsOf(targetSM())
	if len(ids) != 4 {
		t.Fatalf("the fixture yields %d identities, want the SUPI, the PEI (as its IMEISV and the "+
			"IMEI it carries) and the GPSI this POI reads", len(ids))
	}
	for _, id := range ids {
		if _, ok := id.XMLFragment(); !ok {
			t.Errorf("%s renders no fragment, so a record matched on it would carry no matched target identifier", id.Type)
		}
	}
	if got := len(types.XMLFragments(ids)); got != len(ids) {
		t.Errorf("XMLFragments dropped %d of %d identities silently", len(ids)-got, len(ids))
	}
}

// TestAnIMEIWarrantMatchesASessionWhoseUEPresentedItsIMEISV: an IMEISV is the IMEI's Type
// Allocation Code and Serial Number followed by a software version, so a UE that presented one
// is the device a warrant naming the fourteen-digit IMEI targets. Matching only the IMEISV as
// presented would leave that warrant producing nothing for such a UE's sessions.
func TestAnIMEIWarrantMatchesASessionWhoseUEPresentedItsIMEISV(t *testing.T) {
	snd := &captureSender{}
	st := store.New()
	st.Activate(types.InterceptTask{
		XID:      testTaskIRI,
		Targets:  []types.TargetIdentifier{{Type: types.TargetPEI, Value: "35342500000001"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	})
	active.Store(&subsystem{
		store: st, senderFor: func(string) sender { return snd },
		mdf2: configuredMDF2,
		ids:  x2x3.NewIdentity(testNEID, smfInterceptionPoint), neID: testNEID,
	})
	t.Cleanup(func() { active.Store(nil) })

	ReportEstablishment(targetSM())
	if len(snd.pdus) != 1 {
		t.Fatalf("delivered %d records for an IMEI warrant naming a UE that presented its IMEISV, want 1",
			len(snd.pdus))
	}

	attrs := attrsOf(snd.pdus[0])
	if got := attrs[x2x3.AttrMatchedTargetIdentifier]; len(got) != 1 || got[0] != "<peiImei>35342500000001</peiImei>" {
		t.Errorf("matched target identifier = %q, want the IMEI the warrant named", got)
	}
}
