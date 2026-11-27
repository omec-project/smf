// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/util/li/iri"
	"github.com/omec-project/util/li/types"
)

// The conditional members of TS 33.128 the SMF holds and reports.
//
// One assertion per record-field site. A test asking whether "some identity is
// present" passes with all but one of them still missing.

// fullSession is an SMContext holding every value the records below can report.
func fullSession() *smfctx.SMContext {
	sc := &smfctx.SMContext{
		Supi:         testSUPI,
		Pei:          "imeisv-3534250000000151",
		Gpsi:         "msisdn-4915123456789",
		Dnn:          testDNN,
		PDUSessionID: 5,
		RatType:      models.RATTYPE_NR,
		// Region 0xC8, set 0x001, pointer 0x03 -> "c80043":
		//   raw = c8 00 43; set = 0x00<<2 | 0x43>>6 = 1; pointer = 0x43 & 0x3f = 3
		Guami:               models.Guami{AmfId: "c80043", PlmnId: models.PlmnIdNid{Mcc: "262", Mnc: "01"}},
		ServingNetwork:      models.PlmnIdNid{Mcc: "262", Mnc: "01"},
		UnauthenticatedSupi: false,
	}
	sc.PDUAddress = &smfctx.UeIpAddr{Ip: []byte{10, 45, 0, 7}}
	// Mandatory in the two establishment records this session builds, and its enumeration
	// has no zero — see the note in scan_authority_test.go. A session holding an address
	// has completed establishment, so it always has one.
	sc.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
	// gTPTunnelInfo is mandatory in three of its records, and an established session has
	// its uplink tunnel.
	sc.Tunnel = establishedTunnel()

	return sc
}

func TestSMFRecordsCarryTheAMFIdentity(t *testing.T) {
	sc := fullSession()
	want := iri.AMFID{AMFRegionID: 0xC8, AMFSetID: 1, AMFPointer: 3}

	for _, tc := range []struct {
		record string
		got    *iri.AMFID
	}{
		{testRecEstablishment, smfEstablishment(sc).AMFID},
		{testRecStartOfInterception, smfStartOfInterception(sc).AMFID},
		{testRecUnsuccessful, smfUnsuccessful(sc, iri.SMFFailedPDUSessionEstablishment, 26).AMFID},
	} {
		t.Run(tc.record, func(t *testing.T) {
			if tc.got == nil || *tc.got != want {
				t.Errorf("aMFID = %+v, want %+v. It is the AMF region/set/pointer of TS 23.003 "+
					"clause 2.10.1, decomposed from the GUAMI the AMF sent on N11 — not "+
					"ServingNfId, which is an instance UUID and yields no AMF identifier",
					tc.got, want)
			}
		})
	}
}

func TestSMFRecordsCarryTheRATType(t *testing.T) {
	sc := fullSession()
	for _, tc := range []struct {
		record string
		got    iri.RATType
	}{
		{testRecEstablishment, smfEstablishment(sc).RATType},
		{testRecModification, smfModification(sc).RATType},
		{testRecStartOfInterception, smfStartOfInterception(sc).RATType},
		{testRecUnsuccessful, smfUnsuccessful(sc, iri.SMFFailedPDUSessionEstablishment, 26).RATType},
	} {
		t.Run(tc.record, func(t *testing.T) {
			if tc.got != iri.RATNR {
				t.Errorf("rATType = %d, want %d (nR)", tc.got, iri.RATNR)
			}
		})
	}
}

func TestSMFRecordsCarryTheServingNetwork(t *testing.T) {
	sc := fullSession()
	want := iri.SMFServingNetwork{PLMNID: iri.PLMNID{MCC: "262", MNC: "01"}}

	for _, tc := range []struct {
		record string
		got    iri.SMFServingNetwork
	}{
		{testRecEstablishment, smfEstablishment(sc).ServingNetwork},
		{testRecModification, smfModification(sc).ServingNetwork},
		{testRecStartOfInterception, smfStartOfInterception(sc).ServingNetwork},
	} {
		t.Run(tc.record, func(t *testing.T) {
			if tc.got != want {
				t.Errorf("servingNetwork = %+v, want %+v", tc.got, want)
			}
		})
	}
}

// The modification record's uEEndpoint, beside the two other session records that
// carry it.
//
// The modification record's uEEndpoint is the CHOICE itself in the module, not the
// SEQUENCE OF the other records carry, so it must be one address — and must encode.
func TestModificationCarriesTheUEEndpoint(t *testing.T) {
	rec := smfModification(fullSession())
	if rec.UEEndpoint == nil {
		t.Error("SMFPDUSessionModification carries no uEEndpoint, though the SMF holds " +
			"PDUAddress and reports it in the other session records")
	}
	if _, err := iri.EncodeXIRI(rec); err != nil {
		t.Errorf("the modification record does not encode: %v", err)
	}
}

// sUPIUnauthenticated, where false is the whole point: it is the ordinary value, and
// the encoder can only express it because the field is a pointer.
func TestSUPIUnauthenticatedIsCarriedAsFalse(t *testing.T) {
	sc := fullSession()

	for _, tc := range []struct {
		record string
		got    *iri.SUPIUnauthenticatedIndication
	}{
		{testRecEstablishment, smfEstablishment(sc).SUPIUnauthenticated},
		{testRecModification, smfModification(sc).SUPIUnauthenticated},
		{testRecStartOfInterception, smfStartOfInterception(sc).SUPIUnauthenticated},
		{testRecUnsuccessful, smfUnsuccessful(sc, iri.SMFFailedPDUSessionEstablishment, 26).SUPIUnauthenticated},
	} {
		t.Run(tc.record, func(t *testing.T) {
			if tc.got == nil {
				t.Fatal("sUPIUnauthenticated absent though the record carries a SUPI; the table " +
					"says it shall be present whenever one is")
			}
			if bool(*tc.got) {
				t.Error("reported the SUPI as unauthenticated when it was authenticated")
			}
		})
	}

	// true must be reportable too, or the field says nothing.
	sc.UnauthenticatedSupi = true
	if got := smfEstablishment(sc).SUPIUnauthenticated; got == nil || !bool(*got) {
		t.Errorf("an unauthenticated SUPI was not reported as such (%v)", got)
	}
}

// The negatives: absent means the condition does not hold, and must not be confused
// with a zero value that asserts something.
func TestSMFConditionalsAreAbsentWhenUnheld(t *testing.T) {
	bare := &smfctx.SMContext{PDUSessionID: 5, Dnn: testDNN}

	est := smfEstablishment(bare)
	if est.SUPIUnauthenticated != nil {
		t.Errorf("sUPIUnauthenticated is present with no SUPI in the record (%v); that asserts "+
			"an authentication status for an identity the record does not carry",
			*est.SUPIUnauthenticated)
	}
	if est.AMFID != nil {
		t.Errorf("aMFID present with no GUAMI: %+v", *est.AMFID)
	}
	if est.RATType != 0 {
		t.Errorf("rATType = %d, want absent", est.RATType)
	}
	if est.ServingNetwork != (iri.SMFServingNetwork{}) {
		t.Errorf("servingNetwork present with no serving PLMN: %+v", est.ServingNetwork)
	}

	// A malformed GUAMI must yield absent, never a partial AMF identity.
	for _, bad := range []string{"", "c8004", "c800433", "zzzzzz"} {
		sc := fullSession()
		sc.Guami.AmfId = bad
		if got := smfEstablishment(sc).AMFID; got != nil {
			t.Errorf("AmfId %q yielded %+v; a wrong AMF identity is worse than a missing one", bad, *got)
		}
	}
}

// An AMF identifier of all zeros is region 0, set 0, pointer 0 — a real identity, not a
// missing one. It is reported, where a value type would have encoded it as absent.
func TestAnAllZeroAMFIdentityIsReported(t *testing.T) {
	sc := fullSession()
	sc.Guami.AmfId = "000000"

	got := smfEstablishment(sc).AMFID
	if got == nil || *got != (iri.AMFID{}) {
		t.Errorf("AmfId \"000000\" yielded %+v, want the all-zero identity", got)
	}
}

// The retention step, which the tests above do not reach.
//
// They build an SMContext directly, so they prove the builders map what the context
// holds and nothing about whether the context ever holds it. Without these three
// assignments in SetCreateData the builders could be correct while every real record carried none
// of them, and a PEI warrant could match nothing — a field populated in a builder and
// never supplied by the peer is invisible from inside the builder's own test.
//
// Reverting any of the three assignments in SetCreateData fails here.
func TestTheN11RequestSuppliesTheAMFIdentityAndAuthenticationStatus(t *testing.T) {
	guami := models.Guami{AmfId: "c80043", PlmnId: models.PlmnIdNid{Mcc: "262", Mnc: "01"}}
	unauthenticated := true

	supi, dnn := testSUPI, testDNN
	rat := models.RATTYPE_NR
	pei := "imeisv-4901542032375181"
	create := &models.SmContextCreateData{
		Supi:                &supi,
		Pei:                 &pei,
		Dnn:                 &dnn,
		Guami:               &guami,
		UnauthenticatedSupi: &unauthenticated,
		ServingNetwork:      models.PlmnIdNid{Mcc: "262", Mnc: "01"},
		RatType:             &rat,
	}

	// SetCreateData resolves the session's T3591 from the configuration and logs the
	// result, so both have to exist for a bare context.
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig.Configuration = &factory.Configuration{}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	sc := &smfctx.SMContext{PDUSessionID: 5, SubCtxLog: logger.CtxLog}
	sc.SetCreateData(create)

	est := smfEstablishment(sc)

	want := iri.AMFID{AMFRegionID: 0xC8, AMFSetID: 1, AMFPointer: 3}
	if est.AMFID == nil || *est.AMFID != want {
		t.Errorf("aMFID = %+v, want %+v — the AMF sent a GUAMI on N11 and the record does not "+
			"carry it, so SetCreateData is dropping it again", est.AMFID, want)
	}
	switch {
	case est.SUPIUnauthenticated == nil:
		t.Error("sUPIUnauthenticated absent — the AMF said the SUPI was not authenticated and " +
			"the record does not say so, so SetCreateData is dropping it again")
	case !bool(*est.SUPIUnauthenticated):
		t.Error("sUPIUnauthenticated = false, want true")
	}
	if est.RATType != iri.RATNR {
		t.Errorf("rATType = %d, want %d", est.RATType, iri.RATNR)
	}
	var peiTargets int
	for _, id := range targetsOf(sc) {
		if id.Type == types.TargetPEI {
			peiTargets++
		}
	}
	if peiTargets == 0 {
		t.Error("the AMF sent a PEI on N11 and the session offers none as a target, so a " +
			"warrant naming that PEI or IMEI matches nothing")
	}
	if got, want := est.ServingNetwork.PLMNID.MCC, iri.MCC("262"); got != want {
		t.Errorf("servingNetwork MCC = %q, want %q", got, want)
	}
}
