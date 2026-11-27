// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"testing"

	"github.com/omec-project/util/li/iri"
	"github.com/omec-project/util/li/types"
)

// An IMEI as the SMF receives it from the AMF: TS 29.571's "imei-" PEI, fifteen digits, the last
// being the check digit (TS 24.008 clause 10.5.1.4: "the IMEI is composed of 15 digits").
const (
	testPEIIMEI = "imei-356938035643809"
	testIMEI14  = "35693803564380"
)

// TestAnIMEIIsReportedWithoutItsCheckDigit: TS 33.128 defines IMEI as NumericString (SIZE(14)).
// The SMF passed all fifteen digits, so every session record for an IMEI-identified UE was out
// of constraint — and is now refused by the encoder outright.
func TestAnIMEIIsReportedWithoutItsCheckDigit(t *testing.T) {
	sc := fullSession()
	sc.Pei = testPEIIMEI

	if got := peiChoice(sc); got != iri.IMEI(testIMEI14) {
		t.Errorf("PEI = %#v, want the fourteen-digit IMEI %q", got, testIMEI14)
	}
	if _, err := iri.EncodeXIRI(smfEstablishment(sc)); err != nil {
		t.Errorf("an establishment for an IMEI-identified UE is not encodable: %v", err)
	}

	sc.Pei = "imeisv-3569380356438091"
	if got := peiChoice(sc); got != iri.IMEISV("3569380356438091") {
		t.Errorf("PEI = %#v, want the IMEISV unchanged", got)
	}
}

// TestAFourteenDigitIMEITaskMatches: the X1 peiImei is fourteen digits, and the SMF compared it
// against the fifteen it holds, so a schema-valid IMEI warrant never matched a session.
func TestAFourteenDigitIMEITaskMatches(t *testing.T) {
	sc := fullSession()
	sc.Pei = testPEIIMEI
	task := types.InterceptTask{
		Targets:  []types.TargetIdentifier{{Type: types.TargetPEI, Value: testIMEI14}},
		Products: []types.ProductType{types.ProductIRI},
	}

	if !sessionTargets(task, sc) {
		t.Errorf("a warrant naming the IMEI %s does not match the session holding %s", testIMEI14, testPEIIMEI)
	}
}
