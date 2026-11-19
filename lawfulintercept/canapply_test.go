// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
)

// oidUID is the UID relative distinguished name (RFC 4519 section 2.39), which is
// where TS 103 221-1 clause 8.2.4 puts the peer's identifier.
var oidUID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

// admfCert is the certificate the responsible ADMF presents, bound to the
// identifier the request bodies below assert.
func admfCert(t *testing.T, identifier string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "li-peer",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidUID, Value: identifier}},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	return cert
}

// activateWithTargets renders an ActivateTaskRequest naming the given target
// identifier elements verbatim.
func activateWithTargets(targets string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<ns1:X1Request xmlns:ns1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <ns1:x1RequestMessage xsi:type="ns1:ActivateTaskRequest">
    <ns1:admfIdentifier>admf-1</ns1:admfIdentifier>
    <ns1:neIdentifier>smf-1</ns1:neIdentifier>
    <ns1:messageTimestamp>2026-08-16T18:46:21.247432Z</ns1:messageTimestamp>
    <ns1:version>v1.6.1</ns1:version>
    <ns1:x1TransactionId>3741800e-971b-4aa9-85f4-466d2b1adc7f</ns1:x1TransactionId>
    <ns1:taskDetails>
      <ns1:xId>50b93d1e-1b53-4d63-aacb-e4d99811bc0b</ns1:xId>
      <ns1:targetIdentifiers>` + targets + `</ns1:targetIdentifiers>
      <ns1:deliveryType>X2Only</ns1:deliveryType>
      <ns1:listOfDIDs>
        <ns1:dId>7d1c2f60-8a4e-4a1e-9f3b-2c5d6e7f8091</ns1:dId>
      </ns1:listOfDIDs>
    </ns1:taskDetails>
  </ns1:x1RequestMessage>
</ns1:X1Request>`
}

const (
	supiTarget = `<ns1:targetIdentifier><ns1:supiimsi>262019876543210</ns1:supiimsi></ns1:targetIdentifier>`
	ipTarget   = `<ns1:targetIdentifier><ns1:ipv4Address>10.45.0.2</ns1:ipv4Address></ns1:targetIdentifier>`
	// otherSUPITarget is a second subscriber: no UE presents two SUPIs.
	otherSUPITarget = `<ns1:targetIdentifier><ns1:supiimsi>262019876543211</ns1:supiimsi></ns1:targetIdentifier>`
	taskXID         = types.XID("50b93d1e-1b53-4d63-aacb-e4d99811bc0b")
)

// TestX1ServerRefusesTaskingItCannotAct drives the X1 server this element
// actually runs, which is the point: the defect was not a wrong decision but a
// decision never wired in, and a test that calls canApply directly passes with
// the option unregistered.
//
// This element matches subjects by subscriber identity alone, and every criterion of a
// task must match (TS 103 221-1 table 6.2.1.2-1). A warrant naming a UE address — alone
// or beside a subscriber identity — matches nothing here at every moment, and so does
// one naming two SUPIs; acknowledging either tells the ADMF an interception is running
// that cannot be — indistinguishable, from the agency's side, from a tasked subject who
// did nothing.
func TestX1ServerRefusesTaskingItCannotAct(t *testing.T) {
	for _, tc := range []struct {
		name     string
		targets  string
		wantHeld bool
	}{
		{"only an address this element never resolves", ipTarget, false},
		{"a subscriber identity", supiTarget, true},
		{"a subscriber identity and an address", supiTarget + ipTarget, false},
		{"two subscriber identities", supiTarget + otherSUPITarget, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := store.New()
			// The destination the fixture names is declared, because a task naming one
			// this element cannot resolve is now refused — and what this test is about is
			// whether the element can act on the *targets*.
			srv := newX1Server(st, Config{
				NEID: testNEID, AdmfID: testADMFID,
				Destinations: []Destination{{
					DID: "7d1c2f60-8a4e-4a1e-9f3b-2c5d6e7f8091", DeliveryType: "X2Only",
					Address: testDestinationAddr,
				}},
			}, &subsystem{store: st})

			resp, err := srv.Process([]byte(activateWithTargets(tc.targets)), admfCert(t, testADMFID))
			if err != nil {
				t.Fatalf("Process: %v", err)
			}
			if len(resp.Messages) != 1 {
				t.Fatalf("got %d response messages, want 1", len(resp.Messages))
			}

			_, held := st.Get(taskXID)
			if held != tc.wantHeld {
				t.Errorf("task held = %v, want %v", held, tc.wantHeld)
			}

			errInfo := resp.Messages[0].ErrorInformation
			if tc.wantHeld {
				if errInfo != nil {
					t.Errorf("warrant refused with %q — this element can act on one of the "+
						"identifiers it names, and refusing declines interception it can perform",
						errInfo.ErrorDescription)
				}

				return
			}
			if errInfo == nil {
				t.Fatal("a warrant this element cannot act on was acknowledged; the ADMF now " +
					"believes an interception is running that never can be")
			}
			if !strings.Contains(errInfo.ErrorDescription, "every criterion of a task must match") {
				t.Errorf("refusal reason = %q, want it to say why — every criterion must match — "+
					"so a provisioning function can tell this from a fault",
					errInfo.ErrorDescription)
			}
		})
	}
}

// TestAnX3OnlyTaskIsRealWorkHere is the counterpart of the AMF's product refusal, and the
// reason that refusal is the AMF's alone.
//
// An IRI-POI that cannot produce xCC can produce nothing for an X3Only warrant, which is why
// the AMF refuses one. This element is both an IRI-POI and the CC Triggering Function, so an
// X3Only task is real work: it triggers the serving UPFs' CC-POIs and applies duplication,
// delivering no xIRI because none was asked for. Refusing it here would refuse content
// interception outright.
func TestAnX3OnlyTaskIsRealWorkHere(t *testing.T) {
	if err := canApply(types.InterceptTask{
		XID:      taskXID,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
	}); err != nil {
		t.Errorf("an X3Only warrant was refused: %v — this element is the CC Triggering "+
			"Function, so refusing one refuses content interception outright", err)
	}
}
