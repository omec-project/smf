// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/util/li/iri"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
	"github.com/omec-project/util/li/x2x3"
)

// loopbackPKI is liPKI with the key pair as well, so a stub mediation function on the
// loopback can present the same certificate — which carries an IP SAN — and be *verified*
// rather than merely trusted. The distinction is the whole point of this test: a peer that
// fails the handshake is unreachable, and what has to be reproduced here is a peer that is
// reachable.
func loopbackPKI(t *testing.T) (certPath, keyPath, caPath string, pair tls.Certificate) {
	t.Helper()

	certPath, keyPath, caPath = liPKI(t)

	return certPath, keyPath, caPath, liTrust(t).pair
}

// slowMDF2 completes the TLS handshake and then never reads. That is precisely the
// condition a reachability probe deliberately does not answer: the destination is up,
// the connection is established, and product is being offered faster than it is taken.
func slowMDF2(t *testing.T, pair tls.Certificate) string {
	t.Helper()

	ln, err := tls.Listen("tcp", testListenEphemeral, &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup

	held := make(chan struct{})
	t.Cleanup(func() { close(held) })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck // test
				<-held
			}()
		}
	}()

	return ln.Addr().String()
}

// TestProductDroppedByAFullQueueIsReported is the combination that made this silent,
// and it is driven through Init rather than through a pool a test builds itself,
// because what was wrong was the wiring: the hook was passed nil, with a comment
// asserting the worker's unreachability report covered these drops. It does not.
// AsyncSender.Unreachable excludes queue saturation deliberately — a full queue at one
// instant is a burst the buffer exists to absorb — and says in the same paragraph that
// the drops themselves are reported as they happen. At the UPF they were. Here nothing
// reported them, so a reachable-but-slow MDF2 lost xIRI while every channel that could
// have said so reported normality.
func TestProductDroppedByAFullQueueIsReported(t *testing.T) {
	cert, key, ca, pair := loopbackPKI(t)
	admf := newADMFStub(t)
	mdf2 := slowMDF2(t, pair)
	t.Cleanup(func() { active.Store(nil) })

	if err := Init(Config{
		NEID:     testNEID,
		X1Listen: testListenEphemeral,
		MDF2:     mdf2,
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: testADMFID,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	sub := active.Load()
	if sub == nil {
		t.Fatal("interception did not start")
	}
	s := sub.senderFor(mdf2)

	// Comfortably past the queue's 1024, offered faster than a peer that never reads
	// can take them. A PDU the framing accepts, in the shape production builds, so what
	// reaches the slow peer is what production writes. The queue fills before anything is
	// framed, so the report assertion below does not depend on it; the "still reachable"
	// half does, since a PDU that never frames is never written to the peer at all.
	pdu := &x2x3.PDU{
		Type:          x2x3.PDUTypeX2,
		PayloadFormat: x2x3.PayloadFormat3GPP33128,
		Direction:     x2x3.DirectionNotApplicable,
		Payload:       make([]byte, 512),
	}
	if _, err := pdu.Marshal(); err != nil {
		t.Fatalf("the test PDU does not frame: %v", err)
	}
	for range 8000 {
		//nolint:errcheck // enqueueing cannot fail in a way this test acts on
		_ = s.Send(pdu)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(admf.received(), "\n"), "x2DeliveryLost") {
			// The other half, and the reason this was invisible: the destination is
			// still described as healthy, because by every measure it is.
			if r, ok := s.(x2x3.Reachability); ok && r.Unreachable() {
				t.Error("the destination reports unreachable; this test no longer reproduces " +
					"the reachable-but-slow case it exists for")
			}

			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("product was dropped for want of queue space and nothing was reported:\n%s",
		strings.Join(admf.received(), "\n"))
}

// TestADroppedUnitIsReportedAsALossAndNotAsUnreachability is the consumer half of the
// dropped-unit accounting, asserted where the decision is made.
//
// A partial write costs one product unit only where the library's own resend of that unit
// does not land either — it resends it whole on the fresh connection, which recovers the
// ordinary case. What is left is a genuine loss to a destination that took the rest of the
// batch, and the library reports it as ErrUnitDropped precisely so it is not mistaken for
// unreachability: a healthy mediation function reported unreachable would have the watcher
// raise a fault about a working peer and retract it on the next send.
//
// This element then discarded the error and nudged the watcher, which sampled a destination
// it correctly considered reachable. So the loss the library correctly stopped mis-reporting
// as unreachability was reported nowhere at all — product missing from an agency's record
// with every channel that could have said so reporting normality.
//
// The transport that produces the error is tested where it lives (li/x2x3's partial-write
// suite, which drives a real socket). What this element does with it is this hook, and
// driving a real partial write to reach it would be asserting the other half twice while
// leaving this one's outcome to the machine's socket buffers.
func TestADroppedUnitIsReportedAsALossAndNotAsUnreachability(t *testing.T) {
	cert, key, ca, _ := loopbackPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	if err := Init(Config{
		NEID:     testNEID,
		X1Listen: testListenEphemeral,
		MDF2:     testDestinationAddr,
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: testADMFID,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	sub := active.Load()
	if sub == nil {
		t.Fatal("interception did not start")
	}

	// A watcher over no destinations, so the nudge has somewhere to go and reports nothing
	// of its own: what is asserted here is what the hook says, not what the watcher samples.
	watcher := x1.NewDestinationWatcher(func() []x1.DestinationHealth { return nil }, sub.reporter, 0)

	// The error as the library returns it: wrapped, because a caller must match it with
	// errors.Is rather than by comparison.
	sub.reportDeliveryError(fmt.Errorf("%w: send to 10.0.60.122:42069", x2x3.ErrUnitDropped), watcher)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(admf.received(), "\n"), "x2DeliveryLost") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("an xIRI was dropped on the way to a reachable mediation function and reported by "+
		"nothing:\n%s", strings.Join(admf.received(), "\n"))
}

// And the other direction, which is what keeps the fix from turning every delivery failure
// into a product-loss report: an ordinary transport failure says the destination is not
// working, which is the watcher's to report at the scope that names it, not a loss of
// product this element can name.
func TestAnOrdinaryDeliveryFailureIsNotReportedAsALoss(t *testing.T) {
	cert, key, ca, _ := loopbackPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	if err := Init(Config{
		NEID:     testNEID,
		X1Listen: testListenEphemeral,
		MDF2:     testDestinationAddr,
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: testADMFID,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	sub := active.Load()
	if sub == nil {
		t.Fatal("interception did not start")
	}
	watcher := x1.NewDestinationWatcher(func() []x1.DestinationHealth { return nil }, sub.reporter, 0)

	sub.reportDeliveryError(errors.New("dial tcp 10.0.60.122:42069: connection refused"), watcher)

	// Nothing to wait for, so give the asynchronous path a moment to be wrong in.
	time.Sleep(200 * time.Millisecond)
	if joined := strings.Join(admf.received(), "\n"); strings.Contains(joined, "x2DeliveryLost") {
		t.Errorf("a connection failure was reported as lost product:\n%s", joined)
	}
}

// startWithADMF starts interception reporting to admf, and returns the running subsystem.
func startWithADMF(t *testing.T, admf *admfStub) *subsystem {
	t.Helper()

	cert, key, ca, _ := loopbackPKI(t)
	t.Cleanup(func() { active.Store(nil) })

	if err := Init(Config{
		NEID:     testNEID,
		X1Listen: testListenEphemeral,
		MDF2:     testDestinationAddr,
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: testADMFID,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	sub := active.Load()
	if sub == nil {
		t.Fatal("interception did not start")
	}

	return sub
}

// awaitReport waits for a report containing want, and returns everything received.
func awaitReport(t *testing.T, admf *admfStub, want string) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if joined := strings.Join(admf.received(), "\n"); strings.Contains(joined, want) {
			return joined
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("no report containing %q arrived:\n%s", want, strings.Join(admf.received(), "\n"))

	return ""
}

// TestADroppedRunOfXIRIsIsReportedWithItsCount: a resend that does not land loses every unit
// from the one the write stopped in to the end of its batch, and the library counts them. The
// report must say how many, or the agency's gap is larger than this element's account of it.
func TestADroppedRunOfXIRIsIsReportedWithItsCount(t *testing.T) {
	admf := newADMFStub(t)
	sub := startWithADMF(t, admf)
	watcher := x1.NewDestinationWatcher(func() []x1.DestinationHealth { return nil }, sub.reporter, 0)

	sub.reportDeliveryError(&x2x3.DeliveryError{
		Lost: 5,
		Err:  fmt.Errorf("%w: send to 10.0.60.122:42069", x2x3.ErrUnitDropped),
	}, watcher)

	if joined := awaitReport(t, admf, "x2DeliveryLost"); !strings.Contains(joined, "5 xIRIs") {
		t.Errorf("the loss was reported without the number of xIRIs it cost:\n%s", joined)
	}
}

// TestARecordThatCannotBeEncodedIsReportedAgainstItsWarrant: the NE-level report says only
// that something did not encode, which is the signal an unreachable MDF2 also gives. Each
// warrant the record was for must be told, with the record type, as the AMF does.
func TestARecordThatCannotBeEncodedIsReportedAgainstItsWarrant(t *testing.T) {
	admf := newADMFStub(t)
	sub := startWithADMF(t, admf)

	// A SUPI the record's own definition refuses: an IMSI is six to fifteen digits.
	sub.deliverIRI([]types.InterceptTask{iriTask()}, [8]byte{}, nil, time.Now(),
		iri.SMFPDUSessionRelease{SUPI: iri.IMSI("12"), PDUSessionID: 5})

	joined := awaitReport(t, admf, "recordNotEncoded")
	if !strings.Contains(joined, string(iriTask().XID)) {
		t.Errorf("the encoding failure was not reported against the warrant it was for:\n%s", joined)
	}
	if !strings.Contains(joined, "SMFPDUSessionRelease") {
		t.Errorf("the encoding failure did not name the record type:\n%s", joined)
	}
}
