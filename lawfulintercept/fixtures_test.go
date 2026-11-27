// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

// Fixture values shared across this package's tests. Named rather than repeated because
// goconst is part of the lint this repository runs, and a value spelled out in a dozen
// files is one a reader has to compare by eye to know two tests mean the same thing.
const (
	testNEID   = "smf-1"
	testADMFID = "admf-1"

	testTaskCC  = "task-cc"
	testTaskIRI = "task-iri"

	testXIDPrimary   = "11111111-1111-4111-8111-111111111111"
	testXIDSecondary = "22222222-2222-4222-8222-222222222222"
	// testXIDCovering is a warrant covering the duplicating session fixture.
	testXIDCovering = "44444444-4444-4444-8444-444444444444"
	testXIDTertiary = "33333333-3333-4333-8333-333333333333"
	testXIDOrphan   = "99999999-9999-4999-8999-999999999999"
	testXIDHeld     = "aaaaaaaa-1111-4111-8111-111111111111"

	testSUPI = "imsi-262019876543210"
	testDNN  = "internet"

	testListenEphemeral = "127.0.0.1:0"
	testDestinationAddr = "10.0.60.122:42069"
	testMDF3Addr        = "192.0.2.1:42069"
	testKeepalive30s    = "30s"
	testUnhealthyReason = "failed"

	trigNodeB         = "10.0.1.6"
	trigNodeC         = "10.0.4.4"
	trigNodeElsewhere = "10.0.9.9"

	testUPFNEID1 = "upf-1"
	testUPFNEID2 = "upf-2"

	testX1URLUPF1 = "https://upf-1:8443/X1/NE"
	testX1URLUPFA = "https://upf-a:8443/X1/NE"

	testRecEstablishment       = "SMFPDUSessionEstablishment"
	testRecStartOfInterception = "SMFStartOfInterceptionWithEstablishedPDUSession"
	testRecUnsuccessful        = "SMFUnsuccessfulProcedure"
	testRecModification        = "SMFPDUSessionModification"
)
