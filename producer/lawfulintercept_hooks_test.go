// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/transaction"
	"github.com/omec-project/smf/util"
)

// liCalls records which teardown hooks ran, by swapping the package seam.
type liCalls struct{ released, untasked int }

func captureLI(t *testing.T) *liCalls {
	t.Helper()
	c := &liCalls{}
	release, untrigger := liReportRelease, liUntriggerCC
	liReportRelease = func(*smf_context.SMContext) { c.released++ }
	liUntriggerCC = func(*smf_context.SMContext) { c.untasked++ }
	t.Cleanup(func() { liReportRelease, liUntriggerCC = release, untrigger })

	return c
}

// teardownSession builds a session in the global pool, since the teardown paths
// reach it through that.
func teardownSession(t *testing.T) *smf_context.SMContext {
	t.Helper()
	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}
	sc := smf_context.NewSMContext("imsi-262019876543210", 5)
	sc.Supi = "imsi-262019876543210"

	return sc
}

// TestContextReplacementReportsAndUntasks: a session torn down because a newer
// context replaced it must still emit its release and give up its triggers.
//
// The hooks are silent no-ops unless LI is configured, so without a seam a path
// that never calls them is indistinguishable from one that does.
func TestContextReplacementReportsAndUntasks(t *testing.T) {
	calls := captureLI(t)
	sc := teardownSession(t)

	if err := HandlePduSessionContextReplacement(sc.Ref); err != nil {
		t.Fatalf("HandlePduSessionContextReplacement: %v", err)
	}

	if calls.released != 1 {
		t.Errorf("release reported %d times, want 1 — an agency cannot tell a session "+
			"that ended from a subject who went quiet", calls.released)
	}
	if calls.untasked != 1 {
		t.Errorf("triggers withdrawn %d times, want 1 — a trigger left installed keeps "+
			"this element's keepalives flowing, which is what stops the POI's fail-safe "+
			"from reclaiming it", calls.untasked)
	}
}

// TestARestoredSessionReleasedOnReestablishmentReportsAndUntasks is the replacement case for a
// session read back from the datastore: the subscriber established the same PDU session ID again
// after an SMF restart, so the stored session ends without being released.
func TestARestoredSessionReleasedOnReestablishmentReportsAndUntasks(t *testing.T) {
	calls := captureLI(t)
	sc := teardownSession(t)

	ReleaseRestoredSession(sc)

	if calls.released != 1 {
		t.Errorf("release reported %d times, want 1 — the agency holds the stored session's "+
			"establishment and would never see it end", calls.released)
	}
	if calls.untasked != 1 {
		t.Errorf("triggers withdrawn %d times, want 1 — a trigger installed for the stored "+
			"session would outlive it", calls.untasked)
	}
}

// TestARestorationReleaseReportsAndUntasks covers the release a restoration makes of a session
// it will not re-install. Whether the release command could be built does not matter here: the
// session has left the pool either way.
func TestARestorationReleaseReportsAndUntasks(t *testing.T) {
	calls := captureLI(t)
	sc := teardownSession(t)

	n1n2Request, err := markReleasedAndBuild(sc)
	if n1n2Request != nil {
		util.CleanupMultipartTempFiles(n1n2Request)
	}
	if err != nil {
		t.Logf("the release command was not built (%v); the session was removed regardless", err)
	}

	if calls.released != 1 || calls.untasked != 1 {
		t.Errorf("release reported %d times and triggers withdrawn %d times, want 1 and 1 — the "+
			"agency would never see the session end, and its triggers would outlive it",
			calls.released, calls.untasked)
	}
}

// TestAReleaseCompleteReportsAndUntasks covers the UE's Release Complete. After an ordinary
// release it finds both already done; after a Release Command that answered a modification the
// SMF could not carry out, it is the only teardown the session gets.
func TestAReleaseCompleteReportsAndUntasks(t *testing.T) {
	const pduSessionID = 5

	calls := captureLI(t)
	sc := teardownSession(t)
	sc.SMContextState = smf_context.SmStateActive

	request := models.UpdateSmContextRequest{}
	request.SetJsonData(models.SmContextUpdateData{})
	request.SetBinaryDataN1SmMessage(n1SmMessageFile(t, encodeReleaseComplete(t, pduSessionID, requestPti)))

	txn := transaction.NewTransaction(request, nil, svcmsgtypes.UpdateSmContext)
	txn.Ctxt = sc

	if err := HandleUpdateN1Msg(txn, models.NewUpdateSmContext200Response(), &pfcpAction{}); err != nil {
		t.Fatalf("HandleUpdateN1Msg: %v", err)
	}

	if calls.released != 1 || calls.untasked != 1 {
		t.Errorf("release reported %d times and triggers withdrawn %d times, want 1 and 1 — the "+
			"session left the pool without the agency being told it ended, and its triggers "+
			"would outlive it", calls.released, calls.untasked)
	}
}

// TestTeardownHooksTravelTogether pins the pairing itself. Reporting without
// withdrawing is the more damaging half-measure, because the record makes the
// teardown look handled while the trigger stays installed.
func TestTeardownHooksTravelTogether(t *testing.T) {
	calls := captureLI(t)
	sc := teardownSession(t)
	t.Cleanup(func() { smf_context.RemoveSMContext(sc.Ref) })

	reportAndUntask(sc)

	if calls.released != calls.untasked {
		t.Errorf("release reported %d times but triggers withdrawn %d — the two must not "+
			"come apart", calls.released, calls.untasked)
	}
}
