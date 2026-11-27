// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"github.com/omec-project/nas/v2/nasMessage"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/lawfulintercept"
)

// The Lawful Interception teardown hooks, reached through package variables so
// that a test can observe which paths call them.
//
// A test cannot do that by activating the subsystem: `active` is package-private
// to lawfulintercept, and Init needs mTLS material and a TCP bind that this
// package's tests have no business standing up. Without a seam the hooks are
// silent no-ops in every test, so a path that stopped calling them would look
// exactly like a path that calls them.
//
// The seam lives here rather than as test-only API on lawfulintercept, because
// what needs asserting is which of *this* package's paths call the hooks, not
// anything about the subsystem behind them.
//
// In production these are the lawfulintercept functions themselves, silent no-ops
// when LI is not configured.
var (
	liReportRelease             = lawfulintercept.ReportRelease
	liUntriggerCC               = lawfulintercept.UntriggerCC
	liRestoreInterception       = lawfulintercept.RestoreInterception
	liReportReleaseReject       = lawfulintercept.ReportReleaseReject
	liReportEstablishmentReject = lawfulintercept.ReportEstablishmentReject
	liReportModificationReject  = lawfulintercept.ReportModificationReject
)

// ReportEstablishmentFailure ends the interception state of a PDU session whose PFCP
// establishment failed, at the one point every such failure reaches: the state machine's
// create-failure handler, which rejects the UE and removes the context. A UPF that refused, a
// request that timed out, an adapter error and a verdict collected across several UPFs all
// arrive there, and none of them reaches the producer's rejectEstablishment.
//
// **What the agency already holds decides the record.** The establishment record is emitted
// when the anchor UPF accepts, before the verdict from the other UPFs is in, because only the
// anchor's response carries the F-TEID the record describes. So a create can fail after its
// establishment was reported. That session is reported released, which is what happened to
// it: a failed-establishment record after an establishment record would leave the agency
// holding both. A session whose establishment was never reported gets the failed-establishment
// record, with the cause the reject to the UE carries.
//
// **The triggers are withdrawn either way.** The CC trigger is installed at every UPF that
// accepted, the anchor or not, so a create that failed can hold one whether or not its
// establishment was reported, and the context removed after this is the last thing that could
// have withdrawn it. Withdrawing from a session that holds none does nothing.
//
// Takes smContext.SMLock.
func ReportEstablishmentFailure(smContext *smf_context.SMContext) {
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	if smContext.LiEstablishmentReported {
		reportAndUntask(smContext)

		return
	}

	liReportEstablishmentReject(smContext, nasMessage.Cause5GSMRequestRejectedUnspecified)
	liUntriggerCC(smContext)
}

// reportAndUntask ends a session's interception state: the release record for the
// mediation function, and the withdrawal of the triggers that session held.
//
// The two always travel together — a teardown that reports without withdrawing
// leaves the trigger installed, and this element keeps a POI alive while it
// believes that POI holds tasking it installed, so the keepalives that trigger
// earns are what stop the POI's fail-safe from ever reclaiming it. Naming the
// pair once makes a teardown path that calls only one of them visible as an
// omission rather than a plausible line of code.
//
// Caller holds smContext.SMLock.
func reportAndUntask(smContext *smf_context.SMContext) {
	liReportRelease(smContext)
	liUntriggerCC(smContext)
}

// restoreInterception puts back the half of what reportAndUntask took down that can be
// put back, for a release that did not happen: the session is live again, so its
// eventual release is reportable again.
//
// Not the triggers. By the time any caller runs, releaseTunnel has nilled the tunnel, so
// there are no serving UPFs to re-task and the withdrawal already acknowledged by the
// POI stands. See lawfulintercept.RestoreInterception for why re-installing from here
// would produce a trigger that matches nothing while the element believed interception
// was running.
//
// It is the counterpart of reportAndUntask and is named beside it for the same reason —
// a branch that restores the session's state and not its interception state is then
// visibly an omission rather than a plausible line of code.
//
// Caller holds smContext.SMLock.
func restoreInterception(smContext *smf_context.SMContext) {
	liRestoreInterception(smContext)
}
