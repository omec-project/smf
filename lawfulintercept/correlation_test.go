// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"encoding/binary"
	"strconv"
	"testing"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/util/li/types"
)

// A session's PDUs carry one correlation value (TS 103 221-2 clause 5.2.8). The anchor's
// F-SEID is zero while a restarted UPF re-establishes the session, is a new value once it has,
// and is gone with the tunnel after a release; the correlation is the value the anchor first
// accepted the session with throughout.
func TestASessionKeepsItsCorrelationThroughARestartAndARelease(t *testing.T) {
	sub := triggerSubsystem(t, newFakePOI(t))
	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	sc := sessionServedBy(testSUPI, trigNodeA)
	anchor := onlyPFCPContext(t, sc)
	first := anchor.RemoteSEID

	// The anchor's acceptance, which fixes it.
	ReportEstablishment(sc)

	var want [8]byte
	binary.BigEndian.PutUint64(want[:], first)

	anchor.RemoteSEID = 0 // the restarted UPF has not answered the re-establishment yet
	if got := correlationOf(sc); got != want {
		t.Errorf("while the restarted UPF re-establishes the session the correlation is % x, want % x", got, want)
	}

	anchor.RemoteSEID = first + 1 // and it has, with a new F-SEID
	ReportEstablishment(sc)
	if got := correlationOf(sc); got != want {
		t.Errorf("after the restarted UPF re-established the session the correlation is % x, want % x", got, want)
	}

	sc.Tunnel = nil // releaseTunnel, before a refused or timed-out release is reported
	if got := correlationOf(sc); got != want {
		t.Errorf("after the tunnel was released the correlation is % x, want % x", got, want)
	}
}

// The trigger installed again at a restarted UPF detects on the F-SEID the UPF assigned anew,
// and stamps the session's correlation, which the session's records and its triggers at any
// other UPF carry.
func TestATriggerReinstalledAfterARestartCarriesTheSessionsCorrelation(t *testing.T) {
	poi := newFakePOI(t)
	sub := triggerSubsystem(t, poi)
	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	if !sub.store.Activate(types.InterceptTask{
		XID:      testXIDPrimary,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}) {
		t.Fatal("activating the warrant")
	}

	sc := sessionServedBy(testSUPI, trigNodeA)
	anchor := onlyPFCPContext(t, sc)
	first := anchor.RemoteSEID

	// The establishment answer, as the PFCP handler runs it.
	ReportEstablishment(sc)
	TriggerCC(sc)
	awaitMessages(t, poi, "ActivateTaskRequest", 1)

	// The UPF restarts: its claims are discarded, and it re-establishes the session.
	sub.triggers.ForgetPOI(trigNodeA)
	anchor.RemoteSEID = first + 1
	ReportEstablishment(sc)
	TriggerCC(sc)
	awaitMessages(t, poi, "ActivateTaskRequest", 2)

	wantCorrelation := strconv.FormatUint(first, 10)
	corrs := poi.elements("ActivateTaskRequest", "correlationID")
	seids := poi.elements("ActivateTaskRequest", "SEID")
	if len(corrs) != 2 || len(seids) != 2 {
		t.Fatalf("the triggers carried correlations %v and SEIDs %v, want two of each", corrs, seids)
	}
	if corrs[0] != wantCorrelation || corrs[1] != wantCorrelation {
		t.Errorf("the triggers carried correlations %v, want %s on both: the session's records and "+
			"its content before the restart carry it", corrs, wantCorrelation)
	}
	if want := strconv.FormatUint(first+1, 10); seids[1] != want {
		t.Errorf("the re-installed trigger detects on SEID %s, want the restarted UPF's %s", seids[1], want)
	}
}

// A session stored by a version that did not keep the correlation reads back without it, and
// takes the anchor's F-SEID as it stands, as that version did, until its anchor accepts it again.
func TestASessionWithoutAFixedCorrelationTakesTheAnchors(t *testing.T) {
	sc := sessionServedBy(testSUPI, trigNodeA)
	seid := onlyPFCPContext(t, sc).RemoteSEID

	var want [8]byte
	binary.BigEndian.PutUint64(want[:], seid)
	if got := correlationOf(sc); got != want {
		t.Errorf("the correlation is % x, want the anchor's F-SEID % x", got, want)
	}
	if sc.LiCorrelation != 0 {
		t.Errorf("reading the correlation fixed it at %d; only the anchor's acceptance fixes it", sc.LiCorrelation)
	}

	if got := correlationOf(&smfctx.SMContext{}); got != ([8]byte{}) {
		t.Errorf("a session with no anchor has correlation % x, want zero", got)
	}
}

// onlyPFCPContext is the PFCP session of a session served by one UPF.
func onlyPFCPContext(t *testing.T, sc *smfctx.SMContext) *smfctx.PFCPSessionContext {
	t.Helper()

	if len(sc.PFCPContext) != 1 {
		t.Fatalf("the session has %d PFCP sessions, want 1", len(sc.PFCPContext))
	}
	for _, pc := range sc.PFCPContext {
		return pc
	}

	return nil
}
