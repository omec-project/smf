// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/smferrors"
	"github.com/omec-project/util/li/iri"
	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x1"
	"github.com/omec-project/util/li/x2x3"
)

// captureSender records the xIRI PDUs delivered, standing in for the X2 client
// so tests can assert per-warrant delivery isolation.
type captureSender struct{ pdus []*x2x3.PDU }

func (c *captureSender) Send(p *x2x3.PDU) error {
	c.pdus = append(c.pdus, p)
	return nil
}

// targetSM is a fully-identified PDU-session context used across the tests.
func targetSM() *smfctx.SMContext {
	sd := "010203"
	return &smfctx.SMContext{
		Supi:                   testSUPI,
		Pei:                    "imeisv-3534250000000151",
		Gpsi:                   "msisdn-4915123456789",
		Dnn:                    testDNN,
		PDUSessionID:           5,
		SelectedPDUSessionType: 1, // IPv4
		Snssai:                 &models.Snssai{Sst: 1, Sd: &sd},
		// An established session has an address assigned, and it is the subject's
		// own — not the serving UPF's, which servingUPFTEID reports separately.
		PDUAddress: &smfctx.UeIpAddr{Ip: net.ParseIP("10.45.0.2")},
		// And its uplink tunnel: gTPTunnelInfo is mandatory in the establishment,
		// modification and start-of-interception records, and the codec refuses one
		// without it.
		Tunnel: establishedTunnel(),
	}
}

// establishedTunnel is the default data path of an established session: the serving UPF
// and the uplink TEID servingUPFTEID reports.
func establishedTunnel() *smfctx.UPTunnel {
	node := smfctx.NewDataPathNode()
	node.UpLinkTunnel.TEID = 0x0a0b0c0d
	node.UPF = &smfctx.UPF{NodeID: smfctx.NodeID{NodeIdType: smfctx.NodeIdTypeIpv4Address, NodeIdValue: net.ParseIP("10.100.0.9").To4()}}

	return &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{1: &smfctx.DataPath{IsDefaultPath: true, FirstDPNode: node}}}
}

func TestTargetsOf(t *testing.T) {
	got := targetsOf(targetSM())
	// The IMEISV the UE presented, and the IMEI it carries (its first fourteen digits), so an
	// IMEI warrant matches this device as well as an IMEISV one.
	want := map[types.TargetIdentifier]bool{
		{Type: types.TargetSUPI, Value: "262019876543210"}: true,
		{Type: types.TargetPEI, Value: "3534250000000151"}: true,
		{Type: types.TargetPEI, Value: "35342500000001"}:   true,
		{Type: types.TargetGPSI, Value: "4915123456789"}:   true,
	}
	if len(got) != len(want) {
		t.Fatalf("targetsOf returned %d ids, want %d: %+v", len(got), len(want), got)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected identifier %+v", id)
		}
	}
	// An unmappable/absent identifier is not emitted.
	if ids := targetsOf(&smfctx.SMContext{Supi: "suci-0-262-01-..."}); len(ids) != 0 {
		t.Errorf("unmappable SUPI produced identifiers: %+v", ids)
	}
}

func TestEstablishmentMapping(t *testing.T) {
	est := smfEstablishment(targetSM())
	if supi, ok := est.SUPI.(iri.IMSI); !ok || supi != "262019876543210" {
		t.Errorf("SUPI = %#v", est.SUPI)
	}
	if pei, ok := est.PEI.(iri.IMEISV); !ok || pei != "3534250000000151" {
		t.Errorf("PEI = %#v", est.PEI)
	}
	if est.PDUSessionID != 5 || est.PDUSessionType != iri.PDUSessionTypeIPv4 {
		t.Errorf("id=%d type=%d", est.PDUSessionID, est.PDUSessionType)
	}
	if est.DNN != testDNN || est.RequestType != iri.SMRequestInitial {
		t.Errorf("dnn=%q req=%d", est.DNN, est.RequestType)
	}
	if est.SNSSAI.SliceServiceType != 1 || !bytes.Equal(est.SNSSAI.SliceDifferentiator, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("snssai = %+v", est.SNSSAI)
	}
}

func TestModificationAndReleaseMapping(t *testing.T) {
	mod := smfModification(targetSM())
	if mod.RequestType != iri.SMRequestModification || mod.PDUSessionID != 5 {
		t.Errorf("modification req=%d id=%d", mod.RequestType, mod.PDUSessionID)
	}
	rel := smfRelease(targetSM())
	if supi, ok := rel.SUPI.(iri.IMSI); !ok || supi != "262019876543210" || rel.PDUSessionID != 5 {
		t.Errorf("release supi=%#v id=%d", rel.SUPI, rel.PDUSessionID)
	}
}

func TestSnssai(t *testing.T) {
	// nil S-NSSAI → zero value.
	if s := snssai(&smfctx.SMContext{}); s.SliceServiceType != 0 || s.SliceDifferentiator != nil {
		t.Errorf("nil snssai = %+v, want zero", s)
	}
	// SST only (no SD).
	if s := snssai(&smfctx.SMContext{Snssai: &models.Snssai{Sst: 2}}); s.SliceServiceType != 2 || s.SliceDifferentiator != nil {
		t.Errorf("sst-only = %+v", s)
	}
	// SST + SD.
	sd := "0a0b0c"
	s := snssai(&smfctx.SMContext{Snssai: &models.Snssai{Sst: 1, Sd: &sd}})
	if s.SliceServiceType != 1 || !bytes.Equal(s.SliceDifferentiator, []byte{0x0a, 0x0b, 0x0c}) {
		t.Errorf("sst+sd = %+v", s)
	}
}

func TestServingUPFTEIDNilTunnel(t *testing.T) {
	// No tunnel yet → a zero F-TEID (best-effort), never a panic.
	if f := servingUPFTEID(&smfctx.SMContext{}); f.TEID != 0 || f.IPv4Address != nil || f.IPv6Address != nil {
		t.Errorf("nil-tunnel F-TEID = %+v, want zero", f)
	}
}

// TestGTPTunnelInfoIsReported covers a field TS 33.128 marks mandatory in three
// records and that this POI did not emit at all. It is worth its own test for a
// reason that generalises: the published ASN.1 module marks gTPTunnelInfo
// OPTIONAL, so every record encoded and decoded cleanly without it and no
// round-trip, golden or live-decode check could ever have noticed. Only the
// payload tables say it is mandatory.
//
// For SMFPDUSessionModification it is the sole mandatory field, so without it
// that record satisfies none of its mandatory set.
func TestGTPTunnelInfoIsReported(t *testing.T) {
	sc := targetSM()
	node := smfctx.NewDataPathNode()
	node.UpLinkTunnel.TEID = 0x01020304
	node.UPF = &smfctx.UPF{NodeID: smfctx.NodeID{NodeIdType: smfctx.NodeIdTypeIpv4Address, NodeIdValue: net.ParseIP("10.100.0.7").To4()}}
	sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{1: &smfctx.DataPath{IsDefaultPath: true, FirstDPNode: node}}}

	want := servingUPFTEID(sc)
	if want.TEID == 0 {
		t.Fatal("fixture produced no uplink F-TEID, so this test would prove nothing")
	}

	// Every record whose payload table marks the field mandatory must carry it,
	// and each is asserted separately: a helper shared by three call sites is
	// exactly the shape where one call site silently gets it wrong.
	if got := smfEstablishment(sc).GTPTunnelInfo.FiveGSGTPTunnels.ULNGUUPTunnelInformation; got.TEID != want.TEID {
		t.Errorf("establishment gTPTunnelInfo TEID = %d, want %d", got.TEID, want.TEID)
	}
	if got := smfStartOfInterception(sc).GTPTunnelInfo.FiveGSGTPTunnels.ULNGUUPTunnelInformation; got.TEID != want.TEID {
		t.Errorf("start-of-interception gTPTunnelInfo TEID = %d, want %d", got.TEID, want.TEID)
	}
	mod := smfModification(sc).GTPTunnelInfo.FiveGSGTPTunnels.ULNGUUPTunnelInformation
	if mod.TEID != want.TEID {
		t.Errorf("modification gTPTunnelInfo TEID = %d, want %d", mod.TEID, want.TEID)
	}
	if !bytes.Equal(mod.IPv4Address, want.IPv4Address) {
		t.Errorf("modification gTPTunnelInfo address = %v, want %v", mod.IPv4Address, want.IPv4Address)
	}

	// With no data path the POI has no tunnel to report, so the field stays empty
	// rather than reporting a tunnel with endpoint zero, and the codec refuses the
	// record: the payload tables make the field mandatory.
	empty := smfModification(&smfctx.SMContext{}).GTPTunnelInfo.FiveGSGTPTunnels.ULNGUUPTunnelInformation
	if empty.TEID != 0 || empty.IPv4Address != nil || empty.IPv6Address != nil {
		t.Errorf("tunnel-less context produced %+v, want a zero F-TEID", empty)
	}
}

func TestCorrelationOfNilTunnel(t *testing.T) {
	// No PFCP session yet → a zero correlation ID (best-effort), never a panic.
	// The populated value (serving UPF F-SEID, big-endian, matching the UPF's X3)
	// is exercised end-to-end by the datapath integration test.
	if corr := correlationOf(&smfctx.SMContext{}); corr != ([8]byte{}) {
		t.Errorf("nil-tunnel correlation = % x, want zero", corr)
	}
	if seid := servingUPFSEID(&smfctx.SMContext{}); seid != 0 {
		t.Errorf("nil-tunnel serving UPF SEID = %d, want 0", seid)
	}
}

func TestParseXID(t *testing.T) {
	x := parseXID("50b93d1e-1b53-4d63-aacb-e4d99811bc0b")
	if x[0] != 0x50 || x[15] != 0x0b {
		t.Errorf("parseXID = % x", x)
	}
	if got := parseXID("not-a-uuid"); got != ([16]byte{}) {
		t.Errorf("bad XID = % x, want zero", got)
	}
}

// ccSession builds a minimal one-node PDU session whose default uplink PDR
// points at far, so ApplyCCTrigger has a forwarding FAR to act on.
//
// The UPF has answered its establishment: applyCC re-derives only the FARs of a UPF with a
// PFCP session (forEachEstablishedForwardingFAR).
func ccSession(far *smfctx.FAR) *smfctx.SMContext {
	const upf = "10.0.0.1"
	node := smfctx.NewDataPathNode()
	node.UPF = &smfctx.UPF{NodeID: *smfctx.NewNodeID(upf)}
	node.UpLinkTunnel.PDR["default"] = &smfctx.PDR{FAR: far}
	return &smfctx.SMContext{
		Supi:   testSUPI,
		Tunnel: &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{1: &smfctx.DataPath{FirstDPNode: node}}},
		PFCPContext: map[string]*smfctx.PFCPSessionContext{
			upf: {NodeID: node.UPF.NodeID, LocalSEID: 0x1234, RemoteSEID: 0x5678},
		},
	}
}

// activateWith installs sub with a store holding task, and cleans up after.
func activateWith(t *testing.T, task types.InterceptTask) {
	t.Helper()
	st := store.New()
	if !st.Activate(task) {
		t.Fatalf("failed to activate test task %+v", task)
	}
	active.Store(&subsystem{store: st})
	t.Cleanup(func() { active.Store(nil) })
}

func TestApplyCCTriggerSetsDuplication(t *testing.T) {
	activateWith(t, types.InterceptTask{
		XID:      testTaskCC,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI, types.ProductCC},
		State:    types.TaskActive,
	})

	far := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}}
	ApplyCCTrigger(ccSession(far))

	if !far.ApplyAction.Dupl {
		t.Fatal("CC-tasked session: DUPL not set on forwarding FAR")
	}
	if far.DuplicatingParameters == nil ||
		far.DuplicatingParameters.DestinationInterface.InterfaceValue != smfctx.DestinationInterfaceLIFunction {
		t.Errorf("DuplicatingParameters = %+v, want LI Function", far.DuplicatingParameters)
	}
}

func TestApplyCCTriggerClearsWhenNotCCTasked(t *testing.T) {
	// An IRI-only task must not trigger CC duplication, and must clear a FAR that
	// is already duplicating.
	activateWith(t, types.InterceptTask{
		XID:      testTaskIRI,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	})

	far := &smfctx.FAR{
		ApplyAction:           smfctx.ApplyAction{Forw: true, Dupl: true},
		DuplicatingParameters: &smfctx.DuplicatingParameters{},
	}
	ApplyCCTrigger(ccSession(far))

	if far.ApplyAction.Dupl || far.DuplicatingParameters != nil {
		t.Errorf("IRI-only task must clear DUPL: dupl=%v params=%+v", far.ApplyAction.Dupl, far.DuplicatingParameters)
	}
}

func TestApplyCCTriggerSkipsNonForwardingFAR(t *testing.T) {
	activateWith(t, types.InterceptTask{
		XID:      testTaskCC,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	})

	// A drop/buffer FAR (not forwarding) must never be marked for duplication.
	far := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Drop: true}}
	ApplyCCTrigger(ccSession(far))
	if far.ApplyAction.Dupl {
		t.Error("non-forwarding FAR must not be duplicated")
	}
}

// TestApplyCCTriggerMarksInstalledFARForUpdate: when the trigger flips
// DUPL on an already-installed FAR (RULE_CREATE) — e.g. SendPFCPRules re-invoked
// for an established session on a ULCL add / HO path-switch — it must mark the FAR
// RULE_UPDATE, or the modification builder skips it and the flip never reaches the
// UPF. An establishment FAR (RULE_INITIAL) must be left as-is (sent as Create).
func TestApplyCCTriggerMarksInstalledFARForUpdate(t *testing.T) {
	activateWith(t, types.InterceptTask{
		XID:      testTaskCC,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	})

	installed := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}, State: smfctx.RULE_CREATE}
	ApplyCCTrigger(ccSession(installed))
	if !installed.ApplyAction.Dupl {
		t.Fatal("installed FAR: DUPL not set")
	}
	if installed.State != smfctx.RULE_UPDATE {
		t.Errorf("installed FAR State = %v, want RULE_UPDATE so the flip is sent", installed.State)
	}

	fresh := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}, State: smfctx.RULE_INITIAL}
	ApplyCCTrigger(ccSession(fresh))
	if fresh.State != smfctx.RULE_INITIAL {
		t.Errorf("establishment FAR State = %v, want RULE_INITIAL (sent as Create FAR)", fresh.State)
	}
}

// TestApplyCCTriggerRecoversAfterFARReactivation. Several SMF paths
// reconfigure a FAR by replacing its whole ApplyAction — the downlink FAR becoming
// a forwarding FAR once the RAN tunnel is known, a data-notification reactivating
// the uplink FAR, a ULCL path activation — and each of those assignments sets
// Dupl false.
//
// Two consequences, both silent. A downlink FAR is not a forwarding FAR at
// establishment, so the trigger skips it and the interception carries uplink only
// until something re-evaluates. And on a session already tasked, the same
// assignment switches duplication back off. The trigger is authoritative over
// DUPL, so calling it after any such reconfiguration restores the correct state;
// this pins that it actually does.
func TestApplyCCTriggerRecoversAfterFARReactivation(t *testing.T) {
	activateWith(t, types.InterceptTask{
		XID:      testTaskCC,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	})

	// A downlink FAR as created at establishment: buffering, not forwarding.
	far := &smfctx.FAR{
		ApplyAction: smfctx.ApplyAction{Buff: true, Nocp: true},
		State:       smfctx.RULE_INITIAL,
	}
	sc := ccSession(far)

	ApplyCCTrigger(sc)
	if far.ApplyAction.Dupl {
		t.Error("a buffering FAR must not be duplicated")
	}

	// The RAN tunnel arrives and the FAR becomes forwarding, the assignment
	// clearing Dupl as the real code does.
	far.ApplyAction = smfctx.ApplyAction{Forw: true}
	far.State = smfctx.RULE_UPDATE

	ApplyCCTrigger(sc)
	if !far.ApplyAction.Dupl {
		t.Fatal("downlink FAR: DUPL not applied once it became forwarding — the MDF would receive uplink only")
	}
	if far.DuplicatingParameters == nil {
		t.Error("downlink FAR: Duplicating Parameters missing")
	}

	// And on an already-duplicating FAR, a reactivation that clears Dupl must be
	// recovered rather than left off.
	far.ApplyAction = smfContextApplyActionForwardOnly()
	ApplyCCTrigger(sc)
	if !far.ApplyAction.Dupl {
		t.Error("duplication was not restored after the FAR was reactivated")
	}
}

// smfContextApplyActionForwardOnly is the shape the SMF assigns when it
// reactivates forwarding: everything else, including Dupl, reset to false.
func smfContextApplyActionForwardOnly() smfctx.ApplyAction {
	return smfctx.ApplyAction{Forw: true}
}

// TestReportEstablishmentEmitsOnce covers that guard. The record is now emitted
// from the PFCP establishment-response handler, which runs once per UPF, so a
// session spanning several UPFs would otherwise produce one record per response.
func TestReportEstablishmentEmitsOnce(t *testing.T) {
	capture := &captureSender{}
	st := store.New()
	st.Activate(types.InterceptTask{
		XID:      testTaskIRI,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	})
	active.Store(&subsystem{store: st, senderFor: func(string) sender { return capture }, mdf2: configuredMDF2, ids: x2x3.NewIdentity(testNEID, smfInterceptionPoint), neID: "ne"})
	t.Cleanup(func() { active.Store(nil) })

	sc := targetSM()
	ReportEstablishment(sc)
	ReportEstablishment(sc) // a second UPF's response must not emit again

	if len(capture.pdus) != 1 {
		t.Errorf("establishment emitted %d records, want exactly 1", len(capture.pdus))
	}
}

// TestReportReleaseDeduplicates: a teardown that reaches both the
// update-initiated delete and the dedicated release handler must emit only one
// SMFPDUSessionRelease xIRI.
func TestReportReleaseDeduplicates(t *testing.T) {
	capture := &captureSender{}
	st := store.New()
	st.Activate(types.InterceptTask{
		XID:      testTaskIRI,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	})
	active.Store(&subsystem{store: st, senderFor: func(string) sender { return capture }, mdf2: configuredMDF2, ids: x2x3.NewIdentity(testNEID, smfInterceptionPoint), neID: "ne"})
	t.Cleanup(func() { active.Store(nil) })

	sc := targetSM()
	ReportRelease(sc)
	ReportRelease(sc) // second call for the same teardown must be a no-op
	if len(capture.pdus) != 1 {
		t.Fatalf("release emitted %d xIRI, want exactly 1 (dedupe)", len(capture.pdus))
	}
}

func TestApplyCCTriggerInactiveNoop(t *testing.T) {
	// With LI inactive, the trigger must not touch the session (and not panic on
	// a nil tunnel).
	far := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}}
	ApplyCCTrigger(ccSession(far))
	if far.ApplyAction.Dupl {
		t.Error("LI inactive: DUPL must not be set")
	}
	ApplyCCTrigger(&smfctx.SMContext{}) // nil tunnel, must not panic
}

// TestDeliveryIsolation checks multi-agency isolation on the SMF IRI path: two
// agencies tasking the same target each receive exactly their own xIRI tagged
// with their own XID (no cross-delivery), and a CC-only warrant never leaks into
// IRI (X2) delivery.
func TestDeliveryIsolation(t *testing.T) {
	const (
		xidA  = "aaaaaaaa-0000-0000-0000-000000000001"
		xidB  = "bbbbbbbb-0000-0000-0000-000000000002"
		xidCC = "cccccccc-0000-0000-0000-000000000003"
	)
	target := types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"}
	st := store.New()
	st.Activate(types.InterceptTask{XID: xidA, Targets: []types.TargetIdentifier{target}, Products: []types.ProductType{types.ProductIRI}, State: types.TaskActive})
	st.Activate(types.InterceptTask{XID: xidB, Targets: []types.TargetIdentifier{target}, Products: []types.ProductType{types.ProductIRI}, State: types.TaskActive})
	st.Activate(types.InterceptTask{XID: xidCC, Targets: []types.TargetIdentifier{target}, Products: []types.ProductType{types.ProductCC}, State: types.TaskActive})

	capture := &captureSender{}
	active.Store(&subsystem{store: st, senderFor: func(string) sender { return capture }, mdf2: configuredMDF2, ids: x2x3.NewIdentity(testNEID, smfInterceptionPoint)})
	t.Cleanup(func() { active.Store(nil) })

	ReportEstablishment(targetSM())

	if len(capture.pdus) != 2 {
		t.Fatalf("delivered %d xIRI PDUs, want 2 (the two IRI agencies; CC-only excluded)", len(capture.pdus))
	}
	count := map[[16]byte]int{}
	for _, p := range capture.pdus {
		count[p.XID]++
	}
	if count[parseXID(xidA)] != 1 || count[parseXID(xidB)] != 1 {
		t.Errorf("each IRI agency must receive its own xIRI exactly once; XID counts = %v", count)
	}
	if count[parseXID(xidCC)] != 0 {
		t.Error("CC-only warrant leaked into IRI (X2) delivery")
	}
}

// TestEncodeAllEvents verifies every SMF xIRI a reporter can produce encodes
// through the real TS 33.128 encoder without error — mandatory members present,
// CHOICE arms registered. The correctness check a pure-mapping test can't give.
func TestEncodeAllEvents(t *testing.T) {
	sc := targetSM()
	events := map[string]any{
		"establishment":         smfEstablishment(sc),
		"modification":          smfModification(sc),
		"release":               smfRelease(sc),
		"start-of-interception": smfStartOfInterception(sc),
	}
	for name, ev := range events {
		if _, err := iri.EncodeXIRI(ev); err != nil {
			t.Errorf("encode %s: %v", name, err)
		}
	}
}

// subWith returns a subsystem backed by a store holding the given tasks (no X1
// server, no client) — for exercising the mid-session helpers directly.
func subWith(t *testing.T, tasks ...types.InterceptTask) *subsystem {
	t.Helper()
	st := store.New()
	for _, task := range tasks {
		if !st.Activate(task) {
			t.Fatalf("activate %+v", task)
		}
	}
	sub := &subsystem{store: st}
	waitForScans(t, sub)

	return sub
}

// TestApplyCCActivation covers the mid-session CC switch-on: a CC task
// targeting a live session sets DUPL and marks the FAR RULE_UPDATE so a PFCP
// modification re-sends it, and it is idempotent (a second call is a no-op).
func TestApplyCCActivation(t *testing.T) {
	target := types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"}
	sub := subWith(t, types.InterceptTask{
		XID: "cc", Targets: []types.TargetIdentifier{target},
		Products: []types.ProductType{types.ProductCC}, State: types.TaskActive,
	})

	far := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}, State: smfctx.RULE_CREATE}
	sc := ccSession(far)

	if !sub.applyCC(sc) {
		t.Fatal("applyCC must report a change when switching duplication on")
	}
	if !far.ApplyAction.Dupl || far.State != smfctx.RULE_UPDATE {
		t.Errorf("want DUPL set + RULE_UPDATE, got dupl=%v state=%v", far.ApplyAction.Dupl, far.State)
	}
	if sub.applyCC(sc) {
		t.Error("applyCC must be idempotent: no change on the second call")
	}
}

// TestApplyCCDeactivation covers the mid-session CC switch-off: with no
// CC task left in the store, applyCC clears DUPL on a FAR that was duplicating and
// marks it RULE_UPDATE so the clear is pushed to the UPF.
func TestApplyCCDeactivation(t *testing.T) {
	sub := subWith(t) // empty store: target is no longer CC-tasked

	far := &smfctx.FAR{
		ApplyAction:           smfctx.ApplyAction{Forw: true, Dupl: true},
		DuplicatingParameters: &smfctx.DuplicatingParameters{},
		State:                 smfctx.RULE_CREATE,
	}
	sc := ccSession(far)

	if !sub.applyCC(sc) {
		t.Fatal("applyCC must report a change when clearing duplication")
	}
	if far.ApplyAction.Dupl || far.DuplicatingParameters != nil || far.State != smfctx.RULE_UPDATE {
		t.Errorf("want DUPL cleared + RULE_UPDATE, got dupl=%v params=%v state=%v",
			far.ApplyAction.Dupl, far.DuplicatingParameters, far.State)
	}
}

// TestApplyCCMultiAgency: while any CC task still targets the session, deactivating
// one CC warrant must leave duplication on (no change reported).
func TestApplyCCMultiAgency(t *testing.T) {
	target := types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"}
	// One CC task remains after the other agency's warrant was removed.
	sub := subWith(t, types.InterceptTask{
		XID: "cc-b", Targets: []types.TargetIdentifier{target},
		Products: []types.ProductType{types.ProductCC}, State: types.TaskActive,
	})

	far := &smfctx.FAR{
		ApplyAction:           smfctx.ApplyAction{Forw: true, Dupl: true},
		DuplicatingParameters: &smfctx.DuplicatingParameters{},
		State:                 smfctx.RULE_CREATE,
	}
	if sub.applyCC(ccSession(far)) {
		t.Error("duplication must stay on while another CC warrant targets the session")
	}
	if !far.ApplyAction.Dupl {
		t.Error("DUPL must remain set for the still-tasked target")
	}
}

func TestSessionTargets(t *testing.T) {
	sc := ccSession(&smfctx.FAR{}) // Supi = imsi-262019876543210
	if !sessionTargets(types.InterceptTask{Targets: []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}}}, sc) {
		t.Error("a SUPI target must match the session's SUPI")
	}
	if sessionTargets(types.InterceptTask{Targets: []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "111111111111111"}}}, sc) {
		t.Error("a non-matching SUPI must not match")
	}
	// All of a task's criteria must match (TS 103 221-1 table 6.2.1.2-1). This predicate decides
	// the activation scan, a record's re-validation and whether a session is covered, so a task
	// naming this SUPI and a GPSI the session does not present must not reach any of them.
	if sessionTargets(types.InterceptTask{Targets: []types.TargetIdentifier{
		{Type: types.TargetSUPI, Value: "262019876543210"},
		{Type: types.TargetGPSI, Value: "4915100000000"},
	}}, sc) {
		t.Error("a task whose GPSI the session does not present matched on its SUPI alone")
	}
}

// TestEstablishmentReportsTheRealRequestAndAccessType: both fields are mandatory
// in the TS 33.128 establishment record and both come from the session. Hard-coded,
// every session would reach the law-enforcement agency described as an initial
// request over 3GPP access — hiding an emergency session, and misstating whether the
// UE asked for a new session or resumed an existing one.
func TestEstablishmentReportsTheRealRequestAndAccessType(t *testing.T) {
	cases := []struct {
		request models.RequestType
		access  models.AccessType
		wantReq iri.FiveGSMRequestType
		wantAcc iri.AccessType
	}{
		{models.REQUESTTYPE_INITIAL_REQUEST, models.ACCESSTYPE__3_GPP_ACCESS, iri.SMRequestInitial, iri.AccessThreeGPP},
		{models.REQUESTTYPE_EXISTING_PDU_SESSION, models.ACCESSTYPE__3_GPP_ACCESS, iri.SMRequestExisting, iri.AccessThreeGPP},
		{models.REQUESTTYPE_INITIAL_EMERGENCY_REQUEST, models.ACCESSTYPE__3_GPP_ACCESS, iri.SMRequestInitialEmergency, iri.AccessThreeGPP},
		{models.REQUESTTYPE_EXISTING_EMERGENCY_PDU_SESSION, models.ACCESSTYPE_NON_3_GPP_ACCESS, iri.SMRequestExistingEmergency, iri.AccessNonThreeGPP},
		// An unset request type is the closest thing to "initial" available, but the
		// access type must still be reported as configured.
		{"", models.ACCESSTYPE_NON_3_GPP_ACCESS, iri.SMRequestInitial, iri.AccessNonThreeGPP},
	}

	for _, c := range cases {
		sc := targetSM()
		sc.RequestType = c.request
		sc.AnType = c.access

		rec := smfEstablishment(sc)
		if rec.RequestType != c.wantReq {
			t.Errorf("RequestType for %q = %d, want %d", c.request, rec.RequestType, c.wantReq)
		}
		if rec.AccessType != c.wantAcc {
			t.Errorf("AccessType for %q = %d, want %d", c.access, rec.AccessType, c.wantAcc)
		}

		// The modification and start-of-interception records carry the same access
		// type; their request types are fixed by what the record means.
		if got := smfModification(sc).AccessType; got != c.wantAcc {
			t.Errorf("modification AccessType for %q = %d, want %d", c.access, got, c.wantAcc)
		}
		if got := smfStartOfInterception(sc).AccessType; got != c.wantAcc {
			t.Errorf("start-of-interception AccessType for %q = %d, want %d", c.access, got, c.wantAcc)
		}
	}
}

// configuredMDF2 stands in for the endpoint an SMF is configured with. It is deliberately
// not any task's own destination in the tests below, so that "delivered to the task's
// endpoint" and "delivered to configuration" are distinguishable outcomes — with one
// address they are not, which is why this defect survived a passing suite.
const configuredMDF2 = "10.0.60.99:42069"

// addressCapture records what was delivered and where.
type addressCapture struct {
	mu   sync.Mutex
	sent map[string][][16]byte
}

func newAddressCapture() *addressCapture {
	return &addressCapture{sent: map[string][][16]byte{}}
}

func (c *addressCapture) senderFor(addr string) sender {
	return senderFunc(func(p *x2x3.PDU) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.sent[addr] = append(c.sent[addr], p.XID)

		return nil
	})
}

type senderFunc func(*x2x3.PDU) error

func (f senderFunc) Send(p *x2x3.PDU) error { return f(p) }

// TestXIRIGoesToTheDestinationsTheTaskNamed is the SMF half of the conformance fix, and
// the same assertion as the AMF's: two warrants provisioned to two agencies, and neither
// agency receives the other's session.
func TestXIRIGoesToTheDestinationsTheTaskNamed(t *testing.T) {
	const (
		xidA    = "aaaaaaaa-0000-0000-0000-000000000001"
		xidB    = "bbbbbbbb-0000-0000-0000-000000000002"
		agencyA = testDestinationAddr
		agencyB = "10.0.60.123:42070"
	)
	target := types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"}
	st := store.New()
	for _, c := range []struct{ xid, addr string }{{xidA, agencyA}, {xidB, agencyB}} {
		st.Activate(types.InterceptTask{
			XID: types.XID(c.xid), Targets: []types.TargetIdentifier{target},
			Products:   []types.ProductType{types.ProductIRI},
			Deliveries: []types.DeliveryEndpoint{{Type: types.DeliveryX2, Address: c.addr}},
			State:      types.TaskActive,
		})
	}

	capture := newAddressCapture()
	active.Store(&subsystem{
		store: st, senderFor: capture.senderFor, mdf2: configuredMDF2, ids: x2x3.NewIdentity(testNEID, smfInterceptionPoint),
	})
	t.Cleanup(func() { active.Store(nil) })

	ReportEstablishment(targetSM())

	for _, c := range []struct{ addr, xid string }{{agencyA, xidA}, {agencyB, xidB}} {
		got := capture.sent[c.addr]
		if len(got) != 1 {
			t.Errorf("%s received %d records, want 1", c.addr, len(got))

			continue
		}
		if got[0] != parseXID(types.XID(c.xid)) {
			t.Errorf("%s received a record for a warrant it was not provisioned for", c.addr)
		}
	}
	if n := len(capture.sent[configuredMDF2]); n != 0 {
		t.Errorf("the configured endpoint received %d records, want 0: both tasks named a destination", n)
	}
}

// The configured endpoint still serves a task that named no destination, which is
// what every deployment predating the ListOfDIDs requirement relies on.
func TestATaskNamingNoDestinationFallsBackToConfiguration(t *testing.T) {
	st := store.New()
	st.Activate(types.InterceptTask{
		XID:      "aaaaaaaa-0000-0000-0000-000000000001",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	})

	capture := newAddressCapture()
	active.Store(&subsystem{
		store: st, senderFor: capture.senderFor, mdf2: configuredMDF2, ids: x2x3.NewIdentity(testNEID, smfInterceptionPoint),
	})
	t.Cleanup(func() { active.Store(nil) })

	ReportEstablishment(targetSM())

	if n := len(capture.sent[configuredMDF2]); n != 1 {
		t.Errorf("the configured endpoint received %d records, want 1", n)
	}
}

// TestDeliveryFaultIsReportedOnBothEdges covers this element's contribution to its own
// status answer, and all three assertions are the point rather than one of them.
//
// A probe stuck *off* leaves an element that has been failing to deliver for hours
// answering that nothing is wrong — invisible, and the reason an ADMF can ask at all. A
// probe stuck *on* makes every healthy element report itself faulty, which is noticed
// immediately and discredits the whole field; that is how this library's predecessor probe
// failed. So two of the three assertions below are about the probe staying quiet.
func TestDeliveryFaultIsReportedOnBothEdges(t *testing.T) {
	unreachable := 0
	sub := &subsystem{unreachable: func() (int, int) { return unreachable, 2 }}

	if fault := sub.deliveryFault(); fault != nil {
		t.Errorf("with both destinations reachable the element reports itself faulty: %q",
			fault.ErrorDescription)
	}

	unreachable = 1
	fault := sub.deliveryFault()
	if fault == nil {
		t.Fatal("with a destination unreachable the element reports no fault; an ADMF cannot " +
			"tell it apart from one delivering every record")
	}
	if !strings.Contains(fault.ErrorDescription, x1.NEIssueMDFUnreachable) {
		t.Errorf("the fault does not name the condition: %q", fault.ErrorDescription)
	}
	if !strings.Contains(fault.ErrorDescription, "1 of 2") {
		t.Errorf("the fault does not say how much is wrong: %q", fault.ErrorDescription)
	}

	// Nothing clears it. Delivery starts working and the next answer says so, which is the
	// property no design that remembers faults can offer.
	unreachable = 0
	if fault := sub.deliveryFault(); fault != nil {
		t.Errorf("the fault outlived the condition, with nothing having cleared it: %q",
			fault.ErrorDescription)
	}
}

// TestDeliveryFaultNamesNoDestination keeps the NE-level answer at NE level. This element
// may deliver two agencies' warrants to two MDF2s; TS 103 221-1 keeps an element's own
// status separate from per-destination and per-task faults, and an answer naming the failing
// address would put interception detail in a message that is not scoped to a warrant.
func TestDeliveryFaultNamesNoDestination(t *testing.T) {
	sub := &subsystem{unreachable: func() (int, int) { return 1, 2 }}

	fault := sub.deliveryFault()
	if fault == nil {
		t.Fatal("no fault reported for an unreachable destination")
	}
	for _, identity := range []string{"10.0.60.122", "42069", "208930100007488"} {
		if strings.Contains(fault.ErrorDescription, identity) {
			t.Errorf("the element's own status names %q; it must say how much is wrong, never whose",
				identity)
		}
	}
}

// TestDeliveryFaultWithNoAccountingIsSilent: an element that cannot say is not an element
// that is broken. The probe runs on the X1 request goroutine, where reporting a fault
// nobody observed — or panicking — are both worse than answering that nothing is known.
func TestDeliveryFaultWithNoAccountingIsSilent(t *testing.T) {
	if fault := (&subsystem{}).deliveryFault(); fault != nil {
		t.Errorf("an element with no delivery accounting reported a fault: %q", fault.ErrorDescription)
	}
}

// TestDestinationsInUseFollowsTheTasking is what keeps the delivery probe from sticking on.
//
// A delivery client outlives the warrant that created it — nothing removes one — so a
// destination whose last delivery failed and whose warrant was then deactivated could never
// be delivered to again, and nothing would ever clear it. The element would report itself
// faulty for the life of the process, including while holding no tasking at all, which is
// precisely the failure that gets a status answer ignored.
func TestDestinationsInUseFollowsTheTasking(t *testing.T) {
	st := store.New()
	sub := &subsystem{store: st, mdf2: "10.0.60.99:42069"}

	if got := sub.destinationsInUse(); len(got) != 0 {
		t.Errorf("an element holding no tasking delivers to %v, want nothing", got)
	}

	// A warrant naming its agency's own endpoint.
	st.Activate(types.InterceptTask{
		XID:      "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "208930100007488"}},
		Products: []types.ProductType{types.ProductIRI},
		Deliveries: []types.DeliveryEndpoint{
			{Type: types.DeliveryX2, Address: testDestinationAddr},
		},
	})
	if got := sub.destinationsInUse(); len(got) != 1 || got[0] != testDestinationAddr {
		t.Errorf("destinationsInUse() = %v, want the endpoint the warrant named", got)
	}

	// A warrant naming no destination is delivered to the configured endpoint, so that
	// is where product goes and what the probe must ask about.
	st.Activate(types.InterceptTask{
		XID:      "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "208930100007489"}},
		Products: []types.ProductType{types.ProductIRI},
	})
	got := sub.destinationsInUse()
	if len(got) != 2 {
		t.Fatalf("destinationsInUse() = %v, want both warrants' endpoints", got)
	}

	// Both warrants end. Whatever their delivery clients last established, this element no
	// longer delivers anywhere.
	st.Deactivate("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	st.Deactivate("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")
	if got := sub.destinationsInUse(); len(got) != 0 {
		t.Errorf("after every warrant was withdrawn the element still delivers to %v; a client "+
			"left failing there would report a fault nothing could clear", got)
	}
}

// TestUEEndpointMapping: the records carry the subject's own address as well as
// the serving UPF's tunnel endpoint, so an agency can tell what address the target
// is using. The two are different fields and must not be confused.
func TestUEEndpointMapping(t *testing.T) {
	sc := targetSM()

	est := smfEstablishment(sc)
	if len(est.UEEndpoint) != 1 {
		t.Fatalf("establishment uEEndpoint has %d entries, want 1", len(est.UEEndpoint))
	}
	v4, ok := est.UEEndpoint[0].(iri.IPv4Address)
	if !ok {
		t.Fatalf("establishment uEEndpoint[0] = %T, want iri.IPv4Address", est.UEEndpoint[0])
	}
	if !bytes.Equal(v4, iri.IPv4Address{10, 45, 0, 2}) {
		t.Errorf("establishment uEEndpoint = % x, want 0a 2d 00 02", v4)
	}

	soi := smfStartOfInterception(sc)
	if len(soi.UEEndpoint) != 1 {
		t.Fatalf("start-of-interception uEEndpoint has %d entries, want 1", len(soi.UEEndpoint))
	}
	if !bytes.Equal(soi.UEEndpoint[0].(iri.IPv4Address), v4) {
		t.Error("the two records disagree on the session's address")
	}
}

// TestUEEndpointIsNotTheTunnelEndpoint: gTPTunnelID comes from the serving UPF,
// uEEndpoint from the subject's session. Reporting the UPF's address as the
// subject's would be worse than reporting nothing, because it looks like an answer.
func TestUEEndpointIsNotTheTunnelEndpoint(t *testing.T) {
	sc := targetSM()
	est := smfEstablishment(sc)
	tunnel := est.GTPTunnelID.IPv4Address
	ue := []byte(est.UEEndpoint[0].(iri.IPv4Address))
	if tunnel != nil && bytes.Equal(tunnel, ue) {
		t.Errorf("uEEndpoint (% x) equals the tunnel endpoint (% x); they are different addresses", ue, tunnel)
	}
}

// TestUEEndpointAbsentAddress: a session with no address assigned must omit the
// optional field on the establishment record rather than emit an empty list. The
// start-of-interception record still reports the session, with an empty uEEndpoint: TS
// 33.128 table 6.2.3-4 makes it conditional ("if available"), and the module's SEQUENCE
// OF has no OPTIONAL, so an empty list is its only form for a session with no address.
func TestUEEndpointAbsentAddress(t *testing.T) {
	sc := targetSM()
	sc.PDUAddress = nil

	if got := ueEndpoint(sc); got != nil {
		t.Errorf("ueEndpoint with no address = %#v, want nil", got)
	}

	est := smfEstablishment(sc)
	if est.UEEndpoint != nil {
		t.Errorf("establishment uEEndpoint = %#v, want nil (field omitted)", est.UEEndpoint)
	}
	if _, err := iri.EncodeXIRI(est); err != nil {
		t.Errorf("establishment must still encode without an address: %v", err)
	}

	// The start-of-interception record is still produced, stating that no address is
	// available rather than leaving the session unreported.
	if _, err := iri.EncodeXIRI(smfStartOfInterception(sc)); err != nil {
		t.Errorf("start-of-interception must encode for a session with no address: %v", err)
	}
}

// TestUEEndpointIPv6 checks the v6 arm maps through, since PDUAddress carries
// either family.
func TestUEEndpointIPv6(t *testing.T) {
	sc := targetSM()
	sc.PDUAddress = &smfctx.UeIpAddr{Ip: net.ParseIP("2001:db8::1")}

	est := smfEstablishment(sc)
	if len(est.UEEndpoint) != 1 {
		t.Fatalf("uEEndpoint has %d entries, want 1", len(est.UEEndpoint))
	}
	v6, ok := est.UEEndpoint[0].(iri.IPv6Address)
	if !ok {
		t.Fatalf("uEEndpoint[0] = %T, want iri.IPv6Address", est.UEEndpoint[0])
	}
	if len(v6) != 16 {
		t.Errorf("IPv6Address is %d bytes, want 16", len(v6))
	}
}

// activateIRISub installs a subsystem holding tasks and delivering everything to
// snd, wired the way the production one is.
func activateIRISub(t *testing.T, snd sender, tasks ...types.InterceptTask) {
	t.Helper()
	st := store.New()
	for _, task := range tasks {
		if !st.Activate(task) {
			t.Fatalf("activate %+v", task)
		}
	}
	active.Store(&subsystem{
		store:     st,
		senderFor: func(string) sender { return snd },
		mdf2:      configuredMDF2,
		ids:       x2x3.NewIdentity(testNEID, smfInterceptionPoint),
		neID:      "ne",
	})
	t.Cleanup(func() { active.Store(nil) })
}

// iriTask is an IRI warrant for the standard test target, delivering to one
// address so a captureSender sees everything it produces.
func iriTask() types.InterceptTask {
	return types.InterceptTask{
		XID:        types.XID("aaaaaaaa-0000-0000-0000-000000000001"),
		Targets:    []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products:   []types.ProductType{types.ProductIRI},
		Deliveries: []types.DeliveryEndpoint{{Type: types.DeliveryX2, Address: testDestinationAddr}},
		State:      types.TaskActive,
	}
}

// decodeOne decodes the single xIRI a capture holds, and fails if there is not
// exactly one — "at least one record arrived" is the assertion that let an empty
// uEEndpoint through for months.
func decodeOne(t *testing.T, capture *captureSender) wireRecord {
	t.Helper()
	if len(capture.pdus) != 1 {
		t.Fatalf("captured %d PDUs, want exactly 1", len(capture.pdus))
	}
	return decodeRecords(t, capture)[0]
}

// unsuccessfulSM is decodeOne for an SMFUnsuccessfulProcedure, failing on any other record.
func unsuccessfulSM(t *testing.T, capture *captureSender) wireRecord {
	t.Helper()
	rec := decodeOne(t, capture)
	if rec.event != eventUnsuccessfulSMProcedure {
		t.Fatalf("delivered XIRIEvent [%d], want unsuccessfulSMProcedure [%d]", rec.event, eventUnsuccessfulSMProcedure)
	}
	return rec
}

// TestUnsuccessfulProcedureReportsRefusedEstablishment covers the sixteen
// establishment paths: a refused session for a tasked target produces a
// record naming the procedure, the cause and the initiator.
func TestUnsuccessfulProcedureReportsRefusedEstablishment(t *testing.T) {
	capture := &captureSender{}
	activateIRISub(t, capture, iriTask())

	ReportEstablishmentReject(targetSM(), nasMessage.Cause5GSMInsufficientResources)

	rec := unsuccessfulSM(t, capture)
	if got := integer(t, rec.member(t, 1)); got != int64(iri.SMFFailedPDUSessionEstablishment) {
		t.Errorf("failedProcedureType = %d, want pDUSessionEstablishment(1)", got)
	}
	if got := integer(t, rec.member(t, 2)); got != int64(nasMessage.Cause5GSMInsufficientResources) {
		t.Errorf("failureCause = %d, want %d", got, nasMessage.Cause5GSMInsufficientResources)
	}
	if got := integer(t, rec.member(t, 3)); got != int64(iri.InitiatorNetwork) {
		t.Errorf("initiator = %d, want network(2) — the SMF is refusing", got)
	}
	if supi := imsiOf(t, rec.member(t, 5)); supi != "262019876543210" {
		t.Errorf("SUPI = %q", supi)
	}
}

// TestUnsuccessfulProcedureReportsRefusedRelease covers the other three sites:
// same record, different procedure.
func TestUnsuccessfulProcedureReportsRefusedRelease(t *testing.T) {
	capture := &captureSender{}
	activateIRISub(t, capture, iriTask())

	ReportReleaseReject(targetSM(), 5, nasMessage.Cause5GSMRequestRejectedUnspecified)

	rec := unsuccessfulSM(t, capture)
	if got := integer(t, rec.member(t, 1)); got != int64(iri.SMFFailedPDUSessionRelease) {
		t.Errorf("failedProcedureType = %d, want pDUSessionRelease(3)", got)
	}
	if got := integer(t, rec.member(t, 2)); got != int64(nasMessage.Cause5GSMRequestRejectedUnspecified) {
		t.Errorf("failureCause = %d", got)
	}
}

// TestARefusedReleaseNamesTheSessionTheRequestNamed: a release naming another session than
// the context's is refused, and the record describes that refusal. It names the requested
// session, and carries none of the context session's own attributes, which describe a
// session that is still up. A release refused for the context's own session keeps them. No
// release record carries a request type: table 6.2.3-5 sets none for a PDU SESSION RELEASE
// REJECT.
func TestARefusedReleaseNamesTheSessionTheRequestNamed(t *testing.T) {
	const (
		tagPDUSessionID = 9
		tagUEEndpoint   = 10
		tagDNN          = 12
		tagRequestType  = 15
		tagAccessType   = 16
		tagRATType      = 17
	)
	// A context whose access type and RAT type are both set, so that each subtest can tell
	// an attribute left out from one that was never there.
	contextSM := func() *smfctx.SMContext {
		sc := targetSM()
		sc.RatType = models.RATTYPE_NR
		return sc
	}

	t.Run("another session", func(t *testing.T) {
		capture := &captureSender{}
		activateIRISub(t, capture, iriTask())

		ReportReleaseReject(contextSM(), 6, nasMessage.Cause5GSMInvalidPDUSessionIdentity)

		rec := unsuccessfulSM(t, capture)
		if got := integer(t, rec.member(t, tagPDUSessionID)); got != 6 {
			t.Errorf("pDUSessionID = %d, want 6, the session the refused request named, not the context's 5", got)
		}
		for _, tag := range []int{tagUEEndpoint, tagDNN, tagAccessType, tagRATType, tagRequestType} {
			if _, ok := rec.members[tag]; ok {
				t.Errorf("member [%d] present: it describes the context's session 5, not the session the request named", tag)
			}
		}
		if supi := imsiOf(t, rec.member(t, 5)); supi != "262019876543210" {
			t.Errorf("SUPI = %q, want the subscriber's", supi)
		}
	})

	t.Run("this session", func(t *testing.T) {
		capture := &captureSender{}
		activateIRISub(t, capture, iriTask())

		ReportReleaseReject(contextSM(), 5, nasMessage.Cause5GSMRequestRejectedUnspecified)

		rec := unsuccessfulSM(t, capture)
		if got := integer(t, rec.member(t, tagPDUSessionID)); got != 5 {
			t.Errorf("pDUSessionID = %d, want 5", got)
		}
		for _, tag := range []int{tagUEEndpoint, tagDNN, tagAccessType, tagRATType} {
			if _, ok := rec.members[tag]; !ok {
				t.Errorf("member [%d] absent: the refused release names this context's session, whose attributes it is", tag)
			}
		}
		if _, ok := rec.members[tagRequestType]; ok {
			t.Errorf("requestType present on a refused release; table 6.2.3-5 sets none")
		}
	})
}

// TestARefusedModificationIsReportedAsAModificationRequest: table 6.2.3-5 has a refused
// modification reported with request type "modification request", whatever request type
// established the session.
func TestARefusedModificationIsReportedAsAModificationRequest(t *testing.T) {
	sc := targetSM()
	sc.RequestType = models.REQUESTTYPE_EXISTING_PDU_SESSION

	if got := smfUnsuccessful(sc, iri.SMFFailedPDUSessionModification, 26).RequestType; got != iri.SMRequestModification {
		t.Errorf("requestType = %d, want modification request (%d)", got, iri.SMRequestModification)
	}
	if got := smfUnsuccessful(sc, iri.SMFFailedPDUSessionEstablishment, 26).RequestType; got != iri.SMRequestExisting {
		t.Errorf("establishment requestType = %d, want the session's own (%d)", got, iri.SMRequestExisting)
	}
}

// TestUnsuccessfulProcedureSilentForUntaskedSubscriber is the other half of 3.1,
// and the one that matters for undetectability: a refusal for someone who is not
// under warrant must produce nothing at all.
func TestUnsuccessfulProcedureSilentForUntaskedSubscriber(t *testing.T) {
	capture := &captureSender{}
	activateIRISub(t, capture, types.InterceptTask{
		XID:        "aaaaaaaa-0000-0000-0000-000000000009",
		Targets:    []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "999999999999999"}},
		Products:   []types.ProductType{types.ProductIRI},
		Deliveries: []types.DeliveryEndpoint{{Type: types.DeliveryX2, Address: testDestinationAddr}},
		State:      types.TaskActive,
	})

	ReportEstablishmentReject(targetSM(), nasMessage.Cause5GSMInsufficientResources)
	ReportReleaseReject(targetSM(), 5, nasMessage.Cause5GSMRequestRejectedUnspecified)

	if len(capture.pdus) != 0 {
		t.Errorf("an untasked subscriber's refusal produced %d PDU(s)", len(capture.pdus))
	}
}

// TestUnsuccessfulProcedureCannotWorsenTheFailure: reporting a failure must not add one.
// These hooks sit on paths that are already failing, which is where error handling
// is least exercised — so the reporter must survive a nil context, a delivery that
// errors, and no subsystem at all, and must never panic or return anything the
// caller could mistake for a new failure.
func TestUnsuccessfulProcedureCannotWorsenTheFailure(t *testing.T) {
	t.Run("no subsystem", func(t *testing.T) {
		active.Store(nil)
		ReportEstablishmentReject(targetSM(), 26)
		ReportReleaseReject(targetSM(), 5, 26)
	})

	t.Run("nil context", func(t *testing.T) {
		activateIRISub(t, &captureSender{}, iriTask())
		ReportEstablishmentReject(nil, 26)
		ReportReleaseReject(nil, 5, 26)
	})

	t.Run("delivery fails", func(t *testing.T) {
		activateIRISub(t, senderFunc(func(*x2x3.PDU) error { return errors.New("MDF unreachable") }), iriTask())
		ReportEstablishmentReject(targetSM(), 26)
		ReportReleaseReject(targetSM(), 5, 26)
	})

	// Reaching here at all is the assertion: none of the above panicked, blocked,
	// or had a value the rejection path could propagate.
}

// TestUnsuccessfulProcedureCauseMatchesTheReject: the record's
// failureCause is whatever the reject put on the wire, read from the same table.
//
// The assertion is agreement, not distinctness — most keys share
// Cause5GSMRequestRejectedUnspecified, so a test demanding a unique cause per
// path would be asserting something the SMF does not do.
func TestUnsuccessfulProcedureCauseMatchesTheReject(t *testing.T) {
	keys := []string{
		"DnnNotSupported", "UDMDiscoveryFailure", "IpAllocError",
		"SubscriptionDataFetchError", "SubscriptionDataLenError",
		"PDUSessionTypeIPv4OnlyAllowed", "PCFDiscoveryFailure", "PCFPolicyCreateFailure",
		"UPFDataPathError", "InsufficientResourceSliceDnn", "AMFDiscoveryFailure",
		"InvalidPDUSessionIdentity",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			want, ok := smferrors.ErrorCause[key]
			if !ok {
				t.Fatalf("%s is not in smferrors.ErrorCause — the mapping this test guards has moved", key)
			}
			capture := &captureSender{}
			activateIRISub(t, capture, iriTask())

			ReportEstablishmentReject(targetSM(), want)

			if got := integer(t, unsuccessfulSM(t, capture).member(t, 2)); got != int64(want) {
				t.Errorf("failureCause = %d, want %d (the value the reject carries)", got, want)
			}
		})
	}
}

// TestApplyCCDuringEstablishmentKeepsCreateFAR asserts at the level the defect
// lives at: not that applyCC leaves the rule state alone, but that the
// establishment request it precedes still carries the forwarding FAR.
//
// A FAR can still be unsent at a UPF that has a PFCP session: a rule being added,
// or a path being activated. applyCC leaves a UPF still establishing alone
// (forEachEstablishedForwardingFAR), so this is where it can meet one. The
// establishment builder emits a Create FAR only for RULE_INITIAL, so
// an applyCC that marked every FAR it touched RULE_UPDATE would drop the FAR from
// the request while the PDR referring to it was sent anyway. The UPF would hold a
// detection rule pointing at a forwarding rule it had never been given: no
// forwarding action for the subject at all.
//
// Asserting on far.State alone would pass with the builder's rule inverted; what
// the subscriber's service depends on is the IE actually being in the message.
func TestApplyCCDuringEstablishmentKeepsCreateFAR(t *testing.T) {
	task := types.InterceptTask{
		XID:      testTaskCC,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI, types.ProductCC},
		State:    types.TaskActive,
	}
	st := store.New()
	if !st.Activate(task) {
		t.Fatal("failed to activate test task")
	}
	sub := &subsystem{store: st}

	far := &smfctx.FAR{FARID: 1, State: smfctx.RULE_INITIAL}
	far.ApplyAction.Forw = true
	sc := ccSession(far)

	// The warrant lands mid-establishment: the FAR exists and has never been sent.
	if !sub.applyCC(sc) {
		t.Fatal("applyCC reported no change for a session a CC task covers")
	}
	if !far.ApplyAction.Dupl {
		t.Error("duplication was not applied")
	}
	if far.State != smfctx.RULE_INITIAL {
		t.Errorf("FAR state = %v after applyCC on an unsent rule, want RULE_INITIAL — "+
			"an unsent rule marked as an amendment is dropped from the establishment request",
			far.State)
	}

	// Now the establishment request the FSM was already building goes out.
	req, err := message.BuildPfcpSessionEstablishmentRequest(
		1, "10.0.0.1", net.ParseIP("10.0.0.1"), 0x1234,
		[]*smfctx.PDR{sc.Tunnel.DataPathPool[1].FirstDPNode.UpLinkTunnel.PDR["default"]},
		[]*smfctx.FAR{far}, nil,
	)
	if err != nil {
		t.Fatalf("BuildPfcpSessionEstablishmentRequest: %v", err)
	}
	if len(req.CreateFAR) != 1 {
		t.Fatalf("establishment request carries %d Create FAR IEs, want 1 — the session's "+
			"PDR would reference a forwarding rule the UPF was never given, and the "+
			"subscriber's traffic would have no forwarding action at all", len(req.CreateFAR))
	}
	if len(req.CreatePDR) != 1 {
		t.Fatalf("establishment request carries %d Create PDR IEs, want 1", len(req.CreatePDR))
	}

	// And the copy the warrant authorised rides out with it, rather than waiting
	// for a modification that the lost Create FAR would have made meaningless.
	applyAction, err := req.CreateFAR[0].ApplyAction()
	if err != nil {
		t.Fatalf("reading ApplyAction from the Create FAR: %v", err)
	}
	if applyAction[0]&0x10 == 0 {
		t.Errorf("Create FAR ApplyAction = %#x, DUPL bit not set — the FAR was created "+
			"but the interception it was marked for is not in effect", applyAction[0])
	}
}

// establishingSession builds a target's session in the state it holds between the
// establishment request going out and the response coming back: rules built and
// sent (so the FAR is RULE_CREATE), but no F-SEID assigned yet, which is what
// makes its correlation identifier zero.
func establishingSession(t *testing.T, far *smfctx.FAR) *smfctx.SMContext {
	t.Helper()

	// The session has to be in the global pool, because scanSessions reaches
	// sessions through it and reaching them is what is under test. RemoveSMContext
	// is the only way back out, and it publishes a state change that dereferences a
	// configuration these tests otherwise never build — so build the one field it
	// needs, and put it back.
	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	sc := smfctx.NewSMContext(testSUPI, 5)
	t.Cleanup(func() { smfctx.RemoveSMContext(sc.Ref) })
	// No PDUAddress: releasing the context returns the address to a pool these
	// tests do not build, and nothing here matches on it — the task targets SUPI.
	sc.Supi = testSUPI

	node := smfctx.NewDataPathNode()
	node.UpLinkTunnel.PDR["default"] = &smfctx.PDR{FAR: far}
	node.UPF = &smfctx.UPF{NodeID: *smfctx.NewNodeID(trigNodeA)}
	sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
		1: &smfctx.DataPath{FirstDPNode: node, IsDefaultPath: true},
	}}
	sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{trigNodeA: {}}

	return sc
}

// establish assigns the F-SEID the UPF's response carries, which is what makes
// the session exist as far as this element is concerned.
func establish(sc *smfctx.SMContext, seid uint64) {
	sc.PFCPContext[trigNodeA].RemoteSEID = seid
}

// TestWarrantActivatingDuringEstablishmentIsAppliedOnArrival covers the window
// the deferral opens, which is the thing most likely to be got wrong about it.
//
// scanSessions leaves a session whose PFCP session does not exist yet to the
// establishment path, so that it never mutates rules that path is part-way
// through sending. That is only safe if the establishment path then picks the
// session up — otherwise a warrant activating inside the window is applied by
// nobody and the interception silently never starts, which is worse than the race
// it avoids. This asserts the deferral is a deferral.
func TestWarrantActivatingDuringEstablishmentIsAppliedOnArrival(t *testing.T) {
	var modified int
	SetSessionModifier(func(*smfctx.SMContext) error { modified++; return nil })
	t.Cleanup(func() { SetSessionModifier(nil) })

	far := &smfctx.FAR{FARID: 1, State: smfctx.RULE_CREATE}
	far.ApplyAction.Forw = true
	sc := establishingSession(t, far)

	st := store.New()
	sub := &subsystem{store: st}
	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	// The warrant arrives while the session is mid-establishment.
	task := types.InterceptTask{
		XID:      testTaskCC,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}
	if !st.Activate(task) {
		t.Fatal("failed to activate test task")
	}

	done := make(chan struct{})
	sub.scanSessions(task, true, func(*smfctx.SMContext) any { close(done); return nil })
	select {
	case <-done:
		t.Fatal("the X1 scan acted on a session whose PFCP session does not exist yet — " +
			"it would be mutating rules the establishment path is still sending")
	case <-time.After(50 * time.Millisecond):
	}

	sc.SMLock.Lock()
	if far.ApplyAction.Dupl {
		sc.SMLock.Unlock()
		t.Fatal("the deferred session's FAR was modified by the X1 scan")
	}
	sc.SMLock.Unlock()

	// The response arrives: the session now exists, and the establishment path is
	// responsible for a warrant nobody has applied yet.
	sc.SMLock.Lock()
	establish(sc, 0x2632898145f4d191)
	ApplyCCAfterEstablishment(sc)
	sc.SMLock.Unlock()

	if !far.ApplyAction.Dupl {
		t.Error("duplication is not in effect after establishment — a warrant activating " +
			"during the establishment window was applied by neither path, so the " +
			"interception silently never starts")
	}
	if far.State != smfctx.RULE_UPDATE {
		t.Errorf("FAR state = %v, want RULE_UPDATE — the rule has been sent already, so "+
			"the duplication flip only reaches the UPF as a modification", far.State)
	}
	if modified != 1 {
		t.Errorf("session modifier called %d times, want 1 — applying duplication without "+
			"sending it leaves the UPF forwarding without duplicating", modified)
	}
}

// TestEstablishmentReapplyIsSilentWhenNothingChanged: the ordinary path. The
// duplication instruction rode out with the establishment request, so by the time
// the response lands there is nothing to re-derive and no modification to send.
func TestEstablishmentReapplyIsSilentWhenNothingChanged(t *testing.T) {
	var modified int
	SetSessionModifier(func(*smfctx.SMContext) error { modified++; return nil })
	t.Cleanup(func() { SetSessionModifier(nil) })

	far := &smfctx.FAR{FARID: 1, State: smfctx.RULE_CREATE}
	far.ApplyAction.Forw = true
	setDuplication(far, true) // as ApplyCCTrigger did before the request went out
	sc := establishingSession(t, far)
	establish(sc, 0x2632898145f4d191)

	st := store.New()
	if !st.Activate(types.InterceptTask{
		XID:      testTaskCC,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}) {
		t.Fatal("failed to activate test task")
	}
	active.Store(&subsystem{store: st})
	t.Cleanup(func() { active.Store(nil) })

	sc.SMLock.Lock()
	ApplyCCAfterEstablishment(sc)
	sc.SMLock.Unlock()

	if modified != 0 {
		t.Errorf("session modifier called %d times, want 0 — nothing changed since the "+
			"establishment request carried the duplication instruction", modified)
	}
	if far.State != smfctx.RULE_CREATE {
		t.Errorf("FAR state = %v, want RULE_CREATE untouched", far.State)
	}
}

// TestConcurrentEstablishmentAndTasking is the case the -race runs never
// exercised, and the reason the FAR race went unseen: no test drove session
// establishment against X1 tasking on the same session.
//
// The establishment path runs without SMLock (there is none anywhere in smf/fsm
// or smf/transaction), and the X1 path mutates the same far.State and
// far.ApplyAction under it. Two goroutines, one lock between them, is not
// serialisation. What makes this safe now is that the X1 side leaves a session
// whose PFCP session does not exist yet alone — so this asserts that under the
// race detector, and asserts the session survives it with a coherent rule state.
func TestConcurrentEstablishmentAndTasking(t *testing.T) {
	SetSessionModifier(func(*smfctx.SMContext) error { return nil })
	t.Cleanup(func() { SetSessionModifier(nil) })

	st := store.New()
	sub := &subsystem{store: st}
	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	task := types.InterceptTask{
		XID:      testTaskCC,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}
	if !st.Activate(task) {
		t.Fatal("failed to activate test task")
	}

	far := &smfctx.FAR{FARID: 1, State: smfctx.RULE_INITIAL}
	far.ApplyAction.Forw = true
	sc := establishingSession(t, far)

	// The establishment path: ApplyCCTrigger with no lock held, exactly as
	// SendPFCPRules calls it from the create-pending state handler. It runs until
	// told to stop, so the scans below are guaranteed to overlap it — scanSessions
	// does its work on a goroutine of its own, and a fixed-iteration writer can
	// finish before any of them is scheduled, which is a test that races nothing.
	stop := make(chan struct{})

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// A session's rules being built: the FAR is rebuilt from scratch and its
			// whole ApplyAction replaced — which clears Dupl, the case
			// n1n2_data_handler documents — and then the duplication state is derived
			// for the rules about to be sent. Every step of that is an unsynchronised
			// write to the same fields the X1 path writes under SMLock.
			*far = smfctx.FAR{FARID: 1, State: smfctx.RULE_INITIAL}
			far.ApplyAction.Forw = true
			ApplyCCTrigger(sc)
		}
	}()

	// The X1 path: repeated tasking scans, each taking SMLock per session.
	for range 200 {
		sub.scanSessions(task, true, func(s *smfctx.SMContext) any {
			sub.applyCC(s)
			return nil
		})
	}
	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Whatever interleaving happened, the rule must still be one the establishment
	// builder will emit: an unsent rule marked as an amendment is dropped from the
	// request, and the subscriber loses its forwarding action entirely.
	sc.SMLock.Lock()
	state := far.State
	sc.SMLock.Unlock()
	if state != smfctx.RULE_INITIAL {
		t.Errorf("FAR state = %v after concurrent establishment and tasking, want "+
			"RULE_INITIAL — the rule has not been sent, and only RULE_INITIAL is "+
			"emitted as a Create FAR", state)
	}
}

// TestAWarrantNamingTwoIdentitiesMatchesOnlyTheSubjectPresentingBoth is TS 103 221-1 table
// 6.2.1.2-1: "Where multiple criteria are present, all criteria are required to be
// matched." A warrant naming a SUPI and a GPSI describes the subscriber holding both; a
// session of the SUPI under another GPSI belongs to someone else, and reporting it would
// intercept a subject the warrant does not describe.
func TestAWarrantNamingTwoIdentitiesMatchesOnlyTheSubjectPresentingBoth(t *testing.T) {
	task := iriTask()
	task.Targets = []types.TargetIdentifier{
		{Type: types.TargetSUPI, Value: "262019876543210"},
		{Type: types.TargetGPSI, Value: "4915123456789"},
	}
	capture := &captureSender{}
	activateIRISub(t, capture, task)

	ReportEstablishment(targetSM())
	if len(capture.pdus) != 1 {
		t.Fatalf("the session presenting both identities produced %d records, want 1", len(capture.pdus))
	}

	other := targetSM()
	other.Gpsi = "msisdn-4915100000000"
	ReportEstablishment(other)
	if len(capture.pdus) != 1 {
		t.Errorf("a session presenting only the warrant's SUPI produced %d more records, want none",
			len(capture.pdus)-1)
	}
}
