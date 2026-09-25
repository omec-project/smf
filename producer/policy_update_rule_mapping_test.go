// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
)

// twoRuleSession is an established session carrying two PCC rules, the way a slice with a
// catch-all rule and one dedicated flow is established: the catch-all refers to the default QoS
// flow, the dedicated rule to a guaranteed-rate flow of its own. Each PDR carries its rule's flow
// QER and the session QER, as ActivateTunnelAndPDR leaves them.
//
// restored builds it the way a session read back from the database is: the tunnels are decoded
// PDR by PDR, so each PDR holds its own copy of a QER it shares with the others.
type twoRuleSession struct {
	sm                     *smf_context.SMContext
	sessQER                *smf_context.QER
	allowUL, allowDL       *smf_context.PDR
	cirUL, cirDL           *smf_context.PDR
	allowULQER, allowDLQER *smf_context.QER
	cirULQER, cirDLQER     *smf_context.QER
	allowRule, cirRule     models.PccRule
	allowQos, cirQosSent   models.QosData
}

const (
	allowRuleID = "allow"
	cirRuleID   = "cir"
	allowQosID  = "9"
	cirQosID    = "1"
)

func newTwoRuleSession(t *testing.T, restored bool) *twoRuleSession {
	t.Helper()

	upf := smf_context.NewUPF(smf_context.NewNodeID("10.0.0.7"), nil)
	upf.UPFStatus = smf_context.AssociatedSetUpSuccess
	t.Cleanup(func() { smf_context.RemoveUPFNodeByNodeID(upf.NodeID) })

	newQER := func(qfi uint8) *smf_context.QER {
		qer, err := upf.AddQER()
		if err != nil {
			t.Fatalf("AddQER: %v", err)
		}
		qer.QFI.QFI = qfi
		qer.GateStatus = &smf_context.GateStatus{}
		qer.State = smf_context.RULE_CREATE
		return qer
	}
	newPDR := func(qers ...*smf_context.QER) *smf_context.PDR {
		pdr, err := upf.AddPDR()
		if err != nil {
			t.Fatalf("AddPDR: %v", err)
		}
		pdr.QER = qers
		if restored {
			pdr.QER = nil
			for _, qer := range qers {
				decoded := *qer
				pdr.QER = append(pdr.QER, &decoded)
			}
		}
		pdr.State = smf_context.RULE_CREATE
		pdr.FAR.State = smf_context.RULE_CREATE
		return pdr
	}

	s := &twoRuleSession{sm: modifyingSession()}
	s.sessQER = newQER(qos.GetQosFlowIdFromQosId(allowQosID))
	s.allowULQER = newQER(qos.GetQosFlowIdFromQosId(allowQosID))
	s.allowDLQER = newQER(qos.GetQosFlowIdFromQosId(allowQosID))
	s.cirULQER = newQER(qos.GetQosFlowIdFromQosId(cirQosID))
	s.cirDLQER = newQER(qos.GetQosFlowIdFromQosId(cirQosID))
	s.allowUL = newPDR(s.allowULQER, s.sessQER)
	s.allowDL = newPDR(s.allowDLQER, s.sessQER)
	s.cirUL = newPDR(s.cirULQER, s.sessQER)
	s.cirDL = newPDR(s.cirDLQER, s.sessQER)

	node := &smf_context.DataPathNode{
		UPF: upf,
		UpLinkTunnel: &smf_context.GTPTunnel{PDR: map[string]*smf_context.PDR{
			allowRuleID: s.allowUL, cirRuleID: s.cirUL,
		}},
		DownLinkTunnel: &smf_context.GTPTunnel{PDR: map[string]*smf_context.PDR{
			allowRuleID: s.allowDL, cirRuleID: s.cirDL,
		}},
	}
	s.sm.Tunnel = &smf_context.UPTunnel{DataPathPool: smf_context.DataPathPool{
		1: &smf_context.DataPath{IsDefaultPath: true, Activated: true, FirstDPNode: node},
	}}

	s.allowRule = models.PccRule{PccRuleId: allowRuleID, RefQosData: []string{allowQosID}, Precedence: openapi.PtrInt32(255)}
	s.cirRule = models.PccRule{PccRuleId: cirRuleID, RefQosData: []string{cirQosID}, Precedence: openapi.PtrInt32(200)}
	s.allowQos = models.QosData{QosId: allowQosID, Var5qi: openapi.PtrInt32(9), DefQosFlowIndication: openapi.PtrBool(true)}
	s.cirQosSent = models.QosData{
		QosId: cirQosID, Var5qi: openapi.PtrInt32(1),
		MaxbrUl: *openapi.NewNullableString(openapi.PtrString("3 Mbps")), MaxbrDl: *openapi.NewNullableString(openapi.PtrString("6 Mbps")),
		GbrUl: *openapi.NewNullableString(openapi.PtrString("1 Mbps")), GbrDl: *openapi.NewNullableString(openapi.PtrString("2 Mbps")),
	}

	// What the session was established with, as CommitSmPolicyDecision leaves it.
	s.sm.SmPolicyData.Initialize()
	allowRule, cirRule, allowQos, cirQos := s.allowRule, s.cirRule, s.allowQos, s.cirQosSent
	s.sm.SmPolicyData.SmCtxtPccRules.PccRules[allowRuleID] = &allowRule
	s.sm.SmPolicyData.SmCtxtPccRules.PccRules[cirRuleID] = &cirRule
	s.sm.SmPolicyData.SmCtxtQosData.QosData[allowQosID] = &allowQos
	s.sm.SmPolicyData.SmCtxtQosData.QosData[cirQosID] = &cirQos
	s.sm.SmPolicyData.SmCtxtSessionRules.ActiveRule = &models.SessionRule{
		AuthSessAmbr: &models.Ambr{Uplink: "100 Mbps", Downlink: "200 Mbps"},
	}

	return s
}

// rateChange is the decision the PCF sends when an operator edits the dedicated rule's rates: the
// whole decision again, both rules unchanged, one QoS data entry with new rates.
func (s *twoRuleSession) rateChange() *models.SmPolicyDecision {
	changed := s.cirQosSent
	changed.MaxbrUl = *openapi.NewNullableString(openapi.PtrString("5 Mbps"))
	changed.MaxbrDl = *openapi.NewNullableString(openapi.PtrString("8 Mbps"))
	changed.GbrUl = *openapi.NewNullableString(openapi.PtrString("1500 Kbps"))
	changed.GbrDl = *openapi.NewNullableString(openapi.PtrString("2500 Kbps"))

	decision := &models.SmPolicyDecision{
		PccRules: map[string]models.PccRule{allowRuleID: s.allowRule, cirRuleID: s.cirRule},
		QosDecs:  &map[string]models.QosData{allowQosID: s.allowQos, cirQosID: changed},
	}

	return roundTrip(decision)
}

// A changed QoS goes to the rule that refers to it. The builder used to take the first valid rule
// in map order and hang the new QERs on that rule's PDRs, so with two rules it was right half the
// time: seen on the rig, a catch-all rule's uplink was metered at the dedicated flow's new rates
// and more than half of its traffic dropped. Repeated because the defect is map order: one run
// passes by luck as often as not.
func TestAPolicyRateChangeReachesOnlyTheRuleItBelongsTo(t *testing.T) {
	for _, restored := range []bool{false, true} {
		for range 40 {
			if !rateChangeReachesOnlyItsRule(t, newTwoRuleSession(t, restored)) {
				t.Fatalf("restored session: %v", restored)
			}
		}
	}
}

func rateChangeReachesOnlyItsRule(t *testing.T, s *twoRuleSession) bool {
	t.Helper()

	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.rateChange())}

	param := BuildPfcpParam(s.sm)

	sent := map[*smf_context.PDR]bool{}
	for _, pdr := range param.pdrList {
		sent[pdr] = true
	}
	if sent[s.allowUL] || sent[s.allowDL] {
		t.Error("the catch-all rule's PDRs were reprogrammed for a change to another rule's QoS")
		return false
	}
	if !sent[s.cirUL] || !sent[s.cirDL] {
		t.Errorf("the changed rule's PDRs were not both reprogrammed (UL %v, DL %v)", sent[s.cirUL], sent[s.cirDL])
		return false
	}

	for _, qer := range s.allowUL.QER {
		if qer.QERID != s.allowULQER.QERID && qer.QERID != s.sessQER.QERID {
			t.Errorf("the catch-all uplink PDR now carries QER %d, which is not its own", qer.QERID)
		}
	}

	for dir, pdr := range map[string]*smf_context.PDR{"UL": s.cirUL, "DL": s.cirDL} {
		if pdr.State != smf_context.RULE_UPDATE {
			t.Errorf("%s: an established PDR is sent in state %v, want an update of it", dir, pdr.State)
		}

		var keptSession bool
		var flow *smf_context.QER
		for _, qer := range pdr.QER {
			switch qer.QERID {
			case s.sessQER.QERID:
				keptSession = true
			case s.cirULQER.QERID, s.cirDLQER.QERID:
				t.Errorf("%s: the PDR still refers to its superseded flow QER %d", dir, qer.QERID)
			default:
				flow = qer
			}
		}
		if !keptSession {
			t.Errorf("%s: the session-AMBR QER was dropped from the PDR", dir)
		}
		if flow == nil {
			t.Errorf("%s: the PDR carries no flow QER for the new rates", dir)
			continue
		}
		if !queued(param.qerList, flow) {
			t.Errorf("%s: flow QER %d is referenced but never sent to the user plane to be created", dir, flow.QERID)
		}
		if flow.MBR == nil || flow.MBR.ULMBR != 5000 || flow.MBR.DLMBR != 8000 {
			t.Errorf("%s: flow QER MBR = %+v, want 5000/8000 kbps", dir, flow.MBR)
		}
		if flow.GBR == nil || flow.GBR.ULGBR != 1500 || flow.GBR.DLGBR != 2500 {
			t.Errorf("%s: flow QER GBR = %+v, want 1500/2500 kbps", dir, flow.GBR)
		}
	}

	removed := map[uint32]bool{}
	for _, qer := range param.removeQER {
		if removed[qer.QERID] {
			t.Errorf("QER %d is removed twice in one request", qer.QERID)
		}
		removed[qer.QERID] = true
	}
	if !removed[s.cirULQER.QERID] || !removed[s.cirDLQER.QERID] {
		t.Error("the superseded flow QERs were not removed from the user plane")
	}
	if removed[s.sessQER.QERID] || removed[s.allowULQER.QERID] || removed[s.allowDLQER.QERID] {
		t.Error("a QER still in use by an unchanged rule was removed")
	}

	return !t.Failed()
}

// A rule the update adds is programmed on its own new PDRs, carrying its own flow QER and the
// session QER, and the established rules are left as they are. The builder used to program
// whichever valid rule map order gave it first, so an added rule was sent only when it happened
// to be that one -- otherwise it was built, never sent, and its traffic fell to the catch-all.
func TestAnAddedRuleIsProgrammedAndTheEstablishedOnesAreNotTouched(t *testing.T) {
	const appRuleID, appQosID = "app", "2"

	for range 40 {
		s := newTwoRuleSession(t, false)
		// The tunnels put what they build into the session's PFCP context.
		s.sm.PFCPContext = map[string]*smf_context.PFCPSessionContext{
			"10.0.0.7": {PDRs: map[uint16]*smf_context.PDR{}},
		}

		decision := s.rateChange()
		// This decision changes nothing but the added rule.
		(*decision.QosDecs)[cirQosID] = s.cirQosSent
		decision = roundTrip(decision)
		(*decision.QosDecs)[appQosID] = models.QosData{
			QosId: appQosID, Var5qi: openapi.PtrInt32(2),
			MaxbrUl: *openapi.NewNullableString(openapi.PtrString("2 Mbps")),
			MaxbrDl: *openapi.NewNullableString(openapi.PtrString("4 Mbps")),
		}
		decision.PccRules[appRuleID] = models.PccRule{
			PccRuleId: appRuleID, RefQosData: []string{appQosID}, Precedence: openapi.PtrInt32(100),
			FlowInfos: []models.FlowInformation{{
				FlowDescription: openapi.PtrString("permit out ip from 192.168.250.2/32 to assigned"),
				PackFiltId:      openapi.PtrString("7"),
			}},
		}
		s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)}

		param := BuildPfcpParam(s.sm)

		node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
		appUL, appDL := node.UpLinkTunnel.PDR[appRuleID], node.DownLinkTunnel.PDR[appRuleID]
		if appUL == nil || appDL == nil {
			t.Fatalf("the added rule's PDRs were not built (UL %v, DL %v)", appUL != nil, appDL != nil)
		}

		sent := map[*smf_context.PDR]bool{}
		for _, pdr := range param.pdrList {
			sent[pdr] = true
		}
		for name, pdr := range map[string]*smf_context.PDR{
			"catch-all UL": s.allowUL, "catch-all DL": s.allowDL, "dedicated UL": s.cirUL, "dedicated DL": s.cirDL,
		} {
			if sent[pdr] {
				t.Fatalf("the %s PDR was reprogrammed, but the update does not change its rule", name)
			}
		}
		if !sent[appUL] || !sent[appDL] {
			t.Fatalf("the added rule's PDRs were not sent (UL %v, DL %v)", sent[appUL], sent[appDL])
		}

		created := map[uint32]bool{}
		for _, qer := range param.qerList {
			created[qer.QERID] = true
		}
		for dir, pdr := range map[string]*smf_context.PDR{"UL": appUL, "DL": appDL} {
			var keptSession, ownFlow bool
			for _, qer := range pdr.QER {
				switch {
				case qer.QERID == s.sessQER.QERID:
					keptSession = true
				case created[qer.QERID] && qer.MBR != nil && qer.MBR.ULMBR == 2000 && qer.MBR.DLMBR == 4000:
					ownFlow = true
				default:
					t.Errorf("%s: the added rule's PDR carries QER %d, which is neither its own nor the session's", dir, qer.QERID)
				}
			}
			if !keptSession {
				t.Errorf("%s: the added rule's PDR does not carry the session-AMBR QER", dir)
			}
			if !ownFlow {
				t.Errorf("%s: the added rule's PDR does not carry a new QER at its own rates", dir)
			}
		}
		if t.Failed() {
			return
		}
	}
}

// queued reports whether a QER goes out in the request as a creation.
func queued(qerList []*smf_context.QER, qer *smf_context.QER) bool {
	for _, q := range qerList {
		if q == qer && q.State == smf_context.RULE_INITIAL {
			return true
		}
	}
	return false
}

// roundTrip passes a decision through the wire format, as a notification arrives: nothing in the
// result shares a pointer with what the session committed.
func roundTrip(decision *models.SmPolicyDecision) *models.SmPolicyDecision {
	raw, err := json.Marshal(decision)
	if err != nil {
		panic(err)
	}
	decoded := &models.SmPolicyDecision{}
	if err := json.Unmarshal(raw, decoded); err != nil {
		panic(err)
	}
	return decoded
}

// The catch-all rule sits on the default QoS flow, and establishment builds its flow QER from its
// QoS data like any other rule's. The builder this replaced skipped default-flow QoS data, so an
// edit to the catch-all's own rates never reached the user plane.
func TestARateChangeToTheCatchAllReachesItsOwnPDRs(t *testing.T) {
	s := newTwoRuleSession(t, false)

	decision := s.rateChange()
	(*decision.QosDecs)[cirQosID] = s.cirQosSent
	catchAll := s.allowQos
	catchAll.MaxbrUl = *openapi.NewNullableString(openapi.PtrString("20 Mbps"))
	catchAll.MaxbrDl = *openapi.NewNullableString(openapi.PtrString("40 Mbps"))
	(*decision.QosDecs)[allowQosID] = catchAll
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, roundTrip(decision))}

	param := BuildPfcpParam(s.sm)

	sent := map[*smf_context.PDR]bool{}
	for _, pdr := range param.pdrList {
		sent[pdr] = true
	}
	if sent[s.cirUL] || sent[s.cirDL] {
		t.Error("the dedicated rule was reprogrammed for a change to the catch-all's rates")
	}
	for dir, pdr := range map[string]*smf_context.PDR{"UL": s.allowUL, "DL": s.allowDL} {
		if !sent[pdr] {
			t.Errorf("%s: the catch-all's PDR was not reprogrammed", dir)
			continue
		}
		var keptSession, newRates bool
		for _, qer := range pdr.QER {
			switch {
			case qer.QERID == s.sessQER.QERID:
				keptSession = true
			case qer.MBR != nil && qer.MBR.ULMBR == 20000 && qer.MBR.DLMBR == 40000:
				newRates = true
			}
		}
		if !keptSession || !newRates {
			t.Errorf("%s: session QER kept %v, flow QER at the new rates %v", dir, keptSession, newRates)
		}
	}
}

// A rule can be pointed at QoS data the session has not seen before. That data is an addition, not
// a modification, but the rule it belongs to is already established and has to be requalified.
func TestARuleRepointedAtNewQosDataIsRequalified(t *testing.T) {
	const newQosID = "3"

	s := newTwoRuleSession(t, false)

	decision := s.rateChange()
	(*decision.QosDecs)[cirQosID] = s.cirQosSent
	(*decision.QosDecs)[newQosID] = models.QosData{
		QosId: newQosID, Var5qi: openapi.PtrInt32(3),
		MaxbrUl: *openapi.NewNullableString(openapi.PtrString("7 Mbps")),
		MaxbrDl: *openapi.NewNullableString(openapi.PtrString("9 Mbps")),
	}
	repointed := s.cirRule
	repointed.RefQosData = []string{newQosID}
	decision.PccRules[cirRuleID] = repointed
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, roundTrip(decision))}

	param := BuildPfcpParam(s.sm)

	for dir, pdr := range map[string]*smf_context.PDR{"UL": s.cirUL, "DL": s.cirDL} {
		var newRates bool
		for _, qer := range pdr.QER {
			if qer.MBR != nil && qer.MBR.ULMBR == 7000 && qer.MBR.DLMBR == 9000 && queued(param.qerList, qer) {
				newRates = true
			}
		}
		if !newRates {
			t.Errorf("%s: the repointed rule's PDR does not carry a new QER at its new QoS data's rates", dir)
		}
	}
}

// programmedRateChange is the two-rule session with the dedicated rule's rate change pending and
// already programmed into the user plane, as ApplyModification leaves it before the UE is told.
func programmedRateChange(t *testing.T) *twoRuleSession {
	t.Helper()

	s := newTwoRuleSession(t, false)
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.rateChange())}
	BuildPfcpParam(s.sm)
	s.sm.NwModificationPending = true

	return s
}

// Putting the user plane back means the rule the abandoned modification changed goes back to its
// committed rates. The revert used to rebuild with the update discarded and nothing pending, which
// programs nothing, and then log that the user plane had been put back.
func TestARevertPutsTheChangedRuleBackOnItsCommittedRates(t *testing.T) {
	original := sendPfcpSessionModifyReq
	t.Cleanup(func() { sendPfcpSessionModifyReq = original })
	var sent *pfcpParam
	sendPfcpSessionModifyReq = func(_ *smf_context.SMContext, p *pfcpParam) error {
		sent = p
		return nil
	}

	s := programmedRateChange(t)
	installed := map[uint32]bool{}
	for _, pdr := range []*smf_context.PDR{s.cirUL, s.cirDL} {
		for _, qer := range pdr.QER {
			if qer.QERID != s.sessQER.QERID {
				installed[qer.QERID] = true
			}
		}
	}

	if !revertModification(s.sm, "n1n2_transfer_failed") {
		t.Fatal("the revert reported failure")
	}
	if sent == nil {
		t.Fatal("nothing was sent to the user plane")
	}
	if len(s.sm.SmPolicyUpdates) != 0 {
		t.Error("the revert was left pending, where a later commit would record it")
	}

	for _, pdr := range sent.pdrList {
		if pdr == s.allowUL || pdr == s.allowDL {
			t.Error("the revert reprogrammed the catch-all, which the modification never touched")
		}
	}
	for dir, pdr := range map[string]*smf_context.PDR{"UL": s.cirUL, "DL": s.cirDL} {
		var keptSession, committedRates bool
		for _, qer := range pdr.QER {
			switch {
			case qer.QERID == s.sessQER.QERID:
				keptSession = true
			case qer.MBR != nil && qer.MBR.ULMBR == 3000 && qer.MBR.DLMBR == 6000 &&
				qer.GBR != nil && qer.GBR.ULGBR == 1000 && qer.GBR.DLGBR == 2000 && queued(sent.qerList, qer):
				committedRates = true
			}
		}
		if !keptSession || !committedRates {
			t.Errorf("%s: session QER kept %v, flow QER back on the committed rates %v", dir, keptSession, committedRates)
		}
	}

	removed := map[uint32]bool{}
	for _, qer := range sent.removeQER {
		removed[qer.QERID] = true
	}
	for id := range installed {
		if !removed[id] {
			t.Errorf("QER %d, installed by the abandoned modification, was left on the user plane", id)
		}
	}
}

// A UE that never answers never took the new parameters up, so abandoning on T3591's last expiry
// has to put the user plane back as well. It used to only discard the update.
func TestAbandoningOnT3591ExpiryPutsTheUserPlaneBack(t *testing.T) {
	original := sendPfcpSessionModifyReq
	t.Cleanup(func() { sendPfcpSessionModifyReq = original })
	var sent *pfcpParam
	sendPfcpSessionModifyReq = func(_ *smf_context.SMContext, p *pfcpParam) error {
		sent = p
		return nil
	}

	s := programmedRateChange(t)
	timer := &smf_context.Timer{}
	s.sm.T3591 = timer

	abandonIfCurrent(s.sm, timer)

	if sent == nil || !sent.touches(s.cirUL) || !sent.touches(s.cirDL) {
		t.Error("the user plane was not put back after the UE never acknowledged")
	}
}

// touches reports whether the parameters program pdr.
func (p *pfcpParam) touches(pdr *smf_context.PDR) bool {
	for _, sent := range p.pdrList {
		if sent == pdr {
			return true
		}
	}
	return false
}

// Undoing a re-pointing changes no QoS data at all: the rule goes back to data that is still
// there, unchanged. Only the rule itself differs, so a builder that looked only at changed QoS
// data left the rule on the abandoned one's QER.
func TestRevertingARepointingPutsTheRuleBackOnItsOwnQosData(t *testing.T) {
	const newQosID = "3"

	original := sendPfcpSessionModifyReq
	t.Cleanup(func() { sendPfcpSessionModifyReq = original })
	var sent *pfcpParam
	sendPfcpSessionModifyReq = func(_ *smf_context.SMContext, p *pfcpParam) error {
		sent = p
		return nil
	}

	s := newTwoRuleSession(t, false)
	decision := s.rateChange()
	(*decision.QosDecs)[cirQosID] = s.cirQosSent
	(*decision.QosDecs)[newQosID] = models.QosData{
		QosId: newQosID, Var5qi: openapi.PtrInt32(3),
		MaxbrUl: *openapi.NewNullableString(openapi.PtrString("7 Mbps")),
		MaxbrDl: *openapi.NewNullableString(openapi.PtrString("9 Mbps")),
	}
	repointed := s.cirRule
	repointed.RefQosData = []string{newQosID}
	decision.PccRules[cirRuleID] = repointed
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, roundTrip(decision))}
	BuildPfcpParam(s.sm)
	s.sm.NwModificationPending = true

	revertModification(s.sm, "n1n2_transfer_failed")

	if sent == nil {
		t.Fatal("nothing was sent to the user plane")
	}
	for dir, pdr := range map[string]*smf_context.PDR{"UL": s.cirUL, "DL": s.cirDL} {
		var committedRates bool
		for _, qer := range pdr.QER {
			if qer.MBR != nil && qer.MBR.ULMBR == 3000 && qer.MBR.DLMBR == 6000 && queued(sent.qerList, qer) {
				committedRates = true
			}
		}
		if !committedRates {
			t.Errorf("%s: the rule is not back on its own QoS data's rates", dir)
		}
	}
}

// deleteDedicatedRule is the decision withdrawing the dedicated rule and its QoS data.
func (s *twoRuleSession) deleteDedicatedRule() *models.SmPolicyDecision {
	return roundTrip(&models.SmPolicyDecision{
		PccRules: map[string]models.PccRule{allowRuleID: s.allowRule, cirRuleID: {}},
		QosDecs:  &map[string]models.QosData{allowQosID: s.allowQos, cirQosID: {}},
	})
}

// withPfcpContext gives the fixture the PFCP session context the tunnels record their PDRs in,
// holding the PDRs it was established with.
func (s *twoRuleSession) withPfcpContext() {
	pdrs := map[uint16]*smf_context.PDR{}
	for _, pdr := range []*smf_context.PDR{s.allowUL, s.allowDL, s.cirUL, s.cirDL} {
		pdrs[pdr.PDRID] = pdr
	}
	s.sm.PFCPContext = map[string]*smf_context.PFCPSessionContext{"10.0.0.7": {PDRs: pdrs}}
}

// A rule the user plane has accepted withdrawing is no longer the session's. Left in the tunnels,
// it was re-installed by restoration when the UPF restarted -- a rule the policy had deleted, back
// in force -- and its PDR identifier, from a pool of 65535 shared by the whole UPF, was lost when a
// rule was later added under the same name. Its own flow QERs go from the user plane with it.
func TestAWithdrawnRuleLeavesTheSession(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })
	var sent *pfcpParam
	sendPfcpSessionModifyReq = func(_ *smf_context.SMContext, p *pfcpParam) error {
		sent = p
		return nil
	}
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return nil }

	s := newTwoRuleSession(t, false)
	s.withPfcpContext()
	t.Cleanup(func() { s.sm.StopT3591() })

	// Every PDR identifier the UPF has left is taken, so the only ones that can be handed out
	// afterwards are the ones the withdrawal gives back.
	upf := s.sm.Tunnel.DataPathPool[1].FirstDPNode.UPF
	for {
		if _, err := upf.AddPDR(); err != nil {
			break
		}
	}

	if err := ApplyModification(s.sm, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.deleteDedicatedRule())); err != nil {
		t.Fatalf("ApplyModification: %v", err)
	}

	for dir := range 2 {
		if _, err := upf.AddPDR(); err != nil {
			t.Errorf("PDR identifier %d of the withdrawn rule's two was not returned to the pool: %v", dir+1, err)
		}
	}

	removed := map[uint32]bool{}
	for _, qer := range sent.removeQER {
		removed[qer.QERID] = true
	}
	if !removed[s.cirULQER.QERID] || !removed[s.cirDLQER.QERID] {
		t.Error("the withdrawn rule's own flow QERs were left installed")
	}
	if removed[s.sessQER.QERID] {
		t.Error("the session QER was removed with the rule, taking the AMBR off the rules that remain")
	}

	node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
	if _, ok := node.UpLinkTunnel.PDR[cirRuleID]; ok {
		t.Error("the withdrawn rule's uplink PDR is still in the session's tunnel, where restoration re-installs it")
	}
	if _, ok := node.DownLinkTunnel.PDR[cirRuleID]; ok {
		t.Error("the withdrawn rule's downlink PDR is still in the session's tunnel")
	}
	pdrs := s.sm.PFCPContext["10.0.0.7"].PDRs
	if pdrs[s.cirUL.PDRID] != nil || pdrs[s.cirDL.PDRID] != nil {
		t.Error("the withdrawn rule's PDRs are still in the session's PFCP context")
	}
	if pdrs[s.allowUL.PDRID] == nil || node.UpLinkTunnel.PDR[allowRuleID] == nil {
		t.Error("a rule the modification kept was dropped from the session")
	}
}

// And a withdrawal that is then abandoned brings the rule back: on its own PDRs, at its committed
// rates, with the session QER.
func TestRevertingAWithdrawalReinstatesTheRule(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })
	var sent *pfcpParam
	sendPfcpSessionModifyReq = func(_ *smf_context.SMContext, p *pfcpParam) error {
		sent = p
		return nil
	}
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return errors.New("amf unreachable") }

	s := newTwoRuleSession(t, false)
	s.withPfcpContext()
	s.cirRule.FlowInfos = []models.FlowInformation{{
		FlowDescription: openapi.PtrString("permit out ip from 192.168.250.1/32 to assigned"),
		PackFiltId:      openapi.PtrString("5"),
	}}
	committedRule := s.cirRule
	s.sm.SmPolicyData.SmCtxtPccRules.PccRules[cirRuleID] = &committedRule

	// Delivery fails, so ApplyModification reverts what it has just programmed.
	if err := ApplyModification(s.sm, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.deleteDedicatedRule())); err == nil {
		t.Fatal("the undeliverable modification was reported as delivered")
	}

	node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
	for dir, tunnel := range map[string]*smf_context.GTPTunnel{"UL": node.UpLinkTunnel, "DL": node.DownLinkTunnel} {
		pdr := tunnel.PDR[cirRuleID]
		if pdr == nil || !sent.touches(pdr) || pdr.State != smf_context.RULE_INITIAL {
			t.Errorf("%s: the withdrawn rule was not re-created", dir)
			continue
		}
		var keptSession, committedRates bool
		for _, qer := range pdr.QER {
			switch {
			case qer.QERID == s.sessQER.QERID:
				keptSession = true
			case qer.MBR != nil && qer.MBR.ULMBR == 3000 && qer.MBR.DLMBR == 6000 && queued(sent.qerList, qer):
				committedRates = true
			}
		}
		if !keptSession || !committedRates {
			t.Errorf("%s: session QER kept %v, flow QER at the committed rates %v", dir, keptSession, committedRates)
		}
	}
}

// Reverting an addition withdraws the added rule, and once the user plane has accepted that, the
// rule leaves the session exactly as a withdrawal by policy does.
func TestRevertingAnAdditionRemovesTheRuleFromTheSession(t *testing.T) {
	const appRuleID, appQosID = "app", "2"

	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error { return nil }
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return errors.New("amf unreachable") }

	s := newTwoRuleSession(t, false)
	s.withPfcpContext()

	decision := roundTrip(&models.SmPolicyDecision{
		PccRules: map[string]models.PccRule{
			allowRuleID: s.allowRule, cirRuleID: s.cirRule,
			appRuleID: {
				PccRuleId: appRuleID, RefQosData: []string{appQosID}, Precedence: openapi.PtrInt32(100),
				FlowInfos: []models.FlowInformation{{
					FlowDescription: openapi.PtrString("permit out ip from 192.168.250.2/32 to assigned"),
					PackFiltId:      openapi.PtrString("7"),
				}},
			},
		},
		QosDecs: &map[string]models.QosData{
			allowQosID: s.allowQos, cirQosID: s.cirQosSent,
			appQosID: {
				QosId:   appQosID,
				MaxbrUl: *openapi.NewNullableString(openapi.PtrString("2 Mbps")),
				MaxbrDl: *openapi.NewNullableString(openapi.PtrString("4 Mbps")),
			},
		},
	})

	if err := ApplyModification(s.sm, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)); err == nil {
		t.Fatal("the undeliverable modification was reported as delivered")
	}

	node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
	if node.UpLinkTunnel.PDR[appRuleID] != nil || node.DownLinkTunnel.PDR[appRuleID] != nil {
		t.Error("the reverted rule is still in the session's tunnels, where restoration would re-install it")
	}
	if node.UpLinkTunnel.PDR[cirRuleID] != s.cirUL || node.DownLinkTunnel.PDR[allowRuleID] != s.allowDL {
		t.Error("the revert dropped rules the modification never touched")
	}
}

// The UPF's answer to a modification reaches the waiting sender only while the session is in
// PfcpModify: HandlePfcpSessionModificationResponse drops it in any other state. The abandonment
// that precedes a revert settles the session in Active, so a revert sent from there waited for an
// answer that was never delivered -- on a rig, accepted by the UPF and never logged as done.
func TestARevertIsSentWhileTheSessionAwaitsTheAnswer(t *testing.T) {
	original := sendPfcpSessionModifyReq
	t.Cleanup(func() { sendPfcpSessionModifyReq = original })
	var stateAtSend smf_context.SMContextState
	sendPfcpSessionModifyReq = func(sm *smf_context.SMContext, _ *pfcpParam) error {
		stateAtSend = sm.SMContextState
		return nil
	}

	s := programmedRateChange(t)
	timer := &smf_context.Timer{}
	s.sm.T3591 = timer

	abandonIfCurrent(s.sm, timer)

	if stateAtSend != smf_context.SmStatePfcpModify {
		t.Errorf("the revert was sent in state %s; the answer is delivered only in %s",
			stateAtSend, smf_context.SmStatePfcpModify)
	}
	if s.sm.SMContextState != smf_context.SmStateActive {
		t.Errorf("after the revert the session is in %s, want it settled in %s", s.sm.SMContextState, smf_context.SmStateActive)
	}
}

// A revert is part of the procedure it undoes. It runs on T3591's goroutine, outside the queue that
// orders a session's transactions, so a policy notification for the same rule could be built and
// sent while the revert was still waiting on the user plane -- and the revert, restoring the
// committed rules, would then undo it, with both waiting on the session's one response channel.
// The new modification has to wait for the revert, and then program its own rates.
func TestAModificationWaitsForTheRevertBeforeIt(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })

	revertSent, releaseRevert, nextSent := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	var sends int
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		sends++
		if sends == 1 {
			close(revertSent)
			<-releaseRevert
			return nil
		}
		nextSent <- struct{}{}
		return nil
	}
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return nil }

	s := programmedRateChange(t)
	t.Cleanup(func() { s.sm.StopT3591() })
	timer := &smf_context.Timer{}
	s.sm.T3591 = timer

	reverted := make(chan struct{})
	go func() {
		abandonIfCurrent(s.sm, timer)
		close(reverted)
	}()
	<-revertSent

	// The PCF edits the same rule again while the revert is still out.
	s.sm.SMLock.Lock()
	again := qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.rateChange())
	s.sm.SMLock.Unlock()
	applied := make(chan error, 1)
	go func() { applied <- ApplyModification(s.sm, again) }()

	select {
	case <-nextSent:
		t.Fatal("the new modification reached the user plane while the revert before it was still out")
	case <-time.After(300 * time.Millisecond):
	}

	close(releaseRevert)
	<-reverted
	select {
	case <-nextSent:
	case <-time.After(5 * time.Second):
		t.Fatal("the new modification never reached the user plane after the revert finished")
	}
	if err := <-applied; err != nil {
		t.Fatalf("ApplyModification: %v", err)
	}

	for dir, pdr := range map[string]*smf_context.PDR{"UL": s.cirUL, "DL": s.cirDL} {
		var newRates bool
		for _, qer := range pdr.QER {
			if qer.MBR != nil && qer.MBR.ULMBR == 5000 && qer.MBR.DLMBR == 8000 {
				newRates = true
			}
		}
		if !newRates {
			t.Errorf("%s: after the revert and the new modification, the rule is not on the new rates", dir)
		}
	}
}

// A decision that only disables a flow changes the rule's traffic control data and nothing else.
// The gate comes from there, so the rule has to be requalified with its QER closed; the builder used
// to look at QoS data and the rule itself only, so the flow went on forwarding.
func TestDisablingAFlowClosesItsGateOnTheUserPlane(t *testing.T) {
	const tcID = "tc-cir"
	enabled, disabled := models.FLOWSTATUS_ENABLED, models.FLOWSTATUS_DISABLED

	s := newTwoRuleSession(t, false)
	s.cirRule.RefTcData = []string{tcID}
	committedRule := s.cirRule
	s.sm.SmPolicyData.SmCtxtPccRules.PccRules[cirRuleID] = &committedRule
	s.sm.SmPolicyData.SmCtxtTCData.TrafficControlData[tcID] = &models.TrafficControlData{TcId: tcID, FlowStatus: &enabled}

	decision := s.rateChange()
	(*decision.QosDecs)[cirQosID] = s.cirQosSent
	decision.PccRules[cirRuleID] = s.cirRule
	decision.TraffContDecs = &map[string]models.TrafficControlData{tcID: {TcId: tcID, FlowStatus: &disabled}}
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, roundTrip(decision))}

	param := BuildPfcpParam(s.sm)

	if param.touches(s.allowUL) || param.touches(s.allowDL) {
		t.Error("the catch-all was reprogrammed for a change to another rule's gate")
	}
	for dir, pdr := range map[string]*smf_context.PDR{"UL": s.cirUL, "DL": s.cirDL} {
		if !param.touches(pdr) {
			t.Errorf("%s: the disabled rule's PDR was not reprogrammed", dir)
			continue
		}
		var closed bool
		for _, qer := range pdr.QER {
			if qer.QERID != s.sessQER.QERID && qer.GateStatus != nil &&
				qer.GateStatus.ULGate == smf_context.GateClose && qer.GateStatus.DLGate == smf_context.GateClose {
				closed = true
			}
		}
		if !closed {
			t.Errorf("%s: the disabled rule's flow QER is not closed", dir)
		}
	}
}
