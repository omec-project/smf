// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"encoding/json"
	"testing"

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
