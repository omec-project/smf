// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"encoding/json"
	"errors"
	"maps"
	"net"
	"testing"
	"time"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/qos"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
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
	// upfNodeIP is the two-rule session's UPF, and the key of its PFCP context.
	upfNodeIP = "10.0.0.7"
)

func newTwoRuleSession(t *testing.T, restored bool) *twoRuleSession {
	t.Helper()

	upf := smf_context.NewUPF(smf_context.NewNodeID(upfNodeIP), nil)
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
	establishedUplinkTunnel(s.sm, node)

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
		AuthSessAmbr: &models.Ambr{Uplink: "150 Mbps", Downlink: "200 Mbps"},
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
			upfNodeIP: {PDRs: map[uint16]*smf_context.PDR{}},
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

	if !revertModification(s.sm, s.sm.NwModificationGen) {
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
	// A running timer, as abandonment finds one: abandoning stops it.
	timer := smf_context.NewTimer(time.Hour, 4, func(int32) {}, func() {})
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

	revertModification(s.sm, s.sm.NwModificationGen)

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
	s.sm.PFCPContext = map[string]*smf_context.PFCPSessionContext{upfNodeIP: {PDRs: pdrs}}
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
	t.Cleanup(func() {
		s.sm.SMLock.Lock()
		s.sm.StopT3591()
		s.sm.SMLock.Unlock()
	})

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
	pdrs := s.sm.PFCPContext[upfNodeIP].PDRs
	if pdrs[s.cirUL.PDRID] != nil || pdrs[s.cirDL.PDRID] != nil {
		t.Error("the withdrawn rule's PDRs are still in the session's PFCP context")
	}
	if pdrs[s.allowUL.PDRID] == nil || node.UpLinkTunnel.PDR[allowRuleID] == nil {
		t.Error("a rule the modification kept was dropped from the session")
	}
}

// The withdrawn rule leaves the PFCP session context the session recorded it in, found by the UPF's
// NodeID: the entry is keyed by the address resolved when the session was allocated, and an FQDN
// UPF's address can move under the DNS refresh. Looked up by a fresh resolution, the entry was
// missed and kept the withdrawn PDRs, which the session store writes and reads back.
func TestAWithdrawnRuleLeavesThePFCPContextItWasRecordedIn(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error { return nil }
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return nil }

	s := newTwoRuleSession(t, false)
	s.withPfcpContext()
	t.Cleanup(func() {
		s.sm.SMLock.Lock()
		s.sm.StopT3591()
		s.sm.SMLock.Unlock()
	})
	// Recorded under the address the UPF had when the session was allocated, which it no longer
	// resolves to.
	const allocatedAt = "10.99.0.1"
	recorded := s.sm.PFCPContext[upfNodeIP]
	recorded.NodeID = s.sm.Tunnel.DataPathPool[1].FirstDPNode.UPF.NodeID
	s.sm.PFCPContext = map[string]*smf_context.PFCPSessionContext{allocatedAt: recorded}

	if err := ApplyModification(s.sm, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.deleteDedicatedRule())); err != nil {
		t.Fatalf("ApplyModification: %v", err)
	}

	if recorded.PDRs[s.cirUL.PDRID] != nil || recorded.PDRs[s.cirDL.PDRID] != nil {
		t.Error("the withdrawn rule's PDRs are still in the PFCP context recorded under the allocation-time address")
	}
	if recorded.PDRs[s.allowUL.PDRID] == nil {
		t.Error("a rule the modification kept was dropped from the PFCP context")
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

// A revert leaves the session's state alone, and is sent while it is owed: the response handlers
// deliver its answer by RevertOwed, whatever the state. A NAS or NGAP handler that starts a revert
// returns the state it reads after releasing the lock, and its transaction's state machine writes
// that back after the handler returns. The revert used to move the session to SmStatePfcpModify for
// its exchange, so that write, read while the revert was out and made once it had settled, left the
// session in SmStatePfcpModify for good, where no policy notification or release is handled.
func TestARevertLeavesTheSessionsStateAlone(t *testing.T) {
	original := sendPfcpSessionModifyReq
	t.Cleanup(func() { sendPfcpSessionModifyReq = original })
	var stateAtSend smf_context.SMContextState
	var owedAtSend bool
	sendPfcpSessionModifyReq = func(sm *smf_context.SMContext, _ *pfcpParam) error {
		stateAtSend = sm.SMContextState
		owedAtSend = sm.RevertOwed.Load()
		return nil
	}

	s := programmedRateChange(t)
	// A running timer, as abandonment finds one: abandoning stops it.
	timer := smf_context.NewTimer(time.Hour, 4, func(int32) {}, func() {})
	s.sm.T3591 = timer

	abandonIfCurrent(s.sm, timer)

	if !owedAtSend {
		t.Error("the revert was sent with no revert owed, so its answer would be dropped")
	}
	// The starting transaction's trailing write: the state it read while the revert was out.
	s.sm.ChangeState(stateAtSend)
	if s.sm.SMContextState != smf_context.SmStateActive {
		t.Errorf("after the revert and its transaction's state write the session is in %s, want %s",
			s.sm.SMContextState, smf_context.SmStateActive)
	}
}

// A revert started by a NAS or NGAP handler runs beside the transaction that started it, and that
// transaction's store can be taken before the revert has finished, with the rules it is undoing. So
// the revert stores the session itself once it has put the rules back, and while it is still owed,
// so no transaction waiting for it runs first and is stored half done. It used to store nothing,
// and the store kept the abandoned modification until the session's next transaction.
func TestARevertBesideItsTransactionStoresTheSessionItPutBack(t *testing.T) {
	originalSend, originalStore, originalConfig := sendPfcpSessionModifyReq, storeSmContext, factory.SmfConfig
	t.Cleanup(func() {
		sendPfcpSessionModifyReq, storeSmContext, factory.SmfConfig = originalSend, originalStore, originalConfig
	})
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error { return nil }
	disabled := false
	config := factory.Configuration{KafkaInfo: factory.KafkaInfo{EnableKafka: &disabled}}
	if originalConfig.Configuration != nil {
		config = *originalConfig.Configuration
	}
	config.EnableDbStore = true
	factory.SmfConfig.Configuration = &config

	s := programmedRateChange(t)
	// What the store would write: whether the revert was still owed, and the rule's flow rates.
	type snapshot struct {
		owed  bool
		ulMbr uint64
	}
	stored := make(chan snapshot, 1)
	storeSmContext = func(sm *smf_context.SMContext) {
		sm.SMLock.Lock()
		defer sm.SMLock.Unlock()
		seen := snapshot{owed: sm.RevertInFlight != nil}
		for _, qer := range s.cirUL.QER {
			if qer.QERID != s.sessQER.QERID && qer.MBR != nil {
				seen.ulMbr = qer.MBR.ULMBR
			}
		}
		stored <- seen
	}

	s.sm.SMLock.Lock()
	abandonModificationUnderLock(s.sm, "command_reject", "5gsm_cause_26")
	s.sm.SMLock.Unlock()

	select {
	case seen := <-stored:
		if !seen.owed {
			t.Error("the session was stored after its revert was settled, when a transaction waiting for it could have run first")
		}
		if seen.ulMbr != 3000 {
			t.Errorf("the stored rule's uplink MBR is %d, want the committed 3000", seen.ulMbr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session was not stored after its revert")
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
	t.Cleanup(func() {
		s.sm.SMLock.Lock()
		s.sm.StopT3591()
		s.sm.SMLock.Unlock()
	})
	// A running timer, as abandonment finds one: abandoning stops it.
	timer := smf_context.NewTimer(time.Hour, 4, func(int32) {}, func() {})
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

// T3591's last expiry abandons the modification and reverts the user plane. That work is queued in
// the session's transaction slot, not run on the timer's goroutine, where it could overtake a
// transaction that had already checked for an owed revert and was on its way to its own exchange.
func TestT3591ExpiryQueuesItsAbandonment(t *testing.T) {
	originalQueue, originalN1N2, originalRetransmit := queueSessionTask, sendQosN1N2TransferMsg, retransmitModificationCommand
	t.Cleanup(func() {
		queueSessionTask, sendQosN1N2TransferMsg, retransmitModificationCommand = originalQueue, originalN1N2, originalRetransmit
	})
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return nil }
	retransmitModificationCommand = func(*smf_context.SMContext, func() bool) error { return nil }

	queued := make(chan func(), 1)
	queueSessionTask = func(_ *smf_context.SMContext, task func()) { queued <- task }

	s := programmedRateChange(t)
	s.sm.T3591Value = 5 * time.Millisecond
	t.Cleanup(func() {
		s.sm.SMLock.Lock()
		s.sm.StopT3591()
		s.sm.SMLock.Unlock()
	})
	s.sm.SMLock.Lock()
	startT3591Locked(s.sm, 1)
	s.sm.SMLock.Unlock()

	select {
	case task := <-queued:
		if !s.sm.NwModificationPending {
			t.Fatal("the modification was abandoned before the queued work ran")
		}
		original := sendPfcpSessionModifyReq
		t.Cleanup(func() { sendPfcpSessionModifyReq = original })
		var reverted bool
		sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
			reverted = true
			return nil
		}
		task()
		if s.sm.NwModificationPending || !reverted {
			t.Errorf("the queued work did not abandon and revert (pending %v, reverted %v)", s.sm.NwModificationPending, reverted)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("T3591 ran out without queueing its abandonment")
	}
}

// The correction after a partial rejection is a modification, and one that cannot be delivered is
// reverted. It is queued in the session's slot for the same reason T3591's abandonment is: started
// on a goroutine of its own, its revert would set the owed-revert marker behind a transaction that
// had already checked for it.
func TestTheRealignmentIsQueuedInTheSessionSlot(t *testing.T) {
	originalQueue, originalApply := queueSessionTask, applyModification
	t.Cleanup(func() { queueSessionTask, applyModification = originalQueue, originalApply })

	var queued func()
	queueSessionTask = func(_ *smf_context.SMContext, task func()) { queued = task }
	var applied *qos.PolicyUpdate
	applyModification = func(_ *smf_context.SMContext, u *qos.PolicyUpdate) error {
		applied = u
		return nil
	}

	s := newTwoRuleSession(t, false)
	corrective := &qos.PolicyUpdate{}
	realignSession(s.sm, &smf_context.PendingRealignment{RefusedQFIs: []int64{1}}, corrective)

	if queued == nil {
		t.Fatal("the correction was not queued in the session's slot")
	}
	if applied != nil {
		t.Fatal("the correction ran before its queued turn")
	}
	queued()
	if applied != corrective {
		t.Error("the queued work did not apply the correction")
	}
}

// The correction after a partial rejection carries the original decision, refused flows included,
// because RemoveFlows keeps it for the NAS and NGAP builders. Only what the update adds or changes
// is read from it, and a correction adds and changes nothing, so the refused flow's QoS must not
// come back as a QER: the correction withdraws the rule's PDRs and programs nothing else.
func TestACorrectionProgramsNothingForTheFlowItWithdraws(t *testing.T) {
	const appRuleID, appQosID = "app", "2"

	for range 40 {
		s := newTwoRuleSession(t, false)
		s.sm.PFCPContext = map[string]*smf_context.PFCPSessionContext{
			upfNodeIP: {PDRs: map[uint16]*smf_context.PDR{}},
		}

		decision := s.rateChange()
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

		// The modification adding the rule is programmed, and the radio then refuses its flow.
		update := qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)
		s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{update}
		BuildPfcpParam(s.sm)
		node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
		appUL, appDL := node.UpLinkTunnel.PDR[appRuleID], node.DownLinkTunnel.PDR[appRuleID]
		if appUL == nil || appDL == nil {
			t.Fatalf("the added rule's PDRs were not built (UL %v, DL %v)", appUL != nil, appDL != nil)
		}
		corrective := update.RemoveFlows(qos.RefusedFlowSet([]int64{2}))
		if corrective == nil {
			t.Fatal("no correction for a refused addition")
		}
		if err := qos.CommitSmPolicyDecision(&s.sm.SmPolicyData, update); err != nil {
			t.Fatalf("committing the pruned update: %v", err)
		}

		s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{corrective}
		param := BuildPfcpParam(s.sm)

		if len(param.qerList) != 0 {
			for _, qer := range param.qerList {
				t.Errorf("the correction creates QER %d for QFI %d; it withdraws flows and creates nothing", qer.QERID, qer.QFI.QFI)
			}
		}
		if len(param.pdrList) != 0 {
			t.Errorf("the correction programs %d PDRs; it only withdraws the refused rule's", len(param.pdrList))
		}
		removed := map[*smf_context.PDR]bool{}
		for _, pdr := range param.removePDR {
			removed[pdr] = true
		}
		if !removed[appUL] || !removed[appDL] {
			t.Errorf("the refused rule's PDRs were not withdrawn (UL %v, DL %v)", removed[appUL], removed[appDL])
		}
		if t.Failed() {
			return
		}
	}
}

// The radio's end of the session's tunnel, as the setup response at establishment records it.
var (
	gnbN3IP   = net.ParseIP("192.0.2.10")
	gnbN3TEID = uint32(0x2a)
)

// withConnection gives the fixture an access connection: up, with the radio's end of the tunnel
// known, or released to idle.
func (s *twoRuleSession) withConnection(activated bool) {
	s.sm.Tunnel.ANInformation.IPAddress = gnbN3IP
	s.sm.Tunnel.ANInformation.TEID = gnbN3TEID
	s.sm.UpCnxState = models.UPCNXSTATE_DEACTIVATED
	if activated {
		s.sm.UpCnxState = models.UPCNXSTATE_ACTIVATED
	}
}

// addAppRule is a decision adding one rule, with its own QoS data, beside the two established.
func (s *twoRuleSession) addAppRule() *models.SmPolicyDecision {
	const appRuleID, appQosID = "app", "2"

	return roundTrip(&models.SmPolicyDecision{
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
			appQosID: {QosId: appQosID, Var5qi: openapi.PtrInt32(2)},
		},
	})
}

// forwardsToTheRadio reports whether a downlink FAR, as sent, forwards to the radio's end of the
// session's tunnel.
func forwardsToTheRadio(param *pfcpParam, far *smf_context.FAR) bool {
	sent := false
	for _, f := range param.farList {
		sent = sent || f == far
	}
	ohc := far.ForwardingParameters
	return sent && far.ApplyAction.Forw && !far.ApplyAction.Buff && ohc != nil && ohc.OuterHeaderCreation != nil &&
		ohc.DestinationInterface.InterfaceValue == smf_context.DestinationInterfaceAccess &&
		ohc.OuterHeaderCreation.Teid == gnbN3TEID && ohc.OuterHeaderCreation.Ipv4Address.Equal(gnbN3IP)
}

// A rule added to a session whose access connection is up forwards its downlink to the radio.
// It used to be created buffering, as at establishment, and nothing switched it over: the setup
// response that re-points downlink rules comes only when a connection is activated, and a downlink
// report is acted on only for a deactivated one. So the added rule's downlink was held for good.
// With the connection released to idle it still buffers and reports, so its downlink pages the UE.
func TestAnAddedRuleForwardsDownlinkWhileTheConnectionIsUp(t *testing.T) {
	for _, activated := range []bool{true, false} {
		s := newTwoRuleSession(t, false)
		s.withPfcpContext()
		s.withConnection(activated)
		s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.addAppRule())}

		param := BuildPfcpParam(s.sm)

		dl := s.sm.Tunnel.DataPathPool[1].FirstDPNode.DownLinkTunnel.PDR["app"]
		if dl == nil || dl.FAR == nil {
			t.Fatal("the added rule has no downlink PDR and FAR")
		}
		if activated && !forwardsToTheRadio(param, dl.FAR) {
			t.Errorf("connection up: the added rule's downlink FAR is %+v, not forwarding to the radio", dl.FAR.ApplyAction)
		}
		if !activated && (!dl.FAR.ApplyAction.Buff || !dl.FAR.ApplyAction.Nocp || dl.FAR.ApplyAction.Forw) {
			t.Errorf("connection released: the added rule's downlink FAR is %+v, want buffering and reporting", dl.FAR.ApplyAction)
		}
	}
}

// A withdrawal the UE was never told about is reverted by re-creating the rule, which goes through
// the same builder as an added one. With the connection up, its downlink forwards again: buffered,
// the revert reported the user plane restored while the rule's downlink went nowhere.
func TestARuleReinstatedByARevertForwardsDownlink(t *testing.T) {
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
	s.withConnection(true)
	s.cirRule.FlowInfos = []models.FlowInformation{{
		FlowDescription: openapi.PtrString("permit out ip from 192.168.250.1/32 to assigned"),
		PackFiltId:      openapi.PtrString("5"),
	}}
	committedRule := s.cirRule
	s.sm.SmPolicyData.SmCtxtPccRules.PccRules[cirRuleID] = &committedRule

	if err := ApplyModification(s.sm, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.deleteDedicatedRule())); err == nil {
		t.Fatal("the undeliverable modification was reported as delivered")
	}

	dl := s.sm.Tunnel.DataPathPool[1].FirstDPNode.DownLinkTunnel.PDR[cirRuleID]
	if dl == nil || !sent.touches(dl) {
		t.Fatal("the withdrawn rule's downlink PDR was not re-created")
	}
	if !forwardsToTheRadio(sent, dl.FAR) {
		t.Errorf("the reinstated rule's downlink FAR is %+v, not forwarding to the radio", dl.FAR.ApplyAction)
	}
}

// flowQERAfter is the flow QER a reprogrammed PDR carries: the one that is not the session's.
func (s *twoRuleSession) flowQERAfter(param *pfcpParam, pdr *smf_context.PDR) *smf_context.QER {
	if !param.touches(pdr) {
		return nil
	}
	for _, qer := range pdr.QER {
		if qer.QERID != s.sessQER.QERID && queued(param.qerList, qer) {
			return qer
		}
	}
	return nil
}

// A decision is a change to the policy in force, so one that changes a flow's rates need not repeat
// the rule that refers to them (TS 29.512 subclause 4.2.6.1). The rule's PDRs used to be found only
// among the rules the decision carries, so they kept the old rates while the new ones were
// committed. And with no rule in the update, the tunnel build allocated a "default" PDR over
// whatever rule went by that name.
func TestARateChangeThatDoesNotRepeatItsRuleReachesTheRule(t *testing.T) {
	s := newTwoRuleSession(t, false)
	s.withPfcpContext()
	changed := (*s.rateChange().QosDecs)[cirQosID]
	decision := roundTrip(&models.SmPolicyDecision{QosDecs: &map[string]models.QosData{cirQosID: changed}})
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)}

	param := BuildPfcpParam(s.sm)

	if param.touches(s.allowUL) || param.touches(s.allowDL) {
		t.Error("the catch-all was reprogrammed for a change to another rule's rates")
	}
	for dir, pdr := range map[string]*smf_context.PDR{"UL": s.cirUL, "DL": s.cirDL} {
		qer := s.flowQERAfter(param, pdr)
		if qer == nil || qer.MBR == nil || qer.MBR.ULMBR != 5000 || qer.MBR.DLMBR != 8000 {
			t.Errorf("%s: the rule's PDR does not carry a new flow QER at the changed rates (%+v)", dir, qer)
		}
	}
	node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
	for dir, tunnel := range map[string]*smf_context.GTPTunnel{"UL": node.UpLinkTunnel, "DL": node.DownLinkTunnel} {
		if len(tunnel.PDR) != 2 {
			t.Errorf("%s: the tunnel holds %d PDRs after a rate change, want the two rules' own", dir, len(tunnel.PDR))
		}
	}
}

// A decision closing a flow's gate need not repeat the QoS data the flow's rule refers to. The QER
// was built from the decision alone, so it found no QoS data and was not built: the flow went on
// forwarding.
func TestAGateChangeThatLeavesOutTheQosDataClosesTheGate(t *testing.T) {
	const tcID = "tc-cir"
	enabled, disabled := models.FLOWSTATUS_ENABLED, models.FLOWSTATUS_DISABLED

	s := newTwoRuleSession(t, false)
	s.cirRule.RefTcData = []string{tcID}
	committedRule := s.cirRule
	s.sm.SmPolicyData.SmCtxtPccRules.PccRules[cirRuleID] = &committedRule
	s.sm.SmPolicyData.SmCtxtTCData.TrafficControlData[tcID] = &models.TrafficControlData{TcId: tcID, FlowStatus: &enabled}

	decision := roundTrip(&models.SmPolicyDecision{
		PccRules:      map[string]models.PccRule{cirRuleID: s.cirRule},
		TraffContDecs: &map[string]models.TrafficControlData{tcID: {TcId: tcID, FlowStatus: &disabled}},
	})
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)}

	param := BuildPfcpParam(s.sm)

	for dir, pdr := range map[string]*smf_context.PDR{"UL": s.cirUL, "DL": s.cirDL} {
		qer := s.flowQERAfter(param, pdr)
		if qer == nil || qer.GateStatus == nil ||
			qer.GateStatus.ULGate != smf_context.GateClose || qer.GateStatus.DLGate != smf_context.GateClose {
			t.Errorf("%s: the rule's PDR does not carry a closed flow QER (%+v)", dir, qer)
			continue
		}
		if qer.MBR == nil || qer.MBR.ULMBR != 3000 || qer.MBR.DLMBR != 6000 {
			t.Errorf("%s: the closed flow QER is not at the committed rates (%+v)", dir, qer.MBR)
		}
	}
}

// The other way round: a decision changing a disabled flow's rates need not repeat the traffic
// control data that disables it, nor the rule that refers to it. Built from the decision alone, the
// new QER found neither and opened the gate.
func TestARateChangeKeepsADisabledFlowClosed(t *testing.T) {
	const tcID = "tc-cir"
	disabled := models.FLOWSTATUS_DISABLED

	s := newTwoRuleSession(t, false)
	s.cirRule.RefTcData = []string{tcID}
	committedRule := s.cirRule
	s.sm.SmPolicyData.SmCtxtPccRules.PccRules[cirRuleID] = &committedRule
	s.sm.SmPolicyData.SmCtxtTCData.TrafficControlData[tcID] = &models.TrafficControlData{TcId: tcID, FlowStatus: &disabled}

	changed := (*s.rateChange().QosDecs)[cirQosID]
	decision := roundTrip(&models.SmPolicyDecision{QosDecs: &map[string]models.QosData{cirQosID: changed}})
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)}

	param := BuildPfcpParam(s.sm)

	for dir, pdr := range map[string]*smf_context.PDR{"UL": s.cirUL, "DL": s.cirDL} {
		qer := s.flowQERAfter(param, pdr)
		if qer == nil || qer.MBR == nil || qer.MBR.ULMBR != 5000 {
			t.Errorf("%s: the rule's PDR does not carry a new flow QER at the changed rates (%+v)", dir, qer)
			continue
		}
		if qer.GateStatus == nil || qer.GateStatus.ULGate != smf_context.GateClose || qer.GateStatus.DLGate != smf_context.GateClose {
			t.Errorf("%s: the disabled flow's new QER has its gate open (%+v)", dir, qer.GateStatus)
		}
	}
}

// A withdrawal of every rule the user plane accepts leaves the node no PDR to find the session QER
// on. When the UE cannot be told and the withdrawal is reverted, the rules came back with their flow
// QERs only, and the revert reported the user plane put back without the session AMBR.
func TestRevertingAWithdrawalOfEveryRuleRestoresTheSessionAmbr(t *testing.T) {
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
	for name, rule := range map[string]*models.PccRule{allowRuleID: &s.allowRule, cirRuleID: &s.cirRule} {
		packFiltID := map[string]string{allowRuleID: "5", cirRuleID: "6"}[name]
		rule.FlowInfos = []models.FlowInformation{{
			FlowDescription: openapi.PtrString("permit out ip from any to assigned"),
			PackFiltId:      openapi.PtrString(packFiltID),
		}}
		committed := *rule
		s.sm.SmPolicyData.SmCtxtPccRules.PccRules[name] = &committed
	}

	withdrawAll := roundTrip(&models.SmPolicyDecision{
		PccRules: map[string]models.PccRule{allowRuleID: {}, cirRuleID: {}},
		QosDecs:  &map[string]models.QosData{allowQosID: {}, cirQosID: {}},
	})
	if err := ApplyModification(s.sm, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, withdrawAll)); err == nil {
		t.Fatal("the undeliverable modification was reported as delivered")
	}

	node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
	for _, name := range []string{allowRuleID, cirRuleID} {
		for dir, tunnel := range map[string]*smf_context.GTPTunnel{"UL": node.UpLinkTunnel, "DL": node.DownLinkTunnel} {
			pdr := tunnel.PDR[name]
			if pdr == nil || !sent.touches(pdr) {
				t.Errorf("%s %s: the withdrawn rule was not re-created", name, dir)
				continue
			}
			var sessionAmbr bool
			for _, qer := range pdr.QER {
				if qer.MBR != nil && qer.MBR.ULMBR == 150000 && qer.MBR.DLMBR == 200000 && queued(sent.qerList, qer) {
					sessionAmbr = true
				}
			}
			if !sessionAmbr {
				t.Errorf("%s %s: the re-created rule carries no session-AMBR QER", name, dir)
			}
		}
	}
}

// emptyNode leaves the fixture's node as an accepted withdrawal of every rule does: no PDR left.
func (s *twoRuleSession) emptyNode() {
	node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
	node.UpLinkTunnel.PDR = map[string]*smf_context.PDR{}
	node.DownLinkTunnel.PDR = map[string]*smf_context.PDR{}
}

// sessionAmbrQERs is the session QERs queued for creation: at the session AMBR, on the default flow.
// A flow QER can be at the session AMBR too, when its QoS data names no rate, but not on that flow.
func sessionAmbrQERs(param *pfcpParam) int {
	n := 0
	for _, qer := range param.qerList {
		if qer.MBR != nil && qer.MBR.ULMBR == 150000 && qer.MBR.DLMBR == 200000 &&
			qer.QFI.QFI == qos.GetQosFlowIdFromQosId(allowQosID) {
			n++
		}
	}
	return n
}

// A session QER is built for rules added to an emptied node, and only there. A decision adding a
// rule need not repeat the default flow it leaves unchanged; the session QER is built from the
// committed one then. An update adding nothing builds none, and a node that still has rules is not
// emptied, whatever its PDRs share.
func TestASessionQERIsBuiltOnlyForRulesAddedToAnEmptiedNode(t *testing.T) {
	t.Run("an added rule on an emptied node, the default flow left out", func(t *testing.T) {
		s := newTwoRuleSession(t, false)
		s.withPfcpContext()
		s.emptyNode()
		decision := s.addAppRule()
		delete(decision.PccRules, allowRuleID)
		delete(decision.PccRules, cirRuleID)
		delete(*decision.QosDecs, allowQosID)
		delete(*decision.QosDecs, cirQosID)
		s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)}

		param := BuildPfcpParam(s.sm)

		if n := sessionAmbrQERs(param); n != 1 {
			t.Fatalf("%d session QERs built for the rule added to an emptied node, want 1", n)
		}
	})

	t.Run("nothing added to an emptied node", func(t *testing.T) {
		s := newTwoRuleSession(t, false)
		s.withPfcpContext()
		s.emptyNode()
		changed := (*s.rateChange().QosDecs)[cirQosID]
		decision := roundTrip(&models.SmPolicyDecision{QosDecs: &map[string]models.QosData{cirQosID: changed}})
		s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)}

		if param := BuildPfcpParam(s.sm); len(param.qerList) != 0 {
			t.Errorf("%d QERs built for an update that adds no rule", len(param.qerList))
		}
	})

	t.Run("a node with rules that share no QER", func(t *testing.T) {
		s := newTwoRuleSession(t, false)
		s.withPfcpContext()
		for _, pdr := range []*smf_context.PDR{s.allowUL, s.allowDL, s.cirUL, s.cirDL} {
			pdr.QER = pdr.QER[:1]
		}
		s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.addAppRule())}

		if n := sessionAmbrQERs(BuildPfcpParam(s.sm)); n != 0 {
			t.Errorf("%d session QERs built beside rules that are still on the node", n)
		}
	})
}

// A decision with no PCC rule in it -- here one changing only the session AMBR -- adds none, and
// the tunnel build makes PDRs for added rules alone. Called with no rule in the update, it allocated
// a "default" PDR and FAR and stored them over whatever rule went by that name.
func TestADecisionWithNoPccRuleAllocatesNoPdr(t *testing.T) {
	s := newTwoRuleSession(t, false)
	s.withPfcpContext()
	node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
	defaultRuleDL := s.allowDL
	node.DownLinkTunnel.PDR = map[string]*smf_context.PDR{defaultPdrKey: defaultRuleDL, cirRuleID: s.cirDL}

	decision := roundTrip(&models.SmPolicyDecision{SessRules: &map[string]models.SessionRule{
		"session": {SessRuleId: "session", AuthSessAmbr: &models.Ambr{Uplink: "120 Mbps", Downlink: "300 Mbps"}},
	}})
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)}

	BuildPfcpParam(s.sm)

	if got := node.DownLinkTunnel.PDR[defaultPdrKey]; got != defaultRuleDL {
		t.Errorf("the rule named \"default\" now has PDR %v in place of its own", got)
	}
	if len(node.UpLinkTunnel.PDR) != 2 || len(node.DownLinkTunnel.PDR) != 2 {
		t.Errorf("the tunnels hold %d and %d PDRs, want the two rules' own", len(node.UpLinkTunnel.PDR), len(node.DownLinkTunnel.PDR))
	}
}

// An added rule's PDRs name the UE's address, as establishment's do. Without it the user plane
// reads the flow description's "assigned" as any address, and the rule matched every subscriber's
// traffic that fitted its filter: downlink, now forwarded, went to this UE. A rule re-created by a
// revert is built the same way and is bound the same way.
func TestAnAddedRuleMatchesOnlyItsOwnUEsTraffic(t *testing.T) {
	boundToTheUE := func(t *testing.T, node *smf_context.DataPathNode, name string) {
		t.Helper()
		for dir, tunnel := range map[string]*smf_context.GTPTunnel{"UL": node.UpLinkTunnel, "DL": node.DownLinkTunnel} {
			pdr := tunnel.PDR[name]
			if pdr == nil {
				t.Errorf("%s: no PDR for the rule", dir)
				continue
			}
			addr := pdr.PDI.UEIPAddress
			if addr == nil || !addr.V4 || addr.CHV4 || !addr.Ipv4Address.Equal(net.ParseIP("192.168.100.1")) {
				t.Errorf("%s: the PDR names UE address %+v, want the session's own", dir, addr)
			}
		}
	}

	t.Run("added", func(t *testing.T) {
		s := newTwoRuleSession(t, false)
		s.withPfcpContext()
		s.withConnection(true)
		s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.addAppRule())}

		BuildPfcpParam(s.sm)

		boundToTheUE(t, s.sm.Tunnel.DataPathPool[1].FirstDPNode, "app")
	})

	t.Run("re-created by a revert", func(t *testing.T) {
		s, reverted := revertOfWithdrawal(t, func(*twoRuleSession) {})
		if reverted == nil {
			t.Fatal("nothing was sent to put the withdrawn rule back")
		}

		boundToTheUE(t, s.sm.Tunnel.DataPathPool[1].FirstDPNode, cirRuleID)
	})
}

// revertOfWithdrawal withdraws the dedicated rule, which the user plane accepts and the UE is never
// told of, so the withdrawal is reverted. spoil runs between the two. It returns what the revert
// sent, nil if nothing.
func revertOfWithdrawal(t *testing.T, spoil func(*twoRuleSession)) (*twoRuleSession, *pfcpParam) {
	t.Helper()

	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })

	s := newTwoRuleSession(t, false)
	s.withPfcpContext()
	s.withConnection(true)
	s.cirRule.FlowInfos = []models.FlowInformation{{
		FlowDescription: openapi.PtrString("permit out ip from 192.168.250.1/32 to assigned"),
		PackFiltId:      openapi.PtrString("5"),
	}}
	committedRule := s.cirRule
	s.sm.SmPolicyData.SmCtxtPccRules.PccRules[cirRuleID] = &committedRule

	var sends []*pfcpParam
	sendPfcpSessionModifyReq = func(_ *smf_context.SMContext, p *pfcpParam) error {
		sends = append(sends, p)
		return nil
	}
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error {
		spoil(s)
		return errors.New("amf unreachable")
	}

	if err := ApplyModification(s.sm, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.deleteDedicatedRule())); err == nil {
		t.Fatal("the undeliverable modification was reported as delivered")
	}
	if len(sends) < 2 {
		return s, nil
	}

	return s, sends[1]
}

// A revert that cannot be built is a failed revert. A rule the builder cannot program is logged and
// skipped, so an empty revert was reported as one with nothing to put back -- and the session was
// left on parameters the UE was never told about, with nothing marking it -- and a partial one was
// sent and reported as having put the user plane back. Whatever stops the build counts, and only
// what does: a revert that builds nothing new is sent whatever state the node is in.
func TestARevertThatCannotBeBuiltIsAFailedRevert(t *testing.T) {
	failedRevert := func(t *testing.T, s *twoRuleSession, reverted *pfcpParam) {
		t.Helper()
		if reverted != nil {
			t.Errorf("a revert that could not be built was sent: %d PDRs, %d QERs", len(reverted.pdrList), len(reverted.qerList))
		}
		if !s.sm.RevertFailed {
			t.Error("the session is not marked as one whose user plane could not be put back")
		}
	}

	t.Run("re-creating a rule on a node no longer associated", func(t *testing.T) {
		s, reverted := revertOfWithdrawal(t, func(s *twoRuleSession) {
			s.sm.Tunnel.DataPathPool[1].FirstDPNode.UPF.UPFStatus = smf_context.NotAssociated
		})
		failedRevert(t, s, reverted)
	})

	t.Run("re-creating a rule with the node's PDR identifiers used up", func(t *testing.T) {
		s, reverted := revertOfWithdrawal(t, func(s *twoRuleSession) {
			upf := s.sm.Tunnel.DataPathPool[1].FirstDPNode.UPF
			for {
				if _, err := upf.AddPDR(); err != nil {
					return
				}
			}
		})
		failedRevert(t, s, reverted)
	})

	t.Run("re-creating a rule for a session whose UE address is released", func(t *testing.T) {
		s, reverted := revertOfWithdrawal(t, func(s *twoRuleSession) { s.sm.PDUAddress.Ip = net.IPv4zero })
		failedRevert(t, s, reverted)
	})

	t.Run("re-creating a rule with no PFCP session to record it in", func(t *testing.T) {
		s, reverted := revertOfWithdrawal(t, func(s *twoRuleSession) { s.sm.PFCPContext = nil })
		failedRevert(t, s, reverted)
	})

	t.Run("re-creating rules with no session AMBR to give them", func(t *testing.T) {
		s, reverted := revertOfWithdrawal(t, func(s *twoRuleSession) {
			s.emptyNode()
			s.sm.SmPolicyData.SmCtxtSessionRules.ActiveRule = nil
		})
		failedRevert(t, s, reverted)
	})

	t.Run("putting a rule's rates back on a node no longer associated", func(t *testing.T) {
		original := sendPfcpSessionModifyReq
		t.Cleanup(func() { sendPfcpSessionModifyReq = original })
		var reverted *pfcpParam
		sendPfcpSessionModifyReq = func(_ *smf_context.SMContext, p *pfcpParam) error {
			reverted = p
			return nil
		}

		s := programmedRateChange(t)
		s.sm.Tunnel.DataPathPool[1].FirstDPNode.UPF.UPFStatus = smf_context.NotAssociated

		if revertModification(s.sm, s.sm.NwModificationGen) {
			t.Error("the revert reported the user plane put back")
		}
		failedRevert(t, s, reverted)
	})
}

// A rate is converted as written in any of the spellings a policy carries. Read raw, "10.0 Mbps"
// and "10Mbps" were 0 kbps: policy updates build their QERs with CreatePccRuleQer, and the builder
// they used before normalized the rate first.
func TestARateChangeInAnySpellingReachesTheUserPlane(t *testing.T) {
	for _, spelling := range [][2]string{{"10.0 Mbps", "20.0 Mbps"}, {"10Mbps", "20Mbps"}} {
		s := newTwoRuleSession(t, false)
		decision := s.rateChange()
		changed := (*decision.QosDecs)[cirQosID]
		changed.MaxbrUl = *openapi.NewNullableString(openapi.PtrString(spelling[0]))
		changed.MaxbrDl = *openapi.NewNullableString(openapi.PtrString(spelling[1]))
		(*decision.QosDecs)[cirQosID] = changed
		s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)}

		param := BuildPfcpParam(s.sm)

		qer := s.flowQERAfter(param, s.cirDL)
		if qer == nil || qer.MBR == nil || qer.MBR.ULMBR != 10000 || qer.MBR.DLMBR != 20000 {
			t.Errorf("%q/%q: the flow QER is %+v, want 10000/20000 kbps", spelling[0], spelling[1], qer)
		}
	}
}

// A revert that needs nothing built is not refused because the node cannot build. A decision that
// changes nothing the user plane carries is put back by doing nothing, on a node that is not
// associated as on one that is; refused, the session would be marked for good as one whose user
// plane could not be put back, and every later modification of it refused.
func TestARevertThatBuildsNothingIsNotRefused(t *testing.T) {
	original := sendPfcpSessionModifyReq
	t.Cleanup(func() { sendPfcpSessionModifyReq = original })
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
		t.Error("a revert that changes nothing was sent")
		return nil
	}

	s := newTwoRuleSession(t, false)
	unchanged := roundTrip(&models.SmPolicyDecision{
		PccRules: map[string]models.PccRule{allowRuleID: s.allowRule, cirRuleID: s.cirRule},
		QosDecs:  &map[string]models.QosData{allowQosID: s.allowQos, cirQosID: s.cirQosSent},
	})
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, unchanged)}
	s.sm.Tunnel.DataPathPool[1].FirstDPNode.UPF.UPFStatus = smf_context.NotAssociated

	if !revertModification(s.sm, s.sm.NwModificationGen) {
		t.Error("the revert reported failure")
	}
	if s.sm.RevertFailed {
		t.Error("the session is marked as one whose user plane could not be put back")
	}
}

// A rule that names no QoS data has no flow QER, at establishment as when a revert re-creates it,
// and that is not a rule left unbuilt: the revert goes out with the session QER on its PDRs.
func TestARevertReCreatesARuleThatNamesNoQosData(t *testing.T) {
	s, reverted := revertOfWithdrawal(t, func(s *twoRuleSession) {
		s.sm.SmPolicyData.SmCtxtPccRules.PccRules[cirRuleID].RefQosData = nil
	})

	if reverted == nil || !reverted.touches(s.sm.Tunnel.DataPathPool[1].FirstDPNode.DownLinkTunnel.PDR[cirRuleID]) {
		t.Error("the withdrawn rule was not re-created")
	}
	if s.sm.RevertFailed {
		t.Error("the session is marked as one whose user plane could not be put back")
	}
}

// An added rule the tunnel build gives no flow QER is recorded as not built: the build logs and
// skips the QER, and the rule's PDRs went out with the session QER alone.
func TestAnAddedRuleWithoutItsFlowQERIsRecordedAsNotBuilt(t *testing.T) {
	s := newTwoRuleSession(t, false)
	s.withPfcpContext()
	decision := s.addAppRule()
	delete(*decision.QosDecs, "2")
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)}

	if param := BuildPfcpParam(s.sm); len(param.unbuilt) != 2 {
		t.Errorf("recorded as not built: %v, want the added rule's two flow QERs", param.unbuilt)
	}
}

// defaultPathNodeIP is the UPF of the session established with no PCC rule.
const defaultPathNodeIP = "10.0.0.9"

// defaultPathSession is a session established with no PCC rule, so its tunnels hold the "default"
// PDRs the tunnel build makes then, each carrying the session QER, beside the PDRs of an "app" rule
// a later modification added.
type defaultPathSession struct {
	sm                   *smf_context.SMContext
	sessQER              *smf_context.QER
	defaultUL, defaultDL *smf_context.PDR
	appUL, appDL         *smf_context.PDR
	appRule              models.PccRule
	appQos               models.QosData
}

func newDefaultPathSession(t *testing.T) *defaultPathSession {
	t.Helper()
	const appRuleID, appQosID = "app", "2"

	upf := smf_context.NewUPF(smf_context.NewNodeID(defaultPathNodeIP), nil)
	upf.UPFStatus = smf_context.AssociatedSetUpSuccess
	t.Cleanup(func() { smf_context.RemoveUPFNodeByNodeID(upf.NodeID) })

	newQER := func() *smf_context.QER {
		qer, err := upf.AddQER()
		if err != nil {
			t.Fatalf("AddQER: %v", err)
		}
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
		pdr.State = smf_context.RULE_CREATE
		pdr.FAR.State = smf_context.RULE_CREATE
		return pdr
	}

	s := &defaultPathSession{sm: modifyingSession()}
	s.sessQER = newQER()
	s.defaultUL, s.defaultDL = newPDR(s.sessQER), newPDR(s.sessQER)
	s.appUL, s.appDL = newPDR(newQER(), s.sessQER), newPDR(newQER(), s.sessQER)

	node := &smf_context.DataPathNode{
		UPF:            upf,
		UpLinkTunnel:   &smf_context.GTPTunnel{PDR: map[string]*smf_context.PDR{defaultPdrKey: s.defaultUL, appRuleID: s.appUL}},
		DownLinkTunnel: &smf_context.GTPTunnel{PDR: map[string]*smf_context.PDR{defaultPdrKey: s.defaultDL, appRuleID: s.appDL}},
	}
	s.sm.Tunnel = &smf_context.UPTunnel{DataPathPool: smf_context.DataPathPool{
		1: &smf_context.DataPath{IsDefaultPath: true, Activated: true, FirstDPNode: node},
	}}
	establishedUplinkTunnel(s.sm, node)

	s.appRule = models.PccRule{
		PccRuleId: appRuleID, RefQosData: []string{appQosID}, Precedence: openapi.PtrInt32(100),
		FlowInfos: []models.FlowInformation{{
			FlowDescription: openapi.PtrString("permit out ip from 192.168.250.2/32 to assigned"),
			PackFiltId:      openapi.PtrString("7"),
		}},
	}
	s.appQos = models.QosData{QosId: appQosID, Var5qi: openapi.PtrInt32(2)}
	s.sm.SmPolicyData.Initialize()
	s.sm.SmPolicyData.SmCtxtSessionRules.ActiveRule = &models.SessionRule{
		AuthSessAmbr: &models.Ambr{Uplink: "150 Mbps", Downlink: "200 Mbps"},
	}

	return s
}

// A decision withdraws the rules it deletes and nothing else. The builder released the "default"
// PDRs whenever a decision held no valid rule, and on a session established with no PCC rule they
// are its whole traffic path. A decision whose every rule is a deletion holds none, and so does the
// revert of a modification that adds or deletes no rule, which carries an empty rule map: deleting
// the rules added since, or reverting a modification, took the session's traffic and its session
// AMBR with them.
func TestADeletionOrARevertLeavesTheDefaultPathAlone(t *testing.T) {
	const appRuleID, appQosID = "app", "2"

	for _, tc := range []struct {
		name      string
		withdraws bool
		update    func(s *defaultPathSession) *qos.PolicyUpdate
	}{
		{"a decision deleting the added rule", true, func(s *defaultPathSession) *qos.PolicyUpdate {
			appRule, appQos := s.appRule, s.appQos
			s.sm.SmPolicyData.SmCtxtPccRules.PccRules[appRuleID] = &appRule
			s.sm.SmPolicyData.SmCtxtQosData.QosData[appQosID] = &appQos
			return qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, roundTrip(&models.SmPolicyDecision{
				PccRules: map[string]models.PccRule{appRuleID: {}},
				QosDecs:  &map[string]models.QosData{appQosID: {}},
			}))
		}},
		{"the revert of the modification that added it", true, func(s *defaultPathSession) *qos.PolicyUpdate {
			added := qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, roundTrip(&models.SmPolicyDecision{
				PccRules: map[string]models.PccRule{appRuleID: s.appRule},
				QosDecs:  &map[string]models.QosData{appQosID: s.appQos},
			}))
			return qos.RevertOf(&s.sm.SmPolicyData, added)
		}},
		// The session holds QoS data and no PCC rule, so the revert's rule map is empty.
		{"the revert of a change that names no rule", false, func(s *defaultPathSession) *qos.PolicyUpdate {
			appQos := s.appQos
			s.sm.SmPolicyData.SmCtxtQosData.QosData[appQosID] = &appQos
			changed := s.appQos
			changed.MaxbrUl = *openapi.NewNullableString(openapi.PtrString("2 Mbps"))
			changed.MaxbrDl = *openapi.NewNullableString(openapi.PtrString("4 Mbps"))
			rateChange := qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, roundTrip(&models.SmPolicyDecision{
				QosDecs: &map[string]models.QosData{appQosID: changed},
			}))
			return qos.RevertOf(&s.sm.SmPolicyData, rateChange)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDefaultPathSession(t)
			s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{tc.update(s)}

			param := BuildPfcpParam(s.sm)

			removed := map[*smf_context.PDR]bool{}
			for _, pdr := range param.removePDR {
				removed[pdr] = true
			}
			if removed[s.appUL] != tc.withdraws || removed[s.appDL] != tc.withdraws {
				t.Errorf("the added rule withdrawn: UL %v, DL %v, want %v", removed[s.appUL], removed[s.appDL], tc.withdraws)
			}
			if removed[s.defaultUL] || removed[s.defaultDL] {
				t.Error("the default PDRs, the session's traffic path, were withdrawn with the deleted rule")
			}
			for _, qer := range param.removeQER {
				if qer.QERID == s.sessQER.QERID {
					t.Error("the session QER was removed")
				}
			}
		})
	}
}

// qerIDs lists the IDs of the QERs a PDR carries.
func qerIDs(pdr *smf_context.PDR) map[uint32]bool {
	ids := map[uint32]bool{}
	for _, qer := range pdr.QER {
		ids[qer.QERID] = true
	}
	return ids
}

// A rule that loses its QoS data loses the flow QER built from it, as a rule that names none has no
// flow QER at establishment. The builder requalified only rules that name QoS data, so one that no
// longer did kept the flow QER and its rates -- after a decision took the QoS data away, and after
// a revert of one that gave it some, which then reported the user plane put back.
func TestARuleThatLosesItsQosDataLosesItsFlowQER(t *testing.T) {
	type outcome struct {
		param  *pfcpParam
		gone   []*smf_context.QER
		ul, dl *smf_context.PDR
	}

	for _, tc := range []struct {
		name string
		run  func(t *testing.T, s *twoRuleSession) outcome
	}{
		{"a decision", func(t *testing.T, s *twoRuleSession) outcome {
			allow := s.allowRule
			allow.RefQosData = nil
			s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, roundTrip(&models.SmPolicyDecision{
				PccRules: map[string]models.PccRule{allowRuleID: allow, cirRuleID: s.cirRule},
				QosDecs:  &map[string]models.QosData{allowQosID: s.allowQos, cirQosID: s.cirQosSent},
			}))}
			return outcome{BuildPfcpParam(s.sm), []*smf_context.QER{s.allowULQER, s.allowDLQER}, s.allowUL, s.allowDL}
		}},
		{"a revert", func(t *testing.T, s *twoRuleSession) outcome {
			// Established naming no QoS data, so with the session QER alone.
			committed := s.allowRule
			committed.RefQosData = nil
			s.sm.SmPolicyData.SmCtxtPccRules.PccRules[allowRuleID] = &committed
			s.allowUL.QER = []*smf_context.QER{s.sessQER}
			s.allowDL.QER = []*smf_context.QER{s.sessQER}

			given := qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, roundTrip(&models.SmPolicyDecision{
				PccRules: map[string]models.PccRule{allowRuleID: s.allowRule, cirRuleID: s.cirRule},
				QosDecs:  &map[string]models.QosData{allowQosID: s.allowQos, cirQosID: s.cirQosSent},
			}))
			s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{given}
			BuildPfcpParam(s.sm)
			var built []*smf_context.QER
			for _, pdr := range []*smf_context.PDR{s.allowUL, s.allowDL} {
				for _, qer := range pdr.QER {
					if qer.QERID != s.sessQER.QERID {
						built = append(built, qer)
					}
				}
			}
			if len(built) != 2 {
				t.Fatalf("the modification gave the rule %d flow QERs, want one per direction", len(built))
			}

			s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.RevertOf(&s.sm.SmPolicyData, given)}
			return outcome{BuildPfcpParam(s.sm), built, s.allowUL, s.allowDL}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTwoRuleSession(t, false)
			got := tc.run(t, s)

			sent := map[*smf_context.PDR]bool{}
			for _, pdr := range got.param.pdrList {
				sent[pdr] = true
			}
			removed := map[uint32]bool{}
			for _, qer := range got.param.removeQER {
				removed[qer.QERID] = true
			}
			for dir, pdr := range map[string]*smf_context.PDR{"UL": got.ul, "DL": got.dl} {
				if !sent[pdr] {
					t.Errorf("%s: the rule's PDR was not updated", dir)
				}
				if ids := qerIDs(pdr); len(ids) != 1 || !ids[s.sessQER.QERID] {
					t.Errorf("%s: the PDR carries QERs %v, want the session QER %d alone", dir, ids, s.sessQER.QERID)
				}
			}
			for _, qer := range got.gone {
				if !removed[qer.QERID] {
					t.Errorf("flow QER %d stays installed on the user plane", qer.QERID)
				}
			}
			if len(got.param.unbuilt) != 0 {
				t.Errorf("a rule with no QoS data was recorded as not built: %v", got.param.unbuilt)
			}
		})
	}
}

// A precedence change reaches the rule's PDRs. The builder requalified the rule for it and sent its
// PDRs with the old precedence, while the commit recorded the new one: overlapping rules went on
// matching in the old order, and an identical later decision no longer read as a change.
func TestAPrecedenceChangeReachesTheRulesPDRs(t *testing.T) {
	for _, tc := range []struct {
		name string
		// committed is the rule's precedence in force, and installed the PDRs'; nil and 0 are
		// 200 for both.
		committed  *int32
		installed  uint32
		precedence *int32
		revert     bool
		want       uint32
	}{
		{"a new precedence", nil, 0, openapi.PtrInt32(150), false, 150},
		{"a precedence the decision leaves out", nil, 0, nil, false, 200},
		{"the revert of a new precedence", nil, 0, openapi.PtrInt32(150), true, 200},
		// The top of the order, programmed as 1 as an added rule's zero is.
		{"a zero precedence", nil, 0, openapi.PtrInt32(0), false, 1},
		{"the revert to a zero precedence", openapi.PtrInt32(0), 1, openapi.PtrInt32(150), true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTwoRuleSession(t, false)
			s.cirUL.Precedence, s.cirDL.Precedence = 200, 200
			if tc.committed != nil {
				s.sm.SmPolicyData.SmCtxtPccRules.PccRules[cirRuleID].Precedence = tc.committed
				s.cirUL.Precedence, s.cirDL.Precedence = tc.installed, tc.installed
			}
			cir := s.cirRule
			cir.Precedence = tc.precedence
			update := qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, roundTrip(&models.SmPolicyDecision{
				PccRules: map[string]models.PccRule{allowRuleID: s.allowRule, cirRuleID: cir},
				QosDecs:  &map[string]models.QosData{allowQosID: s.allowQos, cirQosID: s.cirQosSent},
			}))
			s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{update}

			param := BuildPfcpParam(s.sm)
			if tc.revert {
				s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.RevertOf(&s.sm.SmPolicyData, update)}
				param = BuildPfcpParam(s.sm)
			}

			for dir, pdr := range map[string]*smf_context.PDR{"UL": s.cirUL, "DL": s.cirDL} {
				if !param.touches(pdr) {
					t.Errorf("%s: the rule's PDR was not updated", dir)
				}
				if pdr.Precedence != tc.want {
					t.Errorf("%s: the PDR is sent with precedence %d, want %d", dir, pdr.Precedence, tc.want)
				}
			}
		})
	}
}

// A modification the user plane does not accept leaves the rules it requalified as the UPF has
// them. The builder changes them in place before the request goes out, and a refused or unsent
// request left them naming flow QERs the UPF never installed: the next update removed those instead
// of the ones the UPF held, and a restoration would have installed the refused rates.
func TestARefusedModificationLeavesItsRulesAsTheUPFHasThem(t *testing.T) {
	type state struct {
		qers       map[uint32]bool
		precedence uint32
		st         smf_context.RuleState
	}
	snapshot := func(pdrs ...*smf_context.PDR) []state {
		var out []state
		for _, pdr := range pdrs {
			out = append(out, state{qerIDs(pdr), pdr.Precedence, pdr.State})
		}
		return out
	}

	for _, tc := range []struct {
		name string
		// run drives the modification and returns the PDRs to check, with what the UPF holds for
		// them.
		run func(t *testing.T, s *twoRuleSession) ([]*smf_context.PDR, []state)
	}{
		{"a refused modification", func(t *testing.T, s *twoRuleSession) ([]*smf_context.PDR, []state) {
			sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error { return errors.New("rejected") }
			held := snapshot(s.cirUL, s.cirDL)
			if err := ApplyModification(s.sm, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.rateChange())); err == nil {
				t.Fatal("the refused modification was reported as applied")
			}
			return []*smf_context.PDR{s.cirUL, s.cirDL}, held
		}},
		{"a refused revert", func(t *testing.T, s *twoRuleSession) ([]*smf_context.PDR, []state) {
			var held []state
			sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
				if held == nil {
					held = snapshot(s.cirUL, s.cirDL)
					return nil
				}
				return errors.New("rejected")
			}
			sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return errors.New("amf unreachable") }
			if err := ApplyModification(s.sm, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.rateChange())); err == nil {
				t.Fatal("the undeliverable modification was reported as delivered")
			}
			if !s.sm.RevertFailed {
				t.Fatal("the refused revert was not marked as failed")
			}
			return []*smf_context.PDR{s.cirUL, s.cirDL}, held
		}},
		{"a revert that could not be built", func(t *testing.T, s *twoRuleSession) ([]*smf_context.PDR, []state) {
			// The modification changes the catch-all's rates and withdraws the dedicated rule, so
			// its revert requalifies the one and re-creates the other, which a released UE address
			// stops.
			s.withPfcpContext()
			s.withConnection(true)
			s.cirRule.FlowInfos = []models.FlowInformation{{
				FlowDescription: openapi.PtrString("permit out ip from 192.168.250.1/32 to assigned"),
				PackFiltId:      openapi.PtrString("5"),
			}}
			committedRule := s.cirRule
			s.sm.SmPolicyData.SmCtxtPccRules.PccRules[cirRuleID] = &committedRule
			var held []state
			sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error {
				held = snapshot(s.allowUL, s.allowDL)
				return nil
			}
			sendQosN1N2TransferMsg = func(*smf_context.SMContext) error {
				s.sm.PDUAddress.Ip = net.IPv4zero
				return errors.New("amf unreachable")
			}
			allowQos := s.allowQos
			allowQos.MaxbrUl = *openapi.NewNullableString(openapi.PtrString("5 Mbps"))
			allowQos.MaxbrDl = *openapi.NewNullableString(openapi.PtrString("8 Mbps"))
			decision := roundTrip(&models.SmPolicyDecision{
				PccRules: map[string]models.PccRule{allowRuleID: s.allowRule, cirRuleID: {}},
				QosDecs:  &map[string]models.QosData{allowQosID: allowQos, cirQosID: {}},
			})
			if err := ApplyModification(s.sm, qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, decision)); err == nil {
				t.Fatal("the undeliverable modification was reported as delivered")
			}
			if !s.sm.RevertFailed {
				t.Fatal("the revert that could not be built was not marked as failed")
			}
			return []*smf_context.PDR{s.allowUL, s.allowDL}, held
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
			t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })

			s := newTwoRuleSession(t, false)
			pdrs, held := tc.run(t, s)
			if len(held) != len(pdrs) {
				t.Fatalf("nothing was sent to the user plane")
			}
			for i, pdr := range pdrs {
				got := snapshot(pdr)[0]
				if len(got.qers) != len(held[i].qers) {
					t.Errorf("PDR %d carries QERs %v, want %v as the UPF has them", pdr.PDRID, got.qers, held[i].qers)
					continue
				}
				for id := range held[i].qers {
					if !got.qers[id] {
						t.Errorf("PDR %d carries QERs %v, want %v as the UPF has them", pdr.PDRID, got.qers, held[i].qers)
						break
					}
				}
				if got.precedence != held[i].precedence || got.st != held[i].st {
					t.Errorf("PDR %d has precedence %d and state %v, want %d and %v",
						pdr.PDRID, got.precedence, got.st, held[i].precedence, held[i].st)
				}
			}
		})
	}
}

// An update of an established uplink PDR names the F-TEID the UPF allocated for it. Establishment
// asks the UPF to choose one and the SMF records it on the tunnel, so the PDR still carried the
// CHOOSE flag, and an Update PDR's PDI replaces the one the UPF holds. The reference UPF allocates
// no F-TEID for an update, so after any rate, gate or precedence change the rule matched any TEID.
func TestAnUplinkUpdateNamesTheInstalledFTEID(t *testing.T) {
	const teid = 0x1234
	access := net.ParseIP("10.0.0.70").To4()
	// established gives the session's uplink PDRs the F-TEID establishment sends, and its tunnel
	// the one the UPF chose; n3 is the UPF's N3 address the RAN was told, if any.
	established := func(t *testing.T, n3 net.IP) *twoRuleSession {
		s := newTwoRuleSession(t, false)
		s.sm.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
		node := s.sm.Tunnel.DataPathPool[1].FirstDPNode
		node.UpLinkTunnel.TEID = teid
		for _, pdr := range []*smf_context.PDR{s.allowUL, s.cirUL} {
			pdr.PDI.LocalFTeid = &smf_context.FTEID{V4: true, Ch: true, Chid: true, ChooseId: 1}
		}
		if n3 != nil {
			node.UPF.N3Interfaces = []smf_context.UPFInterfaceInfo{{IPv4EndPointAddresses: []net.IP{n3}}}
		}
		return s
	}

	t.Run("the update names it", func(t *testing.T) {
		s := established(t, access)
		s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.rateChange())}
		param := BuildPfcpParam(s.sm)
		if len(param.unbuilt) != 0 {
			t.Fatalf("not built: %v", param.unbuilt)
		}

		req, err := pfcp_message.BuildPfcpSessionModificationRequest(1, 1, 2, net.ParseIP("10.0.0.1"),
			param.pdrList, param.farList, param.qerList, param.removePDR, param.removeFAR, param.removeQER)
		if err != nil {
			t.Fatalf("building the request: %v", err)
		}
		wire, err := req.Marshal()
		if err != nil {
			t.Fatalf("encoding the request: %v", err)
		}
		sent, err := message.ParseSessionModificationRequest(wire)
		if err != nil {
			t.Fatalf("decoding the request: %v", err)
		}

		fteids := map[uint16]*ie.FTEIDFields{}
		for _, update := range sent.UpdatePDR {
			id, err := update.PDRID()
			if err != nil {
				t.Fatalf("Update PDR without a PDR ID: %v", err)
			}
			pdi, err := update.PDI()
			if err != nil {
				t.Fatalf("Update PDR %d without a PDI: %v", id, err)
			}
			fteids[id] = nil
			for _, x := range pdi {
				if x.Type == ie.FTEID {
					if fteids[id], err = x.FTEID(); err != nil {
						t.Fatalf("decoding PDR %d's F-TEID: %v", id, err)
					}
				}
			}
		}

		f, ok := fteids[s.cirUL.PDRID]
		if !ok {
			t.Fatal("the rule's uplink PDR was not updated")
		}
		if f == nil {
			t.Fatal("the uplink Update PDR names no F-TEID")
		}
		if f.HasCh() || f.HasChID() {
			t.Errorf("the uplink Update PDR asks the UPF to choose an F-TEID (flags %#x): it allocates none for "+
				"an update, so the rule matches any TEID", f.Flags)
		}
		if f.TEID != teid || !f.IPv4Address.Equal(access) {
			t.Errorf("the uplink Update PDR names TEID %#x at %v, want %#x at %v, the tunnel the RAN sends on",
				f.TEID, f.IPv4Address, teid, access)
		}
		if f, ok := fteids[s.cirDL.PDRID]; !ok || f != nil {
			t.Errorf("the downlink Update PDR: sent %v, F-TEID %+v; want sent with none", ok, f)
		}
	})

	t.Run("a refused update puts the PDR back", func(t *testing.T) {
		s := established(t, access)
		chosen := s.cirUL.PDI.LocalFTeid
		s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.rateChange())}
		undoRequalified(BuildPfcpParam(s.sm))
		if s.cirUL.PDI.LocalFTeid != chosen {
			t.Errorf("after a refused update the uplink PDR names %+v, want the F-TEID it had, %+v",
				s.cirUL.PDI.LocalFTeid, chosen)
		}
	})

	// With no N3 address, or only one the IPv4 F-TEID cannot carry: an IPv6 address goes on the wire
	// as 0.0.0.0. An IPv4v6 session reads the IPv6 one when the UPF has no IPv4 address.
	for name, n3 := range map[string][]smf_context.UPFInterfaceInfo{
		"no N3 address":      nil,
		"an IPv6 N3 address": {{IPv6EndPointAddresses: []net.IP{net.ParseIP("2001:db8::1")}}},
	} {
		t.Run("an unknown F-TEID leaves the uplink PDR alone: "+name, func(t *testing.T) {
			s := established(t, nil)
			s.sm.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4IPv6
			s.sm.Tunnel.DataPathPool[1].FirstDPNode.UPF.N3Interfaces = n3
			held := qerIDs(s.cirUL)
			s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.rateChange())}
			param := BuildPfcpParam(s.sm)
			if param.touches(s.cirUL) {
				t.Errorf("the uplink PDR is updated with F-TEID %+v, which the SMF does not know", s.cirUL.PDI.LocalFTeid)
			}
			if got := qerIDs(s.cirUL); !maps.Equal(got, held) {
				t.Errorf("the uplink PDR carries QERs %v, want the ones it had, %v", got, held)
			}
			if len(param.unbuilt) == 0 {
				t.Error("the update is not recorded as not built")
			}
		})
	}
}

// establishedUplinkTunnel gives node's uplink tunnel the TEID the UPF chose at establishment and
// the UPF the N3 address the RAN was told, which a rule added to the session names its F-TEID by.
func establishedUplinkTunnel(sm *smf_context.SMContext, node *smf_context.DataPathNode) {
	sm.SelectedPDUSessionType = nasMessage.PDUSessionTypeIPv4
	node.UpLinkTunnel.TEID = 0x1234
	node.UPF.N3Interfaces = []smf_context.UPFInterfaceInfo{{IPv4EndPointAddresses: []net.IP{net.ParseIP("10.0.0.70")}}}
}

// A rule added to an established session names the F-TEID the RAN was given, as an Update PDR does,
// and does not ask the UPF to choose one: a CHOOSE with no CHOOSE ID is not tied to the session's
// tunnel, so a UPF that follows the spec would allocate the new PDR a TEID of its own.
func TestAnAddedUplinkPDRNamesTheInstalledFTEID(t *testing.T) {
	s := newTwoRuleSession(t, false)
	s.withPfcpContext()
	s.sm.SmPolicyUpdates = []*qos.PolicyUpdate{qos.BuildSmPolicyUpdate(&s.sm.SmPolicyData, s.addAppRule())}

	param := BuildPfcpParam(s.sm)
	if len(param.unbuilt) != 0 {
		t.Fatalf("not built: %v", param.unbuilt)
	}
	ul := s.sm.Tunnel.DataPathPool[1].FirstDPNode.UpLinkTunnel.PDR["app"]
	f := ul.PDI.LocalFTeid
	if f == nil || f.Ch || f.Chid || !f.V4 || f.Teid != 0x1234 || !f.Ipv4Address.Equal(net.ParseIP("10.0.0.70")) {
		t.Errorf("the added uplink PDR names %+v, want TEID 0x1234 at 10.0.0.70 with no CHOOSE", f)
	}
}
