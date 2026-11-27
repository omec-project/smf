// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/lawfulintercept"
	"github.com/omec-project/smf/producer"
	"github.com/omec-project/util/li/types"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// adapterUPFs stands in for the UPF adapter: it records which UPF each session modification is
// addressed to and which FARs it updates, and accepts it.
type adapterUPFs struct {
	mu   sync.Mutex
	sent map[string][]uint32 // UPF address -> FAR IDs updated, in send order
}

func (a *adapterUPFs) RoundTrip(req *http.Request) (*http.Response, error) {
	var posted struct {
		Msg struct {
			Body []byte `json:"body"`
		} `json:"pfcpMsg"`
		UpNodeID smfctx.NodeID `json:"upNodeID"`
	}
	if err := json.NewDecoder(req.Body).Decode(&posted); err != nil {
		return nil, err
	}
	parsed, err := message.Parse(posted.Msg.Body)
	if err != nil {
		return nil, err
	}
	mod, ok := parsed.(*message.SessionModificationRequest)
	if !ok {
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(&bytes.Buffer{}), Request: req}, nil
	}

	a.mu.Lock()
	node := posted.UpNodeID.ResolveNodeIdToIp().String()
	for _, far := range mod.UpdateFAR {
		if id, err := far.FARID(); err == nil {
			a.sent[node] = append(a.sent[node], id)
		}
	}
	a.mu.Unlock()

	rsp := message.NewSessionModificationResponse(0, 0, 0, mod.Sequence(), 0, ie.NewCause(ie.CauseRequestAccepted))
	buf := make([]byte, rsp.MarshalLen())
	if err := rsp.MarshalTo(buf); err != nil {
		return nil, err
	}

	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(buf)), Request: req}, nil
}

func (a *adapterUPFs) to(node string) []uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]uint32(nil), a.sent[node]...)
}

// secondUPFSession is a session served by two UPFs, of which the anchor has answered its
// establishment and the second has not, with a CC warrant stored whose scan has not run. Calling
// the returned activate runs the scan. calls counts the modifications LI makes.
type secondUPFSession struct {
	sc           *smfctx.SMContext
	farA, farB   *smfctx.FAR
	nodeA, nodeB string
	upfs         *adapterUPFs
	calls        *int
	activate     func()
}

func newSecondUPFSession(t *testing.T, supi string, stateB smfctx.RuleState) *secondUPFSession {
	t.Helper()
	const (
		nodeA = "10.0.9.1"
		nodeB = "10.0.9.2"
	)

	origConfig := factory.SmfConfig.Configuration
	off := false
	factory.SmfConfig.Configuration = &factory.Configuration{
		KafkaInfo:        factory.KafkaInfo{EnableKafka: &off},
		EnableUpfAdapter: true,
	}
	t.Cleanup(func() { factory.SmfConfig.Configuration = origConfig })

	upfs := &adapterUPFs{sent: map[string][]uint32{}}
	origTransport := http.DefaultTransport
	http.DefaultTransport = upfs
	t.Cleanup(func() { http.DefaultTransport = origTransport })

	calls := new(int)
	lawfulintercept.SetSessionModifier(func(sc *smfctx.SMContext) error {
		*calls++
		return producer.ModifySessionForLI(sc)
	})
	t.Cleanup(func() { lawfulintercept.SetSessionModifier(nil) })

	sc := smfctx.NewSMContext(supi, 5)
	t.Cleanup(func() { smfctx.RemoveSMContext(sc.Ref) })

	farA := &smfctx.FAR{FARID: 1, State: smfctx.RULE_CREATE, ApplyAction: smfctx.ApplyAction{Forw: true}}
	farB := &smfctx.FAR{FARID: 2, State: stateB, ApplyAction: smfctx.ApplyAction{Forw: true}}
	a, b := smfctx.NewDataPathNode(), smfctx.NewDataPathNode()
	a.UPF = &smfctx.UPF{NodeID: *smfctx.NewNodeID(nodeA), Port: 8805}
	b.UPF = &smfctx.UPF{NodeID: *smfctx.NewNodeID(nodeB), Port: 8805}
	a.UpLinkTunnel.PDR["ul"] = &smfctx.PDR{PDRID: 1, FAR: farA}
	b.UpLinkTunnel.PDR["ul"] = &smfctx.PDR{PDRID: 2, FAR: farB}
	a.DownLinkTunnel.SrcEndPoint, b.UpLinkTunnel.SrcEndPoint = b, a

	sc.SMLock.Lock()
	sc.Supi = supi
	sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
		1: &smfctx.DataPath{FirstDPNode: a, IsDefaultPath: true, Activated: true},
	}}
	sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{
		nodeA: {NodeID: a.UPF.NodeID, LocalSEID: 0x9101, RemoteSEID: 0x9201},
		nodeB: {NodeID: b.UPF.NodeID, LocalSEID: 0x9102},
	}
	sc.SMLock.Unlock()

	activate := lawfulintercept.ActivateForTest(t, types.InterceptTask{
		XID:      "task-cc-second-upf",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: strings.TrimPrefix(supi, "imsi-")}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	})

	return &secondUPFSession{
		sc: sc, farA: farA, farB: farB, nodeA: nodeA, nodeB: nodeB,
		upfs: upfs, calls: calls, activate: activate,
	}
}

// answer is the second UPF answering its establishment: the handler records its SEID and
// re-derives duplication. It returns the second FAR's state afterwards.
func (s *secondUPFSession) answer() smfctx.RuleState {
	s.sc.SMLock.Lock()
	defer s.sc.SMLock.Unlock()
	s.sc.PFCPContext[s.nodeB].RemoteSEID = 0x9202
	lawfulintercept.ApplyCCAfterEstablishment(s.sc)

	return s.farB.State
}

// TestDuplicationSetWhileASecondUPFEstablishesReachesItWhenItAnswers: a warrant activating while
// the second UPF establishes reaches the anchor at once and the second UPF when it answers. The
// activation leaves the second UPF's FAR alone, since nothing can be sent to it yet, and its
// answer is what applies duplication there.
func TestDuplicationSetWhileASecondUPFEstablishesReachesItWhenItAnswers(t *testing.T) {
	s := newSecondUPFSession(t, "imsi-262019876543299", smfctx.RULE_CREATE)
	s.activate()

	s.sc.SMLock.Lock()
	dupl, state := s.farB.ApplyAction.Dupl, s.farB.State
	s.sc.SMLock.Unlock()
	if dupl || state != smfctx.RULE_CREATE {
		t.Fatalf("precondition: the activation changed the FAR of a UPF with no PFCP session "+
			"(Dupl=%v State=%v)", dupl, state)
	}
	if got := s.upfs.to(s.nodeA); len(got) != 1 || got[0] != s.farA.FARID {
		t.Fatalf("precondition: the anchor was sent FARs %v, want [%d]", got, s.farA.FARID)
	}
	if got := s.upfs.to(s.nodeB); len(got) != 0 {
		t.Fatalf("precondition: a UPF with no PFCP session was sent FARs %v", got)
	}
	before := *s.calls

	stateB := s.answer()

	if *s.calls == before {
		t.Error("no modification was made when the second UPF answered, so it keeps the FAR " +
			"it was established with, without duplication")
	}
	if got := s.upfs.to(s.nodeB); len(got) != 1 || got[0] != s.farB.FARID {
		t.Errorf("the second UPF was sent FARs %v, want [%d]", got, s.farB.FARID)
	}
	if stateB == smfctx.RULE_UPDATE || !s.farB.ApplyAction.Dupl {
		t.Errorf("the second UPF's FAR is State=%v Dupl=%v: the duplication change was never sent",
			stateB, s.farB.ApplyAction.Dupl)
	}
}

// TestAnActivationDuringASecondUPFsBuildIsNotLost is the interleaving the create path allows,
// since it builds requests without SMLock: the second UPF's Create FAR is encoded without
// duplication, the warrant's scan runs, and only then does the builder mark the FAR
// RULE_CREATE. Had the scan set duplication on that FAR, the second UPF's answer would find it
// already duplicating and not RULE_UPDATE, and send nothing, while the UPF was established
// without it.
func TestAnActivationDuringASecondUPFsBuildIsNotLost(t *testing.T) {
	s := newSecondUPFSession(t, "imsi-262019876543298", smfctx.RULE_INITIAL)

	// The builder has encoded the second UPF's Create FAR, without duplication.
	encoded := s.farB.ApplyAction.Dupl

	s.activate()

	// The builder finishes with the FAR, as buildPfcpSessionEstablishmentRequest does.
	s.sc.SMLock.Lock()
	touched := s.farB.ApplyAction.Dupl != encoded
	s.farB.State = smfctx.RULE_CREATE
	s.sc.SMLock.Unlock()
	if touched {
		t.Error("the activation changed the FAR of a UPF whose establishment request may be " +
			"being built without SMLock")
	}

	s.answer()

	if got := s.upfs.to(s.nodeB); len(got) != 1 || got[0] != s.farB.FARID {
		t.Errorf("the second UPF was sent FARs %v after it answered, want [%d]: it was "+
			"established without duplication and is never told", got, s.farB.FARID)
	}
}
