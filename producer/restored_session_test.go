// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
	"github.com/omec-project/util/mongoapi"
	"github.com/prometheus/client_golang/prometheus"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// storedDocuments stands in for the datastore, holding one document per collection.
type storedDocuments struct {
	mongoapi.DBInterface
	docs map[string]map[string]any
}

func (s *storedDocuments) RestfulAPIGetOne(coll string, _ bson.M) (map[string]any, error) {
	return s.docs[coll], nil
}

func (s *storedDocuments) RestfulAPIPost(coll string, _ bson.M, doc map[string]any) (bool, error) {
	s.docs[coll] = doc
	return false, nil
}

// readBack writes a session as the datastore holds it and reads it back, as a lookup after a restart
// does.
func readBack(t *testing.T, sm *smf_context.SMContext) *smf_context.SMContext {
	t.Helper()
	// The fields a stored session carries, without which its document does not decode.
	sm.AnType = models.ACCESSTYPE__3_GPP_ACCESS
	for _, p := range []*models.NFProfileDiscovery{&sm.AMFProfile, &sm.SelectedPCFProfile} {
		p.SetNfInstanceId("nf")
		p.SetNfType(models.NFTYPE_AMF)
		p.SetNfStatus(models.NFSTATUS_REGISTERED)
	}
	sm.DnnConfiguration.SscModes.DefaultSscMode = models.SSCMODE_SSC_MODE_1

	prev := mongoapi.CommonDBClient
	store := &storedDocuments{docs: map[string]map[string]any{}}
	mongoapi.CommonDBClient = store
	store.docs[smf_context.SmContextDataColl] = smf_context.ToBsonM(sm)
	restored := smf_context.GetSMContextByRefInDB(sm.Ref)
	mongoapi.CommonDBClient = prev
	if restored == nil || !restored.RestoredFromStore() {
		t.Fatalf("precondition: the session was not read back from the datastore")
	}
	return restored
}

// A rule a policy update withdraws from a session read back from the datastore carries identifiers
// an earlier start of the SMF allocated, which this one may have given to a live session since.
// The rule leaves the session, and its identifiers stay with the live session.
func TestAWithdrawnRuleOfAStoredSessionLeavesItsIdentifiersToTheLiveSession(t *testing.T) {
	originalPfcp, originalN1N2 := sendPfcpSessionModifyReq, sendQosN1N2TransferMsg
	t.Cleanup(func() { sendPfcpSessionModifyReq, sendQosN1N2TransferMsg = originalPfcp, originalN1N2 })
	sendPfcpSessionModifyReq = func(*smf_context.SMContext, *pfcpParam) error { return nil }
	sendQosN1N2TransferMsg = func(*smf_context.SMContext) error { return nil }

	// The live session holds the identifiers; the stored one carries them too.
	live := newTwoRuleSession(t, false)
	live.withPfcpContext()
	stored := readBack(t, live.sm)
	t.Cleanup(func() {
		stored.SMLock.Lock()
		stored.StopT3591()
		stored.SMLock.Unlock()
	})

	if err := ApplyModification(stored, qos.BuildSmPolicyUpdate(&stored.SmPolicyData, live.deleteDedicatedRule())); err != nil {
		t.Fatalf("ApplyModification: %v", err)
	}

	node := stored.Tunnel.DataPathPool[1].FirstDPNode
	if node.UpLinkTunnel.PDR[cirRuleID] != nil || node.DownLinkTunnel.PDR[cirRuleID] != nil {
		t.Fatalf("precondition: the withdrawn rule is still in the stored session's tunnels")
	}
	upf := node.UPF
	for dir, pdr := range map[string]*smf_context.PDR{"uplink": live.cirUL, "downlink": live.cirDL} {
		if !upf.HoldsPDR(pdr.PDRID) || !upf.HoldsFAR(pdr.FAR.FARID) {
			t.Errorf("withdrawing the stored session's %s rule took PDR %d or FAR %d from the live session",
				dir, pdr.PDRID, pdr.FAR.FARID)
		}
	}
}

// restoredOn is a session read back from the datastore and served, anchored on nodeIP and naming
// peerURL as its AMF and its PCF.
func restoredOn(t *testing.T, supi, nodeIP, peerURL string) *smf_context.SMContext {
	t.Helper()
	sm := sessionOn(t, supi, 1, nodeIP)
	sm.Supi = supi
	for p, service := range map[*models.NFProfileDiscovery]models.ServiceName{
		&sm.AMFProfile:         models.SERVICENAME_NAMF_COMM,
		&sm.SelectedPCFProfile: models.SERVICENAME_NPCF_SMPOLICYCONTROL,
	} {
		var s models.NFService
		s.SetServiceInstanceId(string(service))
		s.SetServiceName(service)
		s.SetApiPrefix(peerURL)
		s.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
		s.SetScheme(models.URISCHEME_HTTP)
		p.SetNfServiceList(map[string]models.NFService{s.GetServiceInstanceId(): s})
	}
	restored := readBack(t, sm)
	smf_context.StoreSmContextPool(restored)
	t.Cleanup(func() { smf_context.RemoveSMContext(restored.Ref) })
	return restored
}

// unrestoredOn reads how many of a user plane's sessions this SMF reports as without service.
func unrestoredOn(t *testing.T, nodeIP string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "smf_upf_unrestored_sessions" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "upf" && label.GetValue() == nodeIP {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("the unrestored gauge is not published for %s", nodeIP)
	return 0
}

// A restored session busy when the restoration came to release it is still anchored on the user
// plane, without service. If the user plane restarts again while the session is still busy, the sweep
// cannot examine it, and it is counted against the user plane as last seen anchored there, instead of
// the user plane reading as having no session without service. That holds whether or not the first
// restoration found sessions to re-install beside it.
func TestABusyRestoredSessionIsCountedWithoutService(t *testing.T) {
	restoreQuickly(t)
	for _, tc := range []struct {
		name, nodeIP string
		beside       string // a session this SMF created, anchored there at the first restart
	}{
		{"alone", "10.32.0.1", ""},
		{"beside a session to re-install", "10.32.0.2", "imsi-208930000000112"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodeID := *smf_context.NewNodeID(tc.nodeIP)
			associatedUpfAt(t, tc.nodeIP)

			// The AMF holds the first release it is sent, naming its subscriber, until resume is closed.
			held, resume := make(chan string, 1), make(chan struct{})
			var hold sync.Once
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if supi, transfer := strings.CutSuffix(r.URL.Path, "/n1-n2-messages"); transfer {
					hold.Do(func() {
						held <- supi[strings.LastIndex(supi, "/")+1:]
						<-resume
					})
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					if _, err := w.Write([]byte(`{"cause":"N1_N2_TRANSFER_INITIATED"}`)); err != nil {
						t.Error(err)
					}
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(peer.Close)
			restored := map[string]*smf_context.SMContext{}
			for _, supi := range []string{"imsi-208930000000110", "imsi-208930000000111"} {
				restored[supi] = restoredOn(t, supi, tc.nodeIP, peer.URL)
			}
			var beside *smf_context.SMContext
			if tc.beside != "" {
				// Found to re-install, and skipped: it has no data path.
				beside = sessionOn(t, tc.beside, 1, tc.nodeIP)
				beside.Tunnel = nil
			}

			done := make(chan struct{})
			go func() {
				defer close(done)
				restoreSessions(nodeID, tc.nodeIP, &restorationRun{recovery: time.Now()})
			}()
			var busy *smf_context.SMContext
			select {
			case first := <-held:
				for supi, s := range restored {
					if supi != first {
						busy = s
					}
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("precondition: neither restored session was released")
			}
			busy.SMLock.Lock()
			defer busy.SMLock.Unlock()
			close(resume)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("precondition: the restoration did not finish")
			}
			if got := unrestoredOn(t, tc.nodeIP); got != 1 {
				t.Fatalf("precondition: the user plane reports %v sessions without service, want the busy one", got)
			}
			if beside != nil {
				smf_context.RemoveSMContext(beside.Ref)
			}

			// The user plane restarts again, and the session is still busy.
			restoreSessions(nodeID, tc.nodeIP, &restorationRun{recovery: time.Now().Add(time.Second)})

			if got := unrestoredOn(t, tc.nodeIP); got != 1 {
				t.Errorf("the user plane reports %v sessions without service, want the busy restored session", got)
			}
		})
	}
}

// A restored session whose release fails is counted without service beside the sessions last seen
// anchored on the user plane that the sweep could not examine. One an earlier sweep saw there is
// still attributed to the user plane after a sweep that found only restored sessions: that sweep
// remembers them beside what was seen before, not in its place.
func TestAFailedRestoredReleaseIsCountedBesideTheSessionsThatCouldNotBeExamined(t *testing.T) {
	restoreQuickly(t)
	const nodeIP = "10.32.0.3"
	nodeID := *smf_context.NewNodeID(nodeIP)
	associatedUpfAt(t, nodeIP)

	// The AMF refuses every transfer, so the restored session's release fails.
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/n1-n2-messages") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(peer.Close)
	restoredOn(t, "imsi-208930000000113", nodeIP, peer.URL)

	// A session this SMF created, which an earlier sweep found anchored here, and which is busy for
	// the whole of this one.
	busy := sessionOn(t, "imsi-208930000000114", 1, nodeIP)
	t.Cleanup(func() { smf_context.RemoveSMContext(busy.Ref) })
	rememberAnchored(nodeIP, []*smf_context.SMContext{busy})
	t.Cleanup(func() { sessionsLastSeenOn.Delete(nodeIP) })
	busy.SMLock.Lock()
	defer busy.SMLock.Unlock()

	restoreSessions(nodeID, nodeIP, &restorationRun{recovery: time.Now()})

	if got := unrestoredOn(t, nodeIP); got != 2 {
		t.Errorf("the user plane reports %v sessions without service, want 2: the busy session, and the "+
			"restored one whose release failed", got)
	}
}
