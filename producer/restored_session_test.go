// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/qos"
	"github.com/omec-project/util/mongoapi"
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
