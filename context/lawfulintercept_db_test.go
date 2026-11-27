// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"bytes"
	"slices"
	"testing"

	gojson "github.com/goccy/go-json"
	"github.com/omec-project/openapi/v2/models"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// throughTheDatastore stores sc as the datastore does and reads it back as a restart does:
// ToBsonM, the BSON codec both ways with nested documents as maps, and the decoding
// GetSMContextByRefInDB applies to what it reads.
func throughTheDatastore(t *testing.T, sc *SMContext) *SMContext {
	t.Helper()

	raw, err := bson.Marshal(ToBsonM(sc))
	if err != nil {
		t.Fatalf("encoding the stored document as BSON: %v", err)
	}
	dec := bson.NewDecoder(bson.NewDocumentReader(bytes.NewReader(raw)))
	dec.DefaultDocumentMap()
	var read map[string]any
	if err = dec.Decode(&read); err != nil {
		t.Fatalf("decoding the stored document: %v", err)
	}
	asRead, err := gojson.Marshal(read)
	if err != nil {
		t.Fatalf("re-encoding the document as read: %v", err)
	}
	decoded := &SMContext{}
	if err = gojson.Unmarshal(asRead, decoded); err != nil {
		t.Fatalf("decoding the session as read: %v", err)
	}

	return decoded
}

// storableSession is the least of a session that decodes once stored: the enumerations below
// refuse their zero value.
func storableSession(ref string) *SMContext {
	return &SMContext{
		Ref:                ref,
		AnType:             models.ACCESSTYPE__3_GPP_ACCESS,
		AMFProfile:         models.NFProfileDiscovery{NfType: models.NFTYPE_AMF, NfStatus: models.NFSTATUS_REGISTERED},
		SelectedPCFProfile: models.NFProfileDiscovery{NfType: models.NFTYPE_PCF, NfStatus: models.NFSTATUS_REGISTERED},
		DnnConfiguration:   models.DnnConfiguration{SscModes: models.SscModes{DefaultSscMode: models.SSCMODE_SSC_MODE_1}},
	}
}

// The Lawful Interception correlation identifier survives a restart of the SMF, all 64 bits of it:
// an F-SEID is not a number a float64 holds exactly.
func TestTheLICorrelationSurvivesTheDatastore(t *testing.T) {
	const correlation uint64 = 0x8877665544332211

	sc := storableSession("li-correlation-ref")
	sc.LiCorrelation = correlation
	read := throughTheDatastore(t, sc)
	if read.LiCorrelation != correlation {
		t.Errorf("the correlation read back as %#x, want %#x", read.LiCorrelation, correlation)
	}

	// And a session without one, as stored by a version that did not keep it, reads back as zero.
	if read := throughTheDatastore(t, storableSession("li-correlation-ref")); read.LiCorrelation != 0 {
		t.Errorf("a session stored without a correlation read back with %#x", read.LiCorrelation)
	}
}

// duplicatingFAR is a forwarding rule Lawful Interception has set to duplicate.
func duplicatingFAR() *FAR {
	return &FAR{
		FARID:       1,
		ApplyAction: ApplyAction{Forw: true, Dupl: true},
		DuplicatingParameters: &DuplicatingParameters{
			DestinationInterface: DestinationInterface{InterfaceValue: DestinationInterfaceLIFunction},
		},
	}
}

// storedKeys returns every key of a stored document, at any depth.
func storedKeys(doc any) []string {
	var keys []string
	switch v := doc.(type) {
	case map[string]any:
		for k, inner := range v {
			keys = append(keys, k)
			keys = append(keys, storedKeys(inner)...)
		}
	case bson.M:
		keys = append(keys, storedKeys(map[string]any(v))...)
	case []any:
		for _, inner := range v {
			keys = append(keys, storedKeys(inner)...)
		}
	}

	return keys
}

// The stored session names the subscriber, so it does not say that the subscriber's traffic is
// duplicated: neither the session document nor the node document it writes beside it carries a
// FAR's duplication. The FAR in memory keeps it.
func TestDuplicationIsNotStoredWithTheSession(t *testing.T) {
	far := duplicatingFAR()
	pdr := &PDR{PDRID: 1, FAR: far}

	sc := storableSession("li-duplication-ref")
	sc.Supi = testSupi
	sc.PFCPContext = map[string]*PFCPSessionContext{
		"10.1.1.1": {NodeID: *NewNodeID("10.1.1.1"), PDRs: map[uint16]*PDR{1: pdr}, RemoteSEID: 1},
	}

	nodeDoc := ToBsonMNodeInDB(&DataPathNodeInDB{
		ULTunnelInfo: &TunnelInfo{PDR: map[string]*PDR{"default": pdr}},
	})
	for name, doc := range map[string]any{"session": ToBsonM(sc), "node": nodeDoc} {
		keys := storedKeys(doc)
		if !slices.Contains(keys, "ApplyAction") {
			t.Fatalf("the %s document carries no FAR, so it shows nothing (keys %v)", name, keys)
		}
		for _, key := range []string{"Dupl", "DuplicatingParameters"} {
			if slices.Contains(keys, key) {
				t.Errorf("the %s document stores %s", name, key)
			}
		}
	}

	read := throughTheDatastore(t, sc)
	readFAR := read.PFCPContext["10.1.1.1"].PDRs[1].FAR
	if readFAR.ApplyAction.Dupl || readFAR.DuplicatingParameters != nil || !readFAR.ApplyAction.Forw {
		t.Errorf("the FAR read back as %+v with %+v, want forwarding without duplication",
			readFAR.ApplyAction, readFAR.DuplicatingParameters)
	}

	if !far.ApplyAction.Dupl || far.DuplicatingParameters == nil {
		t.Error("storing the session cleared the duplication of the FAR in memory")
	}
}
