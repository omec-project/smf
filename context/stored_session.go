// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	gojson "github.com/goccy/go-json"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/util/mongoapi"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// A session read back from the datastore after this process started is not one this process
// created. When its subscriber establishes the same PDU session again it must be released, as one
// held in memory is (TS 24.501 clause 6.4.1.7 c)).

const (
	identifierFilterKey   = "identifier"
	pduSessionIDFilterKey = "pduSessionID"
	smContextKeyIndexName = "identifier_pduSessionID"
)

// ReleaseRestoredSession releases a session built from the datastore: its stored documents and its
// PFCP sessions at the user planes this process holds. The producer installs the full release,
// which can send PFCP; the default removes the context only.
var ReleaseRestoredSession = func(smContext *SMContext) {
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	RemoveSMContextLocked(smContext)
}

// storedRefs lists the references of the sessions stored for one subscriber and PDU session ID. Each
// document is decoded through JSON, as GetSMContextByRefInDB decodes one.
func storedRefs(identifier string, pduSessionID int32) ([]string, error) {
	// The filter's PDU session ID is an int32 and the write path stores the field as a JSON number;
	// the datastore compares numbers by value whatever their stored type, so the two match.
	filter := bson.M{identifierFilterKey: identifier, pduSessionIDFilterKey: pduSessionID}
	docs, err := mongoapi.CommonDBClient.RestfulAPIGetMany(SmContextDataColl, filter)
	if err != nil {
		return nil, err
	}
	refs := make([]string, 0, len(docs))
	for _, doc := range docs {
		var s struct {
			Ref string `json:"ref"`
		}
		if err := gojson.Unmarshal(mapToByte(doc), &s); err != nil || s.Ref == "" {
			logger.DataRepoLog.Warnf("stored session for %s-%d could not be read: %v", identifier, pduSessionID, err)
			continue
		}
		refs = append(refs, s.Ref)
	}
	return refs, nil
}

// restoredInstance returns the context for a stored ref, for releasing it: the instance in the pool,
// so the release and anything else using it act on the same session. On a pool miss it is read from
// the datastore and put in the pool, unless a lookup has put one there meanwhile, which is then the
// one returned: the release deletes the pool's entry for ref, which must not be another instance than
// the one it released. Nil when the document is gone or its delete failed earlier.
func restoredInstance(ref string) *SMContext {
	if value, ok := smContextPool.Load(ref); ok {
		return value.(*SMContext)
	}
	if IsSmContextDeleteFailed(ref) {
		return nil
	}
	smContext := GetSMContextByRefInDB(ref)
	if smContext == nil {
		return nil
	}
	actual, _ := smContextPool.LoadOrStore(ref, smContext)
	return actual.(*SMContext)
}

// ReleaseStoredSessions releases every session stored for a subscriber and PDU session ID, before a
// new session is established with that ID. It is called when the ID resolves to no session in
// memory: after a restart the previous one is in the datastore only, and TS 24.501 clause 6.4.1.7 c)
// requires it to be released as surely as one held in memory. A stored session that a lookup has
// already read into the pool is released as that instance.
func ReleaseStoredSessions(identifier string, pduSessionID int32) {
	refs, err := storedRefs(identifier, pduSessionID)
	if err != nil {
		logger.CtxLog.Warnf("stored sessions for %s-%d could not be listed: %v", identifier, pduSessionID, err)
		return
	}
	for _, ref := range refs {
		smContext := restoredInstance(ref)
		if smContext == nil {
			continue
		}
		smContext.SubPduSessLog.Warn("PDUSessionSMContextCreate, stored session with this PDU session ID exists, releasing it")
		ReleaseRestoredSession(smContext)
	}
}
