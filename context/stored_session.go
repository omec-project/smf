// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"sync"
	"sync/atomic"

	gojson "github.com/goccy/go-json"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/util/mongoapi"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// A session read back from the datastore after this process started is not one this process
// created, and two things follow from that. Its subscriber may have established the same PDU
// session again since, in which case it is superseded and must not be served as live (TS 24.501
// clause 6.4.1.7 c) requires the older one to be released). And it is not re-installed on a user
// plane that restarts: its UE address was allocated by an earlier start of the SMF, and this one's
// allocator, which never reserved it, may have given it to another UE since.

const (
	identifierFilterKey   = "identifier"
	pduSessionIDFilterKey = "pduSessionID"
	smContextKeyIndexName = "identifier_pduSessionID"
)

// smfCountAtStart is the smfCount this start read (setupSmfCount), and creationSeq counts the
// sessions it has created. smfCount counts the starts of the SMF that have used the datastore, so
// the pair orders sessions by when they were created, across restarts.
//
// That order requires smfCount never to go backwards. Resetting it would rank the sessions an
// earlier start created above those of a later one, serving a superseded session and releasing the
// live one, so it must not be reset.
var (
	smfCountAtStart atomic.Int32
	creationSeq     atomic.Uint64
)

// nextCreationStamp is the (smfCount, sequence) a new session records. Ordered lexicographically it
// is the order in which sessions were created, across restarts.
func nextCreationStamp() (int32, uint64) {
	return smfCountAtStart.Load(), creationSeq.Add(1)
}

// ReleaseRestoredSession releases a session built from the datastore: its stored documents and its
// PFCP sessions at the user planes this process holds. The producer installs the full release,
// which can send PFCP; the default removes the context only.
var ReleaseRestoredSession = func(smContext *SMContext) {
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	RemoveSMContextLocked(smContext)
}

// sessionKeyLocks serialises the first restore of a subscriber's PDU session, and the release of
// its stored duplicates on create, so that two requests naming two stored copies cannot each decide
// alone which one is current. An entry lives only while someone holds or waits for it.
var sessionKeyLocks = struct {
	sync.Mutex
	m map[string]*sessionKeyLock
}{m: make(map[string]*sessionKeyLock)}

type sessionKeyLock struct {
	sync.Mutex
	users int
}

func lockSessionKey(key string) (unlock func()) {
	sessionKeyLocks.Lock()
	l, ok := sessionKeyLocks.m[key]
	if !ok {
		l = &sessionKeyLock{}
		sessionKeyLocks.m[key] = l
	}
	l.users++
	sessionKeyLocks.Unlock()

	l.Lock()
	return func() {
		l.Unlock()
		sessionKeyLocks.Lock()
		l.users--
		if l.users == 0 {
			delete(sessionKeyLocks.m, key)
		}
		sessionKeyLocks.Unlock()
	}
}

// storedStamp is the part of a stored session document that orders it.
type storedStamp struct {
	Ref             string `json:"ref"`
	CreatedSmfCount int32  `json:"createdSmfCount"`
	CreatedSeq      uint64 `json:"createdSeq"`
}

func (s storedStamp) stamped() bool { return s.CreatedSmfCount > 0 }

func (s storedStamp) createdAfter(o storedStamp) bool {
	if s.CreatedSmfCount != o.CreatedSmfCount {
		return s.CreatedSmfCount > o.CreatedSmfCount
	}
	return s.CreatedSeq > o.CreatedSeq
}

// storedStamps lists the sessions stored for one subscriber and PDU session ID. Each document is
// decoded through JSON, as GetSMContextByRefInDB decodes one: the write path round-trips through
// JSON, so the numbers in the returned maps are float64, not the integers the struct declares.
func storedStamps(identifier string, pduSessionID int32) ([]storedStamp, error) {
	filter := bson.M{identifierFilterKey: identifier, pduSessionIDFilterKey: pduSessionID}
	docs, err := mongoapi.CommonDBClient.RestfulAPIGetMany(SmContextDataColl, filter)
	if err != nil {
		return nil, err
	}
	stamps := make([]storedStamp, 0, len(docs))
	for _, doc := range docs {
		var s storedStamp
		if err := gojson.Unmarshal(mapToByte(doc), &s); err != nil || s.Ref == "" {
			logger.DataRepoLog.Warnf("stored session for %s-%d could not be read: %v", identifier, pduSessionID, err)
			continue
		}
		stamps = append(stamps, s)
	}
	return stamps, nil
}

// newestStored picks the session to keep among those stored for one key: the most recently created.
// A stamped session outranks an unstamped one, since stamps begin with the version that writes them.
// One unstamped session on its own is kept as before. Several unstamped sessions and nothing stamped
// have no knowable order, and none is chosen.
func newestStored(stamps []storedStamp) (ref string, ordered bool) {
	var best *storedStamp
	for i := range stamps {
		if !stamps[i].stamped() {
			continue
		}
		if best == nil || stamps[i].createdAfter(*best) {
			best = &stamps[i]
		}
	}
	if best != nil {
		return best.Ref, true
	}
	if len(stamps) == 1 {
		return stamps[0].Ref, true
	}
	return "", false
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

// admitRestored decides whether a session just read from the datastore is served. It is not when
// the subscriber's PDU session already resolves to another session, nor when a more recently created
// session is stored for the same key; such a session is released and nil is returned, as for a
// session that does not exist. One that is served is registered as the subscriber's current session
// for that PDU session ID, so a later restore of an older copy is recognised as superseded.
//
// The decision is taken under the key's lock, so two requests naming two stored copies of one
// session decide one after the other, and each copy is released once.
func admitRestored(smContext *SMContext) *SMContext {
	key := canonicalName(smContext.Identifier, smContext.PDUSessionID)

	unlock := lockSessionKey(key)
	defer unlock()
	if current, ok := canonicalRef.Load(key); ok {
		return admitAgainst(smContext, current.(string))
	}

	// The filter's PDU session ID is an int32 and the write path stores the field as a JSON number;
	// the datastore compares numbers by value whatever their stored type, so the two match.
	stamps, err := storedStamps(smContext.Identifier, smContext.PDUSessionID)
	if err != nil {
		// Without the list there is no order to apply. Served as it was before stored sessions were
		// ordered, and not registered, so it supersedes nothing.
		smContext.SubCtxLog.Warnf("stored sessions for this PDU session could not be listed, restoring without ordering: %v", err)
		return storeRestored(smContext)
	}
	listed := false
	for _, s := range stamps {
		listed = listed || s.Ref == smContext.Ref
	}
	if !listed {
		// Either it was released between the read and the listing -- a create releases stored
		// sessions under this lock -- or the listing did not find it. Released, it is not served.
		// Not found, it is served as it was before stored sessions were ordered, and not registered,
		// since nothing is known of the others: a listing that misses every document must not make
		// every restore after a restart fail.
		if !storedByRef(smContext.Ref) {
			return nil
		}
		smContext.SubCtxLog.Warnf("stored sessions for this PDU session were listed without this one; restoring it without ordering")
		return storeRestored(smContext)
	}

	keep, ordered := newestStored(stamps)
	if !ordered {
		smContext.SubCtxLog.Warnf("%d stored sessions for this PDU session carry no creation order; serving none "+
			"until the subscriber establishes it again", len(stamps))
		return nil
	}
	// The kept session is made current before any other is released. A release reports the end of
	// the subscriber's session unless another session is current (see PublishSmCtxtInfo), and the
	// kept one is the subscriber's live session.
	if current, loaded := canonicalRef.LoadOrStore(key, keep); loaded && current.(string) != keep {
		// A session created since the key was found empty. NewSMContext stores its reference
		// unconditionally, so a session created after this point replaces the kept one as current
		// whatever this does.
		return admitAgainst(smContext, current.(string))
	}
	for _, s := range stamps {
		if s.Ref == keep || s.Ref == smContext.Ref {
			continue
		}
		if older := restoredInstance(s.Ref); older != nil {
			older.SubCtxLog.Infof("stored session superseded by a more recently created one; releasing it")
			ReleaseRestoredSession(older)
		}
	}
	if keep != smContext.Ref {
		smContext.SubCtxLog.Infof("stored session superseded by a more recently created one; releasing it")
		ReleaseRestoredSession(smContext)
		return nil
	}
	return storeRestored(smContext)
}

// admitAgainst serves a restored session only if it is the key's current one. A superseded one is
// released, unless it is already gone: whoever made the current session current may have released
// it while this request waited for the key's lock.
func admitAgainst(smContext *SMContext, current string) *SMContext {
	if current == smContext.Ref {
		return storeRestored(smContext)
	}
	if storedByRef(smContext.Ref) {
		smContext.SubCtxLog.Infof("stored session superseded by session %s; releasing it", current)
		ReleaseRestoredSession(smContext)
	}
	return nil
}

// storedByRef reports whether a session document is still stored. A lookup that fails is taken as
// stored: releasing a session twice does no harm, and missing a release leaves it stored.
func storedByRef(ref string) bool {
	doc, err := mongoapi.CommonDBClient.RestfulAPIGetOne(SmContextDataColl, bson.M{refFilterKey: ref})
	return err != nil || doc != nil
}

// SupersededByAnother reports whether this is a restored session whose subscriber's PDU session now
// resolves to a different session.
func (smContext *SMContext) SupersededByAnother() bool {
	if !smContext.restoredFromStore {
		return false
	}
	current, ok := canonicalRef.Load(canonicalName(smContext.Identifier, smContext.PDUSessionID))
	return ok && current.(string) != smContext.Ref
}

func storeRestored(smContext *SMContext) *SMContext {
	actual, _ := smContextPool.LoadOrStore(smContext.Ref, smContext)
	return actual.(*SMContext)
}

// GetSMContextForRelease is GetSMContext for a request to release the session it names. That
// request is honoured whatever the order of the subscriber's other stored sessions: it names the
// session its sender holds, and refusing it would leave the sender holding a session nothing serves.
// The context is put in the pool, so the PFCP answers to its release find it, but not registered as
// the subscriber's current session.
func GetSMContextForRelease(ref string) *SMContext {
	if value, ok := smContextPool.Load(ref); ok {
		return value.(*SMContext)
	}
	if !factory.SmfConfig.Configuration.EnableDbStore || IsSmContextDeleteFailed(ref) {
		return nil
	}
	smContext := GetSMContextByRefInDB(ref)
	if smContext == nil {
		return nil
	}
	return storeRestored(smContext)
}

// ReleaseStoredSessions releases every session stored for a subscriber and PDU session ID, before a
// new session is established with that ID. It is called when the ID resolves to no session in
// memory: after a restart the previous one is in the datastore only, and TS 24.501 clause 6.4.1.7 c)
// requires it to be released as surely as one held in memory. A stored session that a lookup has
// already read into the pool is released as that instance.
func ReleaseStoredSessions(identifier string, pduSessionID int32) {
	unlock := lockSessionKey(canonicalName(identifier, pduSessionID))
	defer unlock()

	stamps, err := storedStamps(identifier, pduSessionID)
	if err != nil {
		logger.CtxLog.Warnf("stored sessions for %s-%d could not be listed: %v", identifier, pduSessionID, err)
		return
	}
	for _, s := range stamps {
		smContext := restoredInstance(s.Ref)
		if smContext == nil {
			continue
		}
		smContext.SubPduSessLog.Warn("PDUSessionSMContextCreate, stored session with this PDU session ID exists, releasing it")
		ReleaseRestoredSession(smContext)
	}
}

// RestoredFromStore reports whether the context was read back from the datastore after this process
// started. It is set before the context is published to the pool and never changes, so it can be
// read without SMLock.
func (smContext *SMContext) RestoredFromStore() bool {
	return smContext.restoredFromStore
}
