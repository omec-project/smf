// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gojson "github.com/goccy/go-json"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/fsm"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/omec-project/smf/producer"
	"github.com/omec-project/smf/transaction"
	"github.com/omec-project/util/httpwrapper"
	mi "github.com/omec-project/util/metricinfo"
	"github.com/omec-project/util/mongoapi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/wmnsk/go-pfcp/message"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// memDB is an in-memory stand-in for the datastore: the collections the SMF writes, answering the
// equality filters it uses. Documents are kept as the write path leaves them, after its JSON round
// trip, so numbers are float64.
type memDB struct {
	mongoapi.DBInterface
	mu       sync.Mutex
	colls    map[string][]map[string]any
	counters map[string]int32

	// Faults a test can arm.
	listingFails  bool   // RestfulAPIGetMany answers an error
	listingMisses bool   // RestfulAPIGetMany answers nothing
	goneAfterRead string // this ref's document is released as soon as it is read

	afterRead func() // run once, after the next read of a session document
}

func newMemDB() *memDB {
	return &memDB{colls: make(map[string][]map[string]any), counters: make(map[string]int32)}
}

// GetUniqueIdentity counts as the datastore's counters do: 1 on the first read, one more on each after.
func (db *memDB) GetUniqueIdentity(name string) int32 {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.counters[name]++
	return db.counters[name]
}

func normalise(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return v
	}
	return out
}

func matches(doc map[string]any, filter bson.M) bool {
	for k, v := range filter {
		if !reflect.DeepEqual(normalise(doc[k]), normalise(v)) {
			return false
		}
	}
	return true
}

func (db *memDB) RestfulAPIGetOne(coll string, filter bson.M) (map[string]any, error) {
	db.mu.Lock()
	var found map[string]any
	for i, doc := range db.colls[coll] {
		if matches(doc, filter) {
			found = copyDoc(doc)
			if coll == context.SmContextDataColl && db.goneAfterRead != "" && doc["ref"] == db.goneAfterRead {
				db.colls[coll] = append(db.colls[coll][:i], db.colls[coll][i+1:]...)
			}
			break
		}
	}
	var after func()
	if coll == context.SmContextDataColl {
		after, db.afterRead = db.afterRead, nil
	}
	db.mu.Unlock()
	if after != nil {
		after()
	}
	return found, nil
}

func (db *memDB) RestfulAPIGetMany(coll string, filter bson.M) ([]map[string]any, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.listingFails {
		return nil, errors.New("simulated listing failure")
	}
	if db.listingMisses {
		return nil, nil
	}
	var out []map[string]any
	for _, doc := range db.colls[coll] {
		if matches(doc, filter) {
			out = append(out, copyDoc(doc))
		}
	}
	return out, nil
}

func (db *memDB) RestfulAPIPost(coll string, filter bson.M, data map[string]any) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	data = normalise(data).(map[string]any)
	for i, doc := range db.colls[coll] {
		if matches(doc, filter) {
			for k, v := range data {
				doc[k] = v
			}
			db.colls[coll][i] = doc
			return true, nil
		}
	}
	db.colls[coll] = append(db.colls[coll], data)
	return false, nil
}

func (db *memDB) RestfulAPIDeleteOne(coll string, filter bson.M) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	for i, doc := range db.colls[coll] {
		if matches(doc, filter) {
			db.colls[coll] = append(db.colls[coll][:i], db.colls[coll][i+1:]...)
			return nil
		}
	}
	return nil
}

func copyDoc(doc map[string]any) map[string]any {
	out := make(map[string]any, len(doc))
	for k, v := range doc {
		out[k] = v
	}
	return out
}

func (db *memDB) put(coll string, doc map[string]any) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.colls[coll] = append(db.colls[coll], normalise(doc).(map[string]any))
}

func (db *memDB) has(coll, key, value string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	for _, doc := range db.colls[coll] {
		if doc[key] == value {
			return true
		}
	}
	return false
}

// withStore runs the SMF with its datastore enabled, backed by a fresh memDB.
func withStore(t *testing.T) *memDB {
	t.Helper()
	prevClient := mongoapi.CommonDBClient
	prevConfig := factory.SmfConfig
	t.Cleanup(func() {
		mongoapi.CommonDBClient = prevClient
		factory.SmfConfig = prevConfig
	})
	disabled := false
	factory.SmfConfig = factory.Config{Configuration: &factory.Configuration{
		EnableDbStore: true,
		KafkaInfo:     factory.KafkaInfo{EnableKafka: &disabled},
	}}
	db := newMemDB()
	mongoapi.CommonDBClient = db
	context.StartSmContextWriteWorkers()
	return db
}

type stamp struct {
	smfCount int32
	seq      uint64
}

type storedOpts struct {
	stamp      *stamp          // nil: written before sessions recorded when they were created
	ip         string          // an address an earlier start of the SMF allocated from ueSubnet
	unknownUPF string          // a node the data path names that this SMF does not hold
	upf        *context.UPF    // a node this SMF holds, which the data path names and the session is anchored on
	rules      [2]*context.PDR // the uplink and downlink rules the session holds on upf
	anchorOn   string          // a node holding the session's PFCP session
	seid       uint64
	amf, pcf   string // API prefixes of the peers the session names
	// acknowledgedAt is the recovery timestamp of the incarnation of upf that acknowledged the
	// session; zero as in a document stored before it was kept.
	acknowledgedAt time.Time
}

// stored writes a session to the datastore as an earlier start of the SMF left it, and drops it from
// memory, as a restart does.
func stored(t *testing.T, db *memDB, supi string, o storedOpts) *context.SMContext {
	t.Helper()
	const psi = int32(1)
	current, err := context.ResolveRef(supi, psi)
	if err != nil {
		current = ""
	}
	smContext := context.NewSMContext(supi, psi)
	smContext.Supi = supi
	smContext.SMContextState = context.SmStateActive
	// The fields a session that reached Active carries, without which its document does not decode.
	smContext.AnType = models.ACCESSTYPE__3_GPP_ACCESS
	smContext.Snssai = models.NewSnssai(1)
	sessionType := models.PDUSESSIONTYPE_IPV4
	smContext.DnnConfiguration = models.DnnConfiguration{
		PduSessionTypes: models.PduSessionTypes{DefaultSessionType: &sessionType},
		SscModes:        models.SscModes{DefaultSscMode: models.SSCMODE_SSC_MODE_1},
	}
	if o.ip != "" {
		earlier, err := context.NewIPAllocator(ueSubnet)
		if err != nil {
			t.Fatal(err)
		}
		smContext.Dnn = dnn
		smContext.PDUAddress = &context.UeIpAddr{Ip: net.ParseIP(o.ip).To4()}
		smContext.DNNInfo = &context.SnssaiSmfDnnInfo{UeIPAllocator: earlier}
	}
	if o.unknownUPF != "" {
		smContext.Tunnel = tunnelOn(&context.UPF{NodeID: *context.NewNodeID(o.unknownUPF)}, &context.PDR{PDRID: 1}, nil)
	}
	if o.upf != nil {
		smContext.Tunnel = tunnelOn(o.upf, o.rules[0], o.rules[1])
		smContext.PFCPContext[o.upf.NodeID.ResolveNodeIdToIp().String()] = &context.PFCPSessionContext{
			NodeID: o.upf.NodeID, LocalSEID: o.seid, RemoteSEID: o.seid + 1000,
			AcknowledgedAtRecovery: o.acknowledgedAt,
		}
	} else if o.anchorOn != "" {
		smContext.PFCPContext[o.anchorOn] = &context.PFCPSessionContext{
			NodeID: *context.NewNodeID(o.anchorOn), LocalSEID: o.seid, RemoteSEID: o.seid + 1000,
		}
	} else if o.seid != 0 {
		smContext.PFCPContext["10.99.0.1"] = &context.PFCPSessionContext{
			NodeID: *context.NewNodeID("10.99.0.1"), LocalSEID: o.seid, RemoteSEID: o.seid + 1000,
		}
	}
	// A stored session always carries both profiles; one whose peer a test does not stand up names
	// no service, so nothing is sent to it.
	smContext.AMFProfile = nfProfile(models.NFTYPE_AMF, models.SERVICENAME_NAMF_COMM, o.amf)
	smContext.SelectedPCFProfile = nfProfile(models.NFTYPE_PCF, models.SERVICENAME_NPCF_SMPOLICYCONTROL, o.pcf)

	doc := context.ToBsonM(smContext)
	if o.stamp == nil {
		delete(doc, "createdSmfCount")
		delete(doc, "createdSeq")
	} else {
		doc["createdSmfCount"] = o.stamp.smfCount
		doc["createdSeq"] = o.stamp.seq
	}
	db.put(context.SmContextDataColl, doc)
	for _, pfcpContext := range smContext.PFCPContext {
		db.put(context.SeidSmContextCol, map[string]any{refKey: smContext.Ref, seidKey: context.SeidConv(pfcpContext.LocalSEID)})
	}
	context.ForgetInMemory(smContext)
	if current != "" {
		// Writing the document went through NewSMContext, which made it current; put back the
		// session that was.
		context.RegisterCurrent(supi, psi, current)
	}
	return smContext
}

// The DNN the stored sessions with an address are on, and its UE subnet.
const (
	dnn       = "internet"
	ueSubnet  = "10.60.0.0/24"
	otherSupi = "imsi-208930018809099"
)

// configuredPool gives the SMF the pool of UE addresses the running configuration holds for dnn on
// the stored sessions' slice, for the length of a test.
func configuredPool(t *testing.T) *context.IPAllocator {
	t.Helper()
	pool, err := context.NewIPAllocator(ueSubnet)
	if err != nil {
		t.Fatal(err)
	}
	self := context.SMF_Self()
	self.Lock()
	prev := self.SnssaiInfos
	self.SnssaiInfos = []context.SnssaiSmfInfo{{
		Snssai:   context.SNssai{Sst: 1},
		DnnInfos: map[string]*context.SnssaiSmfDnnInfo{dnn: {UeIPAllocator: pool}},
	}}
	self.Unlock()
	t.Cleanup(func() {
		self.Lock()
		self.SnssaiInfos = prev
		self.Unlock()
	})
	return pool
}

// tunnelOn is a default data path through one node, holding an uplink and, if given, a downlink
// rule there.
func tunnelOn(upf *context.UPF, uplink, downlink *context.PDR) *context.UPTunnel {
	node := &context.DataPathNode{UPF: upf}
	node.UpLinkTunnel = &context.GTPTunnel{TEID: 1, PDR: map[string]*context.PDR{"uplink": uplink}}
	if downlink != nil {
		node.DownLinkTunnel = &context.GTPTunnel{PDR: map[string]*context.PDR{"downlink": downlink}}
	}
	dataPath := context.NewDataPath()
	dataPath.FirstDPNode = node
	dataPath.IsDefaultPath = true
	return &context.UPTunnel{DataPathPool: context.DataPathPool{1: dataPath}}
}

func nfProfile(nfType models.NFType, service models.ServiceName, apiPrefix string) models.NFProfileDiscovery {
	var p models.NFProfileDiscovery
	p.SetNfInstanceId("nf-" + string(service))
	p.SetNfType(nfType)
	p.SetNfStatus(models.NFSTATUS_REGISTERED)
	if apiPrefix != "" {
		var s models.NFService
		s.SetServiceInstanceId(string(service))
		s.SetServiceName(service)
		s.SetApiPrefix(apiPrefix)
		s.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
		s.SetScheme(models.URISCHEME_HTTP)
		p.SetNfServiceList(map[string]models.NFService{s.GetServiceInstanceId(): s})
	}
	return p
}

// The fields the SMF keys its context and SEID documents by.
const (
	refKey  = "ref"
	seidKey = "seid"
)

func storedRef(db *memDB, ref string) bool { return db.has(context.SmContextDataColl, refKey, ref) }

func inPool(ref string) bool {
	_, ok := context.GetSmContextPool().Load(ref)
	return ok
}

var runs atomic.Int64

// freshSupi is a subscriber no earlier run of the test has used: a run's release finishes clearing
// its subscriber's current session only after its documents are gone, and a repeated run that
// reused the subscriber could find that entry still there.
func freshSupi() string {
	return fmt.Sprintf("imsi-2089300189%05d", runs.Add(1))
}

// freshNode is a user-plane address no earlier run of the test has used: a restoration runs in the
// background and could otherwise take up a later run's session on the same node.
func freshNode() string {
	n := runs.Add(1)
	return fmt.Sprintf("10.78.%d.%d", n/250, n%250+1)
}

// waitReleased waits for a background release to make its last calls, to the AMF and the PCF, so
// the test does not end -- and restore what the release reads -- while it is still running.
func (p *peers) waitReleased(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if policyDelete, n1n2 := p.counts(); policyDelete >= 1 && n1n2 >= 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitGone waits for the asynchronous delete of a stored document.
func waitGone(t *testing.T, db *memDB, ref string) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !storedRef(db, ref) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// createRequest is a create for the subscriber's PDU session 1, the one the stored sessions are for.
func createRequest(supi string) *transaction.Transaction {
	data := models.SmContextCreateData{}
	data.SetSupi(supi)
	data.SetPduSessionId(1)
	req := models.NewPostSmContextsRequest()
	req.SetJsonData(data)
	return transaction.NewTransaction(*req, nil, svcmsgtypes.CreateSmContext)
}

func loadCreate(t *testing.T, supi string) *context.SMContext {
	t.Helper()
	txn := createRequest(supi)
	if _, err := fsm.SmfTxnFsmHandle.TxnLoadCtxt(txn); err != nil {
		t.Fatalf("loading the create: %v", err)
	}
	created := txn.Ctxt.(*context.SMContext)
	t.Cleanup(func() { context.RemoveSMContext(created.Ref) })
	return created
}

// After a restart the previous session for a PDU session ID is in the datastore only. The UE
// establishing that PDU session again must release it, as one held in memory is released (TS 24.501
// clause 6.4.1.7 c)), and not leave it stored beside the new one.
func TestACreateAfterARestartReleasesTheStoredSession(t *testing.T) {
	db := withStore(t)
	const supi = "imsi-208930018809001"
	a := stored(t, db, supi, storedOpts{stamp: &stamp{1, 1}, seid: 9001, unknownUPF: "10.88.0.1"})

	created := loadCreate(t, supi)

	if !waitGone(t, db, a.Ref) {
		t.Errorf("the stored session for PDU session 1 survived the UE establishing PDU session 1 again")
	}
	if db.has(context.SeidSmContextCol, seidKey, context.SeidConv(9001)) {
		t.Errorf("the stored session's SEID record survived its release")
	}
	if ref, err := context.ResolveRef(supi, 1); err != nil || ref != created.Ref {
		t.Errorf("PDU session 1 resolves to %q (%v), want the new session %q", ref, err, created.Ref)
	}
}

// Every stored copy for the key is released, not only the first: a cluster that ran without this
// accumulated one per restart.
func TestACreateReleasesEveryStoredCopy(t *testing.T) {
	db := withStore(t)
	const supi = "imsi-208930018809002"
	copies := []*context.SMContext{
		stored(t, db, supi, storedOpts{seid: 9101}),
		stored(t, db, supi, storedOpts{seid: 9102}),
		stored(t, db, supi, storedOpts{stamp: &stamp{2, 7}, seid: 9103}),
	}

	loadCreate(t, supi)

	for i, c := range copies {
		if !waitGone(t, db, c.Ref) {
			t.Errorf("stored copy %d survived the UE establishing the PDU session again", i)
		}
	}
}

// A stored session that a later session for the same subscriber and PDU session ID has superseded
// is not served as live, by reference or by SEID, and its documents go.
func TestASupersededStoredSessionIsNotServed(t *testing.T) {
	db := withStore(t)
	const supi = "imsi-208930018809003"
	a := stored(t, db, supi, storedOpts{stamp: &stamp{1, 1}, seid: 9201})
	b := context.NewSMContext(supi, 1) // established after the restart
	t.Cleanup(func() { context.RemoveSMContext(b.Ref) })

	if got := context.GetSMContext(a.Ref); got != nil {
		t.Errorf("a stored session superseded by %s was served by reference", b.Ref)
	}
	if inPool(a.Ref) {
		t.Errorf("the superseded session was added to the sessions the SMF holds")
	}
	if !waitGone(t, db, a.Ref) {
		t.Errorf("the superseded session's documents were not removed")
	}

	a2 := stored(t, db, supi, storedOpts{stamp: &stamp{1, 2}, seid: 9202})
	if got := context.GetSMContextBySEID(9202); got != nil {
		t.Errorf("a stored session superseded by %s was served by SEID", b.Ref)
	}
	if inPool(a2.Ref) {
		t.Errorf("the session found by SEID was added to the sessions the SMF holds")
	}
	if !waitGone(t, db, a2.Ref) {
		t.Errorf("the session found by SEID kept its documents")
	}
}

// Between two stored sessions for one key the most recently created is served, whichever a request
// names first, and the order comes from the creation record rather than from which the store
// returns first.
func TestTheMostRecentlyCreatedStoredSessionIsServed(t *testing.T) {
	for i, tc := range []struct {
		name            string
		older, newer    stamp
		nameOlderFirst  bool
		storeNewerFirst bool
	}{
		{"older named first", stamp{1, 1}, stamp{2, 1}, true, false},
		{"newer named first", stamp{1, 1}, stamp{2, 1}, false, false},
		{"same start, by sequence", stamp{3, 4}, stamp{3, 9}, true, true},
		{"same start, by sequence, older stored first", stamp{3, 4}, stamp{3, 9}, true, false},
		{"store returns the newer first", stamp{1, 1}, stamp{2, 1}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := withStore(t)
			supi := fmt.Sprintf("imsi-2089300188092%02d", i)
			var older, newer *context.SMContext
			if tc.storeNewerFirst {
				newer = stored(t, db, supi, storedOpts{stamp: &tc.newer, seid: 9301})
				older = stored(t, db, supi, storedOpts{stamp: &tc.older, seid: 9302})
			} else {
				older = stored(t, db, supi, storedOpts{stamp: &tc.older, seid: 9302})
				newer = stored(t, db, supi, storedOpts{stamp: &tc.newer, seid: 9301})
			}
			t.Cleanup(func() { context.RemoveSMContext(newer.Ref) })

			first, second := newer, older
			if tc.nameOlderFirst {
				first, second = older, newer
			}
			gotFirst := context.GetSMContext(first.Ref)
			gotSecond := context.GetSMContext(second.Ref)

			if served := map[bool]*context.SMContext{true: gotFirst, false: gotSecond}[first == newer]; served == nil || served.Ref != newer.Ref {
				t.Errorf("the most recently created stored session was not served")
			}
			if other := map[bool]*context.SMContext{true: gotSecond, false: gotFirst}[first == newer]; other != nil {
				t.Errorf("the older stored session was served too")
			}
			if !waitGone(t, db, older.Ref) {
				t.Errorf("the older stored session was not released")
			}
			if !storedRef(db, newer.Ref) {
				t.Errorf("the most recently created stored session was released")
			}
		})
	}
}

// Several stored sessions for one key with no creation record have no knowable order. None is
// served and none is released, until the subscriber establishes the session again.
func TestUnorderedStoredSessionsAreNeitherServedNorReleased(t *testing.T) {
	db := withStore(t)
	const supi = "imsi-208930018809004"
	a := stored(t, db, supi, storedOpts{seid: 9401})
	b := stored(t, db, supi, storedOpts{seid: 9402})

	if got := context.GetSMContext(a.Ref); got != nil {
		t.Errorf("one of two unordered stored sessions was served by reference")
	}
	if got := context.GetSMContextBySEID(9402); got != nil {
		t.Errorf("one of two unordered stored sessions was served by SEID")
	}
	time.Sleep(50 * time.Millisecond)
	if !storedRef(db, a.Ref) || !storedRef(db, b.Ref) {
		t.Errorf("an unordered stored session was released; without an order it could be the live one")
	}
}

// A single stored session nothing has superseded is restored as before.
func TestALoneStoredSessionIsRestored(t *testing.T) {
	db := withStore(t)
	const supi = "imsi-208930018809005"
	a := stored(t, db, supi, storedOpts{seid: 9501})
	t.Cleanup(func() { context.RemoveSMContext(a.Ref) })

	got := context.GetSMContext(a.Ref)
	if got == nil || got.Ref != a.Ref {
		t.Fatalf("a lone stored session was not restored")
	}
	if !got.RestoredFromStore() {
		t.Errorf("the restored session is not marked as read from the datastore")
	}
	if ref, err := context.ResolveRef(supi, 1); err != nil || ref != a.Ref {
		t.Errorf("the restored session is not the subscriber's current session for PDU session 1: %q, %v", ref, err)
	}
}

// peers stands up the peers a release informs, recording what each was asked.
type peers struct {
	srv          *httptest.Server
	mu           sync.Mutex
	policyDelete int
	n1n2         int
	n1n2For      map[string]int // transfers by the subscriber they name
	amfRefuses   bool           // the AMF answers every transfer with an error
	held         chan string    // when set, the first transfer names its subscriber here and waits
	resume       chan struct{}  // for this to close
	holdOnce     sync.Once
}

func newPeers(t *testing.T) *peers {
	t.Helper()
	p := &peers{n1n2For: map[string]int{}}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subscriber, transfer := strings.CutSuffix(r.URL.Path, "/n1-n2-messages")
		subscriber = subscriber[strings.LastIndex(subscriber, "/")+1:]
		p.mu.Lock()
		held, resume := p.held, p.resume
		p.mu.Unlock()
		if transfer && held != nil {
			p.holdOnce.Do(func() {
				held <- subscriber
				<-resume
			})
		}

		p.mu.Lock()
		defer p.mu.Unlock()
		if transfer {
			p.n1n2For[subscriber]++
		}
		switch {
		case strings.Contains(r.URL.Path, "/sm-policies/") && strings.HasSuffix(r.URL.Path, "/delete"):
			p.policyDelete++
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/n1-n2-messages") && p.amfRefuses:
			p.n1n2++
			w.WriteHeader(http.StatusInternalServerError)
		case strings.Contains(r.URL.Path, "/n1-n2-messages"):
			p.n1n2++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"cause":"N1_N2_TRANSFER_INITIATED"}`)); err != nil {
				t.Error(err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *peers) counts() (policyDelete, n1n2 int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.policyDelete, p.n1n2
}

func (p *peers) transfersFor(supi string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n1n2For[supi]
}

// holdFirstTransfer holds the first transfer the AMF receives until resume is closed, after naming
// the subscriber it is for on held.
func (p *peers) holdFirstTransfer() (held <-chan string, resume chan<- struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.held, p.resume = make(chan string, 1), make(chan struct{})
	return p.held, p.resume
}

// A request to release a stored session is honoured even when its order against the subscriber's
// other stored sessions cannot be known: it names the session its sender holds. The release
// terminates the policy association and answers success.
func TestAReleaseOfAnUnorderedStoredSessionIsHonoured(t *testing.T) {
	db := withStore(t)
	p := newPeers(t)
	const supi = "imsi-208930018809006"
	a := stored(t, db, supi, storedOpts{seid: 9601, pcf: p.srv.URL})
	stored(t, db, supi, storedOpts{seid: 9602})

	release := models.NewReleaseSmContextRequest()
	release.SetJsonData(models.SmContextReleaseData{})
	txn := transaction.NewTransaction(*release, nil, svcmsgtypes.ReleaseSmContext)
	txn.CtxtKey = a.Ref
	if _, err := fsm.SmfTxnFsmHandle.TxnLoadCtxt(txn); err != nil {
		t.Fatalf("the release named a stored session and was refused: %v", err)
	}

	if err := producer.HandlePDUSessionSMContextRelease(txn); err != nil {
		t.Fatalf("releasing: %v", err)
	}
	if rsp, ok := txn.Rsp.(*httpwrapper.Response); !ok || rsp.Status != http.StatusNoContent {
		t.Errorf("the release was answered %+v, want %d", txn.Rsp, http.StatusNoContent)
	}
	if policyDelete, _ := p.counts(); policyDelete != 1 {
		t.Errorf("the PCF was asked to delete the policy association %d times, want once", policyDelete)
	}
	if !waitGone(t, db, a.Ref) {
		t.Errorf("the released session's documents were not removed")
	}
}

// A restored session anchored on a user plane that restarts is released, with the AMF and the PCF
// told, rather than re-installed: its address was allocated by an earlier start of the SMF.
func TestARestoredSessionIsReleasedNotReinstalledWhenItsUserPlaneRestarts(t *testing.T) {
	db := withStore(t)
	p := newPeers(t)
	nodeIP := freshNode()
	supi := freshSupi()
	upf := context.NewUPF(context.NewNodeID(nodeIP), nil)
	upf.UPFStatus = context.AssociatedSetUpSuccess
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: time.Now()}

	a := stored(t, db, supi, storedOpts{ip: "10.60.0.8", seid: 9701, anchorOn: nodeIP, amf: p.srv.URL, pcf: p.srv.URL})
	restored := context.GetSMContext(a.Ref)
	if restored == nil {
		t.Fatalf("precondition: the stored session was not restored")
	}

	producer.RestoreSessionsOnUPF(*context.NewNodeID(nodeIP), time.Now())

	if !waitGone(t, db, a.Ref) {
		t.Fatalf("the restored session was not released when its user plane restarted")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if policyDelete, n1n2 := p.counts(); policyDelete == 1 && n1n2 == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if policyDelete, n1n2 := p.counts(); policyDelete != 1 || n1n2 != 1 {
		t.Errorf("the release told the PCF %d and the AMF %d times, want once each", policyDelete, n1n2)
	}
	releasedOutcome := map[string]string{upfLabel: nodeIP, "outcome": "releasedRestoredFromStore"}
	deadline = time.Now().Add(2 * time.Second)
	for v, _ := metricValue(t, "smf_upf_restoration_sessions_total", releasedOutcome); v != 1 && time.Now().Before(deadline); v, _ = metricValue(t, "smf_upf_restoration_sessions_total", releasedOutcome) {
		time.Sleep(5 * time.Millisecond)
	}
	if v, _ := metricValue(t, "smf_upf_restoration_sessions_total", releasedOutcome); v != 1 {
		t.Errorf("the restoration outcomes count %v session(s) released as restored from the datastore, want 1", v)
	}
	restored.SMLock.Lock()
	state := restored.SMContextState
	restored.SMLock.Unlock()
	if state != context.SmStateRelease {
		t.Errorf("the restored session is %v, want released", state)
	}
}

// A user plane that restarts with a restored session anchored on it whose lock is held: the sweep
// cannot examine the session, looks again as it does for any session it could not examine, and
// releases it once the lock is free, instead of leaving it in place.
func TestABusyRestoredSessionIsReleasedOnceItCanBeExamined(t *testing.T) {
	db := withStore(t)
	p := newPeers(t)
	nodeIP, supi := freshNode(), freshSupi()
	restartedUPF(t, nodeIP)
	a := stored(t, db, supi, storedOpts{seid: 9702, anchorOn: nodeIP, amf: p.srv.URL, pcf: p.srv.URL})
	restored := context.GetSMContext(a.Ref)
	if restored == nil {
		t.Fatalf("precondition: the stored session was not restored")
	}

	restored.SMLock.Lock()
	producer.RestoreSessionsOnUPF(*context.NewNodeID(nodeIP), time.Now())
	time.Sleep(300 * time.Millisecond) // the sweep finds the session busy, and looks again
	if !storedRef(db, a.Ref) {
		t.Fatalf("precondition: the session was released while its lock was held")
	}
	restored.SMLock.Unlock()

	if !waitGone(t, db, a.Ref) {
		t.Errorf("a restored session busy when its user plane restarted was never released")
	}
	p.waitReleased(t)
}

// A restored session whose release fails is still without service, and the user plane's
// unrestored gauge counts it.
func TestARestoredSessionWhoseReleaseFailsIsCountedUnrestored(t *testing.T) {
	db := withStore(t)
	p := newPeers(t)
	p.amfRefuses = true
	nodeIP, supi := freshNode(), freshSupi()
	restartedUPF(t, nodeIP)
	a := stored(t, db, supi, storedOpts{seid: 9703, anchorOn: nodeIP, amf: p.srv.URL, pcf: p.srv.URL})
	if context.GetSMContext(a.Ref) == nil {
		t.Fatalf("precondition: the stored session was not restored")
	}

	producer.RestoreSessionsOnUPF(*context.NewNodeID(nodeIP), time.Now())

	p.waitReleased(t)
	deadline := time.Now().Add(2 * time.Second)
	for unrestoredGauge(t, nodeIP) != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := unrestoredGauge(t, nodeIP); got != 1 {
		t.Errorf("the user plane reports %v sessions without service, want the 1 whose release failed", got)
	}
}

// When the restarted user plane also holds sessions this SMF created, those go through the
// restoration waves and the restored session is released after them.
func TestARestoredSessionIsReleasedBesideSessionsToReinstall(t *testing.T) {
	db := withStore(t)
	p := newPeers(t)
	nodeIP, supi := freshNode(), freshSupi()
	restartedUPF(t, nodeIP)
	live := context.NewSMContext(freshSupi(), 1)
	t.Cleanup(func() { context.RemoveSMContext(live.Ref) })
	live.SMLock.Lock()
	live.PFCPContext[nodeIP] = &context.PFCPSessionContext{NodeID: *context.NewNodeID(nodeIP), LocalSEID: 9705, RemoteSEID: 9706}
	live.SMLock.Unlock()
	a := stored(t, db, supi, storedOpts{seid: 9704, anchorOn: nodeIP, amf: p.srv.URL, pcf: p.srv.URL})
	if context.GetSMContext(a.Ref) == nil {
		t.Fatalf("precondition: the stored session was not restored")
	}

	producer.RestoreSessionsOnUPF(*context.NewNodeID(nodeIP), time.Now())

	if !waitGone(t, db, a.Ref) {
		t.Errorf("the restored session was not released when its user plane restarted")
	}
	p.waitReleased(t)
	if got := context.GetSMContext(live.Ref); got != live {
		t.Errorf("the session this SMF created was released with the restored one")
	}
}

// A restored session found on the restarted user plane is no reason to stop looking at a session
// this SMF created there that was busy: the sweep looks again, as it would had it found nothing.
func TestABusySessionBesideARestoredOneIsLookedAtAgain(t *testing.T) {
	db := withStore(t)
	p := newPeers(t)
	nodeIP, supi := freshNode(), freshSupi()
	restartedUPF(t, nodeIP)
	live := context.NewSMContext(freshSupi(), 1)
	t.Cleanup(func() { context.RemoveSMContext(live.Ref) })
	live.SMLock.Lock()
	live.PFCPContext[nodeIP] = &context.PFCPSessionContext{NodeID: *context.NewNodeID(nodeIP), LocalSEID: 9707, RemoteSEID: 9708}
	a := stored(t, db, supi, storedOpts{seid: 9709, anchorOn: nodeIP, amf: p.srv.URL, pcf: p.srv.URL})
	if context.GetSMContext(a.Ref) == nil {
		t.Fatalf("precondition: the stored session was not restored")
	}

	producer.RestoreSessionsOnUPF(*context.NewNodeID(nodeIP), time.Now())
	time.Sleep(300 * time.Millisecond) // the sweep finds the live session busy
	live.SMLock.Unlock()

	if !waitGone(t, db, a.Ref) {
		t.Errorf("the restored session was not released when its user plane restarted")
	}
	p.waitReleased(t)
	// The live session has no data path to re-install, so once it is examined it is skipped.
	skipped := map[string]string{upfLabel: nodeIP, "outcome": "skipped"}
	deadline := time.Now().Add(2 * time.Second)
	for v, _ := metricValue(t, "smf_upf_restoration_sessions_total", skipped); v != 1 && time.Now().Before(deadline); v, _ = metricValue(t, "smf_upf_restoration_sessions_total", skipped) {
		time.Sleep(5 * time.Millisecond)
	}
	if v, _ := metricValue(t, "smf_upf_restoration_sessions_total", skipped); v != 1 {
		t.Errorf("the busy session was examined %v times once its lock was free, want once", v)
	}
}

// The restored sessions a restarted user plane holds are released after the restoration waves, from
// the list the sweep took before them. One released or replaced in between is left alone: the
// release command names the subscriber and PDU session ID, and the AMF would release the session
// that replaced it. Nor is it counted as a session without service.
func TestARestoredSessionReleasedSinceTheSweepIsNotReleasedAgain(t *testing.T) {
	reattach := func(t *testing.T, s *context.SMContext) { loadCreate(t, s.Supi) }
	for _, tc := range []struct {
		name         string
		listingFails bool // the sessions are served unregistered, and the new one replaces nothing
		meanwhile    func(t *testing.T, s *context.SMContext)
	}{
		{"its UE establishes the PDU session again", false, reattach},
		{"its UE establishes the PDU session again while the listing fails", true, reattach},
		{"it is released on request", false, func(t *testing.T, s *context.SMContext) { context.RemoveSMContext(s.Ref) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := withStore(t)
			db.listingFails = tc.listingFails
			p := newPeers(t)
			nodeIP := freshNode()
			restartedUPF(t, nodeIP)
			restored := map[string]*context.SMContext{}
			for i := range 2 {
				supi := freshSupi()
				a := stored(t, db, supi, storedOpts{seid: uint64(9901 + i), anchorOn: nodeIP, amf: p.srv.URL, pcf: p.srv.URL})
				if restored[supi] = context.GetSMContext(a.Ref); restored[supi] == nil {
					t.Fatalf("precondition: the stored session was not restored")
				}
			}
			held, resume := p.holdFirstTransfer()

			producer.RestoreSessionsOnUPF(*context.NewNodeID(nodeIP), time.Now())

			var other *context.SMContext
			select {
			case first := <-held:
				for supi, s := range restored {
					if supi != first {
						other = s
					}
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("precondition: neither restored session was released")
			}
			tc.meanwhile(t, other)
			close(resume)

			// The gauge is set once the restored sessions have been dealt with.
			labels := map[string]string{upfLabel: nodeIP}
			deadline := time.Now().Add(2 * time.Second)
			for _, done := metricValue(t, unrestoredMetric, labels); !done && time.Now().Before(deadline); _, done = metricValue(t, unrestoredMetric, labels) {
				time.Sleep(5 * time.Millisecond)
			}
			if n := p.transfersFor(other.Supi); n != 0 {
				t.Errorf("the AMF was sent %d release(s) for the subscriber's PDU session after it was released or replaced", n)
			}
			if got := unrestoredGauge(t, nodeIP); got != 0 {
				t.Errorf("the user plane reports %v sessions without service, want none", got)
			}
		})
	}
}

// A restored session served without being registered as current -- the listing of its subscriber's
// stored sessions failed -- is released like any restored session when its user plane restarts.
func TestAnUnregisteredRestoredSessionIsReleasedWhenItsUserPlaneRestarts(t *testing.T) {
	db := withStore(t)
	p := newPeers(t)
	nodeIP, supi := freshNode(), freshSupi()
	restartedUPF(t, nodeIP)
	a := stored(t, db, supi, storedOpts{seid: 9905, anchorOn: nodeIP, amf: p.srv.URL, pcf: p.srv.URL})
	db.listingFails = true
	if context.GetSMContext(a.Ref) == nil {
		t.Fatalf("precondition: the stored session was not restored")
	}
	if _, err := context.ResolveRef(supi, 1); err == nil {
		t.Fatalf("precondition: the restored session was registered as current")
	}

	producer.RestoreSessionsOnUPF(*context.NewNodeID(nodeIP), time.Now())

	if !waitGone(t, db, a.Ref) {
		t.Errorf("the unregistered restored session was not released when its user plane restarted")
	}
	p.waitReleased(t)
}

// A restored session a later session for its PDU session superseded is not among those the sweep
// releases: the subscriber's PDU session is now that later one, and releasing the restored one would
// tell the AMF to release it. Here the listing failed, so the restored session was served without
// being registered, and the UE's new session replaced nothing.
func TestASupersededRestoredSessionIsNotSweptForRelease(t *testing.T) {
	db := withStore(t)
	nodeIP, supi := freshNode(), freshSupi()
	a := stored(t, db, supi, storedOpts{seid: 9906, anchorOn: nodeIP})
	db.listingFails = true
	restored := context.GetSMContext(a.Ref)
	if restored == nil {
		t.Fatalf("precondition: the stored session was not restored")
	}
	t.Cleanup(func() { context.RemoveSMContext(a.Ref) })
	created := loadCreate(t, supi)
	if !restored.SupersededByAnother() {
		t.Fatalf("precondition: the session %s created since does not supersede the restored one", created.Ref)
	}

	anchored, _, _ := context.SessionsAnchoredOn(*context.NewNodeID(nodeIP), time.Time{})
	for _, s := range anchored {
		if s == restored {
			t.Errorf("the superseded restored session was found anchored, for release")
		}
	}
}

// restartedUPF stands in for a user plane this SMF is associated with, and which has restarted.
func restartedUPF(t *testing.T, nodeIP string) {
	t.Helper()
	upf := context.NewUPF(context.NewNodeID(nodeIP), nil)
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(upf.NodeID) })
	upf.UPFStatus = context.AssociatedSetUpSuccess
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: time.Now()}
}

// The gauge of the sessions a user plane holds without service, and the label naming the user plane.
const (
	unrestoredMetric = "smf_upf_unrestored_sessions"
	upfLabel         = "upf"
)

// unrestoredGauge reads how many of a user plane's sessions this SMF reports as without service.
func unrestoredGauge(t *testing.T, nodeIP string) float64 {
	t.Helper()
	value, _ := metricValue(t, unrestoredMetric, map[string]string{upfLabel: nodeIP})
	return value
}

// Sessions are ordered by the smfCount of the start that created them, read when the SMF sets up its
// datastore: a session a later start creates outranks one an earlier start created, whatever their
// sequences.
func TestALaterStartsSessionOutranksAnEarlierStarts(t *testing.T) {
	db := withStore(t)
	t.Setenv("SMF_COUNT", "")
	const supi = "imsi-208930018809008"

	t.Cleanup(context.SetupSmfCount())
	earlier := context.NewSMContext(supi, 1)
	t.Cleanup(func() { context.RemoveSMContext(earlier.Ref) })
	context.SetupSmfCount() // the SMF restarts
	later := context.NewSMContext(supi, 2)
	t.Cleanup(func() { context.RemoveSMContext(later.Ref) })

	if earlier.CreatedSmfCount != 1 || later.CreatedSmfCount != 2 {
		t.Errorf("sessions record smfCount %d and %d, want the 1 and 2 the two starts read",
			earlier.CreatedSmfCount, later.CreatedSmfCount)
	}
	if got := os.Getenv("SMF_COUNT"); got != "2" {
		t.Errorf("SMF_COUNT is %q, want the 2 the last start read", got)
	}

	// The later start's sequence begins below the earlier one's last, and its session outranks the
	// earlier one's all the same.
	const restoredSupi = "imsi-208930018809009"
	stored(t, db, restoredSupi, storedOpts{stamp: &stamp{earlier.CreatedSmfCount, 100}, seid: 9801})
	newer := stored(t, db, restoredSupi, storedOpts{stamp: &stamp{later.CreatedSmfCount, 1}, seid: 9802})
	got := context.GetSMContext(newer.Ref)
	if got == nil {
		t.Errorf("the session a later start created was not served over an earlier start's")
	} else {
		t.Cleanup(func() { context.RemoveSMContext(got.Ref) })
	}
}

// A restored session is the subscriber's current session for its PDU session ID, and still not one
// to re-install on a user plane that restarts: it is found anchored there marked as restored from
// the datastore, so the restoration releases it instead.
func TestARestoredSessionIsFoundMarkedForRelease(t *testing.T) {
	db := withStore(t)
	const (
		supi   = "imsi-208930018809011"
		nodeIP = "10.77.0.11"
	)
	a := stored(t, db, supi, storedOpts{seid: 9011, anchorOn: nodeIP})
	restored := context.GetSMContext(a.Ref)
	if restored == nil {
		t.Fatalf("precondition: the stored session was not restored")
	}
	t.Cleanup(func() { context.RemoveSMContext(a.Ref) })

	anchored, _, _ := context.SessionsAnchoredOn(*context.NewNodeID(nodeIP), time.Time{})
	found := false
	for _, s := range anchored {
		found = found || s == restored
	}
	if !found {
		t.Errorf("the restored session was not found anchored on its user plane")
	}
	if !restored.RestoredFromStore() {
		t.Errorf("the restored session is not marked as restored from the datastore")
	}
}

// recordReleases wraps the release of stored sessions for the length of a test, recording every
// instance released.
func recordReleases(t *testing.T) func() []*context.SMContext {
	t.Helper()
	var mu sync.Mutex
	var released []*context.SMContext
	release := context.ReleaseRestoredSession
	context.ReleaseRestoredSession = func(smContext *context.SMContext) {
		mu.Lock()
		released = append(released, smContext)
		mu.Unlock()
		release(smContext)
	}
	t.Cleanup(func() { context.ReleaseRestoredSession = release })
	return func() []*context.SMContext {
		mu.Lock()
		defer mu.Unlock()
		return append([]*context.SMContext(nil), released...)
	}
}

// A session read back from the datastore was never counted in the session gauge, so releasing one
// leaves the gauge alone. Decrementing for it undercounted the live sessions.
func TestReleasingAStoredSessionLeavesTheSessionGaugeAlone(t *testing.T) {
	db := withStore(t)
	const supi = "imsi-208930018809012"
	a := stored(t, db, supi, storedOpts{seid: 9012})
	b := stored(t, db, supi, storedOpts{seid: 9013})

	before := sessionGauge(t)
	context.ReleaseStoredSessions(supi, 1)

	if !waitGone(t, db, a.Ref) || !waitGone(t, db, b.Ref) {
		t.Fatalf("precondition: the stored sessions were not released")
	}
	if after := sessionGauge(t); after != before {
		t.Errorf("the session gauge moved from %v to %v releasing sessions it never counted", before, after)
	}
}

// sessionGauge reads the session gauge this SMF publishes.
func sessionGauge(t *testing.T) float64 {
	t.Helper()
	value, ok := metricValue(t, "smf_pdu_sessions", map[string]string{"node_id": context.SMF_Self().NfInstanceID})
	if !ok {
		t.Fatalf("the session gauge is not published")
	}
	return value
}

// metricValue reads the published gauge or counter with the given name and labels.
func metricValue(t *testing.T, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			matched := 0
			for _, label := range metric.GetLabel() {
				if want, ok := labels[label.GetName()]; ok && want == label.GetValue() {
					matched++
				}
			}
			if matched == len(labels) {
				return metric.GetGauge().GetValue() + metric.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}

// A stored session a lookup has already read into the pool is released as that instance, so the
// release and the request holding it act on one session.
func TestAStoredSessionAlreadyInThePoolIsReleasedAsThatInstance(t *testing.T) {
	db := withStore(t)
	released := recordReleases(t)
	const supi = "imsi-208930018809014"
	a := stored(t, db, supi, storedOpts{seid: 9014})
	held := context.GetSMContext(a.Ref)
	if held == nil {
		t.Fatalf("precondition: the stored session was not read into the pool")
	}

	context.ReleaseStoredSessions(supi, 1)

	got := released()
	if len(got) != 1 || got[0] != held {
		t.Errorf("released %d instance(s), want the one already held", len(got))
	}
}

// A lookup can read a stored session into the pool while a create is reading the same session to
// release it. The release acts on the instance in the pool, so the lookup's instance is the one
// released, and the pool is not emptied of an instance the release never touched.
func TestAStoredSessionPooledWhileItIsReadForReleaseIsTheOneReleased(t *testing.T) {
	db := withStore(t)
	released := recordReleases(t)
	const supi = "imsi-208930018809050"
	a := stored(t, db, supi, storedOpts{seid: 9050})
	var pooled *context.SMContext
	db.afterRead = func() {
		// A lookup that missed the pool as well, finishing first.
		pooled = context.GetSMContextByRefInDB(a.Ref)
		context.StoreSmContextPool(pooled)
	}

	context.ReleaseStoredSessions(supi, 1)

	if pooled == nil {
		t.Fatalf("precondition: the release read nothing from the datastore")
	}
	if got := released(); len(got) != 1 || got[0] != pooled {
		t.Errorf("released %d instance(s), want the one the lookup put in the pool", len(got))
	}
	pooled.SMLock.Lock()
	state := pooled.SMContextState
	pooled.SMLock.Unlock()
	if state != context.SmStateRelease {
		t.Errorf("the instance the lookup holds is %v, want it released", state)
	}
}

// A request to release a stored session reads it from the datastore when the pool does not hold it,
// without the subscriber's key lock. A lookup that puts the same session in the pool meanwhile has put
// there the instance the request must act on: storing the request's own copy over it would leave the
// lookup serving an instance nothing releases.
func TestAReleaseRequestRacingALookupActsOnThePooledInstance(t *testing.T) {
	db := withStore(t)
	const supi = "imsi-208930018809053"
	a := stored(t, db, supi, storedOpts{seid: 9053})
	t.Cleanup(func() { context.RemoveSMContext(a.Ref) })
	var pooled *context.SMContext
	db.afterRead = func() {
		// A lookup that missed the pool as well, finishing first.
		pooled = context.GetSMContextByRefInDB(a.Ref)
		context.StoreSmContextPool(pooled)
	}

	got := context.GetSMContextForRelease(a.Ref)

	if pooled == nil {
		t.Fatalf("precondition: the release request read nothing from the datastore")
	}
	if got != pooled {
		t.Errorf("the release request was handed a copy of its own rather than the instance in the pool")
	}
}

// A lookup that reads a stored session while a create is reading the same session to release it
// gets no second copy of its own: the release removes the pool's entry once it is done, and an
// instance the lookup put there in between would be removed with it, unreleased, while the lookup
// went on serving it. The lookup decides whether to serve the session under the subscriber's key
// lock, which the release holds, so it waits for the release to finish and is then handed nothing.
func TestALookupRacingTheReleaseOfAStoredSessionGetsNoSecondCopy(t *testing.T) {
	db := withStore(t)
	const supi = "imsi-208930018809052"
	a := stored(t, db, supi, storedOpts{seid: 9052})
	releasing, proceed, released := make(chan *context.SMContext, 1), make(chan struct{}), make(chan struct{})
	release := context.ReleaseRestoredSession
	context.ReleaseRestoredSession = func(smContext *context.SMContext) {
		releasing <- smContext
		<-proceed
		release(smContext)
	}
	t.Cleanup(func() { context.ReleaseRestoredSession = release })
	var inRelease *context.SMContext
	db.afterRead = func() {
		// The lookup has read the document and not yet put it in the pool. The create reads the
		// same session for release, and puts it there first.
		go func() {
			defer close(released)
			context.ReleaseStoredSessions(supi, 1)
		}()
		inRelease = <-releasing
	}

	looked := make(chan *context.SMContext, 1)
	go func() { looked <- context.GetSMContext(a.Ref) }()
	select {
	case got := <-looked:
		close(proceed)
		<-released
		t.Fatalf("the lookup returned %p while the release held the subscriber's key lock", got)
	case <-time.After(100 * time.Millisecond):
	}
	close(proceed)
	<-released

	if got := <-looked; got != nil {
		t.Errorf("the lookup was handed %p after the release of %p, want nothing", got, inRelease)
	}
}

// A stored session's UE address was allocated by an earlier start of the SMF, and the pool this one
// holds may have given it to another UE since. A create releasing the stored session leaves the
// address with that UE: the context read back carries an allocator with no pool, and the release
// skips it, neither panicking nor returning the address to the pool in use.
func TestReleasingAStoredSessionLeavesItsAddressWithTheUEHoldingItNow(t *testing.T) {
	db := withStore(t)
	pool := configuredPool(t)
	address, err := pool.Allocate(otherSupi)
	if err != nil {
		t.Fatal(err)
	}
	const supi = "imsi-208930018809051"
	a := stored(t, db, supi, storedOpts{ip: address.String(), seid: 9051})

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("releasing the stored session panicked: %v", r)
			}
		}()
		loadCreate(t, supi)
	}()

	if !waitGone(t, db, a.Ref) {
		t.Fatalf("precondition: the stored session was not released")
	}
	if !context.AllocatorHolds(pool, address) {
		t.Errorf("releasing the stored session returned %v to the pool, which holds it for another UE", address)
	}
}

// A listing that fails gives no order to apply; the session is served as before, and not made the
// subscriber's current session, so it supersedes nothing.
func TestARestoreWhoseListingFailsIsServedUnregistered(t *testing.T) {
	db := withStore(t)
	const supi = "imsi-208930018809015"
	a := stored(t, db, supi, storedOpts{seid: 9015})
	t.Cleanup(func() { context.RemoveSMContext(a.Ref) })
	db.listingFails = true

	if got := context.GetSMContext(a.Ref); got == nil {
		t.Fatalf("a stored session was refused because the listing failed")
	}
	if ref, err := context.ResolveRef(supi, 1); err == nil {
		t.Errorf("a session restored without ordering was made current (%s)", ref)
	}
}

// A listing that does not find the session being restored must not make every restore fail: the
// session is served as before, unregistered. One released while it was being read is not.
func TestARestoreTheListingMissesIsServedUnlessReleased(t *testing.T) {
	db := withStore(t)
	const supi = "imsi-208930018809016"
	a := stored(t, db, supi, storedOpts{seid: 9016})
	t.Cleanup(func() { context.RemoveSMContext(a.Ref) })
	db.listingMisses = true

	if got := context.GetSMContext(a.Ref); got == nil {
		t.Errorf("a stored session the listing missed was refused")
	}
	if ref, err := context.ResolveRef(supi, 1); err == nil {
		t.Errorf("a session restored without ordering was made current (%s)", ref)
	}

	b := stored(t, db, "imsi-208930018809017", storedOpts{seid: 9017})
	db.goneAfterRead = b.Ref
	if got := context.GetSMContext(b.Ref); got != nil {
		t.Errorf("a stored session released while it was being read was served")
	}
}

// Two requests naming two stored copies of one session at once decide one after the other: the
// older copy is released once and the newer one served.
func TestConcurrentRestoresOfOneSessionReleaseEachCopyOnce(t *testing.T) {
	db := withStore(t)
	released := recordReleases(t)
	for i := range 20 {
		supi := fmt.Sprintf("imsi-2089300188093%02d", i)
		older := stored(t, db, supi, storedOpts{stamp: &stamp{1, 1}, seid: uint64(9400 + 2*i)})
		newer := stored(t, db, supi, storedOpts{stamp: &stamp{2, 1}, seid: uint64(9401 + 2*i)})
		t.Cleanup(func() { context.RemoveSMContext(newer.Ref) })

		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, ref := range []string{older.Ref, newer.Ref} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				context.GetSMContext(ref)
			}()
		}
		close(start)
		wg.Wait()

		olderReleases, newerReleases := 0, 0
		for _, s := range released() {
			switch s.Ref {
			case older.Ref:
				olderReleases++
			case newer.Ref:
				newerReleases++
			}
		}
		if olderReleases != 1 || newerReleases != 0 {
			t.Fatalf("round %d: the older copy was released %d times and the newer %d, want once and never",
				i, olderReleases, newerReleases)
		}
	}
}

// capturePublished records the subscriber events published for the length of a test, with the event
// stream enabled.
func capturePublished(t *testing.T) func(imsi string) []mi.SubscriberOp {
	t.Helper()
	enabled := true
	factory.SmfConfig.Configuration.KafkaInfo.EnableKafka = &enabled
	var mu sync.Mutex
	var events []mi.CoreSubscriber
	var ops []mi.SubscriberOp
	t.Cleanup(context.CapturePublished(func(s mi.CoreSubscriber, op mi.SubscriberOp) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, s)
		ops = append(ops, op)
		return nil
	}))
	return func(imsi string) []mi.SubscriberOp {
		mu.Lock()
		defer mu.Unlock()
		var out []mi.SubscriberOp
		for i, e := range events {
			if e.Imsi == imsi {
				out = append(out, ops[i])
			}
		}
		return out
	}
}

func hasDel(ops []mi.SubscriberOp) bool {
	for _, op := range ops {
		if op == mi.SubsOpDel {
			return true
		}
	}
	return false
}

// Releasing a stored session a later session replaced does not report the end of the subscriber's
// session: consumers key subscribers by IMSI, and the report would remove the live session's record.
func TestReleasingASupersededStoredSessionReportsNoEnd(t *testing.T) {
	t.Run("refused on restore", func(t *testing.T) {
		db := withStore(t)
		const supi = "imsi-208930018809018"
		a := stored(t, db, supi, storedOpts{stamp: &stamp{1, 1}, seid: 9018})
		b := context.NewSMContext(supi, 1)
		t.Cleanup(func() { context.RemoveSMContext(b.Ref) })
		published := capturePublished(t)

		if context.GetSMContext(a.Ref) != nil || !waitGone(t, db, a.Ref) {
			t.Fatalf("precondition: the superseded session was not refused and released")
		}
		if hasDel(published(supi)) {
			t.Errorf("releasing the superseded session reported the end of the subscriber's session")
		}
	})
	t.Run("an older copy behind the kept one", func(t *testing.T) {
		db := withStore(t)
		const supi = "imsi-208930018809019"
		older := stored(t, db, supi, storedOpts{stamp: &stamp{1, 1}, seid: 9019})
		newer := stored(t, db, supi, storedOpts{stamp: &stamp{2, 1}, seid: 9020})
		t.Cleanup(func() { context.RemoveSMContext(newer.Ref) })
		published := capturePublished(t)

		if context.GetSMContext(newer.Ref) == nil || !waitGone(t, db, older.Ref) {
			t.Fatalf("precondition: the newer copy was not served and the older released")
		}
		if hasDel(published(supi)) {
			t.Errorf("releasing the older copy reported the end of the subscriber's session")
		}
	})
	t.Run("released on request", func(t *testing.T) {
		db := withStore(t)
		const supi = "imsi-208930018809021"
		a := stored(t, db, supi, storedOpts{stamp: &stamp{1, 1}, seid: 9021})
		b := context.NewSMContext(supi, 1)
		t.Cleanup(func() { context.RemoveSMContext(b.Ref) })
		published := capturePublished(t)

		release := models.NewReleaseSmContextRequest()
		release.SetJsonData(models.SmContextReleaseData{})
		txn := transaction.NewTransaction(*release, nil, svcmsgtypes.ReleaseSmContext)
		txn.CtxtKey = a.Ref
		if _, err := fsm.SmfTxnFsmHandle.TxnLoadCtxt(txn); err != nil {
			t.Fatalf("the release was refused: %v", err)
		}
		if err := producer.HandlePDUSessionSMContextRelease(txn); err != nil || !waitGone(t, db, a.Ref) {
			t.Fatalf("precondition: the stored session was not released: %v", err)
		}
		if hasDel(published(supi)) {
			t.Errorf("releasing the superseded session reported the end of the subscriber's session")
		}
	})
}

// A restored session that is the subscriber's current one does end the subscriber's session when it
// is released.
func TestReleasingTheCurrentRestoredSessionReportsItsEnd(t *testing.T) {
	db := withStore(t)
	p := newPeers(t)
	nodeIP := freshNode()
	supi := freshSupi()
	upf := context.NewUPF(context.NewNodeID(nodeIP), nil)
	upf.UPFStatus = context.AssociatedSetUpSuccess
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: time.Now()}
	a := stored(t, db, supi, storedOpts{seid: 9022, anchorOn: nodeIP, amf: p.srv.URL, pcf: p.srv.URL})
	if context.GetSMContext(a.Ref) == nil {
		t.Fatalf("precondition: the stored session was not restored")
	}
	published := capturePublished(t)

	producer.RestoreSessionsOnUPF(*context.NewNodeID(nodeIP), time.Now())

	if !waitGone(t, db, a.Ref) {
		t.Fatalf("precondition: the restored session was not released")
	}
	p.waitReleased(t)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !hasDel(published(supi)) {
		time.Sleep(5 * time.Millisecond)
	}
	if !hasDel(published(supi)) {
		t.Errorf("releasing the subscriber's current session did not report its end")
	}
}

// A SEID document is keyed by the SEID alone, so the one for a stored session's SEID may name another
// session. Releasing the stored session leaves that session's records alone: its context document,
// the SEID document that names it, and its in-memory SEID entry.
func TestReleasingAStoredSessionLeavesAnotherSessionsSEIDAlone(t *testing.T) {
	db := withStore(t)
	const (
		deadSupi = "imsi-208930018809030"
		liveSupi = "imsi-208930018809031"
	)
	const seid = uint64(9030)
	live := context.NewSMContext(liveSupi, 1)
	t.Cleanup(func() { context.RemoveSMContext(live.Ref) })
	dead := stored(t, db, deadSupi, storedOpts{seid: seid})
	context.HoldSEID(seid, live)

	// The live session's records, written when it was established with the same SEID.
	db.put(context.SmContextDataColl, map[string]any{refKey: live.Ref, "identifier": liveSupi, "pduSessionID": 1})
	if _, err := db.RestfulAPIPost(context.SeidSmContextCol, bson.M{seidKey: context.SeidConv(seid)},
		map[string]any{refKey: live.Ref, seidKey: context.SeidConv(seid)}); err != nil {
		t.Fatal(err)
	}

	context.ReleaseStoredSessions(deadSupi, 1)

	if !waitGone(t, db, dead.Ref) {
		t.Fatalf("precondition: the stored session was not released")
	}
	if !storedRef(db, live.Ref) {
		t.Errorf("releasing a stored session deleted the context document of the live session that shares its SEID")
	}
	if !db.has(context.SeidSmContextCol, refKey, live.Ref) {
		t.Errorf("releasing a stored session deleted the SEID document of the live session that shares its SEID")
	}
	if got := context.SEIDHeldBy(seid); got != live {
		t.Errorf("releasing a stored session removed the live session's in-memory SEID entry")
	}
}

// liveRulesOn stands in for a user plane this SMF holds, with a live session's rules allocated
// there: a PDR, its FAR and the FAR's BAR, and a QER, for each direction. It returns the user plane,
// the socket standing in for it, the live rules, and rules carrying the same identifiers, as a
// stored session an earlier start of the SMF allocated them to would carry them.
func liveRulesOn(t *testing.T) (upf *context.UPF, upfConn *net.UDPConn, live, carried [2]*context.PDR) {
	t.Helper()
	upfConn, upfPort := listenLoopback(t)
	startSmfPfcpSocket(t)
	upf = context.NewUPF(context.NewNodeID("127.0.0.1"), nil)
	t.Cleanup(func() { context.RemoveUPFNodeByNodeID(upf.NodeID) })
	upf.UPFStatus = context.AssociatedSetUpSuccess
	// It answered the association with PSREI: it kept the sessions of the one before it.
	upf.SessionsRetained = true
	upf.Port = upfPort
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: upfIncarnation}

	for i := range live {
		pdr, err := upf.AddPDR()
		if err != nil {
			t.Fatalf("allocating the live session's rules: %v", err)
		}
		bar, err := upf.AddBAR()
		if err != nil {
			t.Fatalf("allocating the live session's rules: %v", err)
		}
		qer, err := upf.AddQER()
		if err != nil {
			t.Fatalf("allocating the live session's rules: %v", err)
		}
		pdr.FAR.BAR = bar
		pdr.QER = []*context.QER{qer}
		live[i] = pdr
		carried[i] = &context.PDR{
			PDRID: pdr.PDRID,
			FAR:   &context.FAR{FARID: pdr.FAR.FARID, BAR: &context.BAR{BARID: bar.BARID}},
			QER:   []*context.QER{{QERID: qer.QERID}},
		}
	}
	return upf, upfConn, live, carried
}

// upfIncarnation is the recovery timestamp of the user plane liveRulesOn stands in for, as this SMF
// holds it.
var upfIncarnation = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// stillHeld reports, as a test error, each identifier of the live rules the user plane's pools no
// longer hold.
func stillHeld(t *testing.T, upf *context.UPF, live [2]*context.PDR) {
	t.Helper()
	for i, direction := range []string{"uplink", "downlink"} {
		pdr := live[i]
		for rule, held := range map[string]bool{
			fmt.Sprintf("PDR %d", pdr.PDRID):         upf.HoldsPDR(pdr.PDRID),
			fmt.Sprintf("FAR %d", pdr.FAR.FARID):     upf.HoldsFAR(pdr.FAR.FARID),
			fmt.Sprintf("BAR %d", pdr.FAR.BAR.BARID): upf.HoldsBAR(pdr.FAR.BAR.BARID),
			fmt.Sprintf("QER %d", pdr.QER[0].QERID):  upf.HoldsQER(pdr.QER[0].QERID),
		} {
			if !held {
				t.Errorf("releasing the stored session took %s from the live session's %s rule", rule, direction)
			}
		}
	}
}

// A stored session whose data path names a user plane this SMF holds has its PFCP session deleted
// there. The identifiers of its rules were allocated by an earlier incarnation, and this one may
// have given them to a live session since: releasing the stored session leaves them with that one.
func TestReleasingAStoredSessionDeletesItsPFCPSessionAndFreesNoRuleIdentifiers(t *testing.T) {
	db := withStore(t)
	upf, upfConn, live, carried := liveRulesOn(t)
	const supi = "imsi-208930018809032"
	a := stored(t, db, supi, storedOpts{upf: upf, rules: carried, seid: 9032, acknowledgedAt: upfIncarnation})

	context.ReleaseStoredSessions(supi, 1)

	msg := readPfcp(t, upfConn)
	if msg.MessageType() != message.MsgTypeSessionDeletionRequest || msg.SEID() != 9032+1000 {
		t.Errorf("the user plane received message type %d for SEID %d, want a deletion for %d",
			msg.MessageType(), msg.SEID(), 9032+1000)
	}
	if !waitGone(t, db, a.Ref) {
		t.Errorf("the stored session was not released")
	}
	stillHeld(t, upf, live)
}

// A stored session a lookup reads into the pool is marked as read back, and released as one: the
// session gauge, which never counted it, is left alone, and the identifiers its rules carry stay
// with the live session this start gave them to.
func TestAStoredSessionALookupReadIsReleasedAsReadBack(t *testing.T) {
	db := withStore(t)
	upf, upfConn, live, carried := liveRulesOn(t)
	const supi = "imsi-208930018809033"
	a := stored(t, db, supi, storedOpts{upf: upf, rules: carried, seid: 9033, acknowledgedAt: upfIncarnation})
	if context.GetSMContext(a.Ref) == nil {
		t.Fatalf("precondition: the stored session was not read into the pool")
	}
	before := sessionGauge(t)

	context.ReleaseStoredSessions(supi, 1)

	if msg := readPfcp(t, upfConn); msg.MessageType() != message.MsgTypeSessionDeletionRequest {
		t.Errorf("the user plane received message type %d, want a deletion", msg.MessageType())
	}
	if !waitGone(t, db, a.Ref) {
		t.Fatalf("precondition: the stored session was not released")
	}
	if after := sessionGauge(t); after != before {
		t.Errorf("the session gauge moved from %v to %v releasing a session it never counted", before, after)
	}
	stillHeld(t, upf, live)
}

// A user plane that restarted after acknowledging a stored session no longer holds it, and may have
// given its SEID to another session since: a deletion for that SEID would remove the other session.
// Nor can a document that does not record which incarnation acknowledged it be told apart from one
// acknowledged before a restart. Either is released here without a deletion. So is a session whose
// user plane a heartbeat has reported restarted: the timestamp held for it is still the acknowledging
// one until the re-association replaces it, but the node is marked not associated in between. And so
// is one whose user plane did not answer this SMF's association with PSREI: the association replaced
// the one the session was established under, and without retention the user plane deleted its
// sessions.
func TestAStoredSessionIsDeletedOnlyAtTheIncarnationThatAcknowledgedIt(t *testing.T) {
	for _, tc := range []struct {
		name           string
		acknowledgedAt time.Time
		held           time.Time // the user plane's recovery timestamp as this SMF holds it
		seid           uint64
		status         context.UPFStatus // the association state this SMF holds for the user plane
		retained       bool              // whether the user plane answered the association with PSREI
	}{
		{"acknowledged before the user plane restarted", upfIncarnation.Add(-time.Hour), upfIncarnation, 9034, context.AssociatedSetUpSuccess, true},
		{"incarnation not recorded", time.Time{}, upfIncarnation, 9035, context.AssociatedSetUpSuccess, true},
		{"incarnation not recorded, nor yet held", time.Time{}, time.Time{}, 9036, context.AssociatedSetUpSuccess, true},
		{"acknowledged, the user plane not yet associated since the SMF started", upfIncarnation, time.Time{}, 9038, context.AssociatedSetUpSuccess, true},
		{
			"acknowledged, the user plane reported restarted by a heartbeat and not yet re-associated",
			upfIncarnation, upfIncarnation, 9039, context.NotAssociated, true,
		},
		{
			"acknowledged, the association with the user plane still being set up",
			upfIncarnation, upfIncarnation, 9040, context.AssociatedSettingUp, true,
		},
		{
			// TS 29.244 clause 6.2.6.2.2: re-associating replaced the association the session was
			// established under, and a user plane that does not say it retained that one's sessions
			// deleted them, its own recovery timestamp unchanged.
			"acknowledged by the incarnation held, which did not report retaining the sessions",
			upfIncarnation, upfIncarnation, 9041, context.AssociatedSetUpSuccess, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := withStore(t)
			upf, upfConn, live, carried := liveRulesOn(t)
			upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: tc.held}
			upf.UPFStatus = tc.status
			upf.SessionsRetained = tc.retained
			supi := fmt.Sprintf("imsi-20893001880%04d", tc.seid)
			a := stored(t, db, supi, storedOpts{upf: upf, rules: carried, seid: tc.seid, acknowledgedAt: tc.acknowledgedAt})

			context.ReleaseStoredSessions(supi, 1)

			if !waitGone(t, db, a.Ref) {
				t.Errorf("the stored session was not released")
			}
			if msg, ok := readPfcpWithin(upfConn, 300*time.Millisecond); ok {
				t.Errorf("the user plane received message type %d for SEID %d, want none", msg.MessageType(), msg.SEID())
			}
			stillHeld(t, upf, live)
		})
	}
}

// Both of a session's encoders keep which incarnation of the node acknowledged it: ToBsonM, which
// the datastore writes, and MarshalJSON. The tests above go through the first.
func TestTheAcknowledgingIncarnationSurvivesMarshalJSON(t *testing.T) {
	db := withStore(t)
	upf, _, _, carried := liveRulesOn(t)
	a := stored(t, db, "imsi-208930018809037", storedOpts{upf: upf, rules: carried, seid: 9037, acknowledgedAt: upfIncarnation})

	encoded, err := a.MarshalJSON()
	if err != nil {
		t.Fatalf("encoding the session: %v", err)
	}
	var decoded context.SMContext
	if err := decoded.UnmarshalJSON(encoded); err != nil {
		t.Fatalf("decoding the session: %v", err)
	}
	for key, pfcpContext := range decoded.PFCPContext {
		if !pfcpContext.AcknowledgedAtRecovery.Equal(upfIncarnation) {
			t.Errorf("the session on %s decoded as acknowledged at %v, want %v", key, pfcpContext.AcknowledgedAtRecovery, upfIncarnation)
		}
	}
	if len(decoded.PFCPContext) != 1 {
		t.Errorf("the session decoded with %d PFCP sessions, want 1", len(decoded.PFCPContext))
	}
}

// The tests above store documents in memory, normalised through encoding/json. The datastore stores
// them through the BSON codec instead, and reads them back as the mongoapi client is configured to:
// nested documents as maps. That is the path a restart actually takes, so the acknowledging
// incarnation is carried along it here: ToBsonM, the codec both ways, and the decoding
// GetSMContextByRefInDB applies to what it reads.
func TestTheAcknowledgingIncarnationSurvivesTheDatastoresEncoding(t *testing.T) {
	db := withStore(t)
	upf, _, _, carried := liveRulesOn(t)
	a := stored(t, db, "imsi-208930018809042", storedOpts{upf: upf, rules: carried, seid: 9042, acknowledgedAt: upfIncarnation})

	raw, err := bson.Marshal(context.ToBsonM(a))
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
	var decoded context.SMContext
	if err = gojson.Unmarshal(asRead, &decoded); err != nil {
		t.Fatalf("decoding the session as read: %v", err)
	}

	if len(decoded.PFCPContext) != 1 {
		t.Fatalf("the session decoded with %d PFCP sessions, want 1", len(decoded.PFCPContext))
	}
	for key, pfcpContext := range decoded.PFCPContext {
		// Compared in whole seconds, as the release compares it.
		if pfcpContext.AcknowledgedAtRecovery.Unix() != upfIncarnation.Unix() {
			t.Errorf("the session on %s read back as acknowledged at %v, want %v", key, pfcpContext.AcknowledgedAtRecovery, upfIncarnation)
		}
	}
}

func listenLoopback(t *testing.T) (*net.UDPConn, uint16) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("standing in for the UPF: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// startSmfPfcpSocket gives the SMF a real socket to send from, with retransmissions cut short so a
// request nobody answers does not outlive the test.
func startSmfPfcpSocket(t *testing.T) {
	t.Helper()
	retries, requestTimeout, responseTimeout := udp.GetRetryTimingForTest()
	udp.SetRetryTimingForTest(1, time.Millisecond, time.Millisecond)
	self := context.SMF_Self()
	cpNodeID, pfcpPort := self.CPNodeID, self.PFCPPort
	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserving a port for the SMF: %v", err)
	}
	port := free.LocalAddr().(*net.UDPAddr).Port
	free.Close()

	self.CPNodeID = *context.NewNodeID("127.0.0.1")
	self.PFCPPort = port
	udp.Run(func(*udp.Message) {})
	time.Sleep(50 * time.Millisecond) // let the listener bind before anything is sent

	t.Cleanup(func() {
		udp.WaitForAllTransactions()
		if server := udp.GetServer(); server != nil {
			if server.Conn != nil {
				server.Conn.Close()
				<-server.Done
			}
			udp.SetServer(nil)
		}
		self.CPNodeID, self.PFCPPort = cpNodeID, pfcpPort
		udp.SetRetryTimingForTest(retries, requestTimeout, responseTimeout)
	})
}

// readPfcpWithin returns the next message the user plane receives within d, if one arrives.
func readPfcpWithin(conn *net.UDPConn, d time.Duration) (message.Message, bool) {
	if err := conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		return nil, false
	}
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, false
	}
	msg, err := message.Parse(buf[:n])
	if err != nil {
		return nil, false
	}
	return msg, true
}

func readPfcp(t *testing.T, conn *net.UDPConn) message.Message {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("setting a read deadline: %v", err)
	}
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the user plane received nothing: %v", err)
	}
	msg, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parsing what the user plane received: %v", err)
	}
	return msg
}
