// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/fsm"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/omec-project/smf/transaction"
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
	mu    sync.Mutex
	colls map[string][]map[string]any

	afterRead func() // run once, after the next read of a session document
}

func newMemDB() *memDB { return &memDB{colls: make(map[string][]map[string]any)} }

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
	for _, doc := range db.colls[coll] {
		if matches(doc, filter) {
			found = copyDoc(doc)
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

type storedOpts struct {
	ip         string          // an address an earlier start of the SMF allocated from ueSubnet
	unknownUPF string          // a node the data path names that this SMF does not hold
	upf        *context.UPF    // a node this SMF holds, which the data path names and the session is anchored on
	rules      [2]*context.PDR // the uplink and downlink rules the session holds on upf
	seid       uint64
	// acknowledgedAt is the recovery timestamp of the incarnation of upf that acknowledged the
	// session; zero as in a document stored before it was kept.
	acknowledgedAt time.Time
}

// stored writes a session to the datastore as an earlier SMF incarnation left it, and drops it from
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
	} else if o.seid != 0 {
		smContext.PFCPContext["10.99.0.1"] = &context.PFCPSessionContext{
			NodeID: *context.NewNodeID("10.99.0.1"), LocalSEID: o.seid, RemoteSEID: o.seid + 1000,
		}
	}
	// A stored session always carries both profiles. These name no service, so nothing is sent to
	// either peer.
	smContext.AMFProfile = nfProfile(models.NFTYPE_AMF)
	smContext.SelectedPCFProfile = nfProfile(models.NFTYPE_PCF)

	doc := context.ToBsonM(smContext)
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

func nfProfile(nfType models.NFType) models.NFProfileDiscovery {
	var p models.NFProfileDiscovery
	p.SetNfInstanceId("nf-" + string(nfType))
	p.SetNfType(nfType)
	p.SetNfStatus(models.NFSTATUS_REGISTERED)
	return p
}

// The fields the SMF keys its context and SEID documents by.
const (
	refKey  = "ref"
	seidKey = "seid"
)

func storedRef(db *memDB, ref string) bool { return db.has(context.SmContextDataColl, refKey, ref) }

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
	a := stored(t, db, supi, storedOpts{seid: 9001, unknownUPF: "10.88.0.1"})

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
		stored(t, db, supi, storedOpts{seid: 9103}),
	}

	loadCreate(t, supi)

	for i, c := range copies {
		if !waitGone(t, db, c.Ref) {
			t.Errorf("stored copy %d survived the UE establishing the PDU session again", i)
		}
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
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "smf_pdu_sessions" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "node_id" && label.GetValue() == context.SMF_Self().NfInstanceID {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("the session gauge is not published")
	return 0
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

// A lookup that reads a stored session while a create is reading the same session to release it is
// handed the instance the release put in the pool, never a second copy of its own: the release
// removes the pool's entry once it is done, and an instance the lookup put there in between would be
// removed with it, unreleased, while the lookup went on serving it.
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
	// The lookup takes no lock the release holds, so it returns while the release is under way.
	var got *context.SMContext
	select {
	case got = <-looked:
	case <-time.After(2 * time.Second):
		close(proceed)
		t.Fatalf("the lookup did not return while the release was under way")
	}
	close(proceed)
	<-released

	if got != inRelease {
		t.Errorf("the lookup was handed %p rather than the instance being released (%p)", got, inRelease)
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
// acknowledged before a restart. Either is released here without a deletion.
func TestAStoredSessionIsDeletedOnlyAtTheIncarnationThatAcknowledgedIt(t *testing.T) {
	for _, tc := range []struct {
		name           string
		acknowledgedAt time.Time
		held           time.Time // the user plane's recovery timestamp as this SMF holds it
		seid           uint64
	}{
		{"acknowledged before the user plane restarted", upfIncarnation.Add(-time.Hour), upfIncarnation, 9034},
		{"incarnation not recorded", time.Time{}, upfIncarnation, 9035},
		{"incarnation not recorded, nor yet held", time.Time{}, time.Time{}, 9036},
		{"acknowledged, the user plane not yet associated since the SMF started", upfIncarnation, time.Time{}, 9038},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := withStore(t)
			upf, upfConn, live, carried := liveRulesOn(t)
			upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: tc.held}
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
