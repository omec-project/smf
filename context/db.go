// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package context

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/omec-project/openapi/v2/Namf_Communication"
	"github.com/omec-project/openapi/v2/Npcf_SMPolicyControl"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/util/idgenerator"
	"github.com/omec-project/util/mongoapi"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	SmContextDataColl = "smf.data.smContext"
	SeidSmContextCol  = "smf.data.seidSmContext"
	NodeInDBCol       = "smf.data.nodeInDB"
	RefSeidCol        = "smf.data.refToSeid"
	refFilterKey      = "ref"
)

func SetupSmfCollection() {
	dbName := "sdcore_smf"
	dbUrl := "mongodb://mongodb-arbiter-headless"

	if factory.SmfConfig.Configuration.Mongodb.Url != "" {
		dbUrl = factory.SmfConfig.Configuration.Mongodb.Url
	}

	if factory.SmfConfig.Configuration.SmfDbName != "" {
		dbName = factory.SmfConfig.Configuration.SmfDbName
	}

	logger.CfgLog.Infof("initialising db name [%v] url [%v]", dbName, dbUrl)

	// UUID table
	mongoapi.ConnectMongo(dbUrl, dbName)
	_, err := mongoapi.CommonDBClient.CreateIndex(SmContextDataColl, refFilterKey)
	if err != nil {
		logger.DataRepoLog.Errorln("create index failed on ref field")
	}

	// SEID Table
	_, err = mongoapi.CommonDBClient.CreateIndex(SeidSmContextCol, "seid")
	if err != nil {
		logger.DataRepoLog.Errorln("create index failed on TxnId field")
	}

	smfCount := mongoapi.CommonDBClient.GetUniqueIdentity("smfCount")
	logger.DataRepoLog.Infof("unique id - init smfCount %d", smfCount)

	// set os env
	setEnvErr := os.Setenv("SMF_COUNT", strconv.Itoa(int(smfCount)))
	if setEnvErr != nil {
		logger.DataRepoLog.Errorln("setting SMF_COUNT env variable is failed")
	}

	startSmContextWriteWorkers()
}

// print out sm context
func (smContext *SMContext) String() string {
	return fmt.Sprintf("Ref:[%v],\nSupi: [%v],\nPei:[%v],\nGpsi:[%v],\nPDUSessionID:[%v],\nDnn:[%v],Snssai: [%v],\nHplmnSnssai: [%v],\nServingNetwork: [%v],\nServingNfId: [%v],\nUpCnxState: [%v],\nAnType: [%v],\nRatType: [%v],\nPDUAddress: [%v],\nSelectedPDUSessionType: [%v],\nSmStatusNotifyUri: [%v],\nSelectedPCFProfile: [%v],\nSMContextState: [%v],\nTunnel: [%v],\nPFCPContext: [%v],\nIdentifier: [%v],\nDNNInfo: [%v],\nSmPolicyData: [%v],\nEstAcceptCause5gSMValue: [%v]\n", smContext.Ref, smContext.Supi, smContext.Pei, smContext.Gpsi, smContext.PDUSessionID, smContext.Dnn, smContext.Snssai, smContext.HplmnSnssai, smContext.ServingNetwork, smContext.ServingNfId, smContext.UpCnxState, smContext.AnType, smContext.RatType, smContext.PDUAddress, smContext.SelectedPDUSessionType, smContext.SmStatusNotifyUri, smContext.SelectedPCFProfile, smContext.SMContextState, smContext.Tunnel, smContext.PFCPContext, smContext.Identifier, smContext.DNNInfo, smContext.SmPolicyData, smContext.EstAcceptCause5gSMValue)
}

// MarshalJSON customized marshaller for sm context
func (smContext *SMContext) MarshalJSON() ([]byte, error) {
	type Alias SMContext

	dataPathPoolInDBVal := make(map[int64]*DataPathInDB)

	var dataPathInDBIf interface{}
	var FirstDPNodeIf interface{}

	var upTunnelVal UPTunnelInDB
	if smContext.Tunnel != nil {
		upTunnelVal.ANInformation = smContext.Tunnel.ANInformation

		if smContext.Tunnel.DataPathPool != nil {
			for key, val := range smContext.Tunnel.DataPathPool {
				dataPathInDBIf = val
				dataPath := dataPathInDBIf.(*DataPath)

				firstDPNode := dataPath.FirstDPNode
				FirstDPNodeIf = firstDPNode

				dataPathNode := FirstDPNodeIf.(*DataPathNode)

				dataPathNodeInDBVal := StoreDataPathNode(dataPathNode)
				newDataPathInDB := &DataPathInDB{
					Activated:         dataPath.Activated,
					IsDefaultPath:     dataPath.IsDefaultPath,
					Destination:       dataPath.Destination,
					HasBranchingPoint: dataPath.HasBranchingPoint,
					FirstDPNode:       dataPathNodeInDBVal,
				}

				dataPathPoolInDBVal[key] = newDataPathInDB
			}
			upTunnelVal.DataPathPool = dataPathPoolInDBVal
		}
	}

	var pfcpSessionContextInDB PFCPSessionContextInDB
	PFCPContextVal := make(PFCPContextInDB)
	// store localseid and remoteseid
	for key, pfcpCtx := range smContext.PFCPContext {
		pfcpSessionContextInDB.NodeID = pfcpCtx.NodeID
		pfcpSessionContextInDB.PDRs = pfcpCtx.PDRs
		pfcpSessionContextInDB.LocalSEID = SeidConv(pfcpCtx.LocalSEID)
		pfcpSessionContextInDB.RemoteSEID = SeidConv(pfcpCtx.RemoteSEID)
		PFCPContextVal[key] = pfcpSessionContextInDB
	}

	var bpJSON json.RawMessage
	if smContext.BPManager != nil {
		var err error
		bpJSON, err = sonic.Marshal(smContext.BPManager)
		if err != nil {
			return nil, err
		}
	}

	return sonic.Marshal(&struct {
		*Alias
		PFCPContext         PFCPContextInDB                 `json:"pfcpContext"`
		Tunnel              UPTunnelInDB                    `json:"tunnel"`
		BPManager           json.RawMessage                 `json:"bpManager,omitempty"`
		SMPolicyClient      *Npcf_SMPolicyControl.APIClient `json:"smPolicyClient,omitempty"`
		CommunicationClient *Namf_Communication.APIClient   `json:"communicationClient,omitempty"`
	}{
		Alias:       (*Alias)(smContext),
		PFCPContext: PFCPContextVal,
		Tunnel:      upTunnelVal,
		BPManager:   bpJSON,
	})
}

// UnmarshalJSON customized unmarshaller for sm context
func (smContext *SMContext) UnmarshalJSON(data []byte) error {
	logger.DataRepoLog.Debugln("db - in UnmarshalJSON")
	type Alias SMContext
	aux := &struct {
		*Alias
		PFCPContextVal PFCPContextInDB `json:"pfcpContext"`
		Tunnel         UPTunnelInDB    `json:"tunnel"`
	}{
		Alias: (*Alias)(smContext),
	}

	if err := sonic.Unmarshal(data, &aux); err != nil {
		logger.DataRepoLog.Errorln("err in customized unMarshall")
		return err
	}

	// recover smContext.PFCPContext
	smContext.PFCPContext = make(map[string]*PFCPSessionContext)
	for key, pfcpCtxInDB := range aux.PFCPContextVal {
		smContext.PFCPContext[key] = &PFCPSessionContext{}
		smContext.PFCPContext[key].NodeID = pfcpCtxInDB.NodeID
		smContext.PFCPContext[key].PDRs = pfcpCtxInDB.PDRs
		localSeid, err := strconv.ParseUint(pfcpCtxInDB.LocalSEID, 16, 64)
		if err != nil {
			logger.DataRepoLog.Errorf("localSEID unmarshal error: %v", err)
		}
		smContext.PFCPContext[key].LocalSEID = localSeid
		remoteSeid, err := strconv.ParseUint(pfcpCtxInDB.RemoteSEID, 16, 64)
		if err != nil {
			logger.DataRepoLog.Errorf("remoteSEID unmarshal error: %v", err)
		}
		smContext.PFCPContext[key].RemoteSEID = remoteSeid
	}

	var dataPathInDBIf interface{}
	var FirstDPNodeIf interface{}
	smContext.Tunnel = &UPTunnel{}
	if !reflect.DeepEqual(aux.Tunnel, UPTunnelInDB{}) {
		smContext.Tunnel.ANInformation = aux.Tunnel.ANInformation
		smContext.Tunnel.PathIDGenerator = idgenerator.NewGenerator(1, 2147483647)
		smContext.Tunnel.DataPathPool = NewDataPathPool()
		for key, val := range aux.Tunnel.DataPathPool {
			dataPathInDBIf = val
			dataPathInDB := dataPathInDBIf.(*DataPathInDB)

			firstDPNode := dataPathInDB.FirstDPNode
			FirstDPNodeIf = firstDPNode
			dataPathNodeInDBVal := FirstDPNodeIf.(*DataPathNodeInDB)
			dataPathNodeVal := RecoverDataPathNode(dataPathNodeInDBVal)

			newDataPath := NewDataPath()

			newDataPath.Activated = dataPathInDB.Activated
			newDataPath.IsDefaultPath = dataPathInDB.IsDefaultPath
			newDataPath.Destination = dataPathInDB.Destination
			newDataPath.HasBranchingPoint = dataPathInDB.HasBranchingPoint

			newDataPath.FirstDPNode = dataPathNodeVal

			smContext.Tunnel.DataPathPool[key] = newDataPath
		}
	}
	// recover logs
	smContext.initLogTags()
	// recover SBIPFCPCommunicationChan
	smContext.SBIPFCPCommunicationChan = make(chan PFCPSessionResponseStatus, 1)

	return nil
}

func ToBsonMSeidRef(data SeidSmContextRef) (ret bson.M) {
	tmp, err := sonic.Marshal(data)
	if err != nil {
		logger.DataRepoLog.Errorf("SMContext marshal error: %v", err)
		return
	}
	if err = sonic.Unmarshal(tmp, &ret); err != nil {
		logger.DataRepoLog.Errorf("SMContext unmarshal error: %v", err)
	}
	return
}

// smContextAlias is a type alias that breaks the json.Marshaler interface, letting sonic
// encode it as a plain struct instead of going through EncodeJsonMarshaler.
type smContextAlias SMContext

// smContextForDB is the DB serialization form with complex fields pre-transformed.
type smContextForDB struct {
	*smContextAlias
	PFCPContext PFCPContextInDB `json:"pfcpContext"`
	Tunnel      UPTunnelInDB    `json:"tunnel"`
	BPManager   json.RawMessage `json:"bpManager,omitempty"`
	// Shadow with nil so sonic skips these unreconstructable API handles; they
	// are rebuilt from AMFProfile / SelectedPCFProfile on context recovery.
	SMPolicyClient      *Npcf_SMPolicyControl.APIClient `json:"smPolicyClient,omitempty"`
	CommunicationClient *Namf_Communication.APIClient   `json:"communicationClient,omitempty"`
}

func ToBsonM(data *SMContext) (ret bson.M) {
	var upTunnelVal UPTunnelInDB
	if data.Tunnel != nil {
		upTunnelVal.ANInformation = data.Tunnel.ANInformation
		if data.Tunnel.DataPathPool != nil {
			pool := make(DataPathPoolInDB, len(data.Tunnel.DataPathPool))
			for key, dp := range data.Tunnel.DataPathPool {
				pool[key] = &DataPathInDB{
					Activated:         dp.Activated,
					IsDefaultPath:     dp.IsDefaultPath,
					Destination:       dp.Destination,
					HasBranchingPoint: dp.HasBranchingPoint,
					FirstDPNode:       StoreDataPathNode(dp.FirstDPNode),
				}
			}
			upTunnelVal.DataPathPool = pool
		}
	}

	pfcpContextVal := make(PFCPContextInDB, len(data.PFCPContext))
	var pfcpEntry PFCPSessionContextInDB
	for key, pfcpCtx := range data.PFCPContext {
		pfcpEntry.NodeID = pfcpCtx.NodeID
		pfcpEntry.PDRs = pfcpCtx.PDRs
		pfcpEntry.LocalSEID = SeidConv(pfcpCtx.LocalSEID)
		pfcpEntry.RemoteSEID = SeidConv(pfcpCtx.RemoteSEID)
		pfcpContextVal[key] = pfcpEntry
	}

	var bpJSON json.RawMessage
	if data.BPManager != nil {
		var err error
		bpJSON, err = sonic.Marshal(data.BPManager)
		if err != nil {
			logger.DataRepoLog.Errorf("BPManager marshal error: %v", err)
			return ret
		}
	}

	dbDoc := smContextForDB{
		smContextAlias: (*smContextAlias)(data),
		PFCPContext:    pfcpContextVal,
		Tunnel:         upTunnelVal,
		BPManager:      bpJSON,
	}
	tmp, err := sonic.Marshal(&dbDoc)
	if err != nil {
		logger.DataRepoLog.Errorf("SMContext marshal error: %v", err)
		return ret
	}
	if err = sonic.Unmarshal(tmp, &ret); err != nil {
		logger.DataRepoLog.Errorf("SMContext unmarshal error: %v", err)
	}
	return ret
}

// StoreSmContextInDB Store SmContext In DB
func StoreSmContextInDB(smContext *SMContext) {
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	smContextBsonA := ToBsonM(smContext)
	filter := bson.M{refFilterKey: smContext.Ref}
	logger.DataRepoLog.Debugf("StoreSmContextInDB filter: %+v", filter)

	_, postErr := mongoapi.CommonDBClient.RestfulAPIPost(SmContextDataColl, filter, smContextBsonA)
	if postErr != nil {
		logger.DataRepoLog.Warnln(postErr)
	}
}

// smContextWriteReq is either an upsert (bsonDoc set, delete false) or a delete
// (delete true) of the by-ref document. Both request kinds share one struct so
// they can be ordered on the same per-ref shard queue.
//
// done, if non-nil, receives the Mongo call's result (nil on success) after the worker applies
// this request. A caller that needs the delete to have actually succeeded before it proceeds -
// not merely been applied - checks the error rather than assuming success once the wait returns.
type smContextWriteReq struct {
	bsonDoc bson.M
	ref     string
	delete  bool
	done    chan error
}

// smContextWriteQueues is a per-worker shard of write queues; a stable hash of
// ref routes each SMContext to the same shard, preserving per-ref write order.
var smContextWriteQueues []chan smContextWriteReq

// startSmContextWriteWorkers launches a fixed pool of goroutines that drain
// smContextWriteQueues. Called once from SetupSmfCollection so the workers are
// only active when DB storage is enabled.
func startSmContextWriteWorkers() {
	const (
		workers   = 4
		queueSize = 500
	)
	smContextWriteQueues = make([]chan smContextWriteReq, workers)
	for i := range workers {
		q := make(chan smContextWriteReq, queueSize)
		smContextWriteQueues[i] = q
		go func(q chan smContextWriteReq) {
			for req := range q {
				filter := bson.M{refFilterKey: req.ref}
				var err error
				if req.delete {
					err = mongoapi.CommonDBClient.RestfulAPIDeleteOne(SmContextDataColl, filter)
				} else {
					_, err = mongoapi.CommonDBClient.RestfulAPIPost(SmContextDataColl, filter, req.bsonDoc)
				}
				if err != nil {
					logger.DataRepoLog.Warnln(err)
				}
				if req.done != nil {
					req.done <- err
				}
			}
		}(q)
	}
}

// enqueueSmContextWrite routes req to the shard queue selected by a stable hash
// of req.ref, so every write and delete for the same ref is processed in the
// order it was enqueued.
func enqueueSmContextWrite(req smContextWriteReq) {
	h := fnv.New32a()
	_, _ = h.Write([]byte(req.ref))
	q := smContextWriteQueues[h.Sum32()%uint32(len(smContextWriteQueues))]
	q <- req
}

// AsyncStoreSmContextInDB serializes the context and enqueues the write to the per-ref shard
// worker, both while holding SMLock (blocks if the shard queue is full, to preserve ordering;
// the HTTP response was already returned in TxnSuccess). RemoveSMContext takes the same lock
// around its release transition and DB deletes, so the SmStateRelease check and the enqueue
// below happen atomically with respect to it: a write can never be enqueued after
// RemoveSMContext's deletes and resurrect the document.
func AsyncStoreSmContextInDB(smContext *SMContext) {
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	if smContext.SMContextState == SmStateRelease {
		return
	}

	bsonDoc := ToBsonM(smContext)
	ref := smContext.Ref
	enqueueSmContextWrite(smContextWriteReq{bsonDoc: bsonDoc, ref: ref})
}

type SeidSmContextRef struct {
	Ref  string `json:"ref" yaml:"ref" bson:"ref"`
	Seid string `json:"seid" yaml:"seid" bson:"seid"`
}

func SeidConv(seid uint64) (seidStr string) {
	seidStr = strconv.FormatUint(seid, 16)
	return seidStr
}

// StoreSeidContextInDB Store Context by SEID In DB
func StoreSeidContextInDB(seidUint uint64, smContext *SMContext) {
	seid := SeidConv(seidUint)
	item := SeidSmContextRef{
		Ref:  smContext.Ref,
		Seid: seid,
	}
	itemBsonA := ToBsonMSeidRef(item)
	filter := bson.M{"seid": seid}
	logger.DataRepoLog.Debugf("StoreSeidContextInDB filter: %+v", filter)

	_, postErr := mongoapi.CommonDBClient.RestfulAPIPost(SeidSmContextCol, filter, itemBsonA)
	if postErr != nil {
		logger.DataRepoLog.Warnln(postErr)
	}
}

// StoreRefToSeidInDB store mapping ref to seid in db
func StoreRefToSeidInDB(seidUint uint64, smContext *SMContext) {
	seid := SeidConv(seidUint)
	item := SeidSmContextRef{
		Ref:  smContext.Ref,
		Seid: seid,
	}
	itemBsonA := ToBsonMSeidRef(item)
	filter := bson.M{refFilterKey: smContext.Ref}
	logger.DataRepoLog.Debugf("StoreRefToSeidInDB filter: %+v", filter)

	_, postErr := mongoapi.CommonDBClient.RestfulAPIPost(RefSeidCol, filter, itemBsonA)
	if postErr != nil {
		logger.DataRepoLog.Warnln(postErr)
	}
}

// GetSMContextByRefInDB GetSMContext By Ref from DB
func GetSMContextByRefInDB(ref string) (smContext *SMContext) {
	logger.DataRepoLog.Debugf("GetSMContextByRefInDB: Ref in DB %v", ref)
	smContext = &SMContext{}
	filter := bson.M{}
	filter[refFilterKey] = ref

	result, getOneErr := mongoapi.CommonDBClient.RestfulAPIGetOne(SmContextDataColl, filter)
	if getOneErr != nil {
		logger.DataRepoLog.Warnln(getOneErr)
	}

	if result != nil {
		err := sonic.Unmarshal(mapToByte(result), smContext)
		if err != nil {
			logger.DataRepoLog.Errorf("smContext unmarshal error: %v", err)
			return nil
		}
		smContext.RebuildCommunicationClient()
		smContext.RebuildSMPolicyClient()
	} else {
		logger.DataRepoLog.Warnf("SmContext doesn't exist with ref: %v", ref)
		return nil
	}

	return smContext
}

// GetSMContextBySEIDInDB GetSMContext By SEID from DB
func GetSMContextBySEIDInDB(seidUint uint64) (smContext *SMContext) {
	seid := SeidConv(seidUint)
	filter := bson.M{}
	filter["seid"] = seid

	result, getOneErr := mongoapi.CommonDBClient.RestfulAPIGetOne(SeidSmContextCol, filter)
	if getOneErr != nil {
		logger.DataRepoLog.Warnln(getOneErr)
	}
	if result != nil {
		ref := result[refFilterKey].(string)
		logger.DataRepoLog.Debugln("StoreSeidContextInDB, result string:", ref)
		return GetSMContext(ref)
	} else {
		logger.DataRepoLog.Warnf("SmContext doesn't exist with seid: %v", seid)
		return nil
	}
}

// DeleteSmContextInDBBySEID Delete SMContext By SEID from DB. Callers (RemoveSMContext) must
// hold the SMContext's SMLock across this call for the same reason as DeleteSmContextInDBByRef,
// which this calls.
func DeleteSmContextInDBBySEID(seidUint uint64) {
	seid := SeidConv(seidUint)
	logger.DataRepoLog.Infoln("db - delete SMContext In DB by seid")
	filter := bson.M{"seid": seid}
	logger.DataRepoLog.Infof("filter: %+v", filter)

	result, getOneErr := mongoapi.CommonDBClient.RestfulAPIGetOne(SeidSmContextCol, filter)
	if getOneErr != nil {
		logger.DataRepoLog.Warnln(getOneErr)
	}
	if result != nil {
		ref := result[refFilterKey].(string)

		delOneErr := mongoapi.CommonDBClient.RestfulAPIDeleteOne(SeidSmContextCol, filter)
		if delOneErr != nil {
			logger.DataRepoLog.Warnln(delOneErr)
		}
		DeleteSmContextInDBByRef(ref)
	} else {
		logger.DataRepoLog.Infof("DB entry doesn't exist with seid: %v", seid)
	}
}

// smContextDeleteFailed marks refs whose by-ref Mongo document survived every
// DeleteSmContextInDBByRef retry. GetSMContext consults this before falling back to Mongo on a
// pool miss, so a ref that RemoveSMContextLocked has already released can never be read back from
// a stale document and resurrected into the pool. There is no unmark path: once a context reaches
// SmStateRelease its by-ref document must never be treated as live again, so leaving the entry
// here permanently is the safe outcome of an unrecovered delete failure, not a leak of live state.
var smContextDeleteFailed sync.Map

// IsSmContextDeleteFailed reports whether ref's by-ref document delete previously exhausted
// DeleteSmContextInDBByRef's retries and was never confirmed removed.
func IsSmContextDeleteFailed(ref string) bool {
	_, failed := smContextDeleteFailed.Load(ref)
	return failed
}

// DeleteSmContextInDBByRef deletes the by-ref SMContext document. Callers (RemoveSMContext) must
// hold the SMContext's SMLock across this call, the same lock AsyncStoreSmContextInDB takes
// before enqueueing a write, so a write for this ref can never be enqueued after this delete and
// resurrect the document.
//
// This still routes through the shard queue, so the delete is ordered after any write already
// queued for ref, but it waits for the worker to actually apply it before returning. It retries a
// bounded number of times on failure rather than treating the request as complete once merely
// applied: RemoveSMContextLocked's pool.Delete (which does not go through this queue) runs right
// after this returns, so if the document were still in Mongo a concurrent GetSMContext for the
// same ref could miss the pool, read it back, and reinsert the context this call is meant to
// remove. If every attempt fails, ref is tombstoned in smContextDeleteFailed so that risk stays
// closed even though the document itself could not be removed.
func DeleteSmContextInDBByRef(ref string) {
	logger.DataRepoLog.Infoln("db - delete SMContext In DB w ref")
	const maxAttempts = 3
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		done := make(chan error, 1)
		enqueueSmContextWrite(smContextWriteReq{ref: ref, delete: true, done: done})
		if err = <-done; err == nil {
			return
		}
		if attempt < maxAttempts {
			time.Sleep(100 * time.Millisecond)
		}
	}
	smContextDeleteFailed.Store(ref, struct{}{})
	logger.DataRepoLog.Errorf("delete SMContext In DB w ref %v failed after %d attempts, giving up: %v", ref, maxAttempts, err)
}

func mapToByte(data map[string]interface{}) (ret []byte) {
	ret, err := sonic.Marshal(data)
	if err != nil {
		logger.DataRepoLog.Errorf("map to byte error: %v", err)
	}
	return
}

func GetSmContextPool() *sync.Map {
	return &smContextPool
}

func StoreSmContextPool(smContext *SMContext) {
	smContextPool.Store(smContext.Ref, smContext)
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}
