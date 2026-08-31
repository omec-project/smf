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

type smContextWriteReq struct {
	bsonDoc bson.M
	ref     string
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
				if _, err := mongoapi.CommonDBClient.RestfulAPIPost(SmContextDataColl, filter, req.bsonDoc); err != nil {
					logger.DataRepoLog.Warnln(err)
				}
			}
		}(q)
	}
}

// AsyncStoreSmContextInDB serializes the context while locked, then enqueues
// the write to the per-ref shard worker. Blocks if the shard queue is full to
// preserve ordering; the HTTP response was already returned in TxnSuccess.
func AsyncStoreSmContextInDB(smContext *SMContext) {
	smContext.SMLock.Lock()
	bsonDoc := ToBsonM(smContext)
	ref := smContext.Ref
	smContext.SMLock.Unlock()

	h := fnv.New32a()
	_, _ = h.Write([]byte(ref))
	q := smContextWriteQueues[h.Sum32()%uint32(len(smContextWriteQueues))]
	q <- smContextWriteReq{bsonDoc: bsonDoc, ref: ref}
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

// DeleteSmContextInDBBySEID Delete SMContext By SEID from DB
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

// DeleteSmContextInDBByRef Delete SMContext By ref from DB
func DeleteSmContextInDBByRef(ref string) {
	logger.DataRepoLog.Infoln("db - delete SMContext In DB w ref")
	filter := bson.M{refFilterKey: ref}
	logger.DataRepoLog.Infof("filter: %+v", filter)

	delOneErr := mongoapi.CommonDBClient.RestfulAPIDeleteOne(SmContextDataColl, filter)
	if delOneErr != nil {
		logger.DataRepoLog.Warnln(delOneErr)
	}
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
