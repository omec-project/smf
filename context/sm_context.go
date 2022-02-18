// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/smf/metrics"
	"github.com/free5gc/smf/msgtypes/svcmsgtypes"
	"github.com/free5gc/smf/qos"
	errors "github.com/free5gc/smf/smferrors"
	"github.com/free5gc/smf/transaction"
	"github.com/sirupsen/logrus"

	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/free5gc/nas/nasConvert"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Namf_Communication"
	"github.com/free5gc/openapi/Nnrf_NFDiscovery"
	"github.com/free5gc/openapi/Npcf_SMPolicyControl"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/smf/logger"
)

const (
	PDU_SESS_REL_CMD string = "PDUSessionReleaseCommand"
)

var (
	smContextPool    sync.Map
	canonicalRef     sync.Map
	seidSMContextMap sync.Map
)

var (
	smContextCount  uint64
	smContextActive uint64
)

type SMContextState uint

const (
	SmStateInit SMContextState = iota
	SmStateActivePending
	SmStateActive
	SmStateInActivePending
	SmStateModify
	SmStatePfcpCreatePending
	SmStatePfcpModify
	SmStatePfcpRelease
	SmStateRelease
	SmStateN1N2TransferPending
	SmStateMax
)

func init() {
}

func incSMContextActive() uint64 {
	atomic.AddUint64(&smContextActive, 1)
	return smContextActive
}

func decSMContextActive() uint64 {
	atomic.AddUint64(&smContextActive, ^uint64(0))
	return smContextActive
}

func GetSMContextCount() uint64 {
	atomic.AddUint64(&smContextCount, 1)
	return smContextCount
}

type SMContext struct {
	Ref string

	UnauthenticatedSupi bool
	// SUPI or PEI
	Supi           string
	Pei            string
	Identifier     string
	Gpsi           string
	PDUSessionID   int32
	Dnn            string
	Snssai         *models.Snssai
	HplmnSnssai    *models.Snssai
	ServingNetwork *models.PlmnId
	ServingNfId    string

	UpCnxState models.UpCnxState

	AnType          models.AccessType
	RatType         models.RatType
	PresenceInLadn  models.PresenceState
	UeLocation      *models.UserLocation
	UeTimeZone      string
	AddUeLocation   *models.UserLocation
	OldPduSessionId int32
	HoState         models.HoState

	PDUAddress             net.IP
	SelectedPDUSessionType uint8

	DnnConfiguration models.DnnConfiguration

	// Client
	SMPolicyClient      *Npcf_SMPolicyControl.APIClient
	CommunicationClient *Namf_Communication.APIClient

	AMFProfile         models.NfProfile
	SelectedPCFProfile models.NfProfile
	SmStatusNotifyUri  string

	SMContextState SMContextState

	Tunnel    *UPTunnel
	BPManager *BPManager
	// NodeID(string form) to PFCP Session Context
	PFCPContext                         map[string]*PFCPSessionContext
	SBIPFCPCommunicationChan            chan PFCPSessionResponseStatus
	PendingUPF                          PendingUPF
	PDUSessionRelease_DUE_TO_DUP_PDU_ID bool
	LocalPurged                         bool

	DNNInfo *SnssaiSmfDnnInfo

	// SM Policy related
	// Updates in policy from PCF
	SmPolicyUpdates []*qos.PolicyUpdate
	//Holds Session/PCC Rules and Qos/Cond/Charging Data
	SmPolicyData qos.SmCtxtPolicyData

	// NAS
	Pti                     uint8
	EstAcceptCause5gSMValue uint8

	// PCO Related
	ProtocolConfigurationOptions *ProtocolConfigurationOptions

	// lock
	SMLock sync.Mutex

	SubGsmLog      *logrus.Entry
	SubPfcpLog     *logrus.Entry
	SubPduSessLog  *logrus.Entry
	SubCtxLog      *logrus.Entry
	SubConsumerLog *logrus.Entry
	SubFsmLog      *logrus.Entry
	SubQosLog      *logrus.Entry

	//TxnBus per subscriber
	TxnBus       transaction.TxnBus
	SMTxnBusLock sync.Mutex
	ActiveTxn    *transaction.Transaction
}

func canonicalName(identifier string, pduSessID int32) (canonical string) {
	return fmt.Sprintf("%s-%d", identifier, pduSessID)
}

func ResolveRef(identifier string, pduSessID int32) (ref string, err error) {
	if value, ok := canonicalRef.Load(canonicalName(identifier, pduSessID)); ok {
		ref = value.(string)
		err = nil
	} else {
		ref = ""
		err = fmt.Errorf(
			"UE '%s' - PDUSessionID '%d' not found in SMContext", identifier, pduSessID)
	}
	return
}

func NewSMContext(identifier string, pduSessID int32) (smContext *SMContext) {
	smContext = new(SMContext)
	// Create Ref and identifier
	smContext.Ref = uuid.New().URN()
	smContextPool.Store(smContext.Ref, smContext)
	canonicalRef.Store(canonicalName(identifier, pduSessID), smContext.Ref)

	smContext.SMContextState = SmStateInit
	smContext.Identifier = identifier
	smContext.PDUSessionID = pduSessID
	smContext.PFCPContext = make(map[string]*PFCPSessionContext)

	// initialize SM Policy Data
	smContext.SBIPFCPCommunicationChan = make(chan PFCPSessionResponseStatus, 1)
	smContext.SmPolicyUpdates = make([]*qos.PolicyUpdate, 0)
	smContext.SmPolicyData.Initialize()

	smContext.ProtocolConfigurationOptions = &ProtocolConfigurationOptions{
		DNSIPv4Request: false,
		DNSIPv6Request: false,
	}

	//Sess Stats
	smContextActive := incSMContextActive()
	metrics.SetSessStats(SMF_Self().NfInstanceID, smContextActive)

	//initialise log tags
	smContext.initLogTags()

	return smContext
}

func (smContext *SMContext) initLogTags() {
	subField := logrus.Fields{"uuid": smContext.Ref,
		"id": smContext.Identifier, "pduid": smContext.PDUSessionID}

	smContext.SubPfcpLog = logger.PfcpLog.WithFields(subField)
	smContext.SubCtxLog = logger.CtxLog.WithFields(subField)
	smContext.SubPduSessLog = logger.PduSessLog.WithFields(subField)
	smContext.SubGsmLog = logger.GsmLog.WithFields(subField)
	smContext.SubConsumerLog = logger.ConsumerLog.WithFields(subField)
	smContext.SubFsmLog = logger.FsmLog.WithFields(subField)
	smContext.SubQosLog = logger.QosLog.WithFields(subField)
}

func (smContext *SMContext) ChangeState(nextState SMContextState) {

	//Update Subscriber profile Metrics
	if nextState == SmStateActive || smContext.SMContextState == SmStateActive {
		var upf string
		if smContext.Tunnel != nil {
			//Set UPF FQDN name if provided else IP-address
			if smContext.Tunnel.DataPathPool[1].FirstDPNode.UPF.NodeID.NodeIdType == pfcpType.NodeIdTypeFqdn {
				upf = string(smContext.Tunnel.DataPathPool[1].FirstDPNode.UPF.NodeID.NodeIdValue)
				upf = strings.Split(upf, ".")[0]
			} else {
				upf = smContext.Tunnel.DataPathPool[1].FirstDPNode.UPF.GetUPFIP()
			}
		}

		//enterprise name
		ent := "na"
		if smfContext.EnterpriseList != nil {

			entMap := *smfContext.EnterpriseList
			smContext.SubCtxLog.Infof("context state change, Enterprises configured = [%v], subscriber slice sst [%v], sd [%v]",
				entMap, smContext.Snssai.Sst, smContext.Snssai.Sd)
			ent = entMap[strconv.Itoa(int(smContext.Snssai.Sst))+smContext.Snssai.Sd]
		} else {
			smContext.SubCtxLog.Warn("context state change, enterprise info not available")
		}

		if nextState == SmStateActive {
			metrics.SetSessProfileStats(smContext.Identifier, smContext.PDUAddress.String(), nextState.String(),
				upf, ent, 1)
		} else {
			metrics.SetSessProfileStats(smContext.Identifier, smContext.PDUAddress.String(), smContext.SMContextState.String(),
				upf, ent, 0)
		}
	}

	smContext.SubCtxLog.Infof("context state change, current state[%v] next state[%v]",
		smContext.SMContextState.String(), nextState.String())
	smContext.SMContextState = nextState
}

//*** add unit test ***//
func GetSMContext(ref string) (smContext *SMContext) {
	if value, ok := smContextPool.Load(ref); ok {
		smContext = value.(*SMContext)
	}

	return
}

//*** add unit test ***//
func RemoveSMContext(ref string) {

	var smContext *SMContext
	if value, ok := smContextPool.Load(ref); ok {
		smContext = value.(*SMContext)
	}

	smContext.SubCtxLog.Infof("RemoveSMContext, SM context released ")
	smContext.ChangeState(SmStateInit)

	for _, pfcpSessionContext := range smContext.PFCPContext {
		seidSMContextMap.Delete(pfcpSessionContext.LocalSEID)
	}

	//Release UE IP-Address
	if ip := smContext.PDUAddress; ip != nil {
		smContext.SubPduSessLog.Infof("Release IP[%s]", smContext.PDUAddress.String())
		smContext.DNNInfo.UeIPAllocator.Release(ip)
	}
	smContextPool.Delete(ref)
	//Sess Stats
	smContextActive := decSMContextActive()
	metrics.SetSessStats(SMF_Self().NfInstanceID, smContextActive)
}

//*** add unit test ***//
func GetSMContextBySEID(SEID uint64) (smContext *SMContext) {
	if value, ok := seidSMContextMap.Load(SEID); ok {
		smContext = value.(*SMContext)
	}
	return
}

//*** add unit test ***//
func (smContext *SMContext) SetCreateData(createData *models.SmContextCreateData) {
	smContext.Gpsi = createData.Gpsi
	smContext.Supi = createData.Supi
	smContext.Dnn = createData.Dnn
	smContext.Snssai = createData.SNssai
	smContext.HplmnSnssai = createData.HplmnSnssai
	smContext.ServingNetwork = createData.ServingNetwork
	smContext.AnType = createData.AnType
	smContext.RatType = createData.RatType
	smContext.PresenceInLadn = createData.PresenceInLadn
	smContext.UeLocation = createData.UeLocation
	smContext.UeTimeZone = createData.UeTimeZone
	smContext.AddUeLocation = createData.AddUeLocation
	smContext.OldPduSessionId = createData.OldPduSessionId
	smContext.ServingNfId = createData.ServingNfId
}

func (smContext *SMContext) BuildCreatedData() (createdData *models.SmContextCreatedData) {
	createdData = new(models.SmContextCreatedData)
	createdData.SNssai = smContext.Snssai
	return
}

func (smContext *SMContext) PDUAddressToNAS() (addr [12]byte, addrLen uint8) {
	copy(addr[:], smContext.PDUAddress)
	switch smContext.SelectedPDUSessionType {
	case nasMessage.PDUSessionTypeIPv4:
		addrLen = 4 + 1
	case nasMessage.PDUSessionTypeIPv6:
	case nasMessage.PDUSessionTypeIPv4IPv6:
		addrLen = 12 + 1
	}
	return
}

// PCFSelection will select PCF for this SM Context
func (smContext *SMContext) PCFSelection() error {
	// Send NFDiscovery for find PCF
	localVarOptionals := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{}
	metrics.IncrementSvcNrfMsgStats(SMF_Self().NfInstanceID, string(svcmsgtypes.NnrfNFDiscoveryPcf), "Out", "", "")

	rep, res, err := SMF_Self().
		NFDiscoveryClient.
		NFInstancesStoreApi.
		SearchNFInstances(context.TODO(), models.NfType_PCF, models.NfType_SMF, &localVarOptionals)
	if err != nil {
		metrics.IncrementSvcNrfMsgStats(SMF_Self().NfInstanceID, string(svcmsgtypes.NnrfNFDiscoveryPcf), "In", "Failure", err.Error())
		return err
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.PduSessLog.Errorf("SmfEventExposureNotification response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res != nil {
		if status := res.StatusCode; status != http.StatusOK {
			metrics.IncrementSvcNrfMsgStats(SMF_Self().NfInstanceID, string(svcmsgtypes.NnrfNFDiscoveryPcf), "In", "Failure", err.Error())
			apiError := err.(openapi.GenericOpenAPIError)
			problemDetails := apiError.Model().(models.ProblemDetails)

			logger.CtxLog.Warningf("NFDiscovery PCF return status: %d\n", status)
			logger.CtxLog.Warningf("Detail: %v\n", problemDetails.Title)
		}
	}

	// Select PCF from available PCF
	metrics.IncrementSvcNrfMsgStats(SMF_Self().NfInstanceID, string(svcmsgtypes.NnrfNFDiscoveryPcf), "In", http.StatusText(res.StatusCode), "")

	smContext.SelectedPCFProfile = rep.NfInstances[0]

	// Create SMPolicyControl Client for this SM Context
	for _, service := range *smContext.SelectedPCFProfile.NfServices {
		if service.ServiceName == models.ServiceName_NPCF_SMPOLICYCONTROL {
			SmPolicyControlConf := Npcf_SMPolicyControl.NewConfiguration()
			SmPolicyControlConf.SetBasePath(service.ApiPrefix)
			smContext.SMPolicyClient = Npcf_SMPolicyControl.NewAPIClient(SmPolicyControlConf)
		}
	}

	return nil
}

func (smContext *SMContext) GetNodeIDByLocalSEID(seid uint64) (nodeID pfcpType.NodeID) {
	for _, pfcpCtx := range smContext.PFCPContext {
		if pfcpCtx.LocalSEID == seid {
			nodeID = pfcpCtx.NodeID
		}
	}

	return
}

func (smContext *SMContext) AllocateLocalSEIDForUPPath(path UPPath) {
	for _, upNode := range path {
		NodeIDtoIP := upNode.NodeID.ResolveNodeIdToIp().String()
		if _, exist := smContext.PFCPContext[NodeIDtoIP]; !exist {
			allocatedSEID := AllocateLocalSEID()

			smContext.PFCPContext[NodeIDtoIP] = &PFCPSessionContext{
				PDRs:      make(map[uint16]*PDR),
				NodeID:    upNode.NodeID,
				LocalSEID: allocatedSEID,
			}

			seidSMContextMap.Store(allocatedSEID, smContext)
		}
	}
}

func (smContext *SMContext) AllocateLocalSEIDForDataPath(dataPath *DataPath) {
	logger.PduSessLog.Traceln("In AllocateLocalSEIDForDataPath")
	for curDataPathNode := dataPath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
		NodeIDtoIP := curDataPathNode.UPF.NodeID.ResolveNodeIdToIp().String()
		logger.PduSessLog.Traceln("NodeIDtoIP: ", NodeIDtoIP)
		if _, exist := smContext.PFCPContext[NodeIDtoIP]; !exist {
			allocatedSEID := AllocateLocalSEID()
			smContext.PFCPContext[NodeIDtoIP] = &PFCPSessionContext{
				PDRs:      make(map[uint16]*PDR),
				NodeID:    curDataPathNode.UPF.NodeID,
				LocalSEID: allocatedSEID,
			}

			seidSMContextMap.Store(allocatedSEID, smContext)
		}
	}
}

func (smContext *SMContext) PutPDRtoPFCPSession(nodeID pfcpType.NodeID, pdrList map[string]*PDR) error {
	//TODO: Iterate over PDRS
	NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
	if pfcpSessCtx, exist := smContext.PFCPContext[NodeIDtoIP]; exist {
		for name, pdr := range pdrList {
			pfcpSessCtx.PDRs[pdrList[name].PDRID] = pdr
		}
	} else {
		return fmt.Errorf("error, can't find PFCPContext[%s] to put PDR(%v)", NodeIDtoIP, pdrList)
	}
	return nil
}

func (smContext *SMContext) RemovePDRfromPFCPSession(nodeID pfcpType.NodeID, pdr *PDR) {
	NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
	pfcpSessCtx := smContext.PFCPContext[NodeIDtoIP]
	delete(pfcpSessCtx.PDRs, pdr.PDRID)
}

func (smContext *SMContext) isAllowedPDUSessionType(requestedPDUSessionType uint8) error {
	dnnPDUSessionType := smContext.DnnConfiguration.PduSessionTypes
	if dnnPDUSessionType == nil {
		return fmt.Errorf("this SMContext[%s] has no subscription pdu session type info", smContext.Ref)
	}

	allowIPv4 := false
	allowIPv6 := false
	allowEthernet := false

	for _, allowedPDUSessionType := range smContext.DnnConfiguration.PduSessionTypes.AllowedSessionTypes {
		switch allowedPDUSessionType {
		case models.PduSessionType_IPV4:
			allowIPv4 = true
		case models.PduSessionType_IPV6:
			allowIPv6 = true
		case models.PduSessionType_IPV4_V6:
			allowIPv4 = true
			allowIPv6 = true
		case models.PduSessionType_ETHERNET:
			allowEthernet = true
		}
	}

	supportedPDUSessionType := SMF_Self().SupportedPDUSessionType
	switch supportedPDUSessionType {
	case "IPv4":
		if !allowIPv4 {
			return fmt.Errorf("No SupportedPDUSessionType[%q] in DNN[%s] configuration", supportedPDUSessionType, smContext.Dnn)
		}
	case "IPv6":
		if !allowIPv6 {
			return fmt.Errorf("No SupportedPDUSessionType[%q] in DNN[%s] configuration", supportedPDUSessionType, smContext.Dnn)
		}
	case "IPv4v6":
		if !allowIPv4 && !allowIPv6 {
			return fmt.Errorf("No SupportedPDUSessionType[%q] in DNN[%s] configuration", supportedPDUSessionType, smContext.Dnn)
		}
	case "Ethernet":
		if !allowEthernet {
			return fmt.Errorf("No SupportedPDUSessionType[%q] in DNN[%s] configuration", supportedPDUSessionType, smContext.Dnn)
		}
	}

	smContext.EstAcceptCause5gSMValue = 0
	switch nasConvert.PDUSessionTypeToModels(requestedPDUSessionType) {
	case models.PduSessionType_IPV4:
		if allowIPv4 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_IPV4)
		} else {
			return fmt.Errorf("PduSessionType_IPV4 is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	case models.PduSessionType_IPV6:
		if allowIPv6 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_IPV6)
		} else {
			return fmt.Errorf("PduSessionType_IPV6 is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	case models.PduSessionType_IPV4_V6:
		if allowIPv4 && allowIPv6 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_IPV4_V6)
		} else if allowIPv4 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_IPV4)
			smContext.EstAcceptCause5gSMValue = nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed
		} else if allowIPv6 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_IPV6)
			smContext.EstAcceptCause5gSMValue = nasMessage.Cause5GSMPDUSessionTypeIPv6OnlyAllowed
		} else {
			return fmt.Errorf("PduSessionType_IPV4_V6 is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	case models.PduSessionType_ETHERNET:
		if allowEthernet {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PduSessionType_ETHERNET)
		} else {
			return fmt.Errorf("PduSessionType_ETHERNET is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	default:
		return fmt.Errorf("Requested PDU Sesstion type[%d] is not supported", requestedPDUSessionType)
	}
	return nil
}

// SM Policy related operation

// SelectedSessionRule - return the SMF selected session rule for this SM Context
func (smContext *SMContext) SelectedSessionRule() *models.SessionRule {
	//Policy update in progress
	if len(smContext.SmPolicyUpdates) > 0 {
		return smContext.SmPolicyUpdates[0].SessRuleUpdate.ActiveSessRule
	} else {
		return smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule
	}
}

func (smContextState SMContextState) String() string {
	switch smContextState {
	case SmStateInit:
		return "SmStateInit"
	case SmStateActivePending:
		return "SmStateActivePending"
	case SmStateActive:
		return "SmStateActive"
	case SmStateInActivePending:
		return "SmStateInActivePending"
	case SmStateModify:
		return "SmStateModify"
	case SmStatePfcpCreatePending:
		return "SmStatePfcpCreatePending"
	case SmStatePfcpModify:
		return "SmStatePfcpModify"
	case SmStatePfcpRelease:
		return "SmStatePfcpRelease"
	case SmStateN1N2TransferPending:
		return "SmStateN1N2TransferPending"

	default:
		return "Unknown State"
	}
}

func (smContext *SMContext) GeneratePDUSessionEstablishmentReject(cause string) *http_wrapper.Response {
	var httpResponse *http_wrapper.Response

	if buf, err := BuildGSMPDUSessionEstablishmentReject(
		smContext,
		errors.ErrorCause[cause]); err != nil {
		httpResponse = &http_wrapper.Response{
			Header: nil,
			Status: int(errors.ErrorType[cause].Status),
			Body: models.PostSmContextsErrorResponse{
				JsonData: &models.SmContextCreateError{
					Error:   errors.ErrorType[cause],
					N1SmMsg: &models.RefToBinaryData{ContentId: "n1SmMsg"},
				},
			},
		}
	} else {
		httpResponse = &http_wrapper.Response{
			Header: nil,
			Status: int(errors.ErrorType[cause].Status),
			Body: models.PostSmContextsErrorResponse{
				JsonData: &models.SmContextCreateError{
					Error:   errors.ErrorType[cause],
					N1SmMsg: &models.RefToBinaryData{ContentId: "n1SmMsg"},
				},
				BinaryDataN1SmMessage: buf,
			},
		}
	}

	return httpResponse
}

func (smContext *SMContext) CommitSmPolicyDecision(status bool) error {

	//Lock SM context
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	if status {
		qos.CommitSmPolicyDecision(&smContext.SmPolicyData, smContext.SmPolicyUpdates[0])
	}

	//Release 0th index update
	if len(smContext.SmPolicyUpdates) >= 1 {
		smContext.SmPolicyUpdates = smContext.SmPolicyUpdates[1:]
	}

	//Notify PCF of failure ?
	//TODO
	return nil
}
