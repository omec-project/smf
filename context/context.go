// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/omec-project/openapi/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/Nnrf_NFManagement"
	"github.com/omec-project/openapi/Nudm_SubscriberDataManagement"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/util/drsm"
)

func init() {
	smfContext.NfInstanceID = uuid.New().String()
	metrics.SetNfInstanceId(smfContext.NfInstanceID)
}

const (
	IPV4 = "IPv4"
)

var DefaultPfcpPort uint16 = factory.DEFAULT_PFCP_PORT

var smfContext SMFContext

type DrsmCtxts struct {
	SeidPool drsm.DrsmInterface
	UeIpPool drsm.DrsmInterface
}

type SMFContext struct {
	Name         string
	NfInstanceID string

	URIScheme    models.UriScheme
	BindingIPv4  string
	RegisterIPv4 string

	UPNodeIDs []NodeID
	Key       string
	PEM       string
	KeyLog    string

	SnssaiInfos []SnssaiSmfInfo

	NrfUri                         string
	NFManagementClient             *Nnrf_NFManagement.APIClient
	NFDiscoveryClient              *Nnrf_NFDiscovery.APIClient
	SubscriberDataManagementClient *Nudm_SubscriberDataManagement.APIClient

	UserPlaneInformation *UserPlaneInformation

	// Now only "IPv4" supported
	// TODO: support "IPv6", "IPv4v6", "Ethernet"
	SupportedPDUSessionType string
	UeRoutingManager        *UERoutingManager
	DrsmCtxts               DrsmCtxts
	EnterpriseList          *map[string]string // map to contain slice-name:enterprise-name

	NfStatusSubscriptions sync.Map // map[NfInstanceID]models.NrfSubscriptionData.SubscriptionId
	PodIp                 string

	StaticIpInfo             []factory.StaticIpInfo
	CPNodeID                 NodeID
	PFCPPort                 int
	UDMProfile               models.NfProfile
	NrfCacheEvictionInterval time.Duration
	SBIPort                  int
	LocalSEIDCount           uint64
	EnableNrfCaching         bool

	// For ULCL
	ULCLSupport bool
}

// RetrieveDnnInformation gets the corresponding dnn info from S-NSSAI and DNN
func RetrieveDnnInformation(Snssai models.Snssai, dnn string) *SnssaiSmfDnnInfo {
	for _, snssaiInfo := range SMF_Self().SnssaiInfos {
		if snssaiInfo.Snssai.Sst == Snssai.Sst && snssaiInfo.Snssai.Sd == Snssai.Sd {
			return snssaiInfo.DnnInfos[dnn]
		}
	}
	return nil
}

func AllocateLocalSEID() (uint64, error) {
	if factory.SmfConfig.Configuration.EnableDbStore {
		if smfContext.DrsmCtxts.SeidPool == nil {
			return 0, fmt.Errorf("SEID pool is not initialized")
		}
		seid32, err := smfContext.DrsmCtxts.SeidPool.AllocateInt32ID()
		if err != nil {
			logger.CtxLog.Errorf("allocate SEID error: %+v", err)
			return 0, err
		}

		return uint64(seid32), nil
	} else {
		atomic.AddUint64(&smfContext.LocalSEIDCount, 1)
		return smfContext.LocalSEIDCount, nil
	}
}

func InitSmfContext(config *factory.Config) *SMFContext {
	if config == nil {
		logger.CtxLog.Error("Config is nil")
		return nil
	}

	// Acquire master SMF config lock, no one should update it in parallel
	// until SMF is done updating SMF context
	factory.SmfConfigSyncLock.Lock()
	defer factory.SmfConfigSyncLock.Unlock()

	logger.CtxLog.Infof("smfconfig Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)
	configuration := config.Configuration
	if configuration.SmfName != "" {
		smfContext.Name = configuration.SmfName
	}

	if env := os.Getenv("PFCP_PORT_UPF"); env != "" {
		if v, err := strconv.Atoi(env); err == nil && v >= 0 && v <= 65535 {
			DefaultPfcpPort = uint16(v)
			logger.CtxLog.Infof("using PFCP_PORT_UPF from environment variables: %d", DefaultPfcpPort)
		} else {
			logger.CtxLog.Warnf("invalid PFCP_PORT_UPF value %q: %v. Using default value: %d", env, err, DefaultPfcpPort)
		}
	}

	smfContext.StaticIpInfo = configuration.StaticIpInfo

	sbi := configuration.Sbi
	localIp := GetLocalIP()
	logger.CtxLog.Infof("sbi lb - localIp %v", localIp)
	if sbi == nil {
		logger.CtxLog.Errorln("Configuration needs \"sbi\" value")
		return nil
	} else {
		smfContext.URIScheme = models.UriScheme(sbi.Scheme)
		smfContext.RegisterIPv4 = factory.SMF_DEFAULT_IPV4 // default localhost
		smfContext.SBIPort = factory.SMF_DEFAULT_PORT_INT  // default port

		if sbi.RegisterIPv4 != "" {
			// smfContext.RegisterIPv4 = sbi.RegisterIPv4
			sbi.RegisterIPv4 = localIp
			smfContext.RegisterIPv4 = localIp
			logger.CtxLog.Info("sbi lb - changing smf sbi.RegisterIPv4 ", sbi.RegisterIPv4)
			logger.CtxLog.Info("sbi lb - smf smfContext.RegisterIPv4 ", smfContext.RegisterIPv4)
		}
		if sbi.Port != 0 {
			smfContext.SBIPort = sbi.Port
		}

		if tls := sbi.TLS; tls != nil {
			if tls.Key != "" {
				smfContext.Key = tls.Key
			}
			if tls.PEM != "" {
				smfContext.PEM = tls.PEM
			}
		}

		smfContext.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
		if smfContext.BindingIPv4 != "" {
			logger.CtxLog.Info("Parsing ServerIPv4 address from ENV Variable.")
		} else {
			smfContext.BindingIPv4 = sbi.BindingIPv4
			if smfContext.BindingIPv4 == "" {
				logger.CtxLog.Warn("Error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default.")
				smfContext.BindingIPv4 = "0.0.0.0"
			}
		}
	}

	if configuration.NrfUri != "" {
		smfContext.NrfUri = configuration.NrfUri
	} else {
		logger.CtxLog.Warn("NRF Uri is empty! Using localhost as NRF IPv4 address.")
		smfContext.NrfUri = fmt.Sprintf("%s://%s:%d", smfContext.URIScheme, "127.0.0.1", 29510)
	}

	if pfcp := configuration.PFCP; pfcp != nil {
		if pfcp.Port == 0 {
			pfcp.Port = factory.DEFAULT_PFCP_PORT
		}
		pfcpAddrEnv := os.Getenv(pfcp.Addr)
		if pfcpAddrEnv != "" {
			logger.CtxLog.Info("Parsing PFCP IPv4 address from ENV variable found.")
			pfcp.Addr = pfcpAddrEnv
		}
		if pfcp.Addr == "" {
			logger.CtxLog.Warn("Error parsing PFCP IPv4 address as string. Using the 0.0.0.0 address as default.")
			pfcp.Addr = "0.0.0.0"
		}
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", pfcp.Addr, pfcp.Port))
		if err != nil {
			logger.CtxLog.Errorf("PFCP Parse Addr Fail: %v", err)
			return nil
		}

		smfContext.PFCPPort = int(pfcp.Port)

		smfContext.CPNodeID.NodeIdType = 0
		smfContext.CPNodeID.NodeIdValue = addr.IP.To4()
	}

	// Set client and set url
	ManagementConfig := Nnrf_NFManagement.NewConfiguration()
	ManagementConfig.SetBasePath(SMF_Self().NrfUri)
	smfContext.NFManagementClient = Nnrf_NFManagement.NewAPIClient(ManagementConfig)

	NFDiscovryConfig := Nnrf_NFDiscovery.NewConfiguration()
	NFDiscovryConfig.SetBasePath(SMF_Self().NrfUri)
	smfContext.NFDiscoveryClient = Nnrf_NFDiscovery.NewAPIClient(NFDiscovryConfig)

	smfContext.ULCLSupport = configuration.ULCL

	smfContext.SupportedPDUSessionType = IPV4

	smfContext.EnableNrfCaching = configuration.EnableNrfCaching

	if configuration.EnableNrfCaching {
		if configuration.NrfCacheEvictionInterval == 0 {
			smfContext.NrfCacheEvictionInterval = time.Duration(900) // 15 mins
		} else {
			smfContext.NrfCacheEvictionInterval = time.Duration(configuration.NrfCacheEvictionInterval)
		}
	}

	smfContext.PodIp = os.Getenv("POD_IP")

	return &smfContext
}

func InitSMFUERouting(routingConfig *factory.RoutingConfig) {
	if !smfContext.ULCLSupport {
		logger.CtxLog.Warnln("ULCL is not enabled, skip initializing UERoutingManager")
		return
	}

	if routingConfig == nil {
		logger.CtxLog.Errorln("configuration needs the routing config")
		return
	}

	logger.CtxLog.Infof("ue routing config Info: Version[%s] Description[%s]",
		routingConfig.Info.Version, routingConfig.Info.Description)

	routingManager := NewUERoutingManager()

	for _, routingInfo := range routingConfig.UERoutingInfo {
		supi := routingInfo.SUPI
		uePreConfigPaths, err := NewUEPreConfigPaths(supi, routingInfo.PathList)
		if err != nil {
			logger.CtxLog.Warnf("failed to initialize pre-config paths for SUPI %s: %v", supi, err)
			continue
		}
		routingManager.AddPath(supi, uePreConfigPaths)
	}

	smfContext.UeRoutingManager = routingManager
}

func SMF_Self() *SMFContext {
	return &smfContext
}

func GetUserPlaneInformation() *UserPlaneInformation {
	return smfContext.UserPlaneInformation
}

func (smfCtxt *SMFContext) Clear() {
	smfCtxt.SnssaiInfos = nil
	if smfCtxt.UserPlaneInformation == nil {
		smfCtxt.UserPlaneInformation = &UserPlaneInformation{}
	}
	smfCtxt.UserPlaneInformation.Reset()
}

func (smfCtxt *SMFContext) ExtractExistingUPFs() map[string]*UPNode {
	existing := make(map[string]*UPNode)
	if smfCtxt.UserPlaneInformation == nil {
		return existing
	}
	for name, node := range smfCtxt.UserPlaneInformation.UPNodes {
		if node.Type == UPNODE_UPF {
			existing[name] = node
		}
	}
	return existing
}

func buildSnssaiSmfInfo(sm *nfConfigApi.SessionManagement, staticIpInfo []factory.StaticIpInfo) SnssaiSmfInfo {
	apiPlmnId := sm.GetPlmnId()
	apiSnssai := sm.GetSnssai()
	info := SnssaiSmfInfo{
		PlmnId:   models.PlmnId{Mcc: apiPlmnId.GetMcc(), Mnc: apiPlmnId.GetMnc()},
		Snssai:   SNssai{Sst: apiSnssai.GetSst(), Sd: *apiSnssai.Sd},
		DnnInfos: map[string]*SnssaiSmfDnnInfo{},
	}

	for _, ipdomain := range sm.GetIpDomain() {
		dnn := ipdomain.DnnName
		if _, exists := info.DnnInfos[dnn]; exists {
			logger.CtxLog.Warnf("duplicate DNN %s in IP domain config; overriding", dnn)
		}
		dnnInfo := &SnssaiSmfDnnInfo{MTU: uint16(ipdomain.GetMtu())}
		if ip := net.ParseIP(ipdomain.GetDnsIpv4()); ip != nil {
			dnnInfo.DNS.IPv4Addr = ip
		}
		if subnet := ipdomain.GetUeSubnet(); subnet != "" {
			allocator, err := NewIPAllocator(subnet)
			if err != nil {
				logger.CtxLog.Warnf("Invalid subnet %s for DNN %s: %v", subnet, dnn, err)
			} else {
				dnnInfo.UeIPAllocator = allocator
				reserveStaticIpsIfNeeded(allocator, staticIpInfo, dnn)
			}
		}
		info.DnnInfos[dnn] = dnnInfo
	}

	return info
}

func reserveStaticIpsIfNeeded(allocator *IPAllocator, static []factory.StaticIpInfo, dnn string) {
	if static == nil {
		return
	}
	for _, s := range static {
		if s.Dnn == dnn {
			allocator.ReserveStaticIps(&s.ImsiIpInfo)
		}
	}
}

func UpdateSmfContext(smContext *SMFContext, newConfig []nfConfigApi.SessionManagement) error {
	logger.CtxLog.Infoln("processing config update from polling service")
	if len(newConfig) == 0 {
		logger.CtxLog.Warnln("received empty session management config, skipping update")
		smContext.Clear()
		return nil
	}
	smContext.UserPlaneInformation = BuildUserPlaneInformationFromSessionManagement(smContext.UserPlaneInformation, newConfig)

	var snssaiInfos []SnssaiSmfInfo
	for _, sm := range newConfig {
		snssaiInfos = append(snssaiInfos, buildSnssaiSmfInfo(&sm, smContext.StaticIpInfo))
	}

	smContext.SnssaiInfos = snssaiInfos
	logger.CtxLog.Debugf("SMF context updated from dynamic session management config successfully")
	return nil
}

func (smfCtxt *SMFContext) InitDrsm() error {
	podname := os.Getenv("HOSTNAME")
	podip := os.Getenv("POD_IP")
	podId := drsm.PodId{PodName: podname, PodInstance: smfCtxt.NfInstanceID, PodIp: podip}
	dbName := "sdcore_smf"
	dbUrl := "mongodb://mongodb-arbiter-headless"

	if factory.SmfConfig.Configuration.Mongodb.Url != "" {
		dbUrl = factory.SmfConfig.Configuration.Mongodb.Url
	}

	if factory.SmfConfig.Configuration.SmfDbName != "" {
		dbName = factory.SmfConfig.Configuration.SmfDbName
	}

	logger.CfgLog.Infof("initialising drsm name [%v]", dbName)

	opt := &drsm.Options{ResIdSize: 24, Mode: drsm.ResourceClient}
	db := drsm.DbInfo{Url: dbUrl, Name: dbName}

	// for local FSEID
	if drsmCtxt, err := drsm.InitDRSM("fseid", podId, db, opt); err == nil {
		smfCtxt.DrsmCtxts.SeidPool = drsmCtxt
	} else {
		return err
	}

	// for IP-Addr
	// TODO, use UPF based allocation for now

	return nil
}
