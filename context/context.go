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

	UEPreConfigPathPool map[string]*UEPreConfigPaths
	DrsmCtxts           DrsmCtxts
	EnterpriseList      *map[string]string // map to contain slice-name:enterprise-name

	NfStatusSubscriptions sync.Map // map[NfInstanceID]models.NrfSubscriptionData.SubscriptionId
	PodIp                 string

	StaticIpInfo             *[]factory.StaticIpInfo
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

	// Acquire master SMF config lock, no one should update it in parallel,
	// until SMF is done updating SMF context
	factory.SmfConfigSyncLock.Lock()
	defer factory.SmfConfigSyncLock.Unlock()

	logger.CtxLog.Infof("smfconfig Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)
	configuration := config.Configuration
	if configuration.SmfName != "" {
		smfContext.Name = configuration.SmfName
	}

	// copy static UE IP Addr config
	smfContext.StaticIpInfo = &configuration.StaticIpInfo

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

	// Static config
	for _, snssaiInfoConfig := range configuration.SNssaiInfo {
		err := smfContext.insertSmfNssaiInfo(&snssaiInfoConfig)
		if err != nil {
			logger.CtxLog.Warnln(err)
		}
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

	smfContext.UserPlaneInformation = NewUserPlaneInformation(&configuration.UserPlaneInformation)

	smfContext.EnableNrfCaching = configuration.EnableNrfCaching

	if configuration.EnableNrfCaching {
		if configuration.NrfCacheEvictionInterval == 0 {
			smfContext.NrfCacheEvictionInterval = time.Duration(900) // 15 mins
		} else {
			smfContext.NrfCacheEvictionInterval = time.Duration(configuration.NrfCacheEvictionInterval)
		}
	}

	smfContext.PodIp = os.Getenv("POD_IP")
	SetupNFProfile(config)

	return &smfContext
}

func InitSMFUERouting(routingConfig *factory.RoutingConfig) {
	if !smfContext.ULCLSupport {
		return
	}

	if routingConfig == nil {
		logger.CtxLog.Error("configuration needs the routing config")
		return
	}

	logger.CtxLog.Infof("ue routing config Info: Version[%s] Description[%s]",
		routingConfig.Info.Version, routingConfig.Info.Description)

	UERoutingInfo := routingConfig.UERoutingInfo
	smfContext.UEPreConfigPathPool = make(map[string]*UEPreConfigPaths)

	for _, routingInfo := range UERoutingInfo {
		supi := routingInfo.SUPI
		uePreConfigPaths, err := NewUEPreConfigPaths(supi, routingInfo.PathList)
		if err != nil {
			logger.CtxLog.Warnln(err)
			continue
		}

		smfContext.UEPreConfigPathPool[supi] = uePreConfigPaths
	}
}

func SMF_Self() *SMFContext {
	return &smfContext
}

func GetUserPlaneInformation() *UserPlaneInformation {
	return smfContext.UserPlaneInformation
}

func UpdateSmfContext(smContext *SMFContext, newConfig []nfConfigApi.SessionManagement) error {
	logger.CtxLog.Infof("Processing config update from polling service")

	var updatedSnssaiInfos []SnssaiSmfInfo

	for _, sessionMgmt := range newConfig {
		// Convert PLMN
		apiPlmnId := sessionMgmt.GetPlmnId()
		plmnId := models.PlmnId{
			Mcc: apiPlmnId.GetMcc(),
			Mnc: apiPlmnId.GetMnc(),
		}

		apiSnssai := sessionMgmt.GetSnssai()
		snssaiInfo := SnssaiSmfInfo{
			PlmnId: plmnId,
			Snssai: SNssai{
				Sst: apiSnssai.GetSst(),
				Sd:  apiSnssai.GetSd(),
			},
			DnnInfos: make(map[string]*SnssaiSmfDnnInfo),
		}

		// Process IP domains (DNNs)
		if sessionMgmt.HasIpDomain() {
			for _, ipDomain := range sessionMgmt.GetIpDomain() {
				dnn := ipDomain.GetDnnName()
				ueSubnet := ipDomain.GetUeSubnet()

				dnnInfo := &SnssaiSmfDnnInfo{
					MTU: uint16(ipDomain.GetMtu()),
				}

				// IP allocation
				if ueSubnet != "" {
					allocator, err := NewIPAllocator(ueSubnet)
					if err != nil {
						logger.CtxLog.Warnf("IP allocation failed for DNN %s: %v", dnn, err)
						continue
					}
					dnnInfo.UeIPAllocator = allocator

					// Reserve static IPs
					if smContext.StaticIpInfo != nil {
						for _, static := range *smContext.StaticIpInfo {
							if static.Dnn == dnn {
								allocator.ReserveStaticIps(&static.ImsiIpInfo)
								logger.CtxLog.Infof("Reserved static IPs for DNN %s", dnn)
								break
							}
						}
					}
				}

				// DNS
				if ipv4 := ipDomain.GetDnsIpv4(); ipv4 != "" {
					if ip := net.ParseIP(ipv4); ip != nil {
						dnnInfo.DNS = DNS{IPv4Addr: ip}
					}
				}

				snssaiInfo.DnnInfos[dnn] = dnnInfo
			}
		}

		// Merge in existing DNNs if needed
		if existing := findExistingSnssaiInfo(smContext, plmnId, snssaiInfo.Snssai); existing != nil {
			for dnn, old := range existing.DnnInfos {
				if _, found := snssaiInfo.DnnInfos[dnn]; !found {
					snssaiInfo.DnnInfos[dnn] = old
				}
			}
		}

		updatedSnssaiInfos = append(updatedSnssaiInfos, snssaiInfo)
	}

	// Apply only if there are updates
	if len(updatedSnssaiInfos) > 0 {
		logger.CtxLog.Info("SNSSAI configuration changed; applying update")
		smContext.SnssaiInfos = updatedSnssaiInfos

		for _, sessionMgmt := range newConfig {
			if sessionMgmt.HasUpf() {
				upf := sessionMgmt.GetUpf()
				gnbNames := sessionMgmt.GetGnbNames()

				if err := updateUPFConfiguration(smContext, &upf, gnbNames); err != nil {
					logger.CtxLog.Warnf("Failed to update UPF configuration: %v", err)
					return err
				}
			}
		}
	}

	return nil
}

func resolvePfcpPort(p *int32) uint16 {
	if p != nil && *p >= 0 && *p <= 65535 {
		return uint16(*p)
	}
	if env := os.Getenv("PFCP_PORT_UPF"); env != "" {
		if v, err := strconv.Atoi(env); err == nil && v >= 0 && v <= 65535 {
			return uint16(v)
		}
	}
	return factory.DEFAULT_PFCP_PORT
}

// updateUPFConfiguration updates (or inserts) the UPF information
// Port is optional (*int32) resolved to uint16 with bounds-check
// Existing UPF nodes are updated in-place, missing ones are inserted
// Links are recreated from the supplied selection-params
func updateUPFConfiguration(smfCtx *SMFContext, apiUpf *nfConfigApi.Upf, gnbNames []string) error {
	if apiUpf == nil {
		return nil
	}

	hostname := apiUpf.Hostname
	if hostname == "" {
		return fmt.Errorf("UPF hostname must not be empty")
	}
	port := resolvePfcpPort(apiUpf.Port)

	nodeID := NodeID{
		NodeIdValue: []byte(hostname),
		NodeIdType:  0x0F,
	}

	// ensure UserPlaneInformation is initialized
	if smfCtx.UserPlaneInformation == nil {
		smfCtx.UserPlaneInformation = &UserPlaneInformation{
			UPNodes:              make(map[string]*UPNode),
			DefaultUserPlanePath: make(map[string][]*UPNode),
		}
	}

	// create or update UPF node
	upNode := &UPNode{
		UPF: &UPF{
			NodeID: nodeID,
			Port:   port,
		},
		Type:   UPNodeType("UPF"),
		NodeID: nodeID,
		Port:   port,
		Links:  []*UPNode{},
	}

	smfCtx.UserPlaneInformation.UPNodes[hostname] = upNode

	// Handle gNBs and link them
	for _, gnb := range gnbNames {
		if gnb == "" {
			continue
		}

		anNode, exists := smfCtx.UserPlaneInformation.UPNodes[gnb]
		if !exists {
			anNode = &UPNode{
				Type: UPNodeType("AN"),
				NodeID: NodeID{
					NodeIdValue: []byte(gnb),
					NodeIdType:  0x0F,
				},
			}

			smfCtx.UserPlaneInformation.UPNodes[gnb] = anNode
		}

		anNode.Links = appendIfMissing(anNode.Links, upNode)
		upNode.Links = appendIfMissing(upNode.Links, anNode)
	}

	AllocateUPFID()
	smfCtx.UserPlaneInformation.ResetDefaultUserPlanePath()

	logger.CtxLog.Infof("Updated UPF node: %s (port: %d), linked to %d gNBs", hostname, port, len(gnbNames))
	return nil
}

// Find existing S-NSSAI information
func findExistingSnssaiInfo(smContext *SMFContext, plmnId models.PlmnId, snssai SNssai) *SnssaiSmfInfo {
	if smContext == nil {
		return nil
	}

	for i := range smContext.SnssaiInfos {
		info := &smContext.SnssaiInfos[i]
		if info.PlmnId.Mcc == plmnId.Mcc &&
			info.PlmnId.Mnc == plmnId.Mnc &&
			info.Snssai.Sst == snssai.Sst &&
			info.Snssai.Sd == snssai.Sd {
			return info
		}
	}

	return nil
}

func appendIfMissing(slice []*UPNode, elem *UPNode) []*UPNode {
	for _, s := range slice {
		if s == elem {
			return slice
		}
	}
	return append(slice, elem)
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

func (smfCtxt *SMFContext) GetDnnStaticIpInfo(dnn string) *factory.StaticIpInfo {
	for _, info := range *smfCtxt.StaticIpInfo {
		if info.Dnn == dnn {
			logger.CfgLog.Debugf("get static ip info for dnn [%s] found [%v]", dnn, info)
			return &info
		}
	}
	return nil
}
