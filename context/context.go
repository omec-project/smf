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

	"github.com/google/uuid"

	"github.com/omec-project/openapi/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/Nnrf_NFManagement"
	"github.com/omec-project/openapi/Nudm_SubscriberDataManagement"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/pfcp/pfcpType"
	"github.com/omec-project/pfcp/pfcpUdp"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/util/drsm"
)

func init() {
	smfContext.NfInstanceID = uuid.New().String()
}

var smfContext SMFContext

type DrsmCtxts struct {
	TeidPool *drsm.Drsm
	SeidPool *drsm.Drsm
	UeIpPool *drsm.Drsm
}

type SMFContext struct {
	Name         string
	NfInstanceID string

	URIScheme    models.UriScheme
	BindingIPv4  string
	RegisterIPv4 string
	SBIPort      int
	CPNodeID     pfcpType.NodeID

	UDMProfile models.NfProfile

	UPNodeIDs []pfcpType.NodeID
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

	//*** For ULCL ** //
	ULCLSupport         bool
	UEPreConfigPathPool map[string]*UEPreConfigPaths
	LocalSEIDCount      uint64
	DrsmCtxts           DrsmCtxts

	EnterpriseList *map[string]string // map to contain slice-name:enterprise-name
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
	seid32, err := smfContext.DrsmCtxts.SeidPool.AllocateInt32ID()
	if err != nil {
		logger.CtxLog.Errorf("allocate SEID error: %+v", err)
		return 0, err
	}

	return uint64(seid32), nil
}

func ReleaseLocalSEID(seid uint64) error {
	seid32 := (int32)(seid)
	err := smfContext.DrsmCtxts.SeidPool.ReleaseInt32ID(seid32)
	if err != nil {
		logger.CtxLog.Errorf("allocate SEID error: %+v", err)
		return err
	}
	return nil
}

func InitSmfContext(config *factory.Config) *SMFContext {
	if config == nil {
		logger.CtxLog.Error("Config is nil")
		return nil
	}

	//Acquire master SMF config lock, no one should update it in parallel,
	//until SMF is done updating SMF context
	factory.SmfConfigSyncLock.Lock()
	defer factory.SmfConfigSyncLock.Unlock()

	logger.CtxLog.Infof("smfconfig Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)
	configuration := config.Configuration
	if configuration.SmfName != "" {
		smfContext.Name = configuration.SmfName
	}

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
			smfContext.Key = tls.Key
			smfContext.PEM = tls.PEM
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
			pfcp.Port = pfcpUdp.PFCP_PORT
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
			logger.CtxLog.Warnf("PFCP Parse Addr Fail: %v", err)
		}

		smfContext.CPNodeID.NodeIdType = 0
		smfContext.CPNodeID.NodeIdValue = addr.IP.To4()
	}

	//Static config
	for _, snssaiInfoConfig := range configuration.SNssaiInfo {
		smfContext.insertSmfNssaiInfo(&snssaiInfoConfig)
	}

	// Set client and set url
	ManagementConfig := Nnrf_NFManagement.NewConfiguration()
	ManagementConfig.SetBasePath(SMF_Self().NrfUri)
	smfContext.NFManagementClient = Nnrf_NFManagement.NewAPIClient(ManagementConfig)

	NFDiscovryConfig := Nnrf_NFDiscovery.NewConfiguration()
	NFDiscovryConfig.SetBasePath(SMF_Self().NrfUri)
	smfContext.NFDiscoveryClient = Nnrf_NFDiscovery.NewAPIClient(NFDiscovryConfig)

	smfContext.ULCLSupport = configuration.ULCL

	smfContext.SupportedPDUSessionType = "IPv4"

	smfContext.UserPlaneInformation = NewUserPlaneInformation(&configuration.UserPlaneInformation)

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

func ProcessConfigUpdate() bool {

	logger.CtxLog.Infof("Dynamic config update received [%+v]", factory.UpdatedSmfConfig)

	sendNrfRegistration := false
	//Lets check updated config
	updatedCfg := factory.UpdatedSmfConfig

	//Lets parse through network slice configs first
	if updatedCfg.DelSNssaiInfo != nil {
		for _, slice := range *updatedCfg.DelSNssaiInfo {
			SMF_Self().deleteSmfNssaiInfo(&slice)
		}
		factory.UpdatedSmfConfig.DelSNssaiInfo = nil
		sendNrfRegistration = true
	}

	if updatedCfg.AddSNssaiInfo != nil {
		for _, slice := range *updatedCfg.AddSNssaiInfo {
			SMF_Self().insertSmfNssaiInfo(&slice)
		}
		factory.UpdatedSmfConfig.AddSNssaiInfo = nil
		sendNrfRegistration = true
	}

	if updatedCfg.ModSNssaiInfo != nil {
		for _, slice := range *updatedCfg.ModSNssaiInfo {
			SMF_Self().updateSmfNssaiInfo(&slice)
		}
		factory.UpdatedSmfConfig.ModSNssaiInfo = nil
		sendNrfRegistration = true
	}

	//UP Node Links should be deleted before underlying UPFs are deleted
	if updatedCfg.DelLinks != nil {
		for _, link := range *updatedCfg.DelLinks {
			GetUserPlaneInformation().DeleteUPNodeLinks(&link)
		}
		factory.UpdatedSmfConfig.DelLinks = nil
	}

	//Iterate through UserPlane Info
	if updatedCfg.DelUPNodes != nil {
		for name, upf := range *updatedCfg.DelUPNodes {
			GetUserPlaneInformation().DeleteSmfUserPlaneNode(name, &upf)
		}
		factory.UpdatedSmfConfig.DelUPNodes = nil
	}

	if updatedCfg.AddUPNodes != nil {
		for name, upf := range *updatedCfg.AddUPNodes {
			GetUserPlaneInformation().InsertSmfUserPlaneNode(name, &upf)
		}
		factory.UpdatedSmfConfig.AddUPNodes = nil
		AllocateUPFID()
		//TODO: allocate UPF ID
	}

	if updatedCfg.ModUPNodes != nil {
		for name, upf := range *updatedCfg.ModUPNodes {
			GetUserPlaneInformation().UpdateSmfUserPlaneNode(name, &upf)

		}
		factory.UpdatedSmfConfig.ModUPNodes = nil
	}

	//Iterate through add UP Node Links info
	//UP Links should be added only after underlying UPFs have been added
	if updatedCfg.AddLinks != nil {
		for _, link := range *updatedCfg.AddLinks {
			GetUserPlaneInformation().InsertUPNodeLinks(&link)
		}
		factory.UpdatedSmfConfig.AddLinks = nil
	}

	//Update Enterprise Info
	SMF_Self().EnterpriseList = updatedCfg.EnterpriseList
	logger.CtxLog.Infof("Dynamic config update, enterprise info [%v] ", *updatedCfg.EnterpriseList)

	//Any time config changes(Slices/UPFs/Links) then reset Default path(Key= nssai+Dnn)
	GetUserPlaneInformation().ResetDefaultUserPlanePath()

	//Send NRF Re-register if Slice info got updated
	if sendNrfRegistration {
		SetupNFProfile(&factory.SmfConfig)
	}

	return sendNrfRegistration
}

func (smfCtxt *SMFContext) InitDrsm() error {
	podname := os.Getenv("HOSTNAME")
	podip := os.Getenv("POD_IP")
	podId := drsm.PodId{PodName: podname, PodIp: podip}
	dbName := "sdcore_smf"
	dbUrl := "mongodb://mongodb-arbiter-headless"

	if factory.SmfConfig.Configuration.Mongodb.Url != "" {
		dbUrl = factory.SmfConfig.Configuration.Mongodb.Url
	}

	if factory.SmfConfig.Configuration.SmfDbName != "" {
		dbName = factory.SmfConfig.Configuration.SmfDbName
	}

	logger.CfgLog.Infof("initialising drsm name [%v] url [%v] ", dbName, dbUrl)

	opt := &drsm.Options{ResIdSize: 24, Mode: drsm.ResourceClient}
	db := drsm.DbInfo{Url: dbUrl, Name: dbName}

	//for local FSEID
	if drsmCtxt, err := drsm.InitDRSM("fseid", podId, db, opt); err == nil {
		smfCtxt.DrsmCtxts.SeidPool = drsmCtxt
	} else {
		return err
	}

	//for local FTEID
	if drsmCtxt, err := drsm.InitDRSM("fteid", podId, db, opt); err == nil {
		smfCtxt.DrsmCtxts.TeidPool = drsmCtxt
	} else {
		return err
	}

	//for IP-Addr
	//TODO, use UPF based allocation for now

	return nil
}
