// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package context

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/free5gc/openapi/Nnrf_NFDiscovery"
	"github.com/free5gc/openapi/Nnrf_NFManagement"
	"github.com/free5gc/openapi/Nudm_SubscriberDataManagement"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/pfcp/pfcpUdp"
	"github.com/free5gc/smf/factory"
	"github.com/free5gc/smf/logger"
)

func init() {
	smfContext.NfInstanceID = uuid.New().String()
}

var smfContext SMFContext

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

	EnterpriseList *map[string]string // map to contain slice-name:enterprise-name

	Pprof bool // profiling option
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

func AllocateLocalSEID() uint64 {
	atomic.AddUint64(&smfContext.LocalSEIDCount, 1)
	return smfContext.LocalSEIDCount
}

func InitSmfContext(config *factory.Config) {
	if config == nil {
		logger.CtxLog.Error("Config is nil")
		return
	}

	logger.CtxLog.Infof("smfconfig Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)
	configuration := config.Configuration
	if configuration.SmfName != "" {
		smfContext.Name = configuration.SmfName
	}

	smfContext.Pprof = configuration.Pprof

	sbi := configuration.Sbi
	if sbi == nil {
		logger.CtxLog.Errorln("Configuration needs \"sbi\" value")
		return
	} else {
		smfContext.URIScheme = models.UriScheme(sbi.Scheme)
		smfContext.RegisterIPv4 = factory.SMF_DEFAULT_IPV4 // default localhost
		smfContext.SBIPort = factory.SMF_DEFAULT_PORT_INT  // default port
		if sbi.RegisterIPv4 != "" {
			smfContext.RegisterIPv4 = sbi.RegisterIPv4
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

	//Iterate through UP Node Links info
	if updatedCfg.AddLinks != nil {
		for _, link := range *updatedCfg.AddLinks {
			GetUserPlaneInformation().InsertUPNodeLinks(&link)
		}
		factory.UpdatedSmfConfig.AddLinks = nil
	}

	if updatedCfg.DelLinks != nil {
		for _, link := range *updatedCfg.DelLinks {
			GetUserPlaneInformation().DeleteUPNodeLinks(&link)
		}
		factory.UpdatedSmfConfig.DelLinks = nil
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
