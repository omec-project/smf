// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

/*
 * AMF Configuration Factory
 */

package factory

import (
	"strconv"
	"time"

	"github.com/free5gc/logger_util"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/smf/logger"
	protos "github.com/omec-project/config5g/proto/sdcoreConfig"
)

const (
	SMF_EXPECTED_CONFIG_VERSION        = "1.0.0"
	UE_ROUTING_EXPECTED_CONFIG_VERSION = "1.0.0"
)

type Config struct {
	Info          *Info               `yaml:"info"`
	Configuration *Configuration      `yaml:"configuration"`
	Logger        *logger_util.Logger `yaml:"logger"`
}

type Info struct {
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
}

const (
	SMF_DEFAULT_IPV4     = "127.0.0.2"
	SMF_DEFAULT_PORT     = "8000"
	SMF_DEFAULT_PORT_INT = 8000
)

type Configuration struct {
	SmfName              string               `yaml:"smfName,omitempty"`
	Sbi                  *Sbi                 `yaml:"sbi,omitempty"`
	PFCP                 *PFCP                `yaml:"pfcp,omitempty"`
	NrfUri               string               `yaml:"nrfUri,omitempty"`
	UserPlaneInformation UserPlaneInformation `yaml:"userplane_information"`
	ServiceNameList      []string             `yaml:"serviceNameList,omitempty"`
	SNssaiInfo           []SnssaiInfoItem     `yaml:"snssaiInfos,omitempty"`
	ULCL                 bool                 `yaml:"ulcl,omitempty"`
}

type SnssaiInfoItem struct {
	SNssai   *models.Snssai      `yaml:"sNssai"`
	DnnInfos []SnssaiDnnInfoItem `yaml:"dnnInfos"`
}

type SnssaiDnnInfoItem struct {
	Dnn      string `yaml:"dnn"`
	DNS      DNS    `yaml:"dns"`
	UESubnet string `yaml:"ueSubnet"`
}

type Sbi struct {
	Scheme       string `yaml:"scheme"`
	TLS          *TLS   `yaml:"tls"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty"` // IP that is registered at NRF.
	// IPv6Addr string `yaml:"ipv6Addr,omitempty"`
	BindingIPv4 string `yaml:"bindingIPv4,omitempty"` // IP used to run the server in the node.
	Port        int    `yaml:"port,omitempty"`
}

type TLS struct {
	PEM string `yaml:"pem,omitempty"`
	Key string `yaml:"key,omitempty"`
}

type PFCP struct {
	Addr string `yaml:"addr,omitempty"`
	Port uint16 `yaml:"port,omitempty"`
}

type DNS struct {
	IPv4Addr string `yaml:"ipv4,omitempty"`
	IPv6Addr string `yaml:"ipv6,omitempty"`
}

type Path struct {
	DestinationIP   string   `yaml:"DestinationIP,omitempty"`
	DestinationPort string   `yaml:"DestinationPort,omitempty"`
	UPF             []string `yaml:"UPF,omitempty"`
}

type UERoutingInfo struct {
	SUPI     string `yaml:"SUPI,omitempty"`
	AN       string `yaml:"AN,omitempty"`
	PathList []Path `yaml:"PathList,omitempty"`
}

// RouteProfID is string providing a Route Profile identifier.
type RouteProfID string

// RouteProfile maintains the mapping between RouteProfileID and ForwardingPolicyID of UPF
type RouteProfile struct {
	// Forwarding Policy ID of the route profile
	ForwardingPolicyID string `yaml:"forwardingPolicyID,omitempty"`
}

// PfdContent represents the flow of the application
type PfdContent struct {
	// Identifies a PFD of an application identifier.
	PfdID string `yaml:"pfdID,omitempty"`
	// Represents a 3-tuple with protocol, server ip and server port for
	// UL/DL application traffic.
	FlowDescriptions []string `yaml:"flowDescriptions,omitempty"`
	// Indicates a URL or a regular expression which is used to match the
	// significant parts of the URL.
	Urls []string `yaml:"urls,omitempty"`
	// Indicates an FQDN or a regular expression as a domain name matching
	// criteria.
	DomainNames []string `yaml:"domainNames,omitempty"`
}

// PfdDataForApp represents the PFDs for an application identifier
type PfdDataForApp struct {
	// Identifier of an application.
	AppID string `yaml:"applicationId"`
	// PFDs for the application identifier.
	Pfds []PfdContent `yaml:"pfds"`
	// Caching time for an application identifier.
	CachingTime *time.Time `yaml:"cachingTime,omitempty"`
}

type RoutingConfig struct {
	Info          *Info                        `yaml:"info"`
	UERoutingInfo []*UERoutingInfo             `yaml:"ueRoutingInfo"`
	RouteProf     map[RouteProfID]RouteProfile `yaml:"routeProfile,omitempty"`
	PfdDatas      []*PfdDataForApp             `yaml:"pfdDataForApp,omitempty"`
}

// UserPlaneInformation describe core network userplane information
type UserPlaneInformation struct {
	UPNodes map[string]UPNode `yaml:"up_nodes"`
	Links   []UPLink          `yaml:"links"`
}

// UPNode represent the user plane node
type UPNode struct {
	Type                 string                     `yaml:"type"`
	NodeID               string                     `yaml:"node_id"`
	ANIP                 string                     `yaml:"an_ip"`
	Dnn                  string                     `yaml:"dnn"`
	SNssaiInfos          []models.SnssaiUpfInfoItem `yaml:"sNssaiUpfInfos,omitempty"`
	InterfaceUpfInfoList []InterfaceUpfInfoItem     `yaml:"interfaces,omitempty"`
}

type InterfaceUpfInfoItem struct {
	InterfaceType   models.UpInterfaceType `yaml:"interfaceType"`
	Endpoints       []string               `yaml:"endpoints"`
	NetworkInstance string                 `yaml:"networkInstance"`
}

type UPLink struct {
	A string `yaml:"A"`
	B string `yaml:"B"`
}

var ConfigPodTrigger chan bool

func init() {
	ConfigPodTrigger = make(chan bool, 1)
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}

func (r *RoutingConfig) GetVersion() string {
	if r.Info != nil && r.Info.Version != "" {
		return r.Info.Version
	}
	return ""
}

func (c *Config) updateConfig(commChannel chan *protos.NetworkSliceResponse) bool {
	for {
		rsp := <-commChannel
		logger.GrpcLog.Infof("received updateConfig in the smf app: %+v \n", rsp)

		//update slice info
		if err := c.updateSmfConfig(rsp); err != nil {
			logger.GrpcLog.Errorf("config update error: %v \n", err.Error())
			continue
		}
		ConfigPodTrigger <- true
	}
}

//Update level-1 Configuration(Not actual SMF config structure used by SMF)
func (c *Config) updateSmfConfig(rsp *protos.NetworkSliceResponse) error {

	//Reset previous SNSSAI structure
	if c.Configuration.SNssaiInfo != nil {
		c.Configuration.SNssaiInfo = nil
	}
	c.Configuration.SNssaiInfo = make([]SnssaiInfoItem, 0)

	//Reset existing UP nodes and Links
	if c.Configuration.UserPlaneInformation.UPNodes != nil {
		c.Configuration.UserPlaneInformation.UPNodes = nil
	}
	c.Configuration.UserPlaneInformation.UPNodes = make(map[string]UPNode)

	if c.Configuration.UserPlaneInformation.Links != nil {
		c.Configuration.UserPlaneInformation.Links = nil
	}
	c.Configuration.UserPlaneInformation.Links = make([]UPLink, 0)

	//Iterate through all NS received
	for _, ns := range rsp.NetworkSlice {
		//make new SNSSAI Info structure
		var sNssaiInfoItem SnssaiInfoItem

		//make SNSSAI
		var sNssai models.Snssai
		sNssai.Sd = ns.Nssai.Sd
		numSst, _ := strconv.Atoi(ns.Nssai.Sst)
		sNssai.Sst = int32(numSst)
		sNssaiInfoItem.SNssai = &sNssai

		//make DNN Info structure
		sNssaiInfoItem.DnnInfos = make([]SnssaiDnnInfoItem, 0)
		for _, devGrp := range ns.DeviceGroup {
			var dnnInfo SnssaiDnnInfoItem
			dnnInfo.Dnn = devGrp.IpDomainDetails.DnnName
			dnnInfo.DNS.IPv4Addr = devGrp.IpDomainDetails.DnsPrimary
			dnnInfo.UESubnet = devGrp.IpDomainDetails.UePool

			//update to Slice structure
			sNssaiInfoItem.DnnInfos = append(sNssaiInfoItem.DnnInfos, dnnInfo)
		}

		//Update to SMF config structure
		c.Configuration.SNssaiInfo = append(c.Configuration.SNssaiInfo, sNssaiInfoItem)

		//iterate through UPFs config received
		upf := UPNode{Type: "UPF",
			NodeID:               ns.Site.Upf.UpfName,
			SNssaiInfos:          make([]models.SnssaiUpfInfoItem, 0),
			InterfaceUpfInfoList: make([]InterfaceUpfInfoItem, 0)}

		snsUpfInfoItem := models.SnssaiUpfInfoItem{SNssai: &sNssai,
			DnnUpfInfoList: make([]models.DnnUpfInfoItem, 0)}

		//Popoulate DNN names per UPF slice Info
		for _, devGrp := range ns.DeviceGroup {

			//DNN Info in UPF per Slice
			var dnnUpfInfo models.DnnUpfInfoItem
			dnnUpfInfo.Dnn = devGrp.IpDomainDetails.DnnName
			snsUpfInfoItem.DnnUpfInfoList = append(snsUpfInfoItem.DnnUpfInfoList, dnnUpfInfo)

			//Populate UPF Interface Info and DNN info in UPF per Interface
			intfUpfInfoItem := InterfaceUpfInfoItem{InterfaceType: models.UpInterfaceType_N3,
				Endpoints: make([]string, 0), NetworkInstance: devGrp.IpDomainDetails.DnnName}
			intfUpfInfoItem.Endpoints = append(intfUpfInfoItem.Endpoints, ns.Site.Upf.UpfName)
			upf.InterfaceUpfInfoList = append(upf.InterfaceUpfInfoList, intfUpfInfoItem)
		}
		upf.SNssaiInfos = append(upf.SNssaiInfos, snsUpfInfoItem)

		//Update UPF to SMF Config Structure
		c.Configuration.UserPlaneInformation.UPNodes[ns.Site.Upf.UpfName] = upf

		//Update gNB links to UPF(gNB <-> N3_UPF)
		for _, gNb := range ns.Site.Gnb {
			upLink := UPLink{A: gNb.Name, B: ns.Site.Upf.UpfName}
			c.Configuration.UserPlaneInformation.Links = append(c.Configuration.UserPlaneInformation.Links, upLink)

			//insert gNb to SMF Config Structure
			gNbNode := UPNode{Type: "AN"}
			c.Configuration.UserPlaneInformation.UPNodes[gNb.Name] = gNbNode
		}

		logger.CfgLog.Infof("updated SMF config : %+v \n", c.Configuration)
	}
	return nil
}
