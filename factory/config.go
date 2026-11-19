// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

/*
 * SMF Configuration Factory
 */

package factory

import (
	"time"

	"github.com/omec-project/openapi/v2/models"
	utilLogger "github.com/omec-project/util/logger"
)

const (
	SMF_EXPECTED_CONFIG_VERSION        = "1.0.0"
	UE_ROUTING_EXPECTED_CONFIG_VERSION = "1.0.0"
)

type Config struct {
	Info          *Info              `yaml:"info"`
	Configuration *Configuration     `yaml:"configuration"`
	Logger        *utilLogger.Logger `yaml:"logger"`
	CfgLocation   string
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

const DEFAULT_PFCP_PORT = 8805

type Mongodb struct {
	Name string `yaml:"name"`
	Url  string `yaml:"url"`
}

type KafkaInfo struct {
	EnableKafka *bool  `yaml:"enableKafka,omitempty"`
	BrokerUri   string `yaml:"brokerUri,omitempty"`
	Topic       string `yaml:"topicName,omitempty"`
	BrokerPort  int    `yaml:"brokerPort,omitempty"`
}

type Configuration struct {
	Mongodb                  *Mongodb          `yaml:"mongodb,omitempty"`
	PFCP                     *PFCP             `yaml:"pfcp,omitempty"`
	Sbi                      *Sbi              `yaml:"sbi,omitempty"`
	NrfUri                   string            `yaml:"nrfUri,omitempty"`
	WebuiUri                 string            `yaml:"webuiUri"`
	SmfName                  string            `yaml:"smfName,omitempty"`
	SmfDbName                string            `yaml:"smfDBName,omitempty"`
	StaticIpInfo             []StaticIpInfo    `yaml:"staticIpInfo"`
	ServiceNameList          []string          `yaml:"serviceNameList,omitempty"`
	EnterpriseList           map[string]string `yaml:"enterpriseList,omitempty"`
	KafkaInfo                KafkaInfo         `yaml:"kafkaInfo,omitempty"`
	NrfCacheEvictionInterval int               `yaml:"nrfCacheEvictionInterval"`
	DebugProfilePort         int               `yaml:"debugProfilePort,omitempty"`
	EnableNrfCaching         bool              `yaml:"enableNrfCaching"`
	EnableDbStore            bool              `yaml:"enableDBStore,omitempty"`
	EnableUpfAdapter         bool              `yaml:"enableUPFAdapter,omitempty"`
	ULCL                     bool              `yaml:"ulcl,omitempty"`
	PCSCFInfo                PCSCFInfo         `yaml:"pcscfInfos,omitempty"`
	Li                       *Li               `yaml:"-"` // decoded on its own: see strictLiBlock
	T3591                    *TimerValue       `yaml:"t3591,omitempty"`
}

// Li configures the Lawful Interception IRI-POI and CC triggering function. It is opt-in:
// when absent, no LI component starts.
type Li struct {
	X1Listen string `yaml:"x1Listen"` // address for the X1 provisioning listener
	MDF2     string `yaml:"mdf2"`     // X2 delivery destination (host:port)
	NEID     string `yaml:"neId"`     // this network element's identifier
	Cert     string `yaml:"cert"`     // X0 LI PKI: this NE's certificate
	Key      string `yaml:"key"`      // its private key
	CACert   string `yaml:"caCert"`   // the LI CA trust anchor

	// MDF3 is the X3 destination this SMF, as CC Triggering Function, provisions at
	// each UPF it triggers. The UPF is told where to deliver content over LI_T3 and
	// carries no MDF3 address of its own.
	MDF3 string `yaml:"mdf3"`
	// UPFTriggers lists the LI_T3 triggering endpoints of the UPFs whose CC-POIs
	// this SMF may task. Keyed by N4 node address because the trigger must reach
	// the UPF serving the session; the NE identifier cannot be derived from the URL.
	UPFTriggers []LiUPFTrigger `yaml:"upfTriggers"`

	// Destinations declares DID→endpoint mappings for delivery destinations agreed
	// out of band. A task naming one of these DIDs is delivered to it exactly as if
	// the ADMF had provisioned it with CreateDestination; a destination provisioned
	// over X1 under the same DID takes precedence. Optional — an ADMF that
	// provisions its own destinations needs none of these. `mdf2` above serves only a
	// task that names no destination at all; a task naming a DID this element cannot
	// resolve is refused, not delivered to `mdf2`.
	Destinations []LiDestination `yaml:"destinations,omitempty"`

	AdmfURL string `yaml:"admfUrl"` // ADMF X1 endpoint for NE-initiated issue reports (optional)
	AdmfID  string `yaml:"admfId"`  // responsible ADMF identifier (for reports)
	// The X1 keepalive procedure of ETSI TS 103 221-1 clause 6.6.2, which runs unless
	// keepaliveDisabled is set: the clause enables it by default. keepaliveTimeout is
	// TIME_P2, the silence after which the element reports fault 9050 (default 1h);
	// keepaliveTimeP1 bounds the wait for the ADMF's answer (default 1m), and
	// keepaliveTimeP3 the wait after an acknowledged report (default 2h) before tasking is
	// deactivated — unless keepaliveRetainTasking is set.
	KeepaliveTimeout       string `yaml:"keepaliveTimeout"`                 // duration; TIME_P2 (optional)
	KeepaliveTimeP1        string `yaml:"keepaliveTimeP1,omitempty"`        // duration; TIME_P1 (optional)
	KeepaliveTimeP3        string `yaml:"keepaliveTimeP3,omitempty"`        // duration; TIME_P3 (optional)
	KeepaliveRetainTasking bool   `yaml:"keepaliveRetainTasking,omitempty"` // never deactivate tasking (optional)
	KeepaliveDisabled      bool   `yaml:"keepaliveDisabled,omitempty"`      // agreed with the agency: no procedure (optional)

	// The X2/X3 keepalive mechanism of ETSI TS 103 221-2 clause 6.2.4, which is a
	// different mechanism from keepaliveTimeout above: that one is the X1 fail-safe
	// against an ADMF that goes quiet, this one detects a mediation function that
	// has stopped answering on the delivery connection. Hence the prefix — the two
	// read as halves of one setting otherwise, and they are not related at all.
	//
	// Enabled is a pointer so that "the operator said false" is distinct from "the
	// operator said nothing": unset means the mechanism runs, because the
	// specification requires it and TIME_P1 and TIME_P2 are given normatively (60
	// and 180 seconds), which is what an element configuring nothing must get.
	//
	// Setting it false is for a deployment whose mediation function does not
	// implement the MDF half of clause 6.2.4 — it will never acknowledge, and this
	// element would disconnect it every TIME_P2 and lose whatever was in flight. The
	// reference implementation this project interoperates with is such a peer.
	X2X3KeepaliveEnabled *bool  `yaml:"x2x3KeepaliveEnabled,omitempty"`
	X2X3KeepaliveTimeP1  string `yaml:"x2x3KeepaliveTimeP1,omitempty"` // duration; default 60s
	X2X3KeepaliveTimeP2  string `yaml:"x2x3KeepaliveTimeP2,omitempty"` // duration; default 180s

	// DeactivateAllTasks and RemoveAllDestinations carry what TS 103 221-1 leaves to
	// advance agreement between the operator and the agency: whether this element
	// performs a bulk deactivation of all its tasking, and whether it performs a bulk
	// removal of all its destinations.
	//
	// Both are tri-state. Unset — the pointer is nil — is "no agreement in advance",
	// the standard's own phrase, and yields the standard's own default for both: the
	// bulk operation is performed (TS 103 221-1 clauses 6.2.4 and 6.3.4). They are
	// pointers rather than plain bools so that "the operator said false" is a state
	// distinct from "the operator said nothing", which for the first of them is the
	// difference between refusing to stop every interception on this element and doing it.
	DeactivateAllTasks    *bool `yaml:"deactivateAllTasks,omitempty"`
	RemoveAllDestinations *bool `yaml:"removeAllDestinations,omitempty"`
}

// LiDestination is one pre-shared delivery destination: the identifier an ADMF's tasks
// reference it by, and where it points. Its three fields are the ones CreateDestination
// carries, because the entry has to resolve identically to a provisioned one.
type LiDestination struct {
	DID          string `yaml:"did"`          // UUID, as the X1 schema requires of a DId
	DeliveryType string `yaml:"deliveryType"` // X2Only | X3Only | X2andX3
	Address      string `yaml:"address"`      // host:port
}

// LiUPFTrigger is one UPF's LI_T3 triggering endpoint.
type LiUPFTrigger struct {
	NodeID string `yaml:"nodeId"` // the UPF's N4 node address
	X1URL  string `yaml:"x1Url"`  // its LI_T3 endpoint, e.g. https://upf-1:8443/X1/NE
	NEID   string `yaml:"neId"`   // the identifier its certificate is bound to
}

// TimerValue configures a NAS retransmission timer. It follows the shape the AMF uses for
// its own NAS timers so that operators meet one convention rather than two.
//
// ExpireTime left unset means "resolve automatically": the extended NAS-SM timer indication
// from the AMF if it arrives, and the terrestrial value from 3GPP TS 24.501 otherwise. Setting
// it is a deliberate operator override of that resolution, for deployments whose RAN does not
// advertise the information the indication is derived from.
type TimerValue struct {
	// Enable is a pointer so that an absent key means "on" rather than "off". With a plain bool
	// a configuration that set only expireTime would silently disable the timer, which is the
	// opposite of what writing a value expresses. This follows EnableKafka above.
	Enable        *bool         `yaml:"enable,omitempty"`
	ExpireTime    time.Duration `yaml:"expireTime"`
	MaxRetryTimes int           `yaml:"maxRetryTimes,omitempty"`
}

type StaticIpInfo struct {
	ImsiIpInfo map[string]string `yaml:"imsiIpInfo"`
	Dnn        string            `yaml:"dnn"`
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
	// Caching time for an application identifier.
	CachingTime *time.Time `yaml:"cachingTime,omitempty"`
	// Identifier of an application.
	AppID string `yaml:"applicationId"`
	// PFDs for the application identifier.
	Pfds []PfdContent `yaml:"pfds"`
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
	Port                 uint16                     `yaml:"port"`
}

type InterfaceUpfInfoItem struct {
	NetworkInstance string                 `yaml:"networkInstance"`
	InterfaceType   models.UPInterfaceType `yaml:"interfaceType"`
	Endpoints       []string               `yaml:"endpoints"`
}

type UPLink struct {
	A string `yaml:"A"`
	B string `yaml:"B"`
}

type PCSCFInfo struct {
	IPv4Addr string `yaml:"ipv4,omitempty"`
	IPv6Addr string `yaml:"ipv6,omitempty"`
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
