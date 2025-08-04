// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"bytes"
	"fmt"
	"net"
	"reflect"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
)

// UserPlaneInformation store userplane topology
type UserPlaneInformation struct {
	UPNodes              map[string]*UPNode
	UPFs                 map[string]*UPNode
	AccessNetwork        map[string]*UPNode
	UPFIPToName          map[string]string
	UPFsID               map[string]string    // name to id
	UPFsIPtoID           map[string]string    // ip->id table, for speed optimization
	DefaultUserPlanePath map[string][]*UPNode // DNN to Default Path
}

type UPNodeType string

const (
	UPNODE_UPF UPNodeType = "UPF"
	UPNODE_AN  UPNodeType = "AN"
)

// UPNode represent the user plane node topology
type UPNode struct {
	UPF    *UPF
	Type   UPNodeType
	NodeID NodeID
	ANIP   net.IP
	Dnn    string
	Links  []*UPNode
	Port   uint16
}

// UPPath represent User Plane Sequence of this path
type UPPath []*UPNode

func AllocateUPFID() {
	if smfContext.UserPlaneInformation == nil {
		logger.InitLog.Errorln("UserPlaneInformation is nil")
		return
	}

	if smfContext.UserPlaneInformation.UPFs == nil {
		logger.InitLog.Errorln("UPFs is nil")
		return
	}
	UPFsID := smfContext.UserPlaneInformation.UPFsID
	UPFsIPtoID := smfContext.UserPlaneInformation.UPFsIPtoID

	for upfName, upfNode := range smfContext.UserPlaneInformation.UPFs {
		upfid := upfNode.UPF.UUID()
		upfip := upfNode.NodeID.ResolveNodeIdToIp().String()

		UPFsID[upfName] = upfid
		UPFsIPtoID[upfip] = upfid
	}
}

// NewUserPlaneInformation process the configuration then returns a new instance of UserPlaneInformation
func NewUserPlaneInformation(upTopology *factory.UserPlaneInformation) *UserPlaneInformation {
	userplaneInformation := &UserPlaneInformation{
		UPNodes:              make(map[string]*UPNode),
		UPFs:                 make(map[string]*UPNode),
		AccessNetwork:        make(map[string]*UPNode),
		UPFIPToName:          make(map[string]string),
		UPFsID:               make(map[string]string),
		UPFsIPtoID:           make(map[string]string),
		DefaultUserPlanePath: make(map[string][]*UPNode),
	}

	// Load UP Nodes to SMF
	for name, node := range upTopology.UPNodes {
		err := userplaneInformation.InsertSmfUserPlaneNode(name, &node)
		if err != nil {
			logger.UPNodeLog.Errorf("failed to insert UP Node[%v]", node)
		}
	}

	// Load UP Node Link config to SMF
	for _, link := range upTopology.Links {
		err := userplaneInformation.InsertUPNodeLinks(&link)
		if err != nil {
			logger.UPNodeLog.Errorf("failed to insert UP Node link[%v]", link)
		}
	}
	return userplaneInformation
}

func convertSnssaiInfoToModel(snssaiInfo SnssaiUPFInfo) models.SnssaiUpfInfoItem {
	return models.SnssaiUpfInfoItem{
		SNssai: &models.Snssai{
			Sst: snssaiInfo.SNssai.Sst,
			Sd:  snssaiInfo.SNssai.Sd,
		},
		DnnUpfInfoList: convertDnnUpfInfoToModel(snssaiInfo.DnnList), // Assuming a similar conversion for DNNs
	}
}

func convertDnnUpfInfoToModel(dnnList []DnnUPFInfoItem) []models.DnnUpfInfoItem {
	modelDnnList := make([]models.DnnUpfInfoItem, len(dnnList))
	for i, dnn := range dnnList {
		modelDnnList[i] = models.DnnUpfInfoItem{
			Dnn:             dnn.Dnn,
			DnaiList:        dnn.DnaiList,
			PduSessionTypes: dnn.PduSessionTypes,
		}
	}
	return modelDnnList
}

func BuildUserPlaneInformationFromSessionManagement(existing *UserPlaneInformation, smConfigs []nfConfigApi.SessionManagement) *UserPlaneInformation {
	if existing == nil {
		existing = &UserPlaneInformation{
			UPNodes:              make(map[string]*UPNode),
			UPFs:                 make(map[string]*UPNode),
			AccessNetwork:        make(map[string]*UPNode),
			UPFIPToName:          make(map[string]string),
			UPFsID:               make(map[string]string),
			UPFsIPtoID:           make(map[string]string),
			DefaultUserPlanePath: make(map[string][]*UPNode),
		}
	}
	currentUPFs := make(map[string]bool)
	currentANs := make(map[string]bool)

	for _, sm := range smConfigs {
		if sm.Upf == nil {
			logger.CtxLog.Warn("session management config contains nil UPF, skipping")
			continue
		}
		upfName := sm.Upf.GetHostname()
		logger.CtxLog.Infof("creating UPF node: %s", upfName)
		nodeID := CreateNodeIDFromHostname(upfName)
		logger.CtxLog.Infof("creating UPF node: %s, IP: %s", upfName, nodeID.ResolveNodeIdToIp().String())
		snssai := sm.GetSnssai()
		logger.CtxLog.Infof("creating UPF node: %s, SNSSAI: %+v", upfName, snssai)
		dnnList := convertIpDomainsToDnnList(sm.IpDomain)
		logger.CtxLog.Infof("creating UPF node: %s, DNNs: %+v", upfName, dnnList)
		snssaiInfo := SnssaiUPFInfo{
			SNssai: SNssai{
				Sst: snssai.GetSst(),
				Sd:  snssai.GetSd(),
			},
			DnnList: dnnList,
		}
		snssaiInfoModel := convertSnssaiInfoToModel(snssaiInfo)

		logger.CtxLog.Infof("creating UPF node: %s, SNSSAI: %+v, DNNs: %+v", upfName, snssai, dnnList)
		nodeIDStr := string(nodeID.NodeIdValue)
		logger.CtxLog.Infof("creating UPF node: %s, IP: %s, ID: %s", upfName, nodeID.ResolveNodeIdToIp().String(), nodeIDStr)
		node := &factory.UPNode{
			NodeID:      nodeIDStr,
			SNssaiInfos: []models.SnssaiUpfInfoItem{snssaiInfoModel},
		}
		var interfaceInfoList []factory.InterfaceUpfInfoItem
		ipStr := nodeID.ResolveNodeIdToIp().String()

		for _, ipDomain := range sm.IpDomain {
			n3 := factory.InterfaceUpfInfoItem{
				InterfaceType:   models.UpInterfaceType_N3,
				NetworkInstance: ipDomain.DnnName,
				Endpoints:       []string{ipStr},
			}
			interfaceInfoList = append(interfaceInfoList, n3)
		}
		if sm.Upf.Port != nil {
			node.Port = resolvePfcpPort(*sm.Upf.Port)
		} else {
			node.Port = DefaultPfcpPort
		}
		node.InterfaceUpfInfoList = interfaceInfoList
		upfNode, err := getOrCreateUpfNode(existing, upfName, node)
		if err != nil {
			logger.CtxLog.Errorf("Error creating or getting UPF node: %v", err)
			return nil
		}
		logger.CtxLog.Infof("creating UPF node: %s, IP: %s, ID: %s, UPF: %+v", upfName, nodeID.ResolveNodeIdToIp().String(), nodeIDStr, upfNode.UPF)

		existing.UPFs[upfName] = upfNode
		existing.UPNodes[upfName] = upfNode
		currentUPFs[upfName] = true

		ip := nodeID.ResolveNodeIdToIp()
		if ip != nil {
			ipStr := ip.String()
			existing.UPFIPToName[ipStr] = upfName
			existing.UPFsID[upfName] = string(nodeID.NodeIdValue)
			existing.UPFsIPtoID[ipStr] = string(nodeID.NodeIdValue)
		} else {
			logger.CtxLog.Warnf("invalid IP for UPF node %s", upfName)
		}

		if len(sm.GnbNames) == 0 {
			logger.CtxLog.Warnf("no gNBs provided for UPF %s, no AN-UPF link created", upfName)
		}

		for _, gnbName := range sm.GnbNames {
			if _, exists := existing.UPNodes[gnbName]; !exists {
				anNode := &UPNode{
					Type: UPNODE_AN,
					NodeID: NodeID{
						NodeIdType:  NodeIdTypeFqdn,
						NodeIdValue: []byte(gnbName),
					},
					Links: []*UPNode{},
				}
				existing.UPNodes[gnbName] = anNode
				existing.AccessNetwork[gnbName] = anNode
			}
			linkUpfToGnbNodes(existing, upfNode, []string{gnbName})
			currentANs[gnbName] = true
		}
	}
	existing.RebuildUPFMaps()
	removeInactiveUPNodes(existing.UPNodes, currentUPFs, currentANs)
	logger.CtxLog.Infof("UPF nodes: %+v", existing.UPNodes)
	return existing
}

func CreateNodeIDFromHostname(hostname string) NodeID {
	ip := net.ParseIP(hostname)
	if ip == nil {
		return NodeID{NodeIdType: NodeIdTypeFqdn, NodeIdValue: []byte(hostname)}
	} else if ip.To4() != nil {
		return NodeID{NodeIdType: NodeIdTypeIpv4Address, NodeIdValue: ip.To4()}
	} else {
		return NodeID{NodeIdType: NodeIdTypeIpv6Address, NodeIdValue: ip.To16()}
	}
}

func updateSNssaiInfo(upfNode *UPNode, newInfo models.SnssaiUpfInfoItem) {
	newSnssai := SnssaiUPFInfo{
		SNssai: SNssai{
			Sst: newInfo.SNssai.Sst,
			Sd:  newInfo.SNssai.Sd,
		},
		DnnList: make([]DnnUPFInfoItem, 0),
	}

	for _, dnnInfoConfig := range newInfo.DnnUpfInfoList {
		newSnssai.DnnList = append(newSnssai.DnnList, DnnUPFInfoItem{
			Dnn:             dnnInfoConfig.Dnn,
			DnaiList:        dnnInfoConfig.DnaiList,
			PduSessionTypes: dnnInfoConfig.PduSessionTypes,
		})
	}

	for i, existing := range upfNode.UPF.SNssaiInfos {
		existingSd := existing.SNssai.Sd
		newSd := newSnssai.SNssai.Sd
		sdMatch := (existingSd == newSd) || (existingSd == "" && newSd == "")
		if existing.SNssai.Sst == newSnssai.SNssai.Sst && sdMatch {
			upfNode.UPF.SNssaiInfos[i].DnnList = appendIfMissingDNNItems(
				existing.DnnList,
				newSnssai.DnnList,
			)
			return
		}
	}

	upfNode.UPF.SNssaiInfos = append(upfNode.UPF.SNssaiInfos, newSnssai)
}

func removeInactiveUPNodes(upnodes map[string]*UPNode, currentUPFs, currentANs map[string]bool) {
	for name, node := range upnodes {
		switch node.Type {
		case UPNODE_UPF:
			if _, stillActive := currentUPFs[name]; !stillActive {
				logger.CtxLog.Debugf("removing inactive UPF node: %s", name)
				delete(upnodes, name)
			}
		case UPNODE_AN:
			if _, stillActive := currentANs[name]; !stillActive {
				logger.CtxLog.Debugf("removing inactive AN node: %s", name)
				delete(upnodes, name)
			}
		}
	}
}

func linkUpfToGnbNodes(upi *UserPlaneInformation, upNode *UPNode, gnbNames []string) {
	for _, gnbName := range gnbNames {
		gnbNode, ok := upi.UPNodes[gnbName]
		if !ok {
			logger.CtxLog.Warnf("GNB node %s not found, skipping", gnbName)
			continue
		}

		if !nodeInLinks(upNode.Links, gnbNode) {
			upNode.Links = append(upNode.Links, gnbNode)
		}
		if !nodeInLinks(gnbNode.Links, upNode) {
			gnbNode.Links = append(gnbNode.Links, upNode)
		}
	}
}

func nodeInLinks(links []*UPNode, node *UPNode) bool {
	targetIP := node.NodeID.ResolveNodeIdToIp().String()
	for _, l := range links {
		if l.NodeID.ResolveNodeIdToIp().String() == targetIP {
			return true
		}
	}
	return false
}

func getOrCreateUpfNode(existing *UserPlaneInformation, name string, node *factory.UPNode) (*UPNode, error) {
	upNode, exists := existing.UPNodes[name]
	if exists {
		for _, newSnssaiInfo := range node.SNssaiInfos {
			updateSNssaiInfo(upNode, newSnssaiInfo)
		}
		return upNode, nil
	}

	upNode = new(UPNode)
	if node.Type != string(UPNODE_UPF) && node.Type != string(UPNODE_AN) {
		logger.InitLog.Warnf("UPNodeType not set or invalid for node %s, defaulting to UPNODE_UPF", name)
		upNode.Type = UPNODE_UPF
	} else {
		upNode.Type = UPNodeType(node.Type)
	}
	upNode.Port = node.Port

	switch upNode.Type {
	case UPNODE_AN:
		upNode.ANIP = net.ParseIP(node.ANIP)
		existing.AccessNetwork[name] = upNode

	case UPNODE_UPF:
		var nodeIdType uint8
		var ip net.IP

		if ip = net.ParseIP(node.NodeID); ip != nil {
			if ip.To4() != nil {
				ip = ip.To4()
				nodeIdType = NodeIdTypeIpv4Address
			} else {
				ip = ip.To16()
				nodeIdType = NodeIdTypeIpv6Address
			}
		} else {
			nodeIdType = NodeIdTypeFqdn
			ip = []byte(node.NodeID)
		}

		upNode.NodeID = NodeID{
			NodeIdType:  nodeIdType,
			NodeIdValue: []byte(ip),
		}

		upNode.UPF = NewUPF(&upNode.NodeID, node.InterfaceUpfInfoList)
		upNode.UPF.Port = upNode.Port
		snssaiInfos := make([]SnssaiUPFInfo, 0)
		for _, snssaiInfoConfig := range node.SNssaiInfos {
			snssaiInfo := SnssaiUPFInfo{
				SNssai: SNssai{
					Sst: snssaiInfoConfig.SNssai.Sst,
					Sd:  snssaiInfoConfig.SNssai.Sd,
				},
				DnnList: make([]DnnUPFInfoItem, 0),
			}

			for _, dnnInfoConfig := range snssaiInfoConfig.DnnUpfInfoList {
				snssaiInfo.DnnList = append(snssaiInfo.DnnList, DnnUPFInfoItem{
					Dnn:             dnnInfoConfig.Dnn,
					DnaiList:        dnnInfoConfig.DnaiList,
					PduSessionTypes: dnnInfoConfig.PduSessionTypes,
				})
			}
			snssaiInfos = append(snssaiInfos, snssaiInfo)
		}

		upNode.UPF.SNssaiInfos = snssaiInfos
		upNode.UPF.N3Interfaces = make([]UPFInterfaceInfo, 0)
		upNode.UPF.N9Interfaces = make([]UPFInterfaceInfo, 0)

		for _, iface := range node.InterfaceUpfInfoList {
			upIface := NewUPFInterfaceInfo(&iface)

			switch iface.InterfaceType {
			case models.UpInterfaceType_N3:
				upNode.UPF.N3Interfaces = append(upNode.UPF.N3Interfaces, *upIface)
			case models.UpInterfaceType_N9:
				upNode.UPF.N9Interfaces = append(upNode.UPF.N9Interfaces, *upIface)
			}
		}

		existing.UPFs[name] = upNode

	default:
		logger.InitLog.Warnf("invalid UPNodeType: %s", upNode.Type)
	}

	existing.UPNodes[name] = upNode
	ipStr := upNode.NodeID.ResolveNodeIdToIp().String()
	existing.UPFIPToName[ipStr] = name

	return upNode, nil
}

func resolvePfcpPort(p int32) uint16 {
	if p > 0 && p <= 65535 {
		return uint16(p)
	}
	return DefaultPfcpPort
}

func convertIpDomainsToDnnList(ipDomains []nfConfigApi.IpDomain) []DnnUPFInfoItem {
	dnnList := []DnnUPFInfoItem{}
	for _, domain := range ipDomains {
		dnnList = append(dnnList, DnnUPFInfoItem{
			Dnn:             domain.DnnName,
			DnaiList:        []string{""},
			PduSessionTypes: []models.PduSessionType{models.PduSessionType_IPV4},
		})
	}
	return dnnList
}

func appendIfMissingDNNItems(existingDnnList, newDnnList []DnnUPFInfoItem) []DnnUPFInfoItem {
	dnnMap := make(map[string]struct{})
	for _, existingDnn := range existingDnnList {
		dnnMap[existingDnn.Dnn] = struct{}{}
	}

	for _, newDnn := range newDnnList {
		if _, exists := dnnMap[newDnn.Dnn]; !exists {
			existingDnnList = append(existingDnnList, newDnn)
		}
	}

	return existingDnnList
}

func (upi *UserPlaneInformation) GetUPFNameByIp(ip string) string {
	return upi.UPFIPToName[ip]
}

func (upi *UserPlaneInformation) GetUPFNodeIDByName(name string) NodeID {
	return upi.UPFs[name].NodeID
}

func (upi *UserPlaneInformation) GetUPFNodeByIP(ip string) *UPNode {
	upfName := upi.GetUPFNameByIp(ip)
	return upi.UPFs[upfName]
}

func (upi *UserPlaneInformation) GetUPFIDByIP(ip string) string {
	return upi.UPFsIPtoID[ip]
}

func (upi *UserPlaneInformation) ResetDefaultUserPlanePath() {
	logger.UPNodeLog.Debugf("resetting the default user plane paths [%v]", upi.DefaultUserPlanePath)
	upi.DefaultUserPlanePath = make(map[string][]*UPNode)
}

func (upi *UserPlaneInformation) GetDefaultUserPlanePathByDNN(selection *UPFSelectionParams) (path UPPath) {
	path, pathExist := upi.DefaultUserPlanePath[selection.String()]
	logger.CtxLog.Debugln("in GetDefaultUserPlanePathByDNN")
	logger.CtxLog.Debugln("selection:", selection.String())
	if pathExist {
		return
	}
	logger.CtxLog.Debugln("Generating default path for DNN:", selection.Dnn)
	pathExist = upi.GenerateDefaultPath(selection)
	if pathExist {
		return upi.DefaultUserPlanePath[selection.String()]
	}
	logger.CtxLog.Warnln("Unable to find or generate default path for selection:", selection.String())
	return nil
}

func (upi *UserPlaneInformation) ExistDefaultPath(dnn string) bool {
	_, exist := upi.DefaultUserPlanePath[dnn]
	return exist
}

// Reset clears all internal state of the UserPlaneInformation structure.
// This is useful when rebuilding from scratch (on dynamic config reload).
func (upi *UserPlaneInformation) Reset() {
	upi.UPNodes = make(map[string]*UPNode)
	upi.UPFs = make(map[string]*UPNode)
	upi.AccessNetwork = make(map[string]*UPNode)
	upi.UPFIPToName = make(map[string]string)
	upi.UPFsID = make(map[string]string)
	upi.UPFsIPtoID = make(map[string]string)
	upi.DefaultUserPlanePath = make(map[string][]*UPNode)
}

func (upi *UserPlaneInformation) RebuildUPFMaps() {
	logger.CtxLog.Infoln("rebuilding UPF maps and default user plane paths")
	upi.ResetDefaultUserPlanePath()
	upi.DefaultUserPlanePath = make(map[string][]*UPNode)
	upi.UPFs = make(map[string]*UPNode)
	upi.UPFIPToName = make(map[string]string)
	upi.UPFsID = make(map[string]string)
	upi.UPFsIPtoID = make(map[string]string)

	for name, node := range upi.UPNodes {
		if node.Type != UPNODE_UPF {
			continue
		}
		if node.UPF == nil {
			logger.CtxLog.Warnf("UPF node %s missing UPF config, skipping", name)
			continue
		}
		nodeID := string(node.NodeID.NodeIdValue)
		upi.UPFs[name] = node
		upi.UPFIPToName[nodeID] = name
		upi.UPFsID[name] = nodeID
		upi.UPFsIPtoID[nodeID] = name
		logger.CtxLog.Infof("registered UPF %s with NodeID %s", name, nodeID)

		// create a default path from AN to UPF
		for _, snssaiInfo := range node.UPF.SNssaiInfos {
			for _, dnnInfo := range snssaiInfo.DnnList {
				dnn := dnnInfo.Dnn
				selection := &UPFSelectionParams{
					Dnn: dnn,
					SNssai: &SNssai{
						Sst: snssaiInfo.SNssai.Sst,
						Sd:  snssaiInfo.SNssai.Sd,
					},
				}
				key := selection.String()
				foundLink := false
				for _, an := range node.Links {
					if an == nil || an.Type != UPNODE_AN {
						continue
					}
					if _, exists := upi.DefaultUserPlanePath[key]; !exists {
						upi.DefaultUserPlanePath[key] = []*UPNode{an, node}
						logger.CtxLog.Debugf("default path added: AN %s -> UPF %s for key %s", string(an.NodeID.NodeIdValue), name, key)
					}
					foundLink = true
				}
				if !foundLink {
					logger.CtxLog.Warnf("no AN linked to UPF %s for SNSSAI %+v and DNN %s — default path not created", name, snssaiInfo.SNssai, dnn)
				}
			}
		}
	}
	logger.CtxLog.Debugln("finished rebuilding UPF maps")
}

func GenerateDataPath(upPath UPPath) *DataPath {
	if len(upPath) < 1 {
		logger.CtxLog.Errorf("Invalid data path")
		return nil
	}
	var root *DataPathNode
	var curDataPathNode *DataPathNode
	var prevDataPathNode *DataPathNode

	for _, upNode := range upPath {
		logger.CtxLog.Debugf("GenerateDataPath: processing node %+v", upNode)
		if upNode.Type != UPNODE_UPF || upNode.UPF == nil {
			logger.CtxLog.Debugf("generateDataPath: skipping non-UPF node: %v", upNode.NodeID)
			continue
		}
		curDataPathNode = NewDataPathNode()
		curDataPathNode.UPF = upNode.UPF

		if root == nil {
			root = curDataPathNode
			root.AddPrev(nil)
		} else {
			prevDataPathNode.AddNext(curDataPathNode)
			curDataPathNode.AddPrev(prevDataPathNode)
		}
		prevDataPathNode = curDataPathNode
	}

	if root == nil {
		logger.CtxLog.Error("GenerateDataPath: failed to generate root datapath node (all nodes skipped)")
		return nil
	}

	return &DataPath{
		Destination:   Destination{},
		FirstDPNode:   root,
		Activated:     false,
		IsDefaultPath: false,
	}
}

func (upi *UserPlaneInformation) GenerateDefaultPath(selection *UPFSelectionParams) (pathExist bool) {
	var source *UPNode
	var destinations []*UPNode

	for len(upi.AccessNetwork) == 0 {
		logger.CtxLog.Errorf("there is no AN Node in config file")
		return false
	}
	logger.CtxLog.Infof("UPFs registered: %v", upi.UPFs)
	logger.CtxLog.Infof("AccessNetworks registered: %v", upi.AccessNetwork)
	destinations = upi.selectMatchUPF(selection)
	logger.CtxLog.Debugf("destinations: %+v", destinations)
	logger.CtxLog.Debugf("selectionParams: %+v, count: %d", selection, len(destinations))
	if len(destinations) == 0 {
		logger.CtxLog.Errorf("can not find UPF with DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]", selection.Dnn,
			selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)
		return false
	}
	logger.CtxLog.Debugf("found UPF with DNN[%s] S-NSSAI[sst: %d sd: %s] DNAI[%s]", selection.Dnn,
		selection.SNssai.Sst, selection.SNssai.Sd, selection.Dnai)

	visited := make(map[*UPNode]bool)
	for _, upNode := range upi.UPNodes {
		visited[upNode] = false
	}

	for anName, node := range upi.AccessNetwork {
		if node.Type == UPNODE_AN {
			source = node
			var path []*UPNode
			path, pathExist = getPathBetween(source, destinations[0], visited, selection)

			if pathExist {
				if path[0].Type == UPNODE_AN {
					path = path[1:]
				}
				upi.DefaultUserPlanePath[selection.String()] = path
				logger.CtxLog.Debugf("path successfully generated:")
				logger.CtxLog.Debugf("path: %+v, upf: %s, anName: %s", path, string(destinations[0].NodeID.NodeIdValue), anName)
				break
			} else {
				logger.CtxLog.Debugf("no path between an-node[%v] and upf[%v]", anName, string(destinations[0].NodeID.NodeIdValue))
				continue
			}
		}
	}

	return pathExist
}

func (upi *UserPlaneInformation) selectMatchUPF(selection *UPFSelectionParams) []*UPNode {
	upList := make([]*UPNode, 0)

	for _, upNode := range upi.UPFs {
		logger.CtxLog.Debugf("Checking UPF: %+v", upNode)
		for _, snssaiInfo := range upNode.UPF.SNssaiInfos {
			logger.CtxLog.Debugf("SNssai: %+v", snssaiInfo.SNssai)
			currentSnssai := &snssaiInfo.SNssai
			targetSnssai := selection.SNssai

			if currentSnssai.Equal(targetSnssai) {
				for _, dnnInfo := range snssaiInfo.DnnList {
					logger.CtxLog.Debugf("DNN: %s, DnaiList: %v", dnnInfo.Dnn, dnnInfo.DnaiList)
					if dnnInfo.Dnn == selection.Dnn && dnnInfo.ContainsDNAI(selection.Dnai) {
						logger.CtxLog.Debugf("selectMatchUPF: found match")
						upList = append(upList, upNode)
						break
					}
				}
			}
		}
	}
	return upList
}

func getPathBetween(cur *UPNode, dest *UPNode, visited map[*UPNode]bool,
	selection *UPFSelectionParams,
) (path []*UPNode, pathExist bool) {
	visited[cur] = true

	if reflect.DeepEqual(*cur, *dest) {
		path = make([]*UPNode, 0)
		path = append(path, cur)
		pathExist = true
		return path, pathExist
	}

	selectedSNssai := selection.SNssai

	for _, nodes := range cur.Links {
		if !visited[nodes] {
			if !nodes.UPF.isSupportSnssai(selectedSNssai) {
				visited[nodes] = true
				continue
			}

			path_tail, path_exist := getPathBetween(nodes, dest, visited, selection)

			if path_exist {
				path = make([]*UPNode, 0)
				path = append(path, cur)

				path = append(path, path_tail...)
				pathExist = true

				return path, pathExist
			}
		}
	}

	return nil, false
}

// insert new UPF (only N3)
func (upi *UserPlaneInformation) InsertSmfUserPlaneNode(name string, node *factory.UPNode) error {
	logger.UPNodeLog.Infof("UPNode[%v] to insert, content[%v]", name, node)
	logger.UPNodeLog.Debugf("content of map[UPNodes] %v", upi.UPNodes)

	upNode := new(UPNode)
	upNode.Type = UPNodeType(node.Type)
	upNode.Port = node.Port
	switch upNode.Type {
	case UPNODE_AN:
		upNode.ANIP = net.ParseIP(node.ANIP)
		upi.AccessNetwork[name] = upNode
	case UPNODE_UPF:
		// ParseIp() always return 16 bytes
		// so we can't use the length of return ip to separate IPv4 and IPv6
		var (
			nodeIdType uint8
			ip         net.IP
		)

		// Find IP
		if ip = net.ParseIP(node.NodeID); ip != nil {
			logger.UPNodeLog.Debugf("parsed IP: %s", ip)
			// v4 or v6
			if ip.To4() != nil {
				// IPv4
				ip = ip.To4()
				nodeIdType = NodeIdTypeIpv4Address
			} else {
				// IPv6
				ip = ip.To16()
				nodeIdType = NodeIdTypeIpv6Address
			}
		} else {
			// FQDN
			nodeIdType = NodeIdTypeFqdn
			ip = []byte(node.NodeID)
		}
		// Populate outcome
		upNode.NodeID = NodeID{
			NodeIdType:  nodeIdType,
			NodeIdValue: []byte(ip),
		}

		upNode.UPF = NewUPF(&upNode.NodeID, node.InterfaceUpfInfoList)
		upNode.UPF.Port = upNode.Port

		snssaiInfos := make([]SnssaiUPFInfo, 0)
		for _, snssaiInfoConfig := range node.SNssaiInfos {
			snssaiInfo := SnssaiUPFInfo{
				SNssai: SNssai{
					Sst: snssaiInfoConfig.SNssai.Sst,
					Sd:  snssaiInfoConfig.SNssai.Sd,
				},
				DnnList: make([]DnnUPFInfoItem, 0),
			}

			for _, dnnInfoConfig := range snssaiInfoConfig.DnnUpfInfoList {
				snssaiInfo.DnnList = append(snssaiInfo.DnnList, DnnUPFInfoItem{
					Dnn:             dnnInfoConfig.Dnn,
					DnaiList:        dnnInfoConfig.DnaiList,
					PduSessionTypes: dnnInfoConfig.PduSessionTypes,
				})
			}
			snssaiInfos = append(snssaiInfos, snssaiInfo)
		}
		upNode.UPF.SNssaiInfos = snssaiInfos
		upi.UPFs[name] = upNode
	default:
		logger.InitLog.Warnf("invalid UPNodeType: %s", upNode.Type)
	}

	upi.UPNodes[name] = upNode

	ipStr := upNode.NodeID.ResolveNodeIdToIp().String()
	upi.UPFIPToName[ipStr] = name

	return nil
}

// Update an existing User Plane Node.
// If the node is of type AN, then the node is updated with the new port.
// If the node is of type UPF, then the node is updated with the new port and the new UPF information.
func (upi *UserPlaneInformation) UpdateSmfUserPlaneNode(name string, newNode *factory.UPNode) error {
	logger.UPNodeLog.Infof("UPNode [%v] to update, content[%v]", name, newNode)

	existingNode, exists := upi.UPNodes[name]
	if !exists {
		return fmt.Errorf("UPNode [%s] does not exist", name)
	}

	existingNode.Port = newNode.Port

	switch existingNode.Type {
	case UPNODE_AN:
		existingNode.ANIP = net.ParseIP(newNode.ANIP)
	case UPNODE_UPF:

		var nodeIdType uint8

		ip := net.ParseIP(newNode.NodeID)
		if ip == nil {
			nodeIdType = NodeIdTypeFqdn
			ip = []byte(newNode.NodeID)
		} else if ip.To4() != nil {
			nodeIdType = NodeIdTypeIpv4Address
			ip = ip.To4()
		} else {
			nodeIdType = NodeIdTypeIpv6Address
			ip = ip.To16()
		}

		newNodeID := NodeID{
			NodeIdType:  nodeIdType,
			NodeIdValue: []byte(ip),
		}

		if !reflect.DeepEqual(existingNode.NodeID, newNodeID) {
			existingNode.NodeID = newNodeID
			existingNode.UPF = NewUPF(&existingNode.NodeID, newNode.InterfaceUpfInfoList)
		}

		existingNode.UPF.SNssaiInfos = make([]SnssaiUPFInfo, len(newNode.SNssaiInfos))
		for i, snssaiInfoConfig := range newNode.SNssaiInfos {
			existingNode.UPF.SNssaiInfos[i] = SnssaiUPFInfo{
				SNssai: SNssai{
					Sst: snssaiInfoConfig.SNssai.Sst,
					Sd:  snssaiInfoConfig.SNssai.Sd,
				},
				DnnList: make([]DnnUPFInfoItem, len(snssaiInfoConfig.DnnUpfInfoList)),
			}

			for j, dnnInfoConfig := range snssaiInfoConfig.DnnUpfInfoList {
				existingNode.UPF.SNssaiInfos[i].DnnList[j] = DnnUPFInfoItem{
					Dnn:             dnnInfoConfig.Dnn,
					DnaiList:        dnnInfoConfig.DnaiList,
					PduSessionTypes: dnnInfoConfig.PduSessionTypes,
				}
			}
		}
		upi.UPFs[name] = existingNode
	default:
		logger.InitLog.Warnf("invalid UPNodeType: %s", existingNode.Type)
	}

	upi.UPNodes[name] = existingNode

	ipStr := existingNode.NodeID.ResolveNodeIdToIp().String()
	upi.UPFIPToName[ipStr] = name

	logger.CtxLog.Infof("UPNode [%s] updated successfully", name)
	return nil
}

func (upi *UserPlaneInformation) InsertUPNodeLinks(link *factory.UPLink) error {
	// Update Links
	logger.UPNodeLog.Infof("inserting UP Node link[%v] ", link)
	logger.UPNodeLog.Debugf("current UP Nodes [%+v]", upi.UPNodes)
	nodeA := upi.UPNodes[link.A]
	nodeB := upi.UPNodes[link.B]
	if nodeA == nil || nodeB == nil {
		logger.UPNodeLog.Warnf("UPLink [%s] <=> [%s] not establish", link.A, link.B)
		panic("Invalid UPF Links")
	}
	nodeA.Links = append(nodeA.Links, nodeB)
	nodeB.Links = append(nodeB.Links, nodeA)

	return nil
}

func (upi *UserPlaneInformation) DeleteUPNodeLinks(link *factory.UPLink) error {
	logger.UPNodeLog.Infof("deleting UP Node link[%v]", link)
	logger.UPNodeLog.Debugf("current UP Nodes [%+v]", upi.UPNodes)

	nodeA := upi.UPNodes[link.A]
	nodeB := upi.UPNodes[link.B]

	// Iterate through node-A links and remove Node-B
	if nodeA != nil {
		for index, upNode := range nodeA.Links {
			if bytes.Equal(upNode.NodeID.NodeIdValue, nodeB.NodeID.NodeIdValue) {
				// skip nodeB from Links
				nodeA.Links = append(nodeA.Links[:index], nodeA.Links[index+1:]...)
				break
			}
		}
	}

	// Iterate through node-B links and remove Node-A
	if nodeB != nil {
		for index, upNode := range nodeB.Links {
			if bytes.Equal(upNode.NodeID.NodeIdValue, nodeA.NodeID.NodeIdValue) {
				// skip nodeA from Links
				nodeB.Links = append(nodeB.Links[:index], nodeB.Links[index+1:]...)
				break
			}
		}
	}

	return nil
}
