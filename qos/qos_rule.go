// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package qos

import (
	"bytes"
	"encoding/binary"
	"log"
	"strconv"

	"github.com/free5gc/openapi/models"
)

const (
	OperationCodeCreateNewQoSRule                                   uint8 = 1
	OperationCodeDeleteExistingQoSRule                              uint8 = 2
	OperationCodeModifyExistingQoSRuleAndAddPacketFilters           uint8 = 3
	OperationCodeModifyExistingQoSRuleAndReplaceAllPacketFilters    uint8 = 4
	OperationCodeModifyExistingQoSRuleAndDeletePacketFilters        uint8 = 5
	OperationCodeModifyExistingQoSRuleWithoutModifyingPacketFilters uint8 = 6
)

const (
	PacketFilterDirectionDownlink      uint8 = 1
	PacketFilterDirectionUplink        uint8 = 2
	PacketFilterDirectionBidirectional uint8 = 3
)

// TS 24.501 Table 9.11.4.13.1
const (
	PacketFilterComponentTypeMatchAll                       uint8 = 0x01
	PacketFilterComponentTypeIPv4RemoteAddress              uint8 = 0x10
	PacketFilterComponentTypeIPv4LocalAddress               uint8 = 0x11
	PacketFilterComponentTypeIPv6RemoteAddress              uint8 = 0x21
	PacketFilterComponentTypeIPv6LocalAddress               uint8 = 0x23
	PacketFilterComponentTypeProtocolIdentifierOrNextHeader uint8 = 0x30
	PacketFilterComponentTypeSingleLocalPort                uint8 = 0x40
	PacketFilterComponentTypeLocalPortRange                 uint8 = 0x41
	PacketFilterComponentTypeSingleRemotePort               uint8 = 0x50
	PacketFilterComponentTypeRemotePortRange                uint8 = 0x51
	PacketFilterComponentTypeSecurityParameterIndex         uint8 = 0x60
	PacketFilterComponentTypeTypeOfServiceOrTrafficClass    uint8 = 0x70
	PacketFilterComponentTypeFlowLabel                      uint8 = 0x80
	PacketFilterComponentTypeDestinationMACAddress          uint8 = 0x81
	PacketFilterComponentTypeSourceMACAddress               uint8 = 0x82
	PacketFilterComponentType8021Q_CTAG_VID                 uint8 = 0x83
	PacketFilterComponentType8021Q_STAG_VID                 uint8 = 0x84
	PacketFilterComponentType8021Q_CTAG_PCPOrDEI            uint8 = 0x85
	PacketFilterComponentType8021Q_STAG_PCPOrDEI            uint8 = 0x86
	PacketFilterComponentTypeEthertype                      uint8 = 0x87
)

type PacketFilterComponent struct {
	ComponentType  uint8
	ComponentValue []byte
}

type PacketFilter struct {
	Direction  uint8
	Identifier uint8
	//ComponentType uint8
	Content []PacketFilterComponent
}

func (pf *PacketFilter) MarshalBinary() (data []byte, err error) {
	packetFilterBuffer := bytes.NewBuffer(nil)
	header := 0 | pf.Direction<<4 | pf.Identifier
	// write header
	err = packetFilterBuffer.WriteByte(header)
	if err != nil {
		return nil, err
	}
	// write length of packet filter
	err = packetFilterBuffer.WriteByte(uint8(len(pf.Content)))
	if err != nil {
		return nil, err
	}

	for _, content := range pf.Content {
		err = packetFilterBuffer.WriteByte(content.ComponentType)
		if err != nil {
			return nil, err
		}
		_, err = packetFilterBuffer.Write(content.ComponentValue)
		if err != nil {
			return nil, err
		}
	}
	/*
		err = packetFilterBuffer.WriteByte(pf.Content)
		if err != nil {
			return nil, err
		}

		if pf.ComponentType == PacketFilterComponentTypeMatchAll || pf.Component == nil {
			_, err = packetFilterBuffer.Write(pf.Component)
			if err != nil {
				return nil, err
			}
		}
	*/
	return packetFilterBuffer.Bytes(), nil
}

type QoSRule struct {
	Identifier       uint8
	OperationCode    uint8
	DQR              uint8
	Segregation      uint8
	PacketFilterList []PacketFilter
	Precedence       uint8
	QFI              uint8
}

func (r *QoSRule) MarshalBinary() ([]byte, error) {
	ruleContentBuffer := bytes.NewBuffer(nil)

	// write rule content Header
	ruleContentHeader := r.OperationCode<<5 | r.DQR<<4 | uint8(len(r.PacketFilterList))
	ruleContentBuffer.WriteByte(ruleContentHeader)

	packetFilterListBuffer := &bytes.Buffer{}
	for _, pf := range r.PacketFilterList {
		var packetFilterBytes []byte
		if retPacketFilterByte, err := pf.MarshalBinary(); err != nil {
			return nil, err
		} else {
			packetFilterBytes = retPacketFilterByte
		}

		if _, err := packetFilterListBuffer.Write(packetFilterBytes); err != nil {
			return nil, err
		}
	}

	// write QoS
	if _, err := ruleContentBuffer.ReadFrom(packetFilterListBuffer); err != nil {
		return nil, err
	}

	// write precedence
	if err := ruleContentBuffer.WriteByte(r.Precedence); err != nil {
		return nil, err
	}

	// write Segregation and QFI
	segregationAndQFIByte := r.Segregation<<6 | r.QFI
	if err := ruleContentBuffer.WriteByte(segregationAndQFIByte); err != nil {
		return nil, err
	}

	ruleBuffer := bytes.NewBuffer(nil)
	// write QoS rule identifier
	if err := ruleBuffer.WriteByte(r.Identifier); err != nil {
		return nil, err
	}

	// write QoS rule length
	if err := binary.Write(ruleBuffer, binary.BigEndian, uint16(ruleContentBuffer.Len())); err != nil {
		return nil, err
	}
	// write QoS rule Content
	if _, err := ruleBuffer.ReadFrom(ruleContentBuffer); err != nil {
		return nil, err
	}

	return ruleBuffer.Bytes(), nil
}

type QoSRules []QoSRule

func (rs QoSRules) MarshalBinary() (data []byte, err error) {
	qosRulesBuffer := bytes.NewBuffer(nil)

	for _, rule := range rs {
		var ruleBytes []byte
		if retRuleBytes, err := rule.MarshalBinary(); err != nil {
			return nil, err
		} else {
			ruleBytes = retRuleBytes
		}

		if _, err := qosRulesBuffer.Write(ruleBytes); err != nil {
			return nil, err
		}
	}
	return qosRulesBuffer.Bytes(), nil
}

/*
func BuildDefaultQosRule() *QoSRule {

	return &QoSRule{
		Identifier:    0x01,
		DQR:           0x01,
		OperationCode: OperationCodeCreateNewQoSRule,
		Precedence:    0xff,
		QFI:           uint8(authDefQos.Var5qi),
		PacketFilterList: []PacketFilter{
			{
				Identifier:    0x01,
				Direction:     PacketFilterDirectionBidirectional,
				ComponentType: PacketFilterComponentTypeMatchAll,
			},
		},
	}
}
*/

func BuildQosRules(smPolicyUpdates *PolicyUpdate) QoSRules {
	qosRules := QoSRules{}

	smPolicyDecision := smPolicyUpdates.SmPolicyDecision
	pccRulesUpdate := smPolicyUpdates.PccRuleUpdate

	//New Rules to be added
	for pccRuleName, pccRuleVal := range pccRulesUpdate.add {
		log.Printf("Building QoS Rule from PCC rule [%s]", pccRuleName)
		refQosData := GetQoSDataFromPolicyDecision(smPolicyDecision, pccRuleVal.RefQosData[1])
		qosRule := BuildAddQoSRuleFromPccRule(pccRuleVal, refQosData, OperationCodeCreateNewQoSRule)
		qosRules = append(qosRules, *qosRule)
	}

	//Rules to be modified
	//TODO

	//Rules to be deleted
	//TODO
	return qosRules
}

func BuildAddQoSRuleFromPccRule(pccRule *models.PccRule, qosData *models.QosData, pccRuleOpCode uint8) *QoSRule {

	qRule := QoSRule{
		Identifier:       GetQosRuleIdFromPccRuleId(pccRule.PccRuleId),
		DQR:              btou(qosData.DefQosFlowIndication),
		OperationCode:    pccRuleOpCode,
		Precedence:       uint8(pccRule.Precedence),
		QFI:              uint8(qosData.Var5qi),
		PacketFilterList: BuildPacketFilterListFromPccRule(pccRule),
	}

	return &qRule
}

func BuildModifyQosRuleFromPccRule(pccRule *models.PccRule) *QoSRule {
	return nil
}

func BuildDeleteQosRuleFromPccRule(pccRule *models.PccRule) *QoSRule {
	return nil
}

func btou(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func GetQosRuleIdFromPccRuleId(pccRuleId string) uint8 {
	if id, err := strconv.Atoi(pccRuleId); err != nil {
		//TODO: Error Log
		return 0
	} else {
		return uint8(id)
	}
}

func BuildPacketFilterListFromPccRule(pccRule *models.PccRule) []PacketFilter {

	pfList := []PacketFilter{}

	//Iterate through
	for _, flow := range pccRule.FlowInfos {
		pf := GetPacketFilterFromFlowInfo(&flow)
		pfList = append(pfList, pf)
	}
	return pfList
}

func GetPacketFilterFromFlowInfo(flowInfo *models.FlowInformation) (pf PacketFilter) {

	return PacketFilter{
		Identifier: GetPfId(flowInfo.PackFiltId),
		Direction:  GetPfDirectionFromPccFlowInfo(flowInfo.FlowDirection),
		Content:    GetPfContent(flowInfo.FlowDescription),
	}
}

func GetPfId(ids string) uint8 {
	if id, err := strconv.Atoi(ids); err != nil {
		//TODO: Error Log
		return 0
	} else {
		return uint8(id)
	}
}

//Get Packet Filter Directions
func GetPfDirectionFromPccFlowInfo(flowDir models.FlowDirectionRm) uint8 {
	switch flowDir {
	case models.FlowDirectionRm_UPLINK:
		return PacketFilterDirectionUplink
	case models.FlowDirectionRm_DOWNLINK:
		return PacketFilterDirectionDownlink
	case models.FlowDirectionRm_BIDIRECTIONAL:
		return PacketFilterDirectionBidirectional
	default:
		//TODO: Error Log
		return PacketFilterDirectionBidirectional
	}
}

//BuildPfContent- builds PF content from Flow Description(only if required to be sent to UE)
// e.x. permit out ip from 0.0.0.0/0 to assigned
func GetPfContent(flowDes string) []PacketFilterComponent {
	//Tokenize flow desc and make PF components
	//strings.Fields("string")
	pfc := PacketFilterComponent{
		ComponentType: PacketFilterComponentTypeMatchAll,
	}
	return []PacketFilterComponent{pfc}
}
