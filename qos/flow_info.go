// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package qos

import (
	"log"
	"strconv"
	"strings"

	"github.com/free5gc/openapi/models"
)

// TS 24.501 Table 9.11.4.12
const (
	QosFlowDescriptionParameterId5Qi     uint8 = 0x01
	QosFlowDescriptionParameterIdGfbrUl  uint8 = 0x02
	QosFlowDescriptionParameterIdGfbrDl  uint8 = 0x03
	QosFlowDescriptionParameterIdMfbrUl  uint8 = 0x04
	QosFlowDescriptionParameterIdMfbrDl  uint8 = 0x05
	QosFlowDescriptionParameterIdAvgWind uint8 = 0x06
	QosFlowDescriptionParameterIdEpsBId  uint8 = 0x07
)

const (
	QosFlowBitRate1Kbps uint8 = 0x01
	QosFlowBitRate1Mbps uint8 = 0x06
	QosFlowBitRate1Gbps uint8 = 0x0B
)

const (
	QosFlowDescriptionOpCreate uint8 = 0x01
	QosFlowDescriptionOpModify uint8 = 0x02
	QosFlowDescriptionOpDelete uint8 = 0x03
)

type QoSFlowDescription struct {
	Qfi        uint8
	OpCode     uint8
	NumOfParam uint8
	ParamList  []QosFlowParameter
}

func GetBitRate(sBitRate string) (val uint16, unit uint8) {
	sl := strings.Fields(sBitRate)

	//rate
	if rate, err := strconv.Atoi(sl[0]); err != nil {
		log.Printf("invalid bit rate [%v]", sBitRate)
	} else {
		val = uint16(rate)
	}

	//Unit
	switch sl[2] {
	case "Kbps":
		unit = QosFlowBitRate1Kbps
	case "Mbps":
		unit = QosFlowBitRate1Mbps
	case "Gbps":
		unit = QosFlowBitRate1Gbps
	default:
		unit = QosFlowBitRate1Mbps
	}
	return
}

func (f *QoSFlowDescription) SetQoSFlowDescQfi(val uint8) {
	f.Qfi = 0x3f & val
}

func (f *QoSFlowDescription) SetQoSFlowDescOpCode(val uint8) {
	f.OpCode = 0xe0 & val
}

//make and encode Authorized Qos Flow Description Parameter
type QosFlowParameter struct {
	ParamId      uint8
	ParamLen     uint8
	ParamContent []byte
}

func (p *QosFlowParameter) SetQosFlowParam5Qi(val uint8) {

	p.ParamId = QosFlowDescriptionParameterId5Qi
	p.ParamLen = 1
	p.ParamContent = []byte{val}
}

func (p *QosFlowParameter) SetQosFlowParamBitRate(rateType, rateUnit uint8, rateVal uint16) {

	p.ParamId = rateType //(i.e. QosFlowDescriptionParameterIdGfbrUl)
	p.ParamLen = 0x03    //(Length is rate unit(1 byte) + rate value(2 bytes))
	p.ParamContent = []byte{rateUnit}
	p.ParamContent = append(p.ParamContent, byte(rateVal>>8), byte(rateVal&0xff))
}

func BuildQosFlowDescFromQoSDesc(qosData *models.QosData) {

	qfd := QoSFlowDescription{}

	//Set QFI
	qfd.SetQoSFlowDescQfi(uint8(qosData.Var5qi))

	//Operation Code
	qfd.SetQoSFlowDescOpCode(QosFlowDescriptionOpCreate)

	//Create Params
	//5QI
	qfp5Qi := QosFlowParameter{}
	qfp5Qi.SetQosFlowParam5Qi(uint8(qosData.Var5qi))

	//MFBR uplink
	qfpMfbrUl := QosFlowParameter{}
	bitRate, unit := GetBitRate(qosData.MaxbrUl)
	qfpMfbrUl.SetQosFlowParamBitRate(QosFlowDescriptionParameterIdMfbrUl, unit, bitRate)
}
