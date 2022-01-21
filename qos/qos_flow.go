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
/*
-	01H (5QI);
-	02H (GFBR uplink);
-	03H (GFBR downlink);
-	04H (MFBR uplink);
-	05H (MFBR downlink);
-	06H (Averaging window); and
-	07H (EPS bearer identity).
*/
const (
	QFDParameterId5Qi     uint8 = 0x01
	QFDParameterIdGfbrUl  uint8 = 0x02
	QFDParameterIdGfbrDl  uint8 = 0x03
	QFDParameterIdMfbrUl  uint8 = 0x04
	QFDParameterIdMfbrDl  uint8 = 0x05
	QFDParameterIdAvgWind uint8 = 0x06
	QFDParameterIdEpsBId  uint8 = 0x07
)

const (
	QFBitRate1Kbps uint8 = 0x01
	QFBitRate1Mbps uint8 = 0x06
	QFBitRate1Gbps uint8 = 0x0B
)

const (
	QFDOpCreate uint8 = 0x01
	QFDOpModify uint8 = 0x02
	QFDOpDelete uint8 = 0x03
)

const (
	QFDQfiBitmask    uint8 = 0x3f //bits 6 to 1 of octet
	QFDOpCodeBitmask uint8 = 0xe0 // bits 8 to 6 of octet
	QFDEbit          uint8 = 0x40 // 7th bit of param length octet

)

type QoSFlowDescription struct {
	Qfi        uint8
	OpCode     uint8
	NumOfParam uint8
	ParamList  []QosFlowParameter
}

type QosFlowsUpdate struct {
	add, mod, del map[string]*models.QosData
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
	switch sl[1] {
	case "Kbps":
		unit = QFBitRate1Kbps
	case "Mbps":
		unit = QFBitRate1Mbps
	case "Gbps":
		unit = QFBitRate1Gbps
	default:
		unit = QFBitRate1Mbps
	}
	return
}

//bits 6 to 1 of octet(00xxxxxx)
func (f *QoSFlowDescription) SetQoSFlowDescQfi(val uint8) {
	f.Qfi = QFDQfiBitmask & val
}

//Operation code -bits 8 to 6 of octet(xxx00000)
func (f *QoSFlowDescription) SetQoSFlowDescOpCode(val uint8) {
	f.OpCode = QFDOpCodeBitmask & val
}

//E-Bit Encoding
//For the "create new QoS flow description" operation,
//1:	parameters list is included
func (f *QoSFlowDescription) SetQFDEBitCreateNewQFD() {
	f.NumOfParam |= QFDEbit
}

//For the "Delete existing QoS flow description" operation
//0:	parameters list is not included
func (f *QoSFlowDescription) SetQFDEBitDeleteExistingQFD() {
	f.NumOfParam &= ^QFDEbit
}

//For the "modify existing QoS flow description" operation
//0:	extension of previously provided parameters
func (f *QoSFlowDescription) SetQFDEBitModExtendParamQFD() {
	f.NumOfParam &= ^QFDEbit
}

//For the "modify existing QoS flow description" operation
//1:	replacement of all previously provided parameters
func (f *QoSFlowDescription) SetQFDEBitModReplaceAllParamQFD() {
	f.NumOfParam |= QFDEbit
}

//make and encode Authorized Qos Flow Description Parameter
type QosFlowParameter struct {
	ParamId      uint8
	ParamLen     uint8
	ParamContent []byte
}

func (p *QosFlowParameter) SetQosFlowParam5Qi(val uint8) {

	p.ParamId = QFDParameterId5Qi
	p.ParamLen = 1 //1 Octet
	p.ParamContent = []byte{val}
}

func (p *QosFlowParameter) SetQosFlowParamBitRate(rateType, rateUnit uint8, rateVal uint16) {

	p.ParamId = rateType //(i.e. QosFlowDescriptionParameterIdGfbrUl)
	p.ParamLen = 0x03    //(Length is rate unit(1 byte) + rate value(2 bytes))
	p.ParamContent = []byte{rateUnit}
	p.ParamContent = append(p.ParamContent, byte(rateVal>>8), byte(rateVal&0xff))
}

//Build Qos Flow Description to be sent to UE
func BuildQosFlowDescription(smCtxtPolicyData SmCtxtPolicyData, smPolicyDec *models.SmPolicyDecision) {

}

func BuildQosFlowDescFromQoSDesc(qosData *models.QosData) {

	qfd := QoSFlowDescription{}

	//Set QFI
	qfd.SetQoSFlowDescQfi(uint8(qosData.Var5qi))

	//Operation Code
	qfd.SetQoSFlowDescOpCode(QFDOpCreate)

	//Create Params
	//5QI
	qfp5Qi := QosFlowParameter{}
	qfp5Qi.SetQosFlowParam5Qi(uint8(qosData.Var5qi))
	//Add to QosFlowDescription
	qfd.NumOfParam += 1
	qfd.ParamList = append(qfd.ParamList, qfp5Qi)

	//MFBR uplink
	if qosData.MaxbrUl != "" {
		qfd.addQosFlowRateParam(qosData.MaxbrUl, QFDParameterIdMfbrUl)
	}

	//MFBR downlink
	if qosData.MaxbrDl != "" {
		qfd.addQosFlowRateParam(qosData.MaxbrDl, QFDParameterIdMfbrDl)
	}

	//GFBR uplink
	if qosData.GbrUl != "" {
		qfd.addQosFlowRateParam(qosData.GbrUl, QFDParameterIdGfbrUl)
	}

	//GFBR downlink
	if qosData.GbrDl != "" {
		qfd.addQosFlowRateParam(qosData.GbrDl, QFDParameterIdGfbrDl)
	}
}

func (qfd *QoSFlowDescription) addQosFlowRateParam(rate string, rateType uint8) {
	flowParam := QosFlowParameter{}
	bitRate, unit := GetBitRate(rate)
	flowParam.SetQosFlowParamBitRate(rateType, unit, bitRate)
	//Add to QosFlowDescription
	qfd.NumOfParam += 1
	qfd.ParamList = append(qfd.ParamList, flowParam)
}

func GetQosFlowDescUpdate(pcfQosData, ctxtQosData map[string]*models.QosData) *QosFlowsUpdate {

	update := QosFlowsUpdate{
		add: make(map[string]*models.QosData),
		mod: make(map[string]*models.QosData),
		del: make(map[string]*models.QosData),
	}

	//Iterate through pcf qos data to identify find add/mod qos flows
	for name, pcfQF := range pcfQosData {
		if ctxtQF := ctxtQosData[name]; ctxtQF != nil {
			update.add[name] = pcfQF
		} else if GetQosDataChanges(pcfQF, ctxtQF) {
			update.mod[name] = pcfQF
		}
	}

	//Identify Qos Flow to be deleted
	for name, ctxtQF := range ctxtQosData {
		if pcfQF := pcfQosData[name]; pcfQF != nil {
			update.del[name] = ctxtQF
		}
	}

	return &update
}

//Compare if any change in QoS Data
func GetQosDataChanges(qf1, qf2 *models.QosData) bool {
	return false
}

func GetQoSDataFromPolicyDecision(smPolicyDecision *models.SmPolicyDecision, refQosData string) *models.QosData {
	return smPolicyDecision.QosDecs[refQosData]
}
