// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"maps"
	"strconv"
	"strings"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/logger"
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
	QFDOpCreate uint8 = 0x20
	QFDOpModify uint8 = 0x40
	QFDOpDelete uint8 = 0x60
)

const (
	QFDQfiBitmask    uint8 = 0x3f // bits 6 to 1 of octet
	QFDOpCodeBitmask uint8 = 0xe0 // bits 8 to 6 of octet
	QFDEbit          uint8 = 0x40 // 7th bit of param length octet
)

const (
	QFDFixLen uint8 = 0x03
)

type QosFlowDescriptionsAuthorized struct {
	Content []byte
	IeType  uint8
	IeLen   uint16
}

type QoSFlowDescription struct {
	ParamList  []QosFlowParameter
	Qfi        uint8
	OpCode     uint8
	NumOfParam uint8
	QFDLen     uint8
}

// Qos Flow Description Parameter
type QosFlowParameter struct {
	ParamContent []byte
	ParamId      uint8
	ParamLen     uint8
}

type QosFlowsUpdate struct {
	add, mod, del map[string]*models.QosData
}

func GetQosFlowIdFromQosId(qosId string) uint8 {
	id, err := strconv.Atoi(qosId)
	if err != nil {
		logger.CtxLog.Errorf("string can not be converted to integer: %+v", err)
		return 0
	} else {
		return uint8(id)
	}
}

// Build Qos Flow Description to be sent to UE
func BuildAuthorizedQosFlowDescriptions(smPolicyUpdates *PolicyUpdate) *QosFlowDescriptionsAuthorized {
	QFDescriptions := QosFlowDescriptionsAuthorized{
		IeType:  nasMessage.PDUSessionEstablishmentAcceptAuthorizedQosFlowDescriptionsType,
		Content: make([]byte, 0),
	}

	qosFlowUpdate := smPolicyUpdates.QosFlowUpdate

	// QoS Flow Description to be Added
	if qosFlowUpdate != nil {
		for name, qosFlow := range qosFlowUpdate.add {
			logger.QosLog.Infof("adding Qos Flow Description [%v]", name)
			QFDescriptions.BuildAddQosFlowDescFromQoSDesc(qosFlow)
		}
	}

	// QoS Flow Description to be Modified
	// TODO

	// QoS Flow Description to be Deleted
	// TODO

	return &QFDescriptions
}

func (d *QosFlowDescriptionsAuthorized) BuildAddQosFlowDescFromQoSDesc(qosData *models.QosData) {
	if qosData == nil {
		logger.QosLog.Warn("skipping nil QoS flow description")
		return
	}

	qfd := QoSFlowDescription{QFDLen: QFDFixLen}

	// Set QFI
	qfd.SetQoSFlowDescQfi(GetQosFlowIdFromQosId(qosData.QosId))

	// Operation Code
	qfd.SetQoSFlowDescOpCode(QFDOpCreate)

	// Create Params
	// 5QI
	qfd.AddQosFlowParam5Qi(uint8(qosData.GetVar5qi()))

	// MFBR uplink
	if rate, ok := getNullableString(qosData.MaxbrUl); ok {
		qfd.addQosFlowRateParam(rate, QFDParameterIdMfbrUl)
	}

	// MFBR downlink
	if rate, ok := getNullableString(qosData.MaxbrDl); ok {
		qfd.addQosFlowRateParam(rate, QFDParameterIdMfbrDl)
	}

	// GFBR uplink
	if rate, ok := getNullableString(qosData.GbrUl); ok {
		qfd.addQosFlowRateParam(rate, QFDParameterIdGfbrUl)
	}

	// GFBR downlink
	if rate, ok := getNullableString(qosData.GbrDl); ok {
		qfd.addQosFlowRateParam(rate, QFDParameterIdGfbrDl)
	}

	// Set E-Bit of QFD for the "create new QoS flow description" operation
	qfd.SetQFDEBitCreateNewQFD()

	// Add QFD to Authorised QFD IE
	d.AddQFD(&qfd)
}

func getNullableString(value openapi.NullableString) (string, bool) {
	if !value.IsSet() {
		return "", false
	}

	resolved := value.Get()
	if resolved == nil || strings.TrimSpace(*resolved) == "" {
		return "", false
	}

	return *resolved, true
}

func GetBitRate(sBitRate string) (val uint16, unit uint8) {
	sl := strings.Fields(sBitRate)
	if len(sl) < 2 {
		logger.QosLog.Errorf("invalid bit rate [%v]", sBitRate)
		return 0, QFBitRate1Mbps
	}

	// rate
	if rate, err := strconv.Atoi(sl[0]); err != nil {
		logger.QosLog.Errorf("invalid bit rate [%v]", sBitRate)
	} else {
		val = uint16(rate)
	}

	// Unit
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

// bits 6 to 1 of octet(00xxxxxx)
func (f *QoSFlowDescription) SetQoSFlowDescQfi(val uint8) {
	f.Qfi = QFDQfiBitmask & val
}

// Operation code -bits 8 to 6 of octet(xxx00000)
func (f *QoSFlowDescription) SetQoSFlowDescOpCode(val uint8) {
	f.OpCode = QFDOpCodeBitmask & val
}

// E-Bit Encoding
// For the "create new QoS flow description" operation,
// 1:	parameters list is included
func (f *QoSFlowDescription) SetQFDEBitCreateNewQFD() {
	f.NumOfParam |= QFDEbit
}

func (p *QosFlowParameter) SetQosFlowParamBitRate(rateType, rateUnit uint8, rateVal uint16) {
	p.ParamId = rateType //(i.e. QosFlowDescriptionParameterIdGfbrUl)
	p.ParamLen = 0x03    //(Length is rate unit(1 byte) + rate value(2 bytes))
	p.ParamContent = []byte{rateUnit}
	p.ParamContent = append(p.ParamContent, byte(rateVal>>8), byte(rateVal&0xff))
}

// Encode QoSFlowDescriptions IE
func (d *QosFlowDescriptionsAuthorized) AddQFD(qfd *QoSFlowDescription) {
	// Add QFI byte
	d.Content = append(d.Content, qfd.Qfi)

	// Add Operation Code byte
	d.Content = append(d.Content, qfd.OpCode)

	// Add Num of Param byte
	d.Content = append(d.Content, qfd.NumOfParam)

	// Iterate through Qos Flow Description's parameters
	for _, param := range qfd.ParamList {
		// Add Param Id
		d.Content = append(d.Content, param.ParamId)

		// Add Param Length
		d.Content = append(d.Content, param.ParamLen)

		// Add Param Content
		d.Content = append(d.Content, param.ParamContent...)
	}

	// Add QFD Len
	d.IeLen += uint16(qfd.QFDLen)
}

func (q *QoSFlowDescription) AddQosFlowParam5Qi(val uint8) {
	qfp := QosFlowParameter{}
	qfp.ParamId = QFDParameterId5Qi
	qfp.ParamLen = 1 // 1 Octet
	qfp.ParamContent = []byte{val}

	// Add to QosFlowDescription
	q.NumOfParam += 1
	q.ParamList = append(q.ParamList, qfp)

	q.QFDLen += 3 //(Id + Len + content)
}

func (qfd *QoSFlowDescription) addQosFlowRateParam(rate string, rateType uint8) {
	flowParam := QosFlowParameter{}
	bitRate, unit := GetBitRate(rate)
	flowParam.SetQosFlowParamBitRate(rateType, unit, bitRate)
	// Add to QosFlowDescription
	qfd.NumOfParam += 1
	qfd.ParamList = append(qfd.ParamList, flowParam)

	qfd.QFDLen += 5 //(Id-1 + len-1 + Content-3)
}

func GetQosFlowDescUpdate(pcfQosData *map[string]models.QosData, ctxtQosData map[string]*models.QosData) *QosFlowsUpdate {
	if pcfQosData == nil || len(*pcfQosData) == 0 {
		return nil
	}

	update := QosFlowsUpdate{
		add: make(map[string]*models.QosData),
		mod: make(map[string]*models.QosData),
		del: make(map[string]*models.QosData),
	}

	// Iterate through pcf qos data to identify find add/mod/del qos flows
	for name, pcfQF := range *pcfQosData {
		qosData := pcfQF
		// if pcfQF is null then rule is deleted
		if qosData.GetQosId() == "" {
			update.del[name] = &qosData // nil
			continue
		}

		// Flows to add
		if ctxtQF := ctxtQosData[name]; ctxtQF == nil {
			update.add[name] = &qosData
		} else if GetQosDataChanges(&qosData, ctxtQF) {
			update.mod[name] = &qosData
		}
	}

	return &update
}

func CommitQosFlowDescUpdate(smCtxtPolData *SmCtxtPolicyData, update *QosFlowsUpdate) {
	// Iterate through Add/Mod/Del Qos Flows

	// Add new Flows
	if len(update.add) > 0 {
		maps.Copy(smCtxtPolData.SmCtxtQosData.QosData, update.add)
	}

	// Mod flows
	// TODO

	// Del flows
	if len(update.del) > 0 {
		for name := range update.del {
			delete(smCtxtPolData.SmCtxtQosData.QosData, name)
		}
	}
}

// Compare if any change in QoS Data
func GetQosDataChanges(qf1, qf2 *models.QosData) bool {
	// TODO
	return false
}

func GetQoSDataFromPolicyDecision(smPolicyDecision *models.SmPolicyDecision, refQosData string) *models.QosData {
	if smPolicyDecision.QosDecs == nil {
		return nil
	}
	qosData, exists := (*smPolicyDecision.QosDecs)[refQosData]
	if !exists {
		return nil
	}
	return &qosData
}

func (upd *QosFlowsUpdate) GetAddQosFlowUpdate() map[string]*models.QosData {
	return upd.add
}

func GetDefaultQoSDataFromPolicyDecision(smPolicyDecision *models.SmPolicyDecision) *models.QosData {
	for _, qosData := range smPolicyDecision.GetQosDecs() {
		if qosData.GetDefQosFlowIndication() {
			return &qosData
		}
	}

	logger.QosLog.Fatalln("default Qos Data not received from PCF")
	return nil
}
