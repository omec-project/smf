// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package qos

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/omec-project/nas/nasMessage"
	"github.com/omec-project/openapi/models"
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
	// Initialize QoS Flow Descriptions structure
	QFDescriptions := QosFlowDescriptionsAuthorized{
		IeType:  nasMessage.PDUSessionEstablishmentAcceptAuthorizedQosFlowDescriptionsType,
		Content: make([]byte, 0),
	}

	qosFlowUpdate := smPolicyUpdates.QosFlowUpdate
	hasUpdates := false // Track if any QoS flows were processed

	// ===============================
	// Handle PCC rule deletions if QoS flow updates are nil
	// ===============================
	if smPolicyUpdates == nil || smPolicyUpdates.QosFlowUpdate == nil {
		logger.QosLog.Warn("smPolicyUpdates or QosFlowUpdate is nil, processing PCC rule deletions only")

		for pccRuleID := range smPolicyUpdates.PccRuleUpdate.del {
			logger.QosLog.Infof("Processing deletion for PCC rule ID: %s", pccRuleID)

			qfiVal, err := strconv.Atoi(pccRuleID)
			if err != nil {
				logger.QosLog.Errorf("Invalid QFI string for PCC rule ID '%s': %v", pccRuleID, err)
				continue
			}
			qfi := uint8(qfiVal)

			logger.QosLog.Infof("Deleting QoS Flow Description for QFI=%d (from PCC rule %s)", qfi, pccRuleID)

			// Skip if QFI is zero
			if qfi == 0 {
				logger.QosLog.Warnf("Skipping QoS Flow deletion because QFI=0 for PCC rule ID='%s'", pccRuleID)
				continue
			}

			// Build delete QoS Flow Description
			QFDescriptions.BuildDelQosFlowDescFromQoSDesc(qfi)
			hasUpdates = true
		}

		if hasUpdates {
			logger.QosLog.Infof("Completed building delete QoS flow descriptions for %d PCC rules", len(smPolicyUpdates.PccRuleUpdate.del))
		} else {
			logger.QosLog.Warn("No QoS flow deletions were processed")
		}
	}

	// ===============================
	// Handle Add/Modify/Delete QoS Flow updates
	// ===============================
	if qosFlowUpdate != nil {
		// Add QoS flows
		if len(qosFlowUpdate.add) > 0 {
			logger.QosLog.Infof("Processing %d QoS flows to add", len(qosFlowUpdate.add))
			for name, qosFlow := range qosFlowUpdate.add {
				logger.QosLog.Infof("Adding QoS Flow Description [%v]", name)
				QFDescriptions.BuildAddQosFlowDescFromQoSDesc(qosFlow)
				hasUpdates = true
			}
		}

		// Modify QoS flows
		if len(qosFlowUpdate.mod) > 0 {
			logger.QosLog.Infof("Processing %d QoS flows to modify", len(qosFlowUpdate.mod))
			for name, qosFlow := range qosFlowUpdate.mod {
				logger.QosLog.Infof("Modifying QoS Flow Description [%v]", name)
				QFDescriptions.BuildAddQosFlowDescFromQoSDesc(qosFlow)
				hasUpdates = true
			}
		}

		// Delete QoS flows
		if len(qosFlowUpdate.del) > 0 {
			logger.QosLog.Infof("Processing %d QoS flows to delete", len(qosFlowUpdate.del))
			for qfiStr := range qosFlowUpdate.del {
				qfiVal, err := strconv.Atoi(qfiStr)
				if err != nil {
					logger.QosLog.Errorf("invalid QFI string: %s, err: %v", qfiStr, err)
					continue
				}
				qfi := uint8(qfiVal)

				logger.QosLog.Infof("Deleting QoS Flow Description [QFI=%v]", qfi)
				QFDescriptions.BuildDelQosFlowDescFromQoSDesc(qfi)
				hasUpdates = true
			}
		}
	}

	// ===============================
	// Set IE length based on content
	// ===============================
	QFDescriptions.IeLen = uint16(len(QFDescriptions.Content))

	// Logging summary
	if !hasUpdates {
		logger.QosLog.Warn("No valid QoS flow updates processed, returning empty QoS flow descriptions")
	} else {
		logger.QosLog.Infof("Built QoS flow descriptions with %d bytes of content", QFDescriptions.IeLen)
	}

	return &QFDescriptions
}

// Helper function to validate QoS flow descriptions before sending
func (qfd *QosFlowDescriptionsAuthorized) IsEmpty() bool {
	return qfd.IeLen == 0 || len(qfd.Content) == 0
}

// Helper function to validate QoS flow descriptions
func (qfd *QosFlowDescriptionsAuthorized) Validate() error {
	if qfd.IeLen != uint16(len(qfd.Content)) {
		return fmt.Errorf("length mismatch: IeLen=%d, Content length=%d", qfd.IeLen, len(qfd.Content))
	}

	if qfd.IeLen == 0 {
		return fmt.Errorf("empty QoS flow descriptions")
	}

	return nil
}

func (q *QosFlowsUpdate) GetModified() map[string]*models.QosData {
	if q == nil {
		return nil
	}
	return q.mod
}

func (q *QosFlowsUpdate) GetAdded() map[string]*models.QosData {
	if q == nil {
		return nil
	}
	return q.add
}

func (q *QosFlowsUpdate) GetDeleted() map[string]*models.QosData {
	if q == nil {
		return nil
	}
	return q.del
}

// BuildAddQosFlowDescFromQoSDesc builds a new QoS Flow Description (QFD)
// for the "create new QoS flow" operation, based on QoS data from PCF.
// This is used when a new QoS flow is authorized by policy control.

func (d *QosFlowDescriptionsAuthorized) BuildAddQosFlowDescFromQoSDesc(qosData *models.QosData) {
	qfd := QoSFlowDescription{QFDLen: QFDFixLen}

	// Set QFI
	qfd.SetQoSFlowDescQfi(GetQosFlowIdFromQosId(qosData.QosId))

	// Operation Code
	qfd.SetQoSFlowDescOpCode(QFDOpCreate)

	// Create Params
	// 5QI
	qfd.AddQosFlowParam5Qi(uint8(qosData.Var5qi))

	// MFBR uplink
	if qosData.MaxbrUl != "" {
		qfd.addQosFlowRateParam(qosData.MaxbrUl, QFDParameterIdMfbrUl)
	}

	// MFBR downlink
	if qosData.MaxbrDl != "" {
		qfd.addQosFlowRateParam(qosData.MaxbrDl, QFDParameterIdMfbrDl)
	}

	// GFBR uplink
	if qosData.GbrUl != "" {
		qfd.addQosFlowRateParam(qosData.GbrUl, QFDParameterIdGfbrUl)
	}

	// GFBR downlink
	if qosData.GbrDl != "" {
		qfd.addQosFlowRateParam(qosData.GbrDl, QFDParameterIdGfbrDl)
	}

	// Set E-Bit of QFD for the "create new QoS flow description" operation
	qfd.SetQFDEBitCreateNewQFD()

	// Add QFD to Authorised QFD IE
	d.AddQFD(&qfd)
}

// BuildModQosFlowDescFromQoSDesc builds a QoS Flow Description (QFD)
// for the "modify existing QoS flow" operation, based on updated QoS data.
// Only parameters that are present and need to be modified are added.
func (d *QosFlowDescriptionsAuthorized) BuildModQosFlowDescFromQoSDesc(qosData *models.QosData) {
	qfd := QoSFlowDescription{QFDLen: QFDFixLen}

	// Set QFI
	qfd.SetQoSFlowDescQfi(GetQosFlowIdFromQosId(qosData.QosId))

	// Operation Code
	qfd.SetQoSFlowDescOpCode(QFDOpModify)
	logger.QosLog.Infof("OpCode after setting: 0x%02x\n", qfd.OpCode)

	// Modify Params - only add parameters that need to be modified
	// 5QI (if changed)
	if qosData.Var5qi != 0 {
		qfd.AddQosFlowParam5Qi(uint8(qosData.Var5qi))
	}

	// MFBR uplink (if changed)
	if qosData.MaxbrUl != "" {
		qfd.addQosFlowRateParam(qosData.MaxbrUl, QFDParameterIdMfbrUl)
	}

	// MFBR downlink (if changed)
	if qosData.MaxbrDl != "" {
		qfd.addQosFlowRateParam(qosData.MaxbrDl, QFDParameterIdMfbrDl)
	}

	// GFBR uplink (if changed)
	if qosData.GbrUl != "" {
		qfd.addQosFlowRateParam(qosData.GbrUl, QFDParameterIdGfbrUl)
	}

	// GFBR downlink (if changed)
	if qosData.GbrDl != "" {
		qfd.addQosFlowRateParam(qosData.GbrDl, QFDParameterIdGfbrDl)
	}

	// Set E-Bit of QFD for the "modify existing QoS flow description" operation
	qfd.SetQFDEBitCreateNewQFD()

	// Add QFD to Authorised QFD IE
	d.AddQFD(&qfd)
}

// BuildDelQosFlowDescFromQoSDesc builds a QoS Flow Description (QFD)
// for the "delete existing QoS flow" operation, for a given QFI.
// Unlike Add/Modify, no parameters are included in the delete operation.
func (d *QosFlowDescriptionsAuthorized) BuildDelQosFlowDescFromQoSDesc(qfi uint8) {
	logger.QosLog.Infof("Building Delete QoS Flow Description for QFI=%d", qfi)

	qfd := QoSFlowDescription{QFDLen: QFDFixLen}

	// Set QFI
	qfd.SetQoSFlowDescQfi(qfi)
	logger.QosLog.Infof("Set QFI=%d in QoSFlowDescription", qfi)

	// Operation Code = Delete existing QoS flow description
	qfd.SetQoSFlowDescOpCode(QFDOpDelete)
	logger.QosLog.Infof("Set Operation Code = Delete (%d)", QFDOpDelete)

	// No parameters, E-bit must be 0
	qfd.SetQFDEBitDeleteExistingQFD()
	logger.QosLog.Infof("Set E-bit for delete existing QoS Flow Description")

	// Append to list
	d.AddQFD(&qfd)
	logger.QosLog.Infof("Appended Delete QoS Flow Description for QFI=%d to QFDescriptions list; current total=%d", qfi, len(d.Content))
}

func GetBitRate(sBitRate string) (val uint16, unit uint8) {
	sl := strings.Fields(sBitRate)

	// rate
	// rate
	if rate, err := strconv.ParseFloat(sl[0], 64); err != nil {
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

// For the "Delete existing QoS flow description" operation
// 0:	parameters list is not included
func (f *QoSFlowDescription) SetQFDEBitDeleteExistingQFD() {
	f.NumOfParam &= ^QFDEbit
}

// For the "modify existing QoS flow description" operation
// 0:	extension of previously provided parameters
func (f *QoSFlowDescription) SetQFDEBitModExtendParamQFD() {
	f.NumOfParam &= ^QFDEbit
}

// For the "modify existing QoS flow description" operation
// 1:	replacement of all previously provided parameters
func (f *QoSFlowDescription) SetQFDEBitModReplaceAllParamQFD() {
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

func GetQosFlowDescUpdate(pcfQosData, ctxtQosData map[string]*models.QosData) *QosFlowsUpdate {
	if len(pcfQosData) == 0 {
		return nil
	}

	update := QosFlowsUpdate{
		add: make(map[string]*models.QosData),
		mod: make(map[string]*models.QosData),
		del: make(map[string]*models.QosData),
	}

	// Iterate through pcf qos data to identify find add/mod/del qos flows
	for name, pcfQF := range pcfQosData {
		// if pcfQF is null then rule is deleted
		if pcfQF == nil {
			update.del[name] = pcfQF // nil
			continue
		}

		// Flows to add
		if ctxtQF := ctxtQosData[name]; ctxtQF == nil {
			update.add[name] = pcfQF
		} else if GetQosDataChanges(pcfQF, ctxtQF) {
			update.mod[name] = pcfQF
		}
	}

	return &update
}

func CommitQosFlowDescUpdate(smCtxtPolData *SmCtxtPolicyData, update *QosFlowsUpdate) {
	// Iterate through Add/Mod/Del Qos Flows

	// Add new Flows
	if len(update.add) > 0 {
		for name, qosData := range update.add {
			smCtxtPolData.SmCtxtQosData.QosData[name] = qosData
		}
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
	if qf1 == nil || qf2 == nil {
		return true
	}

	if qf1.QosId != qf2.QosId ||
		qf1.Var5qi != qf2.Var5qi ||
		qf1.MaxbrUl != qf2.MaxbrUl ||
		qf1.MaxbrDl != qf2.MaxbrDl ||
		qf1.GbrUl != qf2.GbrUl ||
		qf1.GbrDl != qf2.GbrDl ||
		qf1.Qnc != qf2.Qnc ||
		qf1.PriorityLevel != qf2.PriorityLevel ||
		qf1.AverWindow != qf2.AverWindow ||
		qf1.MaxDataBurstVol != qf2.MaxDataBurstVol ||
		qf1.ReflectiveQos != qf2.ReflectiveQos ||
		qf1.SharingKeyDl != qf2.SharingKeyDl ||
		qf1.SharingKeyUl != qf2.SharingKeyUl ||
		qf1.MaxPacketLossRateDl != qf2.MaxPacketLossRateDl ||
		qf1.MaxPacketLossRateUl != qf2.MaxPacketLossRateUl ||
		qf1.DefQosFlowIndication != qf2.DefQosFlowIndication {
		return true
	}

	// Compare ARP separately
	if (qf1.Arp == nil) != (qf2.Arp == nil) {
		return true
	}
	if qf1.Arp != nil && qf2.Arp != nil {
		if qf1.Arp.PriorityLevel != qf2.Arp.PriorityLevel ||
			qf1.Arp.PreemptCap != qf2.Arp.PreemptCap ||
			qf1.Arp.PreemptVuln != qf2.Arp.PreemptVuln {
			return true
		}
	}

	return false
}

func GetQoSDataFromPolicyDecision(smPolicyDecision *models.SmPolicyDecision, refQosData string) *models.QosData {
	if smPolicyDecision == nil {
		logger.PduSessLog.Errorln("smPolicyDecision is nil")
		return nil
	}
	if smPolicyDecision.QosDecs == nil {
		logger.PduSessLog.Errorln("QosDecs map is nil")
		return nil
	}
	qos, exists := smPolicyDecision.QosDecs[refQosData]
	if !exists {
		logger.PduSessLog.Errorf("QoS Data [%s] not found in QosDecs. Available keys: %v", refQosData, reflect.ValueOf(smPolicyDecision.QosDecs).MapKeys())
		return nil
	}

	return qos
}

func (upd *QosFlowsUpdate) GetAddQosFlowUpdate() map[string]*models.QosData {
	return upd.add
}

func GetDefaultQoSDataFromPolicyDecision(smPolicyDecision *models.SmPolicyDecision) *models.QosData {
	for id, qosData := range smPolicyDecision.QosDecs {
		logger.QosLog.Infof("QoSData ID=%s, DefQosFlowIndication=%v, 5QI=%d", id, qosData.DefQosFlowIndication, qosData.Var5qi)
		if qosData.DefQosFlowIndication {
			return qosData
		}
	}

	logger.QosLog.Fatalln("default Qos Data not received from PCF")
	return nil
}
